// Copyright (c) AppsCode Inc.
// SPDX-License-Identifier: MPL-2.0

package bootstrap

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"
)

// minRSABits is the floor for any RSA public key presented in a CSR. ECDSA
// curves are accepted regardless of curve size — Go's x509 already rejects
// anything below P-224.
const minRSABits = 2048

// reservedSpokeCNs lists CNs that may never appear as a spoke identity.
// Signing one would let a malicious spoke present a cert that aliases the
// hub itself or the CA, allowing identity confusion at the mTLS layer.
var reservedSpokeCNs = map[string]struct{}{
	"openbao-hub":      {},
	"openbao-spoke-ca": {},
}

const (
	// SpokeCertOrganization is the O= value put into every issued spoke cert.
	// The hub uses this to distinguish bootstrap-issued certs from any other
	// client cert that might be presented.
	SpokeCertOrganization = "openbao-spokes"

	// HubCertOrganization is the O= for the hub TLS cert that serves the gRPC
	// proxy port.
	HubCertOrganization = "openbao-hub"

	// MsgCAAlreadyInitialized is the canonical prefix the relay backend
	// returns when ca/init is called without force on an already-initialized
	// mount. Both the backend and the CLI (`bao relay init` idempotence
	// check) reference this constant so the CLI does not pattern-match
	// against a free-floating string literal.
	MsgCAAlreadyInitialized = "CA already initialized"

	caCertValidity   = 10 * 365 * 24 * time.Hour // 10 years
	hubCertValidity  = 365 * 24 * time.Hour      // 1 year
	spokeCertDefault = 30 * 24 * time.Hour       // 30 days
)

// CABundle is the spoke-CA root: a self-signed cert plus its private key.
// Both are PEM-encoded so storage and over-the-wire serialization are trivial.
type CABundle struct {
	CertPEM []byte
	KeyPEM  []byte
}

// HubServerCert is the TLS cert presented by the hub on its gRPC listener.
// Signed by the spoke-CA so that spokes only have to trust one root.
type HubServerCert struct {
	CertPEM []byte
	KeyPEM  []byte
}

// GenerateCA creates a fresh self-signed ECDSA P-256 root CA valid for ~10 years.
func GenerateCA() (*CABundle, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ca key: %w", err)
	}

	serial, err := randSerial()
	if err != nil {
		return nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "openbao-spoke-ca",
			Organization: []string{SpokeCertOrganization},
		},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().Add(caCertValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("self-sign ca: %w", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal ca key: %w", err)
	}

	return &CABundle{
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		KeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	}, nil
}

// IssueHubServerCert signs a server cert valid for the hub gRPC listener. The
// cert advertises the given DNS names and IP SANs.
func (ca *CABundle) IssueHubServerCert(dnsNames []string, ipSANs []string) (*HubServerCert, error) {
	caCert, caKey, err := ca.parse()
	if err != nil {
		return nil, err
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	serial, err := randSerial()
	if err != nil {
		return nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "openbao-hub",
			Organization: []string{HubCertOrganization},
		},
		NotBefore:   time.Now().Add(-5 * time.Minute),
		NotAfter:    time.Now().Add(hubCertValidity),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    dnsNames,
		IPAddresses: parseIPs(ipSANs),
		// Make the leaf's non-CA status explicit. Without
		// BasicConstraintsValid=true the BasicConstraints extension is
		// omitted entirely, and some non-Go verifiers will then accept a
		// leaf-without-BC as a CA. We don't ever want this cert to chain
		// further.
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("sign hub cert: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}

	return &HubServerCert{
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		KeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	}, nil
}

// SignSpokeCSR verifies a spoke-submitted CSR, enforces the requested CN, and
// returns a signed client cert valid for `validity`. The CN is the
// authoritative spoke identity used by the proxy gRPC server.
//
// We treat the CSR as fully untrusted input:
//   - the public key algorithm is pinned (ECDSA, or RSA >= 2048),
//   - the CN is checked AND denylisted against reserved names so a malicious
//     spoke cannot ask for a cert that aliases the hub or the CA itself,
//   - any SANs (DNS / IP / URI / email) or extra X.509 extensions cause
//     immediate rejection. We do not copy these into the issued cert today,
//     so they are inert — but a future edit that does start copying them
//     would silently turn this hole on.
func (ca *CABundle) SignSpokeCSR(csrDER []byte, expectedCN string, validity time.Duration) ([]byte, error) {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, fmt.Errorf("parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR signature: %w", err)
	}
	if csr.Subject.CommonName != expectedCN {
		return nil, fmt.Errorf("CSR CN %q does not match expected %q",
			csr.Subject.CommonName, expectedCN)
	}
	if _, reserved := reservedSpokeCNs[expectedCN]; reserved {
		return nil, fmt.Errorf("CN %q is reserved; cannot issue spoke cert with this identity", expectedCN)
	}
	switch pub := csr.PublicKey.(type) {
	case *ecdsa.PublicKey:
		// Any P-curve. We use P-256 ourselves; the curve check belongs to
		// Go's x509 parser which already rejects pathologically small curves.
	case *rsa.PublicKey:
		if bits := pub.N.BitLen(); bits < minRSABits {
			return nil, fmt.Errorf("CSR RSA key is %d bits; require >= %d", bits, minRSABits)
		}
	default:
		return nil, fmt.Errorf("CSR public key algorithm %T is not supported", csr.PublicKey)
	}
	if len(csr.DNSNames) > 0 || len(csr.IPAddresses) > 0 ||
		len(csr.URIs) > 0 || len(csr.EmailAddresses) > 0 {
		return nil, fmt.Errorf("CSR must not include SANs")
	}
	if len(csr.ExtraExtensions) > 0 {
		// csr.Extensions reflects everything parsed (incl. the SAN extension
		// covered above). ExtraExtensions is the explicit "smuggle these
		// through" channel — BasicConstraints, EKU, etc. — that a future
		// edit that copies it into the template would honor. Refuse outright.
		return nil, fmt.Errorf("CSR must not include extra X.509 extensions")
	}

	caCert, caKey, err := ca.parse()
	if err != nil {
		return nil, err
	}

	if validity <= 0 {
		validity = spokeCertDefault
	}
	serial, err := randSerial()
	if err != nil {
		return nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   expectedCN,
			Organization: []string{SpokeCertOrganization},
		},
		NotBefore:   time.Now().Add(-5 * time.Minute),
		NotAfter:    time.Now().Add(validity),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		// Explicit non-CA leaf. See IssueHubServerCert for the rationale —
		// the BC extension must be present and IsCA must be false so no
		// non-Go verifier can mis-interpret this as a sub-CA.
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, csr.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("sign spoke cert: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// parse decodes the CA cert + key from PEM. Cached lazily would be nicer, but
// the CA is touched at most once per join, so we keep this stateless.
func (ca *CABundle) parse() (*x509.Certificate, *ecdsa.PrivateKey, error) {
	certBlock, err := decodeSinglePEM(ca.CertPEM, "CERTIFICATE")
	if err != nil {
		return nil, nil, fmt.Errorf("ca cert: %w", err)
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse ca cert: %w", err)
	}

	keyBlock, err := decodeSinglePEM(ca.KeyPEM, "EC PRIVATE KEY")
	if err != nil {
		return nil, nil, fmt.Errorf("ca key: %w", err)
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse ca key: %w", err)
	}
	return cert, key, nil
}

// ParseCert returns the parsed leaf cert from a PEM-encoded chain (first block).
func ParseCert(certPEM []byte) (*x509.Certificate, error) {
	block, err := decodeSinglePEM(certPEM, "CERTIFICATE")
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(block.Bytes)
}

// decodeSinglePEM decodes a PEM blob and asserts that
//  1. there is exactly one block (no trailing junk), and
//  2. its Type matches one of expectedTypes.
//
// pem.Decode by itself silently skips trailing data and accepts any Type,
// which would let an attacker piggyback a second block (e.g. a fake CA after
// a legit cert) or substitute an unrelated block type for the same bytes
// (e.g. "EC PRIVATE KEY" disguised as "PUBLIC KEY").
func decodeSinglePEM(data []byte, expectedTypes ...string) (*pem.Block, error) {
	block, rest := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("PEM decode returned no block")
	}
	matched := false
	for _, t := range expectedTypes {
		if block.Type == t {
			matched = true
			break
		}
	}
	if !matched {
		return nil, fmt.Errorf("PEM block type %q, want one of %q", block.Type, expectedTypes)
	}
	// Trailing whitespace / line endings around the block are normal; trailing
	// non-whitespace is another block we did not expect.
	for _, b := range rest {
		if b != ' ' && b != '\t' && b != '\n' && b != '\r' {
			return nil, fmt.Errorf("trailing data after PEM block")
		}
	}
	return block, nil
}

// DecodeCSRPEM returns the DER bytes of a PEM-encoded PKCS#10 CSR. Accepts
// both "CERTIFICATE REQUEST" and the legacy "NEW CERTIFICATE REQUEST" block
// types. Uses the same strict single-block decode as the rest of the
// package, so trailing data or block-type substitution is rejected outright.
//
// Shared between relay/sign-csr (the unauthenticated bootstrap path) and
// proxy.RenewCert (the mTLS-authenticated renewal RPC) so both entry points
// stay aligned on what counts as a valid CSR envelope.
func DecodeCSRPEM(csrPEM []byte) ([]byte, error) {
	block, err := decodeSinglePEM(csrPEM, "CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST")
	if err != nil {
		return nil, fmt.Errorf("csr_pem: %w", err)
	}
	return block.Bytes, nil
}

// randSerial returns a 128-bit positive integer for use as a cert serial.
// rand.Int returns values in [0, max), so a zero result is rare but possible
// — RFC 5280 §4.1.2.2 requires positive serials, and strict verifiers reject
// zero. Bump zero to one rather than looping; the probability is 1 in 2^128.
func randSerial() (*big.Int, error) {
	max := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return nil, err
	}
	if n.Sign() == 0 {
		n.SetInt64(1)
	}
	return n, nil
}

func parseIPs(s []string) []net.IP {
	out := make([]net.IP, 0, len(s))
	for _, x := range s {
		if ip := net.ParseIP(x); ip != nil {
			out = append(out, ip)
		}
	}
	return out
}
