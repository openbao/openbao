// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package pki

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestCNSA20_RoleEnforcement verifies that a role with cnsa_2_0=true only
// accepts ML-DSA-87 configuration and only signs ML-DSA-87 CSRs (CCSPM-6497
// CNSA 2.0 / enforced-PQC mode).
func TestCNSA20_RoleEnforcement(t *testing.T) {
	t.Parallel()
	b, s := CreateBackendWithStorage(t)

	// Post-quantum ML-DSA-87 root CA.
	_, err := CBWrite(b, s, "root/generate/internal", map[string]any{
		"common_name": "pqc-root.example.com",
		"key_type":    "mldsa",
		"key_bits":    87,
		"ttl":         "8760h",
	})
	require.NoError(t, err, "failed generating ML-DSA-87 root CA")

	// A cnsa_2_0 role with key_type=mldsa succeeds and pins key_bits to 87.
	resp, err := CBWrite(b, s, "roles/cnsa", map[string]any{
		"cnsa_2_0":       true,
		"key_type":       "mldsa",
		"allow_any_name": true,
		"require_cn":     false,
	})
	require.NoError(t, err, "cnsa role with mldsa should be accepted")
	require.EqualValues(t, 87, resp.Data["key_bits"], "cnsa role must pin key_bits=87")
	require.Equal(t, true, resp.Data["cnsa_2_0"])

	// A cnsa_2_0 role with a non-ML-DSA key type is rejected.
	_, err = CBWrite(b, s, "roles/bad-type", map[string]any{
		"cnsa_2_0": true,
		"key_type": "ec",
	})
	require.ErrorContains(t, err, "requires key_type")

	// A cnsa_2_0 role with ML-DSA but a weaker parameter set is rejected.
	_, err = CBWrite(b, s, "roles/bad-bits", map[string]any{
		"cnsa_2_0": true,
		"key_type": "mldsa",
		"key_bits": 65,
	})
	require.ErrorContains(t, err, "requires key_bits=87")

	// Signing a valid ML-DSA-87 CSR through the cnsa role succeeds and yields
	// a post-quantum certificate.
	_, _, csr87 := generateCSR(t, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "leaf.example.com"},
	}, "mldsa", 87)
	resp, err = CBWrite(b, s, "sign/cnsa", map[string]any{
		"common_name": "leaf.example.com",
		"csr":         csr87,
		"ttl":         "5m",
	})
	require.NoError(t, err, "cnsa role should sign an ML-DSA-87 CSR")
	certPem := resp.Data["certificate"].(string)
	block, _ := pem.Decode([]byte(certPem))
	require.NotNil(t, block, "expected a PEM certificate in the response")
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	require.Equal(t, x509.MLDSA, cert.PublicKeyAlgorithm, "issued cert must be ML-DSA")

	// A weaker ML-DSA-65 CSR must be rejected by the cnsa role.
	_, _, csr65 := generateCSR(t, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "leaf.example.com"},
	}, "mldsa", 65)
	_, err = CBWrite(b, s, "sign/cnsa", map[string]any{
		"common_name": "leaf.example.com",
		"csr":         csr65,
		"ttl":         "5m",
	})
	require.Error(t, err, "cnsa role must reject an ML-DSA-65 CSR")
}

// TestCNSA20_RequiresMLDSAIssuer verifies that a cnsa_2_0 role refuses to sign
// with a non-ML-DSA issuer, so the entire chain remains post-quantum.
func TestCNSA20_RequiresMLDSAIssuer(t *testing.T) {
	t.Parallel()
	b, s := CreateBackendWithStorage(t)

	// Classical EC root CA.
	_, err := CBWrite(b, s, "root/generate/internal", map[string]any{
		"common_name": "ec-root.example.com",
		"key_type":    "ec",
		"key_bits":    256,
		"ttl":         "8760h",
	})
	require.NoError(t, err, "failed generating EC root CA")

	// The role config itself is valid (ML-DSA leaf).
	_, err = CBWrite(b, s, "roles/cnsa", map[string]any{
		"cnsa_2_0":       true,
		"key_type":       "mldsa",
		"allow_any_name": true,
		"require_cn":     false,
	})
	require.NoError(t, err)

	// Signing an ML-DSA CSR against an EC issuer must fail: the chain is not
	// fully post-quantum.
	_, _, csr87 := generateCSR(t, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "leaf.example.com"},
	}, "mldsa", 87)
	_, err = CBWrite(b, s, "sign/cnsa", map[string]any{
		"common_name": "leaf.example.com",
		"csr":         csr87,
		"ttl":         "5m",
	})
	require.ErrorContains(t, err, "requires an ML-DSA issuer")
}
