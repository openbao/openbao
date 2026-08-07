// Copyright (c) AppsCode Inc.
// SPDX-License-Identifier: MPL-2.0

package bootstrap

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"strings"
	"testing"
	"time"
)

func generateTestCSR(t *testing.T, cn string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestSignSpokeCSR_HappyPath(t *testing.T) {
	ca, err := GenerateCA()
	if err != nil {
		t.Fatal(err)
	}
	csrDER := generateTestCSR(t, "spoke-1")
	certPEM, err := ca.SignSpokeCSR(csrDER, "spoke-1", 24*time.Hour)
	if err != nil {
		t.Fatalf("SignSpokeCSR: %v", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("no PEM block in signed cert")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "spoke-1" {
		t.Errorf("CN = %q, want spoke-1", cert.Subject.CommonName)
	}
	// O must be the fixed SpokeCertOrganization — operators cannot inject
	// their own O via the CSR.
	if got := cert.Subject.Organization; len(got) != 1 || got[0] != SpokeCertOrganization {
		t.Errorf("O = %v, want [%s]", got, SpokeCertOrganization)
	}
	// Validity should be ~24h from now, give or take the 5m back-date.
	if d := time.Until(cert.NotAfter); d < 23*time.Hour || d > 25*time.Hour {
		t.Errorf("NotAfter is %s away; want ~24h", d)
	}
	// ExtKeyUsage must be ClientAuth so the cert can only be used for mTLS.
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Errorf("ExtKeyUsage = %v, want [ClientAuth]", cert.ExtKeyUsage)
	}

	// And the resulting cert must verify against the CA.
	caCert, err := ParseCert(ca.CertPEM)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("verify against CA: %v", err)
	}
}

func TestSignSpokeCSR_RejectsCNMismatch(t *testing.T) {
	ca, _ := GenerateCA()
	csrDER := generateTestCSR(t, "attacker")
	_, err := ca.SignSpokeCSR(csrDER, "spoke-1", time.Hour)
	if err == nil {
		t.Fatal("CN mismatch must be rejected")
	}
	if !strings.Contains(err.Error(), "CN") {
		t.Fatalf("expected CN error, got %v", err)
	}
}

func TestSignSpokeCSR_RejectsGarbageCSR(t *testing.T) {
	ca, _ := GenerateCA()
	if _, err := ca.SignSpokeCSR([]byte("not a CSR"), "spoke-1", time.Hour); err == nil {
		t.Fatal("garbage CSR must be rejected")
	}
}

func TestSignSpokeCSR_DefaultsZeroTTL(t *testing.T) {
	ca, _ := GenerateCA()
	csrDER := generateTestCSR(t, "spoke-1")
	certPEM, err := ca.SignSpokeCSR(csrDER, "spoke-1", 0)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := ParseCert(certPEM)
	if d := time.Until(cert.NotAfter); d < 29*24*time.Hour || d > 31*24*time.Hour {
		t.Errorf("zero TTL should yield ~30d cert; got %s", d)
	}
}

func TestGenerateCA_RootHasIsCAAndMaxPathZero(t *testing.T) {
	ca, _ := GenerateCA()
	caCert, _ := ParseCert(ca.CertPEM)
	if !caCert.IsCA {
		t.Error("root CA must have IsCA=true")
	}
	if !caCert.MaxPathLenZero {
		t.Error("root CA must have MaxPathLenZero so no subordinate CAs can be issued")
	}
}
