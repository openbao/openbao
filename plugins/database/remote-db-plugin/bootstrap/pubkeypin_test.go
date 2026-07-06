// Copyright (c) AppsCode Inc.
// SPDX-License-Identifier: MPL-2.0

package bootstrap

import (
	"crypto/x509"
	"strings"
	"testing"
)

// generateTestCA is a small helper to get a real cert + key for the
// SPKI hash tests. Rather than re-stating x509 boilerplate inline, we lean
// on GenerateCA so any future changes to its parameters automatically
// flow into the tests.
func generateTestCA(t *testing.T) *CABundle {
	t.Helper()
	ca, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	return ca
}

func TestHashCert_FormatAndStability(t *testing.T) {
	ca := generateTestCA(t)
	cert, err := ParseCert(ca.CertPEM)
	if err != nil {
		t.Fatal(err)
	}

	pin := HashCert(cert)
	if !strings.HasPrefix(pin, PinPrefix) {
		t.Fatalf("pin %q missing %q prefix", pin, PinPrefix)
	}
	// sha256 hex = 64 chars after the prefix.
	if len(pin) != len(PinPrefix)+64 {
		t.Fatalf("pin %q has unexpected length %d", pin, len(pin))
	}
	// Stable: re-hashing the same cert yields the same pin.
	if HashCert(cert) != pin {
		t.Fatal("HashCert is not deterministic on the same input")
	}
}

func TestVerifyPin_AcceptsMatch(t *testing.T) {
	ca := generateTestCA(t)
	cert, _ := ParseCert(ca.CertPEM)
	if err := VerifyPin(cert, HashCert(cert)); err != nil {
		t.Fatalf("VerifyPin should accept its own hash: %v", err)
	}
}

func TestVerifyPin_RejectsMismatch(t *testing.T) {
	a := generateTestCA(t)
	b := generateTestCA(t)
	aCert, _ := ParseCert(a.CertPEM)
	bCert, _ := ParseCert(b.CertPEM)
	bPin := HashCert(bCert)
	if err := VerifyPin(aCert, bPin); err == nil {
		t.Fatal("VerifyPin must reject a foreign pin")
	}
}

func TestVerifyPin_RejectsMissingPrefix(t *testing.T) {
	ca := generateTestCA(t)
	cert, _ := ParseCert(ca.CertPEM)
	raw := strings.TrimPrefix(HashCert(cert), PinPrefix)
	if err := VerifyPin(cert, raw); err == nil {
		t.Fatal("VerifyPin must reject a pin without the sha256: prefix")
	}
}

func TestVerifyPin_IsCaseInsensitiveOnHex(t *testing.T) {
	ca := generateTestCA(t)
	cert, _ := ParseCert(ca.CertPEM)
	pin := HashCert(cert)
	upper := strings.ToUpper(strings.TrimPrefix(pin, PinPrefix))
	if err := VerifyPin(cert, PinPrefix+upper); err != nil {
		t.Fatalf("VerifyPin should tolerate uppercase hex: %v", err)
	}
}

// keep the x509 import used even if the file evolves
var _ = (*x509.Certificate)(nil)
