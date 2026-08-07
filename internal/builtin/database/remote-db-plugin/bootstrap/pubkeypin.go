// Copyright (c) AppsCode Inc.
// SPDX-License-Identifier: MPL-2.0

package bootstrap

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"log"
	"strings"
)

// PinPrefix is the only hash algorithm we support for CA cert pinning, matching
// kubeadm's `--discovery-token-ca-cert-hash sha256:<hex>` flag.
const PinPrefix = "sha256:"

// HashCert returns the kubeadm-compatible pin for cert: lower-case hex of
// SHA-256 over the DER-encoded SubjectPublicKeyInfo, prefixed with "sha256:".
//
// We hash the SPKI (not the full cert) so a CA rotated to a new cert with the
// same key still validates — the public key is the trust anchor.
func HashCert(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return PinPrefix + strings.ToLower(hex.EncodeToString(sum[:]))
}

// VerifyPin checks that cert matches a pin produced by HashCert.
//
// The byte compare is constant-time. The hash itself isn't a secret, but
// pin verification runs against attacker-controlled `pin` values during
// `bao relay join` — a string `!=` compare leaks which prefix bytes
// matched, letting a malicious cluster-info server grind a colliding pin
// one byte at a time. The error returned to callers is generic; the
// computed hash (which would hand the grinder the answer outright) is
// logged locally instead.
func VerifyPin(cert *x509.Certificate, pin string) error {
	if !strings.HasPrefix(pin, PinPrefix) {
		return fmt.Errorf("pin %q missing %q prefix", pin, PinPrefix)
	}
	expected := strings.ToLower(strings.TrimPrefix(pin, PinPrefix))
	actual := strings.TrimPrefix(HashCert(cert), PinPrefix)
	if subtle.ConstantTimeCompare([]byte(expected), []byte(actual)) != 1 {
		log.Printf("[bootstrap] SPKI pin mismatch: expected %s, computed %s", expected, actual)
		return fmt.Errorf("hub CA cert SPKI hash does not match pin")
	}
	return nil
}
