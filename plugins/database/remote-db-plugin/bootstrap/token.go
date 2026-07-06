// Copyright (c) AppsCode Inc.
// SPDX-License-Identifier: MPL-2.0

// Package bootstrap implements the kubeadm-style trust-bootstrap primitives
// used by `bao relay init` and `bao relay join`:
//
//   - bootstrap token format <6-char-id>.<16-char-secret>
//   - detached JWS-HS256 over cluster-info, keyed by the token secret
//   - SPKI SHA-256 pinning of the hub CA certificate
//
// None of the helpers here touch storage or OpenBao APIs; the logical backend
// composes them with persisted state.
package bootstrap

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

const (
	TokenIDBytes     = 3 // 6 hex chars
	TokenSecretBytes = 8 // 16 hex chars

	TokenIDLen     = 6
	TokenSecretLen = 16
)

// TokenPattern matches `abcdef.0123456789abcdef`.
var TokenPattern = regexp.MustCompile(`^([a-z0-9]{6})\.([a-z0-9]{16})$`)

// TokenIDPattern matches just the id half. Used by paths that take token_id
// as an unauthenticated query parameter, so we can reject obviously-malformed
// input before touching storage and limit how cheap brute-force probes are.
var TokenIDPattern = regexp.MustCompile(`^[a-z0-9]{6}$`)

// ValidTokenID reports whether s is a syntactically-valid token id.
func ValidTokenID(s string) bool { return TokenIDPattern.MatchString(s) }

// Token holds the parsed halves of a bootstrap token.
type Token struct {
	ID     string
	Secret string
}

// String returns the canonical `<id>.<secret>` form.
func (t Token) String() string {
	return t.ID + "." + t.Secret
}

// ParseToken validates and splits a token string.
func ParseToken(s string) (Token, error) {
	m := TokenPattern.FindStringSubmatch(s)
	if m == nil {
		return Token{}, fmt.Errorf("token %q does not match %q", s, TokenPattern.String())
	}
	return Token{ID: m[1], Secret: m[2]}, nil
}

// GenerateToken returns a fresh token using crypto/rand.
func GenerateToken() (Token, error) {
	id, err := randomHex(TokenIDBytes)
	if err != nil {
		return Token{}, err
	}
	secret, err := randomHex(TokenSecretBytes)
	if err != nil {
		return Token{}, err
	}
	return Token{ID: id, Secret: secret}, nil
}

func randomHex(n int) (string, error) {
	buf := make([]byte, n)
	if _, ok := readRand(buf); !ok {
		return "", fmt.Errorf("rand read failed")
	}
	const hex = "0123456789abcdef"
	out := make([]byte, n*2)
	for i, b := range buf {
		out[2*i] = hex[b>>4]
		out[2*i+1] = hex[b&0x0f]
	}
	return string(out), nil
}

func readRand(buf []byte) (int, bool) {
	n, err := rand.Read(buf)
	return n, err == nil && n == len(buf)
}

// ConstantTimeEqualSecret compares two token secrets without leaking timing,
// including the length-mismatch case. subtle.ConstantTimeCompare returns 0
// quickly when len(a) != len(b), which would let a remote caller distinguish
// "wrong-length secret" from "right-length, wrong content" via response
// timing. Pad both inputs into a fixed-size buffer and fold a constant-time
// length-equal flag into the result so any of (a != b, len(a) != len(b),
// either side longer than TokenSecretLen) returns false in the same time
// envelope as a right-length-wrong-content compare.
func ConstantTimeEqualSecret(a, b string) bool {
	var pa, pb [TokenSecretLen]byte
	copy(pa[:], a)
	copy(pb[:], b)
	contentEq := subtle.ConstantTimeCompare(pa[:], pb[:])
	lenEq := subtle.ConstantTimeEq(int32(len(a)), int32(len(b)))
	// Either side larger than the buffer would truncate-and-match in the
	// content compare; reject so we never silently accept a longer string
	// whose first TokenSecretLen bytes happen to match.
	aFits := subtle.ConstantTimeLessOrEq(len(a), TokenSecretLen)
	bFits := subtle.ConstantTimeLessOrEq(len(b), TokenSecretLen)
	return contentEq&lenEq&aFits&bFits == 1
}

// --- Detached JWS (HS256) -----------------------------------------------------

// jwsHeader is the static header used for all signatures. We pin alg=HS256 and
// include the token id as `kid` so a verifier can look up which secret to use.
type jwsHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

// SignDetached produces a detached JWS-HS256 signature over payload using the
// token's secret half. Output format mirrors kubeadm:
//
//	<base64url(header)>..<base64url(signature)>
//
// The payload itself is not embedded; verifiers must already hold the bytes.
func SignDetached(tok Token, payload []byte) (string, error) {
	h, err := json.Marshal(jwsHeader{Alg: "HS256", Kid: tok.ID})
	if err != nil {
		return "", err
	}
	encHeader := base64URL(h)
	signingInput := encHeader + "." + base64URL(payload)

	mac := hmac.New(sha256.New, []byte(tok.Secret))
	mac.Write([]byte(signingInput))
	sig := mac.Sum(nil)

	return encHeader + ".." + base64URL(sig), nil
}

// VerifyDetached verifies that detached was produced by SignDetached with the
// given token secret over the given payload. Returns nil if the signature is
// valid. Constant-time on the signature comparison.
func VerifyDetached(secret string, payload []byte, detached string) error {
	parts := strings.SplitN(detached, "..", 2)
	if len(parts) != 2 {
		return fmt.Errorf("detached JWS is not in <header>..<signature> form")
	}
	headerB64, sigB64 := parts[0], parts[1]

	headerBytes, err := base64URLDecode(headerB64)
	if err != nil {
		return fmt.Errorf("decode header: %w", err)
	}
	var hdr jwsHeader
	if err := json.Unmarshal(headerBytes, &hdr); err != nil {
		return fmt.Errorf("parse header: %w", err)
	}
	if hdr.Alg != "HS256" {
		return fmt.Errorf("unexpected alg %q (want HS256)", hdr.Alg)
	}

	expectedSig, err := base64URLDecode(sigB64)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(headerB64 + "." + base64URL(payload)))
	computed := mac.Sum(nil)

	if !hmac.Equal(expectedSig, computed) {
		return fmt.Errorf("JWS signature mismatch")
	}
	return nil
}

func base64URL(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func base64URLDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}
