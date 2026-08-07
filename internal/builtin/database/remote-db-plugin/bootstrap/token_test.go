// Copyright (c) AppsCode Inc.
// SPDX-License-Identifier: MPL-2.0

package bootstrap

import (
	"strings"
	"testing"
)

func TestParseToken_Valid(t *testing.T) {
	tok, err := ParseToken("abcdef.0123456789abcdef")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok.ID != "abcdef" || tok.Secret != "0123456789abcdef" {
		t.Fatalf("got id=%q secret=%q", tok.ID, tok.Secret)
	}
}

func TestParseToken_Invalid(t *testing.T) {
	for _, s := range []string{
		"",
		"abcdef",                   // no dot
		"abcde.0123456789abcdef",   // id too short
		"abcdefg.0123456789abcdef", // id too long
		"abcdef.0123456789abcde",   // secret too short
		"ABCDEF.0123456789abcdef",  // uppercase id
		"abcdef.0123456789ABCDEF",  // uppercase secret
		"abc-ef.0123456789abcdef",  // illegal char
	} {
		if _, err := ParseToken(s); err == nil {
			t.Errorf("ParseToken(%q) should have failed", s)
		}
	}
}

func TestGenerateToken_Format(t *testing.T) {
	tok, err := GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	if !TokenPattern.MatchString(tok.String()) {
		t.Fatalf("generated token %q doesn't match pattern", tok.String())
	}
}

func TestValidTokenID(t *testing.T) {
	if !ValidTokenID("abcdef") {
		t.Error("abcdef should be valid")
	}
	for _, s := range []string{"", "ABCDEF", "abcde", "abcdefg", "abc-ef", "abc def"} {
		if ValidTokenID(s) {
			t.Errorf("%q should be rejected", s)
		}
	}
}

func TestJWS_VerifySucceedsOnMatch(t *testing.T) {
	tok, _ := GenerateToken()
	payload := []byte("hello world")
	sig, err := SignDetached(tok, payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyDetached(tok.Secret, payload, sig); err != nil {
		t.Fatalf("verify should succeed: %v", err)
	}
}

func TestJWS_RejectsTamperedPayload(t *testing.T) {
	tok, _ := GenerateToken()
	sig, _ := SignDetached(tok, []byte("original"))
	if err := VerifyDetached(tok.Secret, []byte("tampered"), sig); err == nil {
		t.Fatal("verify must fail for tampered payload")
	}
}

func TestJWS_RejectsWrongSecret(t *testing.T) {
	tok, _ := GenerateToken()
	sig, _ := SignDetached(tok, []byte("payload"))
	if err := VerifyDetached("wrong-secret-1234", []byte("payload"), sig); err == nil {
		t.Fatal("verify must fail with wrong secret")
	}
}

func TestJWS_RejectsAlgorithmDowngrade(t *testing.T) {
	// "eyJhbGciOiJub25lIn0" = base64url("{"alg":"none"}").
	bogus := "eyJhbGciOiJub25lIiwia2lkIjoiYWJjZGVmIn0..AAAA"
	if err := VerifyDetached("anysecret1234567", []byte("payload"), bogus); err == nil {
		t.Fatal("verify must reject alg!=HS256")
	} else if !strings.Contains(err.Error(), "alg") {
		t.Fatalf("expected alg error, got %v", err)
	}
}

func TestJWS_RejectsMalformedDetached(t *testing.T) {
	for _, s := range []string{
		"",
		"only-one-part",
		"header.payload.sig", // wrong separator
		"not-base64..xxxx",
	} {
		if err := VerifyDetached("1234567890abcdef", []byte("p"), s); err == nil {
			t.Errorf("VerifyDetached(%q) should fail", s)
		}
	}
}

func TestConstantTimeEqualSecret(t *testing.T) {
	if !ConstantTimeEqualSecret("abc", "abc") {
		t.Error("equal strings should compare equal")
	}
	if ConstantTimeEqualSecret("abc", "abd") {
		t.Error("different strings should not compare equal")
	}
	if ConstantTimeEqualSecret("abc", "abcd") {
		t.Error("different lengths should not compare equal")
	}
}
