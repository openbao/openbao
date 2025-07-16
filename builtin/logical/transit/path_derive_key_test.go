// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package transit

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"strconv"
	"strings"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
)

// Nominal workflow for ECDH key agreement between Alice and Bob.
func TestTransit_ECDH_NominalCase(t *testing.T) {
	t.Parallel()

	nonce := make([]byte, 8)
	rand.Read(nonce)
	nonceBase64 := base64.StdEncoding.EncodeToString(nonce)

	transit_ECDH_NominalCase(t, "ecdsa-p256", "", "", "", true)
	transit_ECDH_NominalCase(t, "ecdsa-p256", "", nonceBase64, nonceBase64, true)

	transit_ECDH_NominalCase(t, "ecdsa-p256", "aes128-gcm96", "", "", true)
	transit_ECDH_NominalCase(t, "ecdsa-p256", "aes128-gcm96", nonceBase64, nonceBase64, true)
	transit_ECDH_NominalCase(t, "ecdsa-p384", "aes128-gcm96", "", "", true)
	transit_ECDH_NominalCase(t, "ecdsa-p384", "aes128-gcm96", nonceBase64, nonceBase64, true)
	transit_ECDH_NominalCase(t, "ecdsa-p521", "aes128-gcm96", "", "", true)
	transit_ECDH_NominalCase(t, "ecdsa-p521", "aes128-gcm96", nonceBase64, nonceBase64, true)

	nonce = make([]byte, 16)
	rand.Read(nonce)
	nonceBase64 = base64.StdEncoding.EncodeToString(nonce)

	transit_ECDH_NominalCase(t, "ecdsa-p256", "aes256-gcm96", "", "", true)
	transit_ECDH_NominalCase(t, "ecdsa-p256", "aes256-gcm96", nonceBase64, nonceBase64, true)
	transit_ECDH_NominalCase(t, "ecdsa-p384", "aes256-gcm96", "", "", true)
	transit_ECDH_NominalCase(t, "ecdsa-p384", "aes256-gcm96", nonceBase64, nonceBase64, true)
	transit_ECDH_NominalCase(t, "ecdsa-p521", "aes256-gcm96", "", "", true)
	transit_ECDH_NominalCase(t, "ecdsa-p521", "aes256-gcm96", nonceBase64, nonceBase64, true)

	nonce = make([]byte, 32)
	rand.Read(nonce)
	nonceBase64 = base64.StdEncoding.EncodeToString(nonce)

	nonce = make([]byte, 32)
	rand.Read(nonce)
	nonceBobBase64 := base64.StdEncoding.EncodeToString(nonce)

	transit_ECDH_NominalCase(t, "ecdsa-p256", "chacha20-poly1305", "", "", true)
	transit_ECDH_NominalCase(t, "ecdsa-p256", "chacha20-poly1305", nonceBase64, nonceBase64, true)
	transit_ECDH_NominalCase(t, "ecdsa-p384", "chacha20-poly1305", "", "", true)
	transit_ECDH_NominalCase(t, "ecdsa-p384", "chacha20-poly1305", nonceBase64, nonceBase64, true)
	transit_ECDH_NominalCase(t, "ecdsa-p521", "chacha20-poly1305", "", "", true)
	transit_ECDH_NominalCase(t, "ecdsa-p521", "chacha20-poly1305", nonceBase64, nonceBase64, true)
	transit_ECDH_NominalCase(t, "ecdsa-p521", "chacha20-poly1305", nonceBase64, nonceBobBase64, false)

	nonce = make([]byte, 64)
	rand.Read(nonce)
	nonceBase64 = base64.StdEncoding.EncodeToString(nonce)

	nonce = make([]byte, 64)
	rand.Read(nonce)
	nonceBobBase64 = base64.StdEncoding.EncodeToString(nonce)

	transit_ECDH_NominalCase(t, "ecdsa-p256", "xchacha20-poly1305", "", "", true)
	transit_ECDH_NominalCase(t, "ecdsa-p256", "xchacha20-poly1305", nonceBase64, nonceBase64, true)
	transit_ECDH_NominalCase(t, "ecdsa-p256", "xchacha20-poly1305", nonceBase64, nonceBobBase64, false)
	transit_ECDH_NominalCase(t, "ecdsa-p384", "xchacha20-poly1305", "", "", true)
	transit_ECDH_NominalCase(t, "ecdsa-p384", "xchacha20-poly1305", nonceBase64, nonceBase64, true)
	transit_ECDH_NominalCase(t, "ecdsa-p521", "xchacha20-poly1305", "", "", true)
	transit_ECDH_NominalCase(t, "ecdsa-p521", "xchacha20-poly1305", nonceBase64, nonceBase64, true)
}

func transit_ECDH_NominalCase(t *testing.T, baseKeyType string, derivedKeyType string, nonceAlice string, nonceBob string, isSuccess bool) {
	var resp *logical.Response
	var err error

	b, s := createBackendWithStorage(t)

	// Generate Alice EC key pair
	policyReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "keys/alice_ec_key",
		Data: map[string]interface{}{
			"type": baseKeyType,
		},
		Storage: s,
	}
	resp, err = b.HandleRequest(context.Background(), policyReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	// Export Alice's public key
	exportReq := &logical.Request{
		Storage:   s,
		Operation: logical.ReadOperation,
		Path:      "export/public-key/alice_ec_key",
		Data: map[string]interface{}{
			"format": "pem",
		},
	}

	resp, err = b.HandleRequest(context.Background(), exportReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	keysRaw, ok := resp.Data["keys"]
	if !ok {
		t.Fatal("could not find keys value")
	}
	keys, ok := keysRaw.(map[string]string)
	if !ok {
		t.Fatal("could not cast to keys map")
	}
	if len(keys) != 1 {
		t.Fatal("unexpected number of keys found")
	}

	publicKeyAlice := keys[strconv.Itoa(1)]
	if publicKeyAlice == "" {
		t.Fatalf("error getting pem public key")
	}

	// Generate Bob EC key pair
	policyReq = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "keys/bob_ec_key",
		Data: map[string]interface{}{
			"type": baseKeyType,
		},
		Storage: s,
	}
	resp, err = b.HandleRequest(context.Background(), policyReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	// Export Bob's public key
	exportReq = &logical.Request{
		Storage:   s,
		Operation: logical.ReadOperation,
		Path:      "export/public-key/bob_ec_key",
		Data: map[string]interface{}{
			"format": "pem",
		},
	}

	resp, err = b.HandleRequest(context.Background(), exportReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	keysRaw, ok = resp.Data["keys"]
	if !ok {
		t.Fatal("could not find keys value")
	}
	keys, ok = keysRaw.(map[string]string)
	if !ok {
		t.Fatal("could not cast to keys map")
	}
	if len(keys) != 1 {
		t.Fatal("unexpected number of keys found")
	}

	publicKeyBob := keys[strconv.Itoa(1)]
	if publicKeyBob == "" {
		t.Fatalf("error getting pem public key")
	}

	// Alice key derivation: she uses her private key and Bob's public key for getting a symmetric key
	policyReq = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "derive-key/alice_derived_key",
		Data: map[string]interface{}{
			"key_derivation_algorithm": "ecdh",
			"peer_public_key":          publicKeyBob,
			"base_key_name":            "alice_ec_key",
		},
		Storage: s,
	}

	if len(derivedKeyType) > 0 {
		policyReq.Data["derived_key_type"] = derivedKeyType
	}

	if len(nonceAlice) > 0 {
		policyReq.Data["nonce"] = nonceAlice
	}

	resp, err = b.HandleRequest(context.Background(), policyReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	// Alice encrypts some data using the symmetric key generated by ECDH derivation
	plaintext := "dGhlIHF1aWNrIGJyb3duIGZveA==" // "the quick brown fox"

	encData := map[string]interface{}{
		"plaintext": plaintext,
	}

	encReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "encrypt/alice_derived_key",
		Storage:   s,
		Data:      encData,
	}
	resp, err = b.HandleRequest(context.Background(), encReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	keyVersion := resp.Data["key_version"].(int)
	if keyVersion != 1 {
		t.Fatalf("unexpected key version; got: %d, expected: %d", keyVersion, 1)
	}

	ciphertext := resp.Data["ciphertext"]

	// Bob key derivation: he uses his private key and Alice's public key for getting a symmetric key (the same as Alice's)
	policyReq = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "derive-key/bob_derived_key",
		Data: map[string]interface{}{
			"key_derivation_algorithm": "ecdh",
			"peer_public_key":          publicKeyAlice,
			"base_key_name":            "bob_ec_key",
		},
		Storage: s,
	}

	if len(derivedKeyType) > 0 {
		policyReq.Data["derived_key_type"] = derivedKeyType
	}

	if len(nonceBob) > 0 {
		policyReq.Data["nonce"] = nonceBob
	}

	resp, err = b.HandleRequest(context.Background(), policyReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	// Bob decrypts data encrypted by Alice using the symmetric key generated by ECDH derivation (the same as Alice's)
	decData := map[string]interface{}{
		"ciphertext": ciphertext,
	}
	decReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "decrypt/bob_derived_key",
		Storage:   s,
		Data:      decData,
	}
	resp, err = b.HandleRequest(context.Background(), decReq)
	if err != nil || (resp != nil && resp.IsError()) {
		// Warning: the string "message authentication failed" may change over the time in the underlying implementation and therefore falsely trigger a failed test!
		if !isSuccess && strings.Contains(resp.Error().Error(), "message authentication failed") {
			// Expected failure, return early
			return
		}

		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	if isSuccess {
		if resp.Data["plaintext"] != plaintext {
			t.Fatalf("bad: plaintext. Expected: %q, Actual: %q", plaintext, resp.Data["plaintext"])
		}
	} else {
		// This is for non-authencticated encryption algorithms, where the decryption may fail because of a wrong nonce.
		if resp.Data["plaintext"] == plaintext {
			t.Fatal("bad: expecting decryption to fail, but it succeeded")
		}
	}
}
