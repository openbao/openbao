// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package transit

import (
	"context"
	"fmt"
	"strconv"
	"testing"

	uuid "github.com/hashicorp/go-uuid"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// Case1: nominal workflow for ECDH key agreement between Alice and Bob.
func TestTransit_ECDHCase1(t *testing.T) {
	var resp *logical.Response
	var err error

	b, s := createBackendWithStorage(t)

	// Generate Alice EC key pair

	// Create the policy
	policyReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "keys/alice_key",
		Data: map[string]interface{}{
			"type": "ecdsa-p256",
		},
		Storage: s,
	}
	resp, err = b.HandleRequest(context.Background(), policyReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	exportReq := &logical.Request{
		Storage:   s,
		Operation: logical.ReadOperation,
		Path:      "export/public-key/alice_key",
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
	fmt.Println(string(publicKeyAlice))

	// Generate Bob EC key pair

	// Create the policy
	policyReq = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "keys/bob_key",
		Data: map[string]interface{}{
			"type": "ecdsa-p256",
		},
		Storage: s,
	}
	resp, err = b.HandleRequest(context.Background(), policyReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	exportReq = &logical.Request{
		Storage:   s,
		Operation: logical.ReadOperation,
		Path:      "export/public-key/bob_key",
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

	// Alice key agreement
	policyReq = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "derive-key/alice_shared_key",
		Data: map[string]interface{}{
			"key_derivation_algorithm": "ecdh",
			"peer_public_key":          publicKeyBob,
			"base_key_name":            "alice_key",
			"derived_key_name":         "alice_shared_key",
			"derived_key_type":         "aes256-gcm96",
		},
		Storage: s,
	}
	resp, err = b.HandleRequest(context.Background(), policyReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	// Bob key agreement
	policyReq = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "derive-key/bob_shared_key",
		Data: map[string]interface{}{
			"key_derivation_algorithm": "ecdh",
			"peer_public_key":          publicKeyBob,
			"base_key_name":            "bob_key",
			"derived_key_name":         "bob_shared_key",
			"derived_key_type":         "aes256-gcm96",
		},
		Storage: s,
	}
	resp, err = b.HandleRequest(context.Background(), policyReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

}

func TestTransit_EncryptWithRSAPublicKeyDGH(t *testing.T) {
	generateKeys(t)
	b, s := createBackendWithStorage(t)
	keyType := "rsa-2048"
	keyID, err := uuid.GenerateUUID()
	if err != nil {
		t.Fatalf("failed to generate key ID: %s", err)
	}

	// Get key
	privateKey := getKey(t, keyType)
	publicKeyBytes, err := getPublicKey(privateKey, keyType)
	if err != nil {
		t.Fatal(err)
	}

	// Import key
	req := &logical.Request{
		Storage:   s,
		Operation: logical.UpdateOperation,
		Path:      fmt.Sprintf("keys/%s/import", keyID),
		Data: map[string]interface{}{
			"public_key": publicKeyBytes,
			"type":       keyType,
		},
	}
	_, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("failed to import public key: %s", err)
	}

	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      fmt.Sprintf("encrypt/%s", keyID),
		Storage:   s,
		Data: map[string]interface{}{
			"plaintext": "bXkgc2VjcmV0IGRhdGE=",
		},
	}
	_, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
}
