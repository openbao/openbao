// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package transit

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	uuid "github.com/hashicorp/go-uuid"
	"github.com/mitchellh/mapstructure"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func TestTransit_MissingPlaintext(t *testing.T) {
	var resp *logical.Response
	var err error

	b, s := createBackendWithStorage(t)

	// Create the policy
	policyReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "keys/existing_key",
		Storage:   s,
	}
	resp, err = b.HandleRequest(context.Background(), policyReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	encReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "encrypt/existing_key",
		Storage:   s,
		Data:      map[string]interface{}{},
	}
	resp, err = b.HandleRequest(context.Background(), encReq)
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected error due to missing plaintext in request, err:%v resp:%#v", err, resp)
	}
}

func TestTransit_MissingPlaintextInBatchInput(t *testing.T) {
	var resp *logical.Response
	var err error

	b, s := createBackendWithStorage(t)

	// Create the policy
	policyReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "keys/existing_key",
		Storage:   s,
	}
	resp, err = b.HandleRequest(context.Background(), policyReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	batchInput := []interface{}{
		map[string]interface{}{}, // Note that there is no map entry for plaintext
	}

	batchData := map[string]interface{}{
		"batch_input": batchInput,
	}
	batchReq := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "encrypt/upserted_key",
		Storage:   s,
		Data:      batchData,
	}
	resp, err = b.HandleRequest(context.Background(), batchReq)
	if err == nil {
		t.Fatalf("expected error due to missing plaintext in request, err:%v resp:%#v", err, resp)
	}
}

// Case1: Ensure that batch encryption did not affect the normal flow of
// encrypting the plaintext with a pre-existing key.
func TestTransit_BatchEncryptionCase1(t *testing.T) {
	var resp *logical.Response
	var err error

	b, s := createBackendWithStorage(t)

	// Create the policy
	policyReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "keys/existing_key",
		Storage:   s,
	}
	resp, err = b.HandleRequest(context.Background(), policyReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	plaintext := "dGhlIHF1aWNrIGJyb3duIGZveA==" // "the quick brown fox"

	encData := map[string]interface{}{
		"plaintext": plaintext,
	}

	encReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "encrypt/existing_key",
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

	decData := map[string]interface{}{
		"ciphertext": ciphertext,
	}
	decReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "decrypt/existing_key",
		Storage:   s,
		Data:      decData,
	}
	resp, err = b.HandleRequest(context.Background(), decReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	if resp.Data["plaintext"] != plaintext {
		t.Fatalf("bad: plaintext. Expected: %q, Actual: %q", plaintext, resp.Data["plaintext"])
	}
}

// Case2: Ensure that batch encryption did not affect the normal flow of
// encrypting the plaintext with the key upserted.
func TestTransit_BatchEncryptionCase2(t *testing.T) {
	var resp *logical.Response
	var err error
	b, s := createBackendWithStorage(t)

	// Upsert the key and encrypt the data
	plaintext := "dGhlIHF1aWNrIGJyb3duIGZveA=="

	encData := map[string]interface{}{
		"plaintext": plaintext,
	}

	encReq := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "encrypt/upserted_key",
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
	decData := map[string]interface{}{
		"ciphertext": ciphertext,
	}

	policyReq := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "keys/upserted_key",
		Storage:   s,
	}

	resp, err = b.HandleRequest(context.Background(), policyReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	decReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "decrypt/upserted_key",
		Storage:   s,
		Data:      decData,
	}
	resp, err = b.HandleRequest(context.Background(), decReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	if resp.Data["plaintext"] != plaintext {
		t.Fatalf("bad: plaintext. Expected: %q, Actual: %q", plaintext, resp.Data["plaintext"])
	}
}

// Case3: If batch encryption input is not base64 encoded, it should fail.
func TestTransit_BatchEncryptionCase3(t *testing.T) {
	var err error

	b, s := createBackendWithStorage(t)

	batchInput := `[{"plaintext":"dGhlIHF1aWNrIGJyb3duIGZveA=="}]`
	batchData := map[string]interface{}{
		"batch_input": batchInput,
	}

	batchReq := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "encrypt/upserted_key",
		Storage:   s,
		Data:      batchData,
	}
	_, err = b.HandleRequest(context.Background(), batchReq)
	if err == nil {
		t.Fatal("expected an error")
	}
}

// Case4: Test batch encryption with an existing key (and test references)
func TestTransit_BatchEncryptionCase4(t *testing.T) {
	var resp *logical.Response
	var err error

	b, s := createBackendWithStorage(t)

	policyReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "keys/existing_key",
		Storage:   s,
	}
	resp, err = b.HandleRequest(context.Background(), policyReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	batchInput := []interface{}{
		map[string]interface{}{"plaintext": "dGhlIHF1aWNrIGJyb3duIGZveA==", "reference": "b"},
		map[string]interface{}{"plaintext": "dGhlIHF1aWNrIGJyb3duIGZveA==", "reference": "a"},
	}

	batchData := map[string]interface{}{
		"batch_input": batchInput,
	}
	batchReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "encrypt/existing_key",
		Storage:   s,
		Data:      batchData,
	}
	resp, err = b.HandleRequest(context.Background(), batchReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	batchResponseItems := resp.Data["batch_results"].([]EncryptBatchResponseItem)

	decReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "decrypt/existing_key",
		Storage:   s,
	}

	plaintext := "dGhlIHF1aWNrIGJyb3duIGZveA=="

	for i, item := range batchResponseItems {
		if item.KeyVersion != 1 {
			t.Fatalf("unexpected key version; got: %d, expected: %d", item.KeyVersion, 1)
		}

		decReq.Data = map[string]interface{}{
			"ciphertext": item.Ciphertext,
		}
		resp, err = b.HandleRequest(context.Background(), decReq)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%v resp:%#v", err, resp)
		}

		if resp.Data["plaintext"] != plaintext {
			t.Fatalf("bad: plaintext. Expected: %q, Actual: %q", plaintext, resp.Data["plaintext"])
		}
		inputItem := batchInput[i].(map[string]interface{})
		if item.Reference != inputItem["reference"] {
			t.Fatalf("reference mismatch.  Expected %s, Actual: %s", inputItem["reference"], item.Reference)
		}
	}
}

// Case5: Test batch encryption with an existing derived key
func TestTransit_BatchEncryptionCase5(t *testing.T) {
	var resp *logical.Response
	var err error

	b, s := createBackendWithStorage(t)

	policyData := map[string]interface{}{
		"derived": true,
	}

	policyReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "keys/existing_key",
		Storage:   s,
		Data:      policyData,
	}

	resp, err = b.HandleRequest(context.Background(), policyReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	batchInput := []interface{}{
		map[string]interface{}{"plaintext": "dGhlIHF1aWNrIGJyb3duIGZveA==", "context": "dmlzaGFsCg=="},
		map[string]interface{}{"plaintext": "dGhlIHF1aWNrIGJyb3duIGZveA==", "context": "dmlzaGFsCg=="},
	}

	batchData := map[string]interface{}{
		"batch_input": batchInput,
	}

	batchReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "encrypt/existing_key",
		Storage:   s,
		Data:      batchData,
	}
	resp, err = b.HandleRequest(context.Background(), batchReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	batchResponseItems := resp.Data["batch_results"].([]EncryptBatchResponseItem)

	decReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "decrypt/existing_key",
		Storage:   s,
	}

	plaintext := "dGhlIHF1aWNrIGJyb3duIGZveA=="

	for _, item := range batchResponseItems {
		if item.KeyVersion != 1 {
			t.Fatalf("unexpected key version; got: %d, expected: %d", item.KeyVersion, 1)
		}

		decReq.Data = map[string]interface{}{
			"ciphertext": item.Ciphertext,
			"context":    "dmlzaGFsCg==",
		}
		resp, err = b.HandleRequest(context.Background(), decReq)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%v resp:%#v", err, resp)
		}

		if resp.Data["plaintext"] != plaintext {
			t.Fatalf("bad: plaintext. Expected: %q, Actual: %q", plaintext, resp.Data["plaintext"])
		}
	}
}

// Case6: Test batch encryption with an upserted non-derived key
func TestTransit_BatchEncryptionCase6(t *testing.T) {
	var resp *logical.Response
	var err error

	b, s := createBackendWithStorage(t)

	batchInput := []interface{}{
		map[string]interface{}{"plaintext": "dGhlIHF1aWNrIGJyb3duIGZveA=="},
		map[string]interface{}{"plaintext": "dGhlIHF1aWNrIGJyb3duIGZveA=="},
	}

	batchData := map[string]interface{}{
		"batch_input": batchInput,
	}
	batchReq := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "encrypt/upserted_key",
		Storage:   s,
		Data:      batchData,
	}
	resp, err = b.HandleRequest(context.Background(), batchReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	batchResponseItems := resp.Data["batch_results"].([]EncryptBatchResponseItem)

	decReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "decrypt/upserted_key",
		Storage:   s,
	}

	plaintext := "dGhlIHF1aWNrIGJyb3duIGZveA=="

	for _, responseItem := range batchResponseItems {
		var item EncryptBatchResponseItem
		if err := mapstructure.Decode(responseItem, &item); err != nil {
			t.Fatal(err)
		}

		if item.KeyVersion != 1 {
			t.Fatalf("unexpected key version; got: %d, expected: %d", item.KeyVersion, 1)
		}

		decReq.Data = map[string]interface{}{
			"ciphertext": item.Ciphertext,
		}
		resp, err = b.HandleRequest(context.Background(), decReq)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%v resp:%#v", err, resp)
		}

		if resp.Data["plaintext"] != plaintext {
			t.Fatalf("bad: plaintext. Expected: %q, Actual: %q", plaintext, resp.Data["plaintext"])
		}
	}
}

// Case7: Test batch encryption with an upserted derived key
func TestTransit_BatchEncryptionCase7(t *testing.T) {
	var resp *logical.Response
	var err error

	b, s := createBackendWithStorage(t)

	batchInput := []interface{}{
		map[string]interface{}{"plaintext": "dGhlIHF1aWNrIGJyb3duIGZveA==", "context": "dmlzaGFsCg=="},
		map[string]interface{}{"plaintext": "dGhlIHF1aWNrIGJyb3duIGZveA==", "context": "dmlzaGFsCg=="},
	}

	batchData := map[string]interface{}{
		"batch_input": batchInput,
	}
	batchReq := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "encrypt/upserted_key",
		Storage:   s,
		Data:      batchData,
	}
	resp, err = b.HandleRequest(context.Background(), batchReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	batchResponseItems := resp.Data["batch_results"].([]EncryptBatchResponseItem)

	decReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "decrypt/upserted_key",
		Storage:   s,
	}

	plaintext := "dGhlIHF1aWNrIGJyb3duIGZveA=="

	for _, item := range batchResponseItems {
		if item.KeyVersion != 1 {
			t.Fatalf("unexpected key version; got: %d, expected: %d", item.KeyVersion, 1)
		}

		decReq.Data = map[string]interface{}{
			"ciphertext": item.Ciphertext,
			"context":    "dmlzaGFsCg==",
		}
		resp, err = b.HandleRequest(context.Background(), decReq)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%v resp:%#v", err, resp)
		}

		if resp.Data["plaintext"] != plaintext {
			t.Fatalf("bad: plaintext. Expected: %q, Actual: %q", plaintext, resp.Data["plaintext"])
		}
	}
}

// Case8: If plaintext is not base64 encoded, encryption should fail
func TestTransit_BatchEncryptionCase8(t *testing.T) {
	var resp *logical.Response
	var err error

	b, s := createBackendWithStorage(t)

	// Create the policy
	policyReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "keys/existing_key",
		Storage:   s,
	}
	resp, err = b.HandleRequest(context.Background(), policyReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	batchInput := []interface{}{
		map[string]interface{}{"plaintext": "simple_plaintext"},
	}
	batchData := map[string]interface{}{
		"batch_input": batchInput,
	}
	batchReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "encrypt/existing_key",
		Storage:   s,
		Data:      batchData,
	}
	resp, err = b.HandleRequest(context.Background(), batchReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	plaintext := "simple plaintext"

	encData := map[string]interface{}{
		"plaintext": plaintext,
	}

	encReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "encrypt/existing_key",
		Storage:   s,
		Data:      encData,
	}
	resp, err = b.HandleRequest(context.Background(), encReq)
	if err == nil {
		t.Fatal("expected an error")
	}
}

// Case9: If both plaintext and batch inputs are supplied, plaintext should be
// ignored.
func TestTransit_BatchEncryptionCase9(t *testing.T) {
	var resp *logical.Response
	var err error

	b, s := createBackendWithStorage(t)

	batchInput := []interface{}{
		map[string]interface{}{"plaintext": "dGhlIHF1aWNrIGJyb3duIGZveA=="},
		map[string]interface{}{"plaintext": "dGhlIHF1aWNrIGJyb3duIGZveA=="},
	}
	plaintext := "dGhlIHF1aWNrIGJyb3duIGZveA=="
	batchData := map[string]interface{}{
		"batch_input": batchInput,
		"plaintext":   plaintext,
	}
	batchReq := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "encrypt/upserted_key",
		Storage:   s,
		Data:      batchData,
	}
	resp, err = b.HandleRequest(context.Background(), batchReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	_, ok := resp.Data["ciphertext"]
	if ok {
		t.Fatal("ciphertext field should not be set")
	}
}

// Case10: Inconsistent presence of 'context' in batch input should be caught
func TestTransit_BatchEncryptionCase10(t *testing.T) {
	var err error

	b, s := createBackendWithStorage(t)

	batchInput := []interface{}{
		map[string]interface{}{"plaintext": "dGhlIHF1aWNrIGJyb3duIGZveA=="},
		map[string]interface{}{"plaintext": "dGhlIHF1aWNrIGJyb3duIGZveA==", "context": "dmlzaGFsCg=="},
	}

	batchData := map[string]interface{}{
		"batch_input": batchInput,
	}

	batchReq := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "encrypt/upserted_key",
		Storage:   s,
		Data:      batchData,
	}
	_, err = b.HandleRequest(context.Background(), batchReq)
	if err == nil {
		t.Fatal("expected an error")
	}
}

// Case11: Incorrect inputs for context should not fail the operation
func TestTransit_BatchEncryptionCase11(t *testing.T) {
	var err error

	b, s := createBackendWithStorage(t)

	batchInput := []interface{}{
		map[string]interface{}{"plaintext": "dGhlIHF1aWNrIGJyb3duIGZveA==", "context": "dmlzaGFsCg=="},
		map[string]interface{}{"plaintext": "dGhlIHF1aWNrIGJyb3duIGZveA==", "context": "not-encoded"},
	}

	batchData := map[string]interface{}{
		"batch_input": batchInput,
	}
	batchReq := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "encrypt/upserted_key",
		Storage:   s,
		Data:      batchData,
	}
	_, err = b.HandleRequest(context.Background(), batchReq)
	if err != nil {
		t.Fatal(err)
	}
}

// Case12: Invalid batch input
func TestTransit_BatchEncryptionCase12(t *testing.T) {
	var err error
	b, s := createBackendWithStorage(t)

	batchInput := []interface{}{
		map[string]interface{}{},
		"unexpected_interface",
	}

	batchData := map[string]interface{}{
		"batch_input": batchInput,
	}
	batchReq := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "encrypt/upserted_key",
		Storage:   s,
		Data:      batchData,
	}
	_, err = b.HandleRequest(context.Background(), batchReq)
	if err == nil {
		t.Fatal("expected an error")
	}
}

// Test that the fast path function decodeBatchRequestItems behave like mapstructure.Decode() to decode []BatchRequestItem.
func TestTransit_decodeBatchRequestItems(t *testing.T) {
	tests := []struct {
		name              string
		src               interface{}
		requirePlaintext  bool
		requireCiphertext bool
		dest              []BatchRequestItem
		wantErrContains   string
	}{
		// basic edge cases of nil values
		{name: "nil-nil", src: nil, dest: nil},
		{name: "nil-empty", src: nil, dest: []BatchRequestItem{}},
		{name: "empty-nil", src: []interface{}{}, dest: nil},
		{
			name: "src-nil",
			src:  []interface{}{map[string]interface{}{}},
			dest: nil,
		},
		// empty src & dest
		{
			name: "src-dest",
			src:  []interface{}{map[string]interface{}{}},
			dest: []BatchRequestItem{},
		},
		// empty src but with already populated dest, mapstructure discard pre-populated data.
		{
			name: "src-dest_pre_filled",
			src:  []interface{}{map[string]interface{}{}},
			dest: []BatchRequestItem{{}},
		},
		// two test per properties to test valid and invalid input
		{
			name: "src_plaintext-dest",
			src:  []interface{}{map[string]interface{}{"plaintext": "dGhlIHF1aWNrIGJyb3duIGZveA=="}},
			dest: []BatchRequestItem{},
		},
		{
			name:            "src_plaintext_invalid-dest",
			src:             []interface{}{map[string]interface{}{"plaintext": 666}},
			dest:            []BatchRequestItem{},
			wantErrContains: "expected type 'string', got unconvertible type 'int'",
		},
		{
			name: "src_ciphertext-dest",
			src:  []interface{}{map[string]interface{}{"ciphertext": "dGhlIHF1aWNrIGJyb3duIGZveA=="}},
			dest: []BatchRequestItem{},
		},
		{
			name:            "src_ciphertext_invalid-dest",
			src:             []interface{}{map[string]interface{}{"ciphertext": 666}},
			dest:            []BatchRequestItem{},
			wantErrContains: "expected type 'string', got unconvertible type 'int'",
		},
		{
			name: "src_key_version-dest",
			src:  []interface{}{map[string]interface{}{"key_version": 1}},
			dest: []BatchRequestItem{},
		},
		{
			name:            "src_key_version_invalid-dest",
			src:             []interface{}{map[string]interface{}{"key_version": "666"}},
			dest:            []BatchRequestItem{},
			wantErrContains: "expected type 'int', got unconvertible type 'string'",
		},
		{
			name:            "src_key_version_invalid-number-dest",
			src:             []interface{}{map[string]interface{}{"plaintext": "dGhlIHF1aWNrIGJyb3duIGZveA==", "key_version": json.Number("1.1")}},
			dest:            []BatchRequestItem{},
			wantErrContains: "error decoding json.Number into [0].key_version",
		},
		{
			name: "src_context-dest",
			src:  []interface{}{map[string]interface{}{"context": "dGVzdGNvbnRleHQ="}},
			dest: []BatchRequestItem{},
		},
		{
			name:            "src_context_invalid-dest",
			src:             []interface{}{map[string]interface{}{"context": 666}},
			dest:            []BatchRequestItem{},
			wantErrContains: "expected type 'string', got unconvertible type 'int'",
		},
		{
			name: "src_multi_order-dest",
			src: []interface{}{
				map[string]interface{}{"context": "1"},
				map[string]interface{}{"context": "2"},
				map[string]interface{}{"context": "3"},
			},
			dest: []BatchRequestItem{},
		},
		{
			name: "src_multi_with_invalid-dest",
			src: []interface{}{
				map[string]interface{}{"context": "1"},
				map[string]interface{}{"context": "2", "key_version": "666"},
				map[string]interface{}{"context": "3"},
			},
			dest:            []BatchRequestItem{},
			wantErrContains: "expected type 'int', got unconvertible type 'string'",
		},
		{
			name: "src_multi_with_multi_invalid-dest",
			src: []interface{}{
				map[string]interface{}{"context": "1"},
				map[string]interface{}{"context": "2", "key_version": "666"},
				map[string]interface{}{"context": "3", "key_version": "1337"},
			},
			dest:            []BatchRequestItem{},
			wantErrContains: "expected type 'int', got unconvertible type 'string'",
		},
		// required fields
		{
			name:             "required_plaintext_present",
			src:              []interface{}{map[string]interface{}{"plaintext": ""}},
			requirePlaintext: true,
			dest:             []BatchRequestItem{},
		},
		{
			name:             "required_plaintext_missing",
			src:              []interface{}{map[string]interface{}{}},
			requirePlaintext: true,
			dest:             []BatchRequestItem{},
			wantErrContains:  "missing plaintext",
		},
		{
			name:              "required_ciphertext_present",
			src:               []interface{}{map[string]interface{}{"ciphertext": "dGhlIHF1aWNrIGJyb3duIGZveA=="}},
			requireCiphertext: true,
			dest:              []BatchRequestItem{},
		},
		{
			name:              "required_ciphertext_missing",
			src:               []interface{}{map[string]interface{}{}},
			requireCiphertext: true,
			dest:              []BatchRequestItem{},
			wantErrContains:   "missing ciphertext",
		},
		{
			name:              "required_plaintext_and_ciphertext_missing",
			src:               []interface{}{map[string]interface{}{}},
			requirePlaintext:  true,
			requireCiphertext: true,
			dest:              []BatchRequestItem{},
			wantErrContains:   "missing ciphertext",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expectedDest := append(tt.dest[:0:0], tt.dest...) // copy of the dest state
			expectedErr := mapstructure.Decode(tt.src, &expectedDest) != nil || tt.wantErrContains != ""

			gotErr := decodeBatchRequestItems(tt.src, tt.requirePlaintext, tt.requireCiphertext, &tt.dest)
			gotDest := tt.dest

			if expectedErr {
				if gotErr == nil {
					t.Fatal("decodeBatchRequestItems unexpected error value; expected error but got none")
				}
				if tt.wantErrContains == "" {
					t.Fatal("missing error condition")
				}
				if !strings.Contains(gotErr.Error(), tt.wantErrContains) {
					t.Errorf("decodeBatchRequestItems unexpected error value, want err contains: '%v', got: '%v'", tt.wantErrContains, gotErr)
				}
			}

			if !reflect.DeepEqual(expectedDest, gotDest) {
				t.Errorf("decodeBatchRequestItems unexpected dest value, want: '%v', got: '%v'", expectedDest, gotDest)
			}
		})
	}
}

func TestTransit_EncryptWithRSAPublicKey(t *testing.T) {
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
