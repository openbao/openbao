// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package transit

import (
	"strconv"
	"strings"
	"testing"

	"github.com/openbao/openbao/sdk/v2/helper/keysutil"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
)

func TestTransit_HMAC(t *testing.T) {
	b, storage := createBackendWithSysView(t)
	keyName := "foo"

	req := &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "keys/" + keyName,
	}
	_, err := b.HandleRequest(t.Context(), req)
	require.NoError(t, err)

	// Now, change the key value to something we control
	p, _, err := b.GetPolicy(t.Context(), keysutil.PolicyRequest{
		Storage: storage,
		Name:    keyName,
	}, b.GetRandomReader())
	require.NoError(t, err)

	// We don't care as we're the only one using this
	latestVersion := strconv.Itoa(p.LatestVersion)
	keyEntry := p.Keys[latestVersion]
	keyEntry.HMACKey = []byte("01234567890123456789012345678901")
	keyEntry.Key = []byte("01234567890123456789012345678901")
	p.Keys[latestVersion] = keyEntry
	require.NoError(t, p.Persist(t.Context(), storage))

	p.Unlock()

	req.Path = "hmac/" + keyName
	req.Data = map[string]any{
		"input": "dGhlIHF1aWNrIGJyb3duIGZveA==",
	}

	doRequest := func(req *logical.Request, errExpected bool, expected string) {
		path := req.Path
		defer func() { req.Path = path }()

		resp, err := b.HandleRequest(t.Context(), req)
		if !errExpected {
			require.NoError(t, err)
		}
		require.NotNil(t, resp)

		if errExpected {
			require.True(t, resp.IsError())
			return
		}

		require.False(t, resp.IsError())

		value, ok := resp.Data["hmac"]
		require.Truef(t, ok, "no hmac key found in returned data, got resp data %#v", resp.Data)
		require.Equalf(t, expected, value.(string), "mismatched hashes; expected %s, got resp data %#v", expected, resp.Data)

		// Test hmac verification
		req.Path = strings.ReplaceAll(req.Path, "hmac", "verify")

		req.Data["hmac"] = value.(string)
		// Verify respects `hash_algorithm` first, as `algorithm` field name was deprecated.
		req.Data["hash_algorithm"] = req.Data["algorithm"]
		resp, err = b.HandleRequest(t.Context(), req)
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.Truef(t, resp.Data["valid"].(bool), "error validating hmac\nreq\n%#v\nresp\n%#v", *req, *resp)
	}

	// Comparisons are against values generated via openssl

	// Test defaults -- sha2-256
	doRequest(req, false, "vault:v1:UcBvm5VskkukzZHlPgm3p5P/Yr/PV6xpuOGZISya3A4=")

	// Test algorithm selection in the path
	req.Path = "hmac/" + keyName + "/sha2-224"
	doRequest(req, false, "vault:v1:3p+ZWVquYDvu2dSTCa65Y3fgoMfIAc6fNaBbtg==")

	// Reset and test algorithm selection in the data
	req.Path = "hmac/" + keyName
	req.Data["algorithm"] = "sha2-224"
	doRequest(req, false, "vault:v1:3p+ZWVquYDvu2dSTCa65Y3fgoMfIAc6fNaBbtg==")

	req.Data["algorithm"] = "sha2-384"
	doRequest(req, false, "vault:v1:jDB9YXdPjpmr29b1JCIEJO93IydlKVfD9mA2EO9OmJtJQg3QAV5tcRRRb7IQGW9p")

	req.Data["algorithm"] = "sha2-512"
	doRequest(req, false, "vault:v1:PSXLXvkvKF4CpU65e2bK1tGBZQpcpCEM32fq2iUoiTyQQCfBcGJJItQ+60tMwWXAPQrC290AzTrNJucGrr4GFA==")

	// Test returning as base64
	req.Data["format"] = "base64"
	doRequest(req, false, "vault:v1:PSXLXvkvKF4CpU65e2bK1tGBZQpcpCEM32fq2iUoiTyQQCfBcGJJItQ+60tMwWXAPQrC290AzTrNJucGrr4GFA==")

	// Test SHA3
	req.Path = "hmac/" + keyName
	req.Data["algorithm"] = "sha3-224"
	doRequest(req, false, "vault:v1:TGipmKH8LR/BkMolYpDYy0BJCIhTtGPDhV2VkQ==")

	req.Data["algorithm"] = "sha3-256"
	doRequest(req, false, "vault:v1:+px9V/7QYLfdK808zPESC2T/L33uFf4Blzsn9Jy838o=")

	req.Data["algorithm"] = "sha3-384"
	doRequest(req, false, "vault:v1:YGoRwN4UdTRYZeOER86jsQOB8piWenzLDzJ2wJQK/Jq59rAsY8lh7SCdqqCyFg70")

	req.Data["algorithm"] = "sha3-512"
	doRequest(req, false, "vault:v1:GrNA8sU88naMPEQ7UZGj9EJl7YJhl03AFHfxcEURFrtvnobdea9ZlZHePpxAx/oCaC7R2HkrAO+Tu3uXPIl3lg==")

	// Test returning SHA3 as base64
	req.Data["format"] = "base64"
	doRequest(req, false, "vault:v1:GrNA8sU88naMPEQ7UZGj9EJl7YJhl03AFHfxcEURFrtvnobdea9ZlZHePpxAx/oCaC7R2HkrAO+Tu3uXPIl3lg==")

	req.Data["algorithm"] = "foobar"
	doRequest(req, true, "")

	req.Data["algorithm"] = "sha2-256"
	req.Data["input"] = "foobar"
	doRequest(req, true, "")
	req.Data["input"] = "dGhlIHF1aWNrIGJyb3duIGZveA=="

	// Rotate
	require.NoError(t, p.Rotate(t.Context(), storage, b.GetRandomReader()))
	keyEntry = p.Keys["2"]
	// Set to another value we control
	keyEntry.HMACKey = []byte("12345678901234567890123456789012")
	p.Keys["2"] = keyEntry
	require.NoError(t, p.Persist(t.Context(), storage))

	doRequest(req, false, "vault:v2:Dt+mO/B93kuWUbGMMobwUNX5Wodr6dL3JH4DMfpQ0kw=")

	// Verify a previous version
	req.Path = "verify/" + keyName

	req.Data["hmac"] = "vault:v1:UcBvm5VskkukzZHlPgm3p5P/Yr/PV6xpuOGZISya3A4="
	resp, err := b.HandleRequest(t.Context(), req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Truef(t, resp.Data["valid"].(bool), "error validating hmac\nreq\n%#v\nresp\n%#v", *req, *resp)

	// Try a bad value
	req.Data["hmac"] = "vault:v1:UcBvm4VskkukzZHlPgm3p5P/Yr/PV6xpuOGZISya3A4="
	resp, err = b.HandleRequest(t.Context(), req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.False(t, resp.Data["valid"].(bool))

	// Set min decryption version, attempt to verify
	p.MinDecryptionVersion = 2
	require.NoError(t, p.Persist(t.Context(), storage))

	req.Data["hmac"] = "vault:v1:UcBvm5VskkukzZHlPgm3p5P/Yr/PV6xpuOGZISya3A4="
	_, err = b.HandleRequest(t.Context(), req)
	require.Error(t, err)
	require.ErrorIs(t, err, logical.ErrInvalidRequest)
}

func TestTransit_batchHMAC(t *testing.T) {
	b, storage := createBackendWithSysView(t)

	// First create a key
	req := &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "keys/foo",
	}
	_, err := b.HandleRequest(t.Context(), req)
	if err != nil {
		t.Fatal(err)
	}

	// Now, change the key value to something we control
	p, _, err := b.GetPolicy(t.Context(), keysutil.PolicyRequest{
		Storage: storage,
		Name:    "foo",
	}, b.GetRandomReader())
	if err != nil {
		t.Fatal(err)
	}
	// We don't care as we're the only one using this
	latestVersion := strconv.Itoa(p.LatestVersion)
	keyEntry := p.Keys[latestVersion]
	keyEntry.HMACKey = []byte("01234567890123456789012345678901")
	p.Keys[latestVersion] = keyEntry
	if err = p.Persist(t.Context(), storage); err != nil {
		t.Fatal(err)
	}
	p.Unlock()

	req.Path = "hmac/foo"
	batchInput := []batchRequestHMACItem{
		{"input": "dGhlIHF1aWNrIGJyb3duIGZveA==", "reference": "one"},
		{"input": "dGhlIHF1aWNrIGJyb3duIGZveA==", "reference": "two"},
		{"input": "", "reference": "three"},
		{"input": ":;.?", "reference": "four"},
		{},
	}

	expected := []batchResponseHMACItem{
		{HMAC: "vault:v1:UcBvm5VskkukzZHlPgm3p5P/Yr/PV6xpuOGZISya3A4=", Reference: "one"},
		{HMAC: "vault:v1:UcBvm5VskkukzZHlPgm3p5P/Yr/PV6xpuOGZISya3A4=", Reference: "two"},
		{HMAC: "vault:v1:BCfVv6rlnRsIKpjCZCxWvh5iYwSSabRXpX9XJniuNgc=", Reference: "three"},
		{Error: "unable to decode input as base64: illegal base64 data at input byte 0", Reference: "four"},
		{Error: "missing input for HMAC"},
	}

	req.Data = map[string]any{
		"batch_input": batchInput,
	}

	resp, err := b.HandleRequest(t.Context(), req)

	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	batchResponseItems := resp.Data["batch_results"].([]batchResponseHMACItem)

	if len(batchResponseItems) != len(batchInput) {
		t.Fatalf("Expected %d items in response. Got %d", len(batchInput), len(batchResponseItems))
	}

	for i, m := range batchResponseItems {
		if expected[i].Error == "" && expected[i].HMAC != m.HMAC {
			t.Fatalf("Expected HMAC %s got %s in result %d", expected[i].HMAC, m.HMAC, i)
		}
		if expected[i].Error != "" && expected[i].Error != m.Error {
			t.Fatalf("Expected Error %q got %q in result %d", expected[i].Error, m.Error, i)
		}
		if expected[i].Reference != m.Reference {
			t.Fatalf("Expected references to match, Got %s, Expected %s", m.Reference, expected[i].Reference)
		}
	}

	// Verify a previous version
	req.Path = "verify/foo"
	good_hmac := "vault:v1:UcBvm5VskkukzZHlPgm3p5P/Yr/PV6xpuOGZISya3A4="
	bad_hmac := "vault:v1:UcBvm4VskkukzZHlPgm3p5P/Yr/PV6xpuOGZISya3A4="
	verifyBatch := []batchRequestHMACItem{
		{"input": "dGhlIHF1aWNrIGJyb3duIGZveA==", "hmac": good_hmac},
	}

	req.Data = map[string]any{
		"batch_input": verifyBatch,
	}

	resp, err = b.HandleRequest(t.Context(), req)
	if err != nil {
		t.Fatalf("%v: %v", err, resp)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}

	batchHMACVerifyResponseItems := resp.Data["batch_results"].([]batchResponseHMACItem)

	if !batchHMACVerifyResponseItems[0].Valid {
		t.Fatalf("error validating hmac\nreq\n%#v\nresp\n%#v", *req, *resp)
	}

	// Try a bad value
	verifyBatch[0]["hmac"] = bad_hmac
	resp, err = b.HandleRequest(t.Context(), req)
	if err != nil {
		t.Fatalf("%v: %v", err, resp)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}

	batchHMACVerifyResponseItems = resp.Data["batch_results"].([]batchResponseHMACItem)

	if batchHMACVerifyResponseItems[0].Valid {
		t.Fatalf("expected error validating hmac\nreq\n%#v\nresp\n%#v", *req, *resp)
	}

	// Rotate
	err = p.Rotate(t.Context(), storage, b.GetRandomReader())
	if err != nil {
		t.Fatal(err)
	}
	keyEntry = p.Keys["2"]
	// Set to another value we control
	keyEntry.HMACKey = []byte("12345678901234567890123456789012")
	p.Keys["2"] = keyEntry
	if err = p.Persist(t.Context(), storage); err != nil {
		t.Fatal(err)
	}

	// Set min decryption version, attempt to verify
	p.MinDecryptionVersion = 2
	if err = p.Persist(t.Context(), storage); err != nil {
		t.Fatal(err)
	}

	// supply a good hmac, but with expired key version
	verifyBatch[0]["hmac"] = good_hmac

	resp, err = b.HandleRequest(t.Context(), req)
	if err != nil {
		t.Fatalf("%v: %v", err, resp)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}

	batchHMACVerifyResponseItems = resp.Data["batch_results"].([]batchResponseHMACItem)

	if batchHMACVerifyResponseItems[0].Valid {
		t.Fatalf("expected error validating hmac\nreq\n%#v\nresp\n%#v", *req, *resp)
	}
}
