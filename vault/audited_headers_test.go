// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"reflect"
	"testing"

	"github.com/openbao/openbao/sdk/v2/helper/salt"
	"github.com/openbao/openbao/vault/barrier"
	"github.com/stretchr/testify/require"
)

func mockAuditedHeadersConfig(t *testing.T) *AuditedHeadersConfig {
	_, barr, _ := barrier.MockBarrier(t, logger)
	view := barrier.NewView(barr, "foo/")
	return &AuditedHeadersConfig{
		Headers: make(map[string]*auditedHeaderSettings),
		view:    view,
	}
}

func TestAuditedHeadersConfig_CRUD(t *testing.T) {
	conf := mockAuditedHeadersConfig(t)

	testAuditedHeadersConfig_Add(t, conf)
	testAuditedHeadersConfig_Remove(t, conf)
}

func testAuditedHeadersConfig_Add(t *testing.T, conf *AuditedHeadersConfig) {
	err := conf.add(t.Context(), "X-Test-Header", false)
	if err != nil {
		t.Fatalf("Error when adding header to config: %s", err)
	}

	settings, ok := conf.Headers["x-test-header"]
	if !ok {
		t.Fatal("Expected header to be found in config")
	}

	if settings.HMAC {
		t.Fatal("Expected HMAC to be set to false, got true")
	}

	out, err := conf.view.Get(t.Context(), auditedHeadersEntry)
	if err != nil {
		t.Fatalf("Could not retrieve headers entry from config: %s", err)
	}
	if out == nil {
		t.Fatal("nil value")
	}

	headers := make(map[string]*auditedHeaderSettings)
	err = out.DecodeJSON(&headers)
	if err != nil {
		t.Fatalf("Error decoding header view: %s", err)
	}

	expected := map[string]*auditedHeaderSettings{
		"x-test-header": {
			HMAC: false,
		},
	}

	if !reflect.DeepEqual(headers, expected) {
		t.Fatalf("Expected config didn't match actual. Expected: %#v, Got: %#v", expected, headers)
	}

	err = conf.add(t.Context(), "X-Vault-Header", true)
	if err != nil {
		t.Fatalf("Error when adding header to config: %s", err)
	}

	settings, ok = conf.Headers["x-vault-header"]
	if !ok {
		t.Fatal("Expected header to be found in config")
	}

	if !settings.HMAC {
		t.Fatal("Expected HMAC to be set to true, got false")
	}

	out, err = conf.view.Get(t.Context(), auditedHeadersEntry)
	if err != nil {
		t.Fatalf("Could not retrieve headers entry from config: %s", err)
	}
	if out == nil {
		t.Fatal("nil value")
	}

	headers = make(map[string]*auditedHeaderSettings)
	err = out.DecodeJSON(&headers)
	if err != nil {
		t.Fatalf("Error decoding header view: %s", err)
	}

	expected["x-vault-header"] = &auditedHeaderSettings{
		HMAC: true,
	}

	if !reflect.DeepEqual(headers, expected) {
		t.Fatalf("Expected config didn't match actual. Expected: %#v, Got: %#v", expected, headers)
	}
}

func testAuditedHeadersConfig_Remove(t *testing.T, conf *AuditedHeadersConfig) {
	err := conf.remove(t.Context(), "X-Test-Header")
	if err != nil {
		t.Fatalf("Error when adding header to config: %s", err)
	}

	_, ok := conf.Headers["x-Test-HeAder"]
	if ok {
		t.Fatal("Expected header to not be found in config")
	}

	out, err := conf.view.Get(t.Context(), auditedHeadersEntry)
	if err != nil {
		t.Fatalf("Could not retrieve headers entry from config: %s", err)
	}
	if out == nil {
		t.Fatal("nil value")
	}

	headers := make(map[string]*auditedHeaderSettings)
	err = out.DecodeJSON(&headers)
	if err != nil {
		t.Fatalf("Error decoding header view: %s", err)
	}

	expected := map[string]*auditedHeaderSettings{
		"x-vault-header": {
			HMAC: true,
		},
	}

	if !reflect.DeepEqual(headers, expected) {
		t.Fatalf("Expected config didn't match actual. Expected: %#v, Got: %#v", expected, headers)
	}

	err = conf.remove(t.Context(), "x-VaulT-Header")
	if err != nil {
		t.Fatalf("Error when adding header to config: %s", err)
	}

	_, ok = conf.Headers["x-vault-header"]
	if ok {
		t.Fatal("Expected header to not be found in config")
	}

	out, err = conf.view.Get(t.Context(), auditedHeadersEntry)
	if err != nil {
		t.Fatalf("Could not retrieve headers entry from config: %s", err)
	}
	if out == nil {
		t.Fatal("nil value")
	}

	headers = make(map[string]*auditedHeaderSettings)
	err = out.DecodeJSON(&headers)
	if err != nil {
		t.Fatalf("Error decoding header view: %s", err)
	}

	expected = make(map[string]*auditedHeaderSettings)

	if !reflect.DeepEqual(headers, expected) {
		t.Fatalf("Expected config didn't match actual. Expected: %#v, Got: %#v", expected, headers)
	}
}

func TestAuditedHeadersConfig_ApplyConfig(t *testing.T) {
	conf := mockAuditedHeadersConfig(t)

	require.NoError(t, conf.add(t.Context(), "X-TesT-Header", false))
	require.NoError(t, conf.add(t.Context(), "X-Vault-HeAdEr", true))

	reqHeaders := map[string][]string{
		"X-Test-Header":  {"foo"},
		"X-Vault-Header": {"bar", "bar"},
		"Content-Type":   {"json"},
	}

	hashFunc := func(ctx context.Context, s string) (string, error) { return "hashed", nil }

	result, err := conf.ApplyConfig(t.Context(), reqHeaders, hashFunc)
	if err != nil {
		t.Fatal(err)
	}

	expected := map[string][]string{
		"x-test-header":  {"foo"},
		"x-vault-header": {"hashed", "hashed"},
	}

	if !reflect.DeepEqual(result, expected) {
		t.Fatalf("Expected headers did not match actual: Expected %#v\n Got %#v\n", expected, result)
	}

	// Make sure we didn't edit the reqHeaders map
	reqHeadersCopy := map[string][]string{
		"X-Test-Header":  {"foo"},
		"X-Vault-Header": {"bar", "bar"},
		"Content-Type":   {"json"},
	}

	if !reflect.DeepEqual(reqHeaders, reqHeadersCopy) {
		t.Fatalf("Req headers were changed, expected %#v\n got %#v", reqHeadersCopy, reqHeaders)
	}
}

func BenchmarkAuditedHeaderConfig_ApplyConfig(b *testing.B) {
	conf := &AuditedHeadersConfig{
		Headers: make(map[string]*auditedHeaderSettings),
		view:    nil,
	}

	conf.Headers = map[string]*auditedHeaderSettings{
		"X-Test-Header":  {false},
		"X-Vault-Header": {true},
	}

	reqHeaders := map[string][]string{
		"X-Test-Header":  {"foo"},
		"X-Vault-Header": {"bar", "bar"},
		"Content-Type":   {"json"},
	}

	salter, err := salt.NewSalt(b.Context(), nil, nil)
	if err != nil {
		b.Fatal(err)
	}

	hashFunc := func(ctx context.Context, s string) (string, error) { return salter.GetIdentifiedHMAC(s), nil }

	// Reset the timer since we did a lot above
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err = conf.ApplyConfig(b.Context(), reqHeaders, hashFunc)
		require.NoError(b, err)
	}
}
