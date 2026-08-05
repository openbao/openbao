// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package api

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestParseRawSecretStringsBecomeBytes(t *testing.T) {
	body := `{"data":{"private_key":"super-secret","accessor":"public"}}`

	secret, err := ParseRawSecret(strings.NewReader(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	value, ok := secret.Data["private_key"].([]byte)
	if !ok {
		t.Fatalf("private_key is %T, want []byte", secret.Data["private_key"])
	}
	if !bytes.Equal(value, []byte("super-secret")) {
		t.Errorf("got %q, want %q", value, "super-secret")
	}
}

func TestParseRawSecretNestedValues(t *testing.T) {
	// KV v2 keeps the secret under data.data.
	body := `{"data":{"data":{"password":"hunter2"},` +
		`"metadata":{"created_time":"2026-01-01T00:00:00Z","version":3,"destroyed":false}}}`

	secret, err := ParseRawSecret(strings.NewReader(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	inner, ok := secret.Data["data"].(map[string]any)
	if !ok {
		t.Fatalf("data.data is %T, want map[string]any", secret.Data["data"])
	}
	password, ok := inner["password"].([]byte)
	if !ok {
		t.Fatalf("password is %T, want []byte", inner["password"])
	}
	if !bytes.Equal(password, []byte("hunter2")) {
		t.Errorf("got %q, want %q", password, "hunter2")
	}

	metadata, ok := secret.Data["metadata"].(map[string]any)
	if !ok {
		t.Fatalf("metadata is %T, want map[string]any", secret.Data["metadata"])
	}
	if _, ok := metadata["created_time"].([]byte); !ok {
		t.Errorf("created_time is %T, want []byte", metadata["created_time"])
	}
	if got, ok := metadata["version"].(json.Number); !ok || got != "3" {
		t.Errorf("version is %v (%T), want json.Number 3", metadata["version"], metadata["version"])
	}
	if got, ok := metadata["destroyed"].(bool); !ok || got {
		t.Errorf("destroyed is %v (%T), want false", metadata["destroyed"], metadata["destroyed"])
	}
}

func TestParseRawSecretNonStringTypes(t *testing.T) {
	body := `{"data":{"num":-1.5e10,"yes":true,"no":false,"nothing":null,` +
		`"list":["a",2,null,{"k":"v"}],"empty_list":[],"empty_obj":{}}}`

	secret, err := ParseRawSecret(strings.NewReader(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got, ok := secret.Data["num"].(json.Number); !ok || got != "-1.5e10" {
		t.Errorf("num is %v (%T), want json.Number -1.5e10", secret.Data["num"], secret.Data["num"])
	}
	if got, ok := secret.Data["yes"].(bool); !ok || !got {
		t.Errorf("yes is %v, want true", secret.Data["yes"])
	}
	if got, ok := secret.Data["no"].(bool); !ok || got {
		t.Errorf("no is %v, want false", secret.Data["no"])
	}
	if secret.Data["nothing"] != nil {
		t.Errorf("nothing is %v, want nil", secret.Data["nothing"])
	}

	list, ok := secret.Data["list"].([]any)
	if !ok {
		t.Fatalf("list is %T, want []any", secret.Data["list"])
	}
	if len(list) != 4 {
		t.Fatalf("list has %d entries, want 4", len(list))
	}
	if first, ok := list[0].([]byte); !ok || !bytes.Equal(first, []byte("a")) {
		t.Errorf("list[0] is %v (%T), want []byte \"a\"", list[0], list[0])
	}
	if nested, ok := list[3].(map[string]any); !ok {
		t.Errorf("list[3] is %T, want map[string]any", list[3])
	} else if v, ok := nested["k"].([]byte); !ok || !bytes.Equal(v, []byte("v")) {
		t.Errorf("list[3].k is %v (%T), want []byte \"v\"", nested["k"], nested["k"])
	}

	if got, ok := secret.Data["empty_list"].([]any); !ok || len(got) != 0 {
		t.Errorf("empty_list is %v (%T), want empty []any", secret.Data["empty_list"], secret.Data["empty_list"])
	}
	if got, ok := secret.Data["empty_obj"].(map[string]any); !ok || len(got) != 0 {
		t.Errorf("empty_obj is %v (%T), want empty map", secret.Data["empty_obj"], secret.Data["empty_obj"])
	}
}

// RawSecret must have the same shape as Secret, with strings as []byte.
func TestParseRawSecretMatchesParseSecret(t *testing.T) {
	body := `{"request_id":"req-1","lease_id":"lease-1","lease_duration":3600,` +
		`"renewable":true,"data":{"key":"value","nested":{"inner":"deep","n":7},` +
		`"list":["a",1,true,null],"flag":false,"nothing":null},` +
		`"warnings":["be careful"],` +
		`"auth":{"client_token":"token-1","accessor":"acc-1","policies":["default"],` +
		`"lease_duration":60,"renewable":true},` +
		`"wrap_info":{"token":"wrap-1","accessor":"wacc-1","ttl":60,` +
		`"creation_time":"2026-01-01T00:00:00Z","creation_path":"kv/data/x"}}`

	plain, err := ParseSecret(strings.NewReader(body))
	if err != nil {
		t.Fatalf("ParseSecret: %v", err)
	}
	raw, err := ParseRawSecret(strings.NewReader(body))
	if err != nil {
		t.Fatalf("ParseRawSecret: %v", err)
	}

	if !reflect.DeepEqual(stringsToBytes(plain.Data), raw.Data) {
		t.Errorf("Data mismatch:\n ParseSecret (normalized): %#v\n ParseRawSecret:           %#v",
			stringsToBytes(plain.Data), raw.Data)
	}

	if raw.RequestID != plain.RequestID {
		t.Errorf("RequestID = %q, want %q", raw.RequestID, plain.RequestID)
	}
	if raw.LeaseID != plain.LeaseID {
		t.Errorf("LeaseID = %q, want %q", raw.LeaseID, plain.LeaseID)
	}
	if raw.LeaseDuration != plain.LeaseDuration {
		t.Errorf("LeaseDuration = %d, want %d", raw.LeaseDuration, plain.LeaseDuration)
	}
	if raw.Renewable != plain.Renewable {
		t.Errorf("Renewable = %v, want %v", raw.Renewable, plain.Renewable)
	}
	if !reflect.DeepEqual(raw.Warnings, plain.Warnings) {
		t.Errorf("Warnings = %v, want %v", raw.Warnings, plain.Warnings)
	}
	if !reflect.DeepEqual(raw.Auth, plain.Auth) {
		t.Errorf("Auth = %#v, want %#v", raw.Auth, plain.Auth)
	}
	if !reflect.DeepEqual(raw.WrapInfo, plain.WrapInfo) {
		t.Errorf("WrapInfo = %#v, want %#v", raw.WrapInfo, plain.WrapInfo)
	}
}

// Responses without a top-level "data" object fall back to raw data.
func TestParseRawSecretRawBody(t *testing.T) {
	body := `{"keys":["a","b"],"counter":5}`

	secret, err := ParseRawSecret(strings.NewReader(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if secret == nil {
		t.Fatal("secret is nil")
	}

	keys, ok := secret.Data["keys"].([]any)
	if !ok {
		t.Fatalf("keys is %T, want []any", secret.Data["keys"])
	}
	if first, ok := keys[0].([]byte); !ok || !bytes.Equal(first, []byte("a")) {
		t.Errorf("keys[0] is %v (%T), want []byte \"a\"", keys[0], keys[0])
	}
	if got, ok := secret.Data["counter"].(json.Number); !ok || got != "5" {
		t.Errorf("counter is %v (%T), want json.Number 5", secret.Data["counter"], secret.Data["counter"])
	}
}

func TestParseRawSecretErrorsOnly(t *testing.T) {
	secret, err := ParseRawSecret(strings.NewReader(`{"errors":["permission denied"]}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if secret != nil {
		t.Errorf("got %v, want nil secret", secret)
	}
}

func TestParseRawSecretErrorsWithData(t *testing.T) {
	_, err := ParseRawSecret(strings.NewReader(`{"errors":["one","two"],"keys":["a"]}`))
	if err == nil {
		t.Fatal("expected an error, got none")
	}
	if err.Error() != "one two" {
		t.Errorf("got %q, want %q", err.Error(), "one two")
	}
}

func TestParseRawSecretEmptyBody(t *testing.T) {
	secret, err := ParseRawSecret(strings.NewReader(``))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if secret != nil {
		t.Errorf("got %v, want nil secret", secret)
	}
}

func TestParseRawSecretNullData(t *testing.T) {
	secret, err := ParseRawSecret(strings.NewReader(`{"request_id":"r","data":null}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if secret.Data != nil {
		t.Errorf("Data = %v, want nil", secret.Data)
	}
}

// stringsToBytes rewrites every string in a decoded JSON value as []byte.
func stringsToBytes(v any) any {
	switch typed := v.(type) {
	case string:
		return []byte(typed)
	case map[string]any:
		out := make(map[string]any, len(typed))
		for k, value := range typed {
			out[k] = stringsToBytes(value)
		}
		return out
	case []any:
		out := make([]any, len(typed))
		for i, value := range typed {
			out[i] = stringsToBytes(value)
		}
		return out
	default:
		return v
	}
}
