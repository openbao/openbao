package kv

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/go-test/deep"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// TestVersionedKV_Subkeys_NotFound verifies that a nil logical.Response is
// returned when an entry that does not exist is requested
func TestVersionedKV_Subkeys_NotFound(t *testing.T) {
	b, storage := getBackend(t)

	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "subkeys/foo",
		Storage:   storage,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || resp != nil {
		t.Fatalf("unexpected ReadOperation response, err: %v, resp %#v", err, resp)
	}
}

// TestVersionedKV_Subkeys_CurrentVersion verifies that the current
// version of an entry is read if the version param is not provided
func TestVersionedKV_Subkeys_CurrentVersion(t *testing.T) {
	b, storage := getBackend(t)

	data := map[string]interface{}{
		"data": map[string]interface{}{
			"foo": "does-not-matter",
			"bar": map[string]interface{}{
				"a": map[string]interface{}{
					"c": map[string]interface{}{
						"d": "does-not-matter",
					},
				},
				"b": map[string]interface{}{},
			},
			"baz": map[string]interface{}{
				"e": 3.14,
			},
			"quux": 123,
			"quuz": []string{"does-not-matter"},
		},
	}

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "data/foo",
		Storage:   storage,
		Data:      data,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("CreateOperation request failed, err: %v, resp %#v", err, resp)
	}

	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "subkeys/foo",
		Storage:   storage,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("ReadOperation request failed, err: %v, resp %#v", err, resp)
	}

	expectedRespKeys := map[string]struct{}{
		"subkeys":  {},
		"metadata": {},
	}

	if diff := deep.Equal(getKeySet(resp.Data), expectedRespKeys); len(diff) > 0 {
		t.Fatalf("expected top-level resp keys mismatch, diff: %#v", diff)
	}

	metadata, ok := resp.Data["metadata"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected metadata to be map, actual: %#v", metadata)
	}

	if diff := deep.Equal(getKeySet(metadata), expectedMetadataKeys()); len(diff) > 0 {
		t.Fatalf("metadata map keys mismatch, diff: %#v", diff)
	}

	expectedSubkeys := map[string]interface{}{
		"foo": nil,
		"bar": map[string]interface{}{
			"a": map[string]interface{}{
				"c": map[string]interface{}{
					"d": nil,
				},
			},
			"b": nil,
		},
		"baz": map[string]interface{}{
			"e": nil,
		},
		"quux": nil,
		"quuz": nil,
	}

	if diff := deep.Equal(resp.Data["subkeys"], expectedSubkeys); len(diff) > 0 {
		t.Fatalf("resp and expected data mismatch, diff: %#v", diff)
	}
}

// TestVersionedKV_Subkeys_VersionParam verifies that the correct
// version is read when the version flag is provided
func TestVersionedKV_Subkeys_VersionParam(t *testing.T) {
	b, storage := getBackend(t)

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "data/foo",
		Storage:   storage,
		Data: map[string]interface{}{
			"data": map[string]interface{}{
				"foo": "abc",
			},
		},
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("data CreateOperation request failed, err: %v, resp %#v", err, resp)
	}

	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "data/foo",
		Storage:   storage,
		Data: map[string]interface{}{
			"data": map[string]interface{}{
				"foo": "abc",
				"bar": "def",
			},
		},
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("data CreateOperation request failed, err: %v, resp %#v", err, resp)
	}

	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "subkeys/foo",
		Storage:   storage,
		Data: map[string]interface{}{
			"version": 1,
		},
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("subkeys ReadOperation request failed, err: %v, resp %#v", err, resp)
	}

	expectedSubkeys := map[string]interface{}{
		"foo": nil,
	}
	if diff := deep.Equal(resp.Data["subkeys"], expectedSubkeys); len(diff) > 0 {
		t.Fatalf("resp and expected data mismatch, diff: %#v", diff)
	}
}

// TestVersionedKV_Subkeys_VersionParamDoesNotExist verifies that a nil
// logical.Response is returned if the requested version does not exist
func TestVersionedKV_Subkeys_VersionParamDoesNotExist(t *testing.T) {
	b, storage := getBackend(t)

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "data/foo",
		Storage:   storage,
		Data: map[string]interface{}{
			"data": map[string]interface{}{
				"foo": "abc",
			},
		},
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("data CreateOperation request failed, err: %v, resp %#v", err, resp)
	}

	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "data/foo",
		Storage:   storage,
		Data: map[string]interface{}{
			"data": map[string]interface{}{
				"foo": "abc",
				"bar": "def",
			},
		},
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("data CreateOperation request failed, err: %v, resp %#v", err, resp)
	}

	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "subkeys/foo",
		Storage:   storage,
		Data: map[string]interface{}{
			"version": 10,
		},
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || resp != nil {
		t.Fatalf("unexpected subkeys ReadOperation response, err: %v, resp %#v", err, resp)
	}
}

// TestVersionedKV_Subkeys_DepthParam verifies that the depth param
// handling is correct. Failure to parse the value will result in an
// error response. No limit will be imposed if the param is not
// provided or its value is 0.
func TestVersionedKV_Subkeys_DepthParam(t *testing.T) {
	cases := []struct {
		name      string
		depth     interface{}
		expected  map[string]interface{}
		expectErr bool
	}{
		{
			name:      "invalid",
			depth:     "not-an-integer",
			expected:  nil,
			expectErr: true,
		},
		{
			name:  "not_provided",
			depth: nil,
			expected: map[string]interface{}{
				"foo": map[string]interface{}{
					"bar": map[string]interface{}{
						"baz": nil,
					},
				},
			},
			expectErr: false,
		},
		{
			name:  "zero",
			depth: 0,
			expected: map[string]interface{}{
				"foo": map[string]interface{}{
					"bar": map[string]interface{}{
						"baz": nil,
					},
				},
			},
			expectErr: false,
		},
		{
			name:  "non_zero",
			depth: 2,
			expected: map[string]interface{}{
				"foo": map[string]interface{}{
					"bar": nil,
				},
			},
			expectErr: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc := tc

			t.Parallel()

			b, storage := getBackend(t)

			req := &logical.Request{
				Operation: logical.CreateOperation,
				Path:      "data/foo",
				Storage:   storage,
				Data: map[string]interface{}{
					"data": map[string]interface{}{
						"foo": map[string]interface{}{
							"bar": map[string]interface{}{
								"baz": 123,
							},
						},
					},
				},
			}

			resp, err := b.HandleRequest(context.Background(), req)
			if err != nil || (resp != nil && resp.IsError()) {
				t.Fatalf("data CreateOperation request failed, err: %v, resp %#v", err, resp)
			}

			subkeysData := map[string]interface{}{}

			if tc.depth != nil {
				subkeysData["depth"] = tc.depth
			}

			req = &logical.Request{
				Operation: logical.ReadOperation,
				Path:      "subkeys/foo",
				Storage:   storage,
				Data:      subkeysData,
			}

			resp, err = b.HandleRequest(context.Background(), req)
			if err != nil || resp == nil {
				t.Fatalf("subkeys ReadOperation request failed, err: %v, resp %#v", err, resp)
			}

			if tc.expectErr != resp.IsError() {
				t.Fatalf("unexpected ReadOperation request response, expected err: %t, is error: %t, resp %#v", tc.expectErr, resp.IsError(), resp)
			}

			if tc.expected != nil {
				if diff := deep.Equal(resp.Data["subkeys"], tc.expected); len(diff) > 0 {
					t.Fatalf("resp and expected data mismatch, diff: %#v", diff)
				}
			}
		})
	}
}

// TestVersionedKV_Subkeys_EmptyData verifies that an empty map is
// returned if the underlying data is also empty
func TestVersionedKV_Subkeys_EmptyData(t *testing.T) {
	b, storage := getBackend(t)

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "data/foo",
		Storage:   storage,
		Data: map[string]interface{}{
			"data": map[string]interface{}{},
		},
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("CreateOperation request failed, err: %v, resp %#v", err, resp)
	}

	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "subkeys/foo",
		Storage:   storage,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("ReadOperation request failed, err: %v, resp %#v", err, resp)
	}

	if diff := deep.Equal(resp.Data["subkeys"], map[string]interface{}{}); len(diff) > 0 {
		t.Fatalf("resp and expected data mismatch, diff: %#v", diff)
	}
}

// TestVersionedKV_Subkeys_VersionDeleted verifies that a 404 HTTP response
// is returned if the requested entry has been deleted
func TestVersionedKV_Subkeys_VersionDeleted(t *testing.T) {
	b, storage := getBackend(t)

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "data/foo",
		Storage:   storage,
		Data: map[string]interface{}{
			"data": map[string]interface{}{
				"foo": "bar",
			},
		},
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("data CreateOperation request failed, err: %v, resp %#v", err, resp)
	}

	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "subkeys/foo",
		Storage:   storage,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("subkeys ReadOperation request failed, err: %v, resp %#v", err, resp)
	}

	expectedSubkeys := map[string]interface{}{
		"foo": nil,
	}
	if diff := deep.Equal(resp.Data["subkeys"], expectedSubkeys); len(diff) > 0 {
		t.Fatalf("resp and expected data mismatch, diff: %#v", diff)
	}

	req = &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "data/foo",
		Storage:   storage,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("metadata DeleteOperation request failed - err: %v, resp: %#v\n", err, resp)
	}

	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "subkeys/foo",
		Storage:   storage,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("subkeys ReadOperation request failed, err: %v, resp %#v", err, resp)
	}

	// Use of logical.RespondWithStatusCode in handler will
	// serialize the JSON response body as a string
	respBody := map[string]interface{}{}

	if resp.Data["http_status_code"] != http.StatusNotFound {
		t.Fatalf("expected 404 response for subkeys ReadOperation: resp: %#v", resp)
	}

	if rawRespBody, ok := resp.Data[logical.HTTPRawBody]; ok {
		err = json.Unmarshal([]byte(rawRespBody.(string)), &respBody)
		if err != nil {
			t.Fatalf("Failed to unmarshal response body: %v", err)
		}
	}

	respDataRaw, ok := respBody["data"]
	if !ok {
		t.Fatalf("no data provided in subkeys response, resp: %#v\n", resp)
	}

	respData := respDataRaw.(map[string]interface{})

	respMetadataRaw, ok := respData["metadata"]
	if !ok {
		t.Fatalf("no metadata provided in subkeys response, resp: %#v\n", resp)
	}

	respMetadata := respMetadataRaw.(map[string]interface{})

	if respMetadata["deletion_time"] == "" {
		t.Fatalf("expected deletion_time to be set, resp: %#v\n", resp)
	}
}

// TestVersionedKV_Subkeys_VersionDestroyed verifies that a 404 HTTP response
// is returned if the requested entry has been destroyed
func TestVersionedKV_Subkeys_VersionDestroyed(t *testing.T) {
	b, storage := getBackend(t)

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "data/foo",
		Storage:   storage,
		Data: map[string]interface{}{
			"data": map[string]interface{}{
				"foo": "bar",
			},
		},
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("data CreateOperation request failed, err: %v, resp %#v", err, resp)
	}

	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "subkeys/foo",
		Storage:   storage,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("subkeys ReadOperation request failed, err: %v, resp %#v", err, resp)
	}

	expectedSubkeys := map[string]interface{}{
		"foo": nil,
	}
	if diff := deep.Equal(resp.Data["subkeys"], expectedSubkeys); len(diff) > 0 {
		t.Fatalf("resp and expected data mismatch, diff: %#v", diff)
	}

	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "destroy/foo",
		Storage:   storage,
		Data: map[string]interface{}{
			"versions": []int{1},
		},
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("destroy CreateOperation request failed - err: %v resp:%#v\n", err, resp)
	}

	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "subkeys/foo",
		Storage:   storage,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("subkeys ReadOperation request failed, err: %v, resp %#v", err, resp)
	}

	// Use of logical.RespondWithStatusCode in handler will
	// serialize the JSON response body as a string
	respBody := map[string]interface{}{}

	if resp.Data["http_status_code"] != http.StatusNotFound {
		t.Fatalf("expected 404 response for subkeys ReadOperation: resp:%#v", resp)
	}

	if rawRespBody, ok := resp.Data[logical.HTTPRawBody]; ok {
		err = json.Unmarshal([]byte(rawRespBody.(string)), &respBody)
		if err != nil {
			t.Fatalf("Failed to unmarshal response body: %v", err)
		}
	}

	respDataRaw, ok := respBody["data"]
	if !ok {
		t.Fatalf("no data provided in subkeys response, resp: %#v\n", resp)
	}

	respData := respDataRaw.(map[string]interface{})

	respMetadataRaw, ok := respData["metadata"]
	if !ok {
		t.Fatalf("no metadata provided in subkeys response, resp: %#v\n", resp)
	}

	respMetadata := respMetadataRaw.(map[string]interface{})

	if respMetadata["destroyed"] == nil || !respMetadata["destroyed"].(bool) {
		t.Fatalf("expected version to be destroyed, resp: %#v\n", resp)
	}
}
