package kv

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/go-test/deep"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func TestVersionedKV_Metadata_Put(t *testing.T) {
	b, storage := getBackend(t)

	d := 5 * time.Minute

	expectedCustomMetadata := map[string]string{
		"foo": "abc",
		"bar": "123",
	}

	data := map[string]interface{}{
		"max_versions":         2,
		"cas_required":         true,
		"delete_version_after": d.String(),
		"custom_metadata":      expectedCustomMetadata,
	}

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "metadata/foo",
		Storage:   storage,
		Data:      data,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "metadata/foo",
		Storage:   storage,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	if resp.Data["max_versions"] != uint32(2) {
		t.Fatalf("Bad response: %#v", resp)
	}

	if resp.Data["cas_required"] != true {
		t.Fatalf("Bad response: %#v", resp)
	}
	if resp.Data["delete_version_after"] != d.String() {
		t.Fatalf("Bad response: %#v", resp)
	}

	if diff := deep.Equal(resp.Data["custom_metadata"], expectedCustomMetadata); len(diff) > 0 {
		t.Fatal(diff)
	}

	data = map[string]interface{}{
		"data": map[string]interface{}{
			"bar": "baz1",
		},
	}

	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "data/foo",
		Storage:   storage,
		Data:      data,
	}

	// Should fail with with cas required error
	resp, err = b.HandleRequest(context.Background(), req)
	if err == nil || resp.Error().Error() != "check-and-set parameter required for this call" {
		t.Fatalf("expected error, %#v", resp)
	}

	data = map[string]interface{}{
		"data": map[string]interface{}{
			"bar": "baz1",
		},
		"options": map[string]interface{}{
			"cas": 0,
		},
	}

	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "data/foo",
		Storage:   storage,
		Data:      data,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	if resp.Data["version"] != uint64(1) {
		t.Fatalf("Bad response: %#v", resp)
	}

	data = map[string]interface{}{
		"data": map[string]interface{}{
			"bar": "baz1",
		},
		"options": map[string]interface{}{
			"cas": 1,
		},
	}

	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "data/foo",
		Storage:   storage,
		Data:      data,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	if resp.Data["version"] != uint64(2) {
		t.Fatalf("Bad response: %#v", resp)
	}

	data = map[string]interface{}{
		"data": map[string]interface{}{
			"bar": "baz1",
		},
		"options": map[string]interface{}{
			"cas": 2,
		},
	}

	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "data/foo",
		Storage:   storage,
		Data:      data,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	if resp.Data["version"] != uint64(3) {
		t.Fatalf("Bad response: %#v", resp)
	}

	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "metadata/foo",
		Storage:   storage,
		Data:      data,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	if resp.Data["current_version"] != uint64(3) {
		t.Fatalf("Bad response: %#v", resp)
	}

	if resp.Data["oldest_version"] != uint64(2) {
		t.Fatalf("Bad response: %#v", resp)
	}

	if _, ok := resp.Data["versions"].(map[string]interface{})["2"]; !ok {
		t.Fatalf("Bad response: %#v", resp)
	}

	if _, ok := resp.Data["versions"].(map[string]interface{})["3"]; !ok {
		t.Fatalf("Bad response: %#v", resp)
	}

	// Update the metadata settings, remove the cas requirement and lower the
	// max versions.
	data = map[string]interface{}{
		"max_versions": 1,
		"cas_required": false,
	}

	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "metadata/foo",
		Storage:   storage,
		Data:      data,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	data = map[string]interface{}{
		"data": map[string]interface{}{
			"bar": "baz1",
		},
	}

	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "data/foo",
		Storage:   storage,
		Data:      data,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	if resp.Data["version"] != uint64(4) {
		t.Fatalf("Bad response: %#v", resp)
	}

	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "metadata/foo",
		Storage:   storage,
		Data:      data,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	if resp.Data["current_version"] != uint64(4) {
		t.Fatalf("Bad response: %#v", resp)
	}

	if resp.Data["oldest_version"] != uint64(4) {
		t.Fatalf("Bad response: %#v", resp)
	}

	if _, ok := resp.Data["versions"].(map[string]interface{})["4"]; !ok {
		t.Fatalf("Bad response: %#v", resp)
	}

	if len(resp.Data["versions"].(map[string]interface{})) != 1 {
		t.Fatalf("Bad response: %#v", resp)
	}

	// Do the same via a list on detailed-metadata and compare the results.
	// It should have a keyInfo that is the same as the read response data.
	req = &logical.Request{
		Operation: logical.ListOperation,
		Path:      "detailed-metadata/",
		Storage:   storage,
	}

	listResp, err := b.HandleRequest(context.Background(), req)
	if err != nil || listResp == nil || listResp.IsError() {
		t.Fatalf("err:%s resp:%#v\n", err, listResp)
	}

	if len(listResp.Data["keys"].([]string)) != 1 || listResp.Data["keys"].([]string)[0] != "foo" {
		t.Fatalf("expected one key (foo) - resp: %#v", listResp)
	}

	actual := listResp.Data["key_info"].(map[string]interface{})["foo"]
	expected := resp.Data
	if diff := deep.Equal(actual, expected); len(diff) > 0 {
		t.Fatalf("expected detailed-metadata/ listing to have same contents as read on foo/\ndiff: %#v", diff)
	}
}

func TestVersionedKV_Metadata_Delete(t *testing.T) {
	b, storage := getBackend(t)

	// Create a few versions
	for i := 0; i <= 5; i++ {
		data := map[string]interface{}{
			"data": map[string]interface{}{
				"bar": fmt.Sprintf("baz%d", i),
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
			t.Fatalf("err:%s resp:%#v\n", err, resp)
		}

		if resp.Data["version"] != uint64(i+1) {
			t.Fatalf("Bad response: %#v", resp)
		}
	}

	req := &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "metadata/foo",
		Storage:   storage,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	// Read the data path
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "data/foo",
		Storage:   storage,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}
	if resp != nil {
		t.Fatalf("Bad response: %#v", resp)
	}

	// Read the metadata path
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "metadata/foo",
		Storage:   storage,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}
	if resp != nil {
		t.Fatalf("Bad response: %#v", resp)
	}

	// Verify all the version data was deleted.
	for i := 0; i <= 5; i++ {
		versionKey, err := b.(*versionedKVBackend).getVersionKey(context.Background(), "foo", uint64(i+1), req.Storage)
		if err != nil {
			t.Fatal(err)
		}

		v, err := storage.Get(context.Background(), versionKey)
		if err != nil {
			t.Fatal(err)
		}

		if v != nil {
			t.Fatal("Version wasn't deleted")
		}

	}
}

func TestVersionedKV_Metadata_Put_Bad_CustomMetadata(t *testing.T) {
	b, storage := getBackend(t)
	metadataPath := "metadata/foo"

	stringToRepeat := "a"
	longKeyLength := 129
	longKey := strings.Repeat(stringToRepeat, longKeyLength)

	longValueKey := "long_value"
	longValueLength := 513

	emptyValueKey := "empty_value"
	unprintableString := "unprint\u200bable"
	unprintableValueKey := "unprintable"

	customMetadata := map[string]interface{}{
		longValueKey:        strings.Repeat(stringToRepeat, longValueLength),
		longKey:             "abc123",
		"":                  "abc123",
		emptyValueKey:       "",
		unprintableString:   "abc123",
		unprintableValueKey: unprintableString,
	}

	data := map[string]interface{}{
		"custom_metadata": customMetadata,
	}

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      metadataPath,
		Storage:   storage,
		Data:      data,
	}

	resp, err := b.HandleRequest(context.Background(), req)

	if err != nil || resp == nil {
		t.Fatalf("Write err: %s resp: %#v\n", err, resp)
	}

	// Should fail with validation errors
	if !resp.IsError() {
		t.Fatalf("expected resp error, resp: %#v", resp)
	}

	respError := resp.Error().Error()

	if keyCount := len(customMetadata); !strings.Contains(respError, fmt.Sprintf("%d errors occurred", keyCount)) {
		t.Fatalf("Expected %d validation errors, resp: %#v", keyCount, resp)
	}

	if !strings.Contains(respError, fmt.Sprintf("length of key %q is %d",
		longKey,
		longKeyLength)) {
		t.Fatalf("Expected key length error for key %q, resp: %#v", longKey, resp)
	}

	if !strings.Contains(respError, fmt.Sprintf("length of value for key %q is %d",
		longValueKey,
		longValueLength)) {
		t.Fatalf("Expected value length error for key %q, resp: %#v", longValueKey, resp)
	}

	if !strings.Contains(respError, "length of key \"\" is 0") {
		t.Fatalf("Expected key length error for key \"\", resp: %#v", resp)
	}

	if !strings.Contains(respError, fmt.Sprintf("length of value for key %q is 0", emptyValueKey)) {
		t.Fatalf("Expected value length error for key %q, resp: %#v", emptyValueKey, resp)
	}

	if !strings.Contains(respError, fmt.Sprintf("key %q (%s) contains unprintable", unprintableString, unprintableString)) {
		t.Fatalf("Expected unprintable character error for key %q, resp: %#v", unprintableString, resp)
	}

	if !strings.Contains(respError, fmt.Sprintf("key %q contains unprintable", unprintableValueKey)) {
		t.Fatalf("Expected unpritnable character for value of key %q, resp: %#v", unprintableValueKey, resp)
	}

	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      metadataPath,
		Storage:   storage,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("Read err: %#v, resp: %#v", err, resp)
	}

	if resp != nil {
		t.Fatalf("Expected empty read due to validation errors, resp: %#v", resp)
	}

	data = map[string]interface{}{
		"custom_metadata": map[string]interface{}{
			"foo": map[string]interface{}{
				"bar": "baz",
			},
		},
	}

	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      metadataPath,
		Storage:   storage,
		Data:      data,
	}

	resp, err = b.HandleRequest(context.Background(), req)

	if err != nil || resp == nil {
		t.Fatalf("Write err: %s resp: %#v\n", err, resp)
	}

	if !resp.IsError() {
		t.Fatalf("expected resp error, resp: %#v", resp)
	}

	respError = resp.Error().Error()
	expectedError := "got unconvertible type"

	if !strings.Contains(respError, expectedError) {
		t.Fatalf("expected response error %q to include %q validation errors", respError, expectedError)
	}
}

func TestVersionedKv_Metadata_Put_Too_Many_CustomMetadata_Keys(t *testing.T) {
	b, storage := getBackend(t)

	metadataPath := "metadata/foo"

	customMetadata := map[string]string{}

	for i := 0; i < maxCustomMetadataKeys+1; i++ {
		k := fmt.Sprint(i)
		customMetadata[k] = k
	}

	data := map[string]interface{}{
		"custom_metadata": customMetadata,
	}

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      metadataPath,
		Storage:   storage,
		Data:      data,
	}

	resp, err := b.HandleRequest(context.Background(), req)

	if err != nil || resp == nil {
		t.Fatalf("Write err: %s resp: %#v\n", err, resp)
	}

	if !resp.IsError() {
		t.Fatalf("expected resp error, resp: %#v", resp)
	}

	respError := resp.Error().Error()

	if !strings.Contains(respError, "1 error occurred") {
		t.Fatalf("Expected 1 validation error, resp: %#v", resp)
	}

	if !strings.Contains(respError, fmt.Sprintf("payload must contain at most %d keys, provided %d",
		maxCustomMetadataKeys,
		len(customMetadata))) {
		t.Fatalf("Expected max custom metadata keys error, resp: %#v", resp)
	}

	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      metadataPath,
		Storage:   storage,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("Read err: %#v, resp :%#v", err, resp)
	}

	if resp != nil {
		t.Fatalf("Expected empty read due to validation errors, resp: %#v", resp)
	}
}

func TestVersionedKV_Metadata_Put_Empty_CustomMetadata(t *testing.T) {
	b, storage := getBackend(t)

	metadataPath := "metadata/foo"

	data := map[string]interface{}{
		"custom_metadata": map[string]string{},
	}

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      metadataPath,
		Storage:   storage,
		Data:      data,
	}

	resp, err := b.HandleRequest(context.Background(), req)

	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("Write err: %s, resp: %#v", err, resp)
	}

	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      metadataPath,
		Storage:   storage,
	}

	resp, err = b.HandleRequest(context.Background(), req)

	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("Read err: %s, resp %#v", err, resp)
	}

	// writing custom_metadata as {} should result in nil
	if diff := deep.Equal(resp.Data["custom_metadata"], map[string]string(nil)); len(diff) > 0 {
		t.Fatal(diff)
	}
}

func TestVersionedKV_Metadata_Put_Merge_Behavior(t *testing.T) {
	b, storage := getBackend(t)

	metadataPath := "metadata/foo"
	expectedMaxVersions := uint32(5)
	expectedCasRequired := true

	data := map[string]interface{}{
		"max_versions": expectedMaxVersions,
		"cas_required": expectedCasRequired,
	}

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      metadataPath,
		Storage:   storage,
		Data:      data,
	}

	resp, err := b.HandleRequest(context.Background(), req)

	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("Write err: %s, resp: %#v", err, resp)
	}

	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      metadataPath,
		Storage:   storage,
	}

	resp, err = b.HandleRequest(context.Background(), req)

	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("Read err: %s, resp %#v", err, resp)
	}

	if resp.Data["max_versions"] != expectedMaxVersions {
		t.Fatalf("max_versions mismatch, expected: %d, actual: %d, resp: %#v",
			expectedMaxVersions,
			resp.Data["max_versions"],
			resp)
	}

	if resp.Data["cas_required"] != expectedCasRequired {
		t.Fatalf("cas_required mismatch, expected: %t, actual: %t, resp: %#v",
			expectedCasRequired,
			resp.Data["cas_required"],
			resp)
	}

	// custom_metadata was not provided so it should come back as a nil map
	if diff := deep.Equal(resp.Data["custom_metadata"], map[string]string(nil)); len(diff) > 0 {
		t.Fatal(diff)
	}

	expectedCasRequired = false
	expectedCustomMetadata := map[string]string{
		"foo": "abc",
		"bar": "123",
	}

	data = map[string]interface{}{
		"cas_required":    expectedCasRequired,
		"custom_metadata": expectedCustomMetadata,
	}

	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      metadataPath,
		Storage:   storage,
		Data:      data,
	}

	resp, err = b.HandleRequest(context.Background(), req)

	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("Write err: %s, resp: %#v", err, resp)
	}

	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      metadataPath,
		Storage:   storage,
	}

	resp, err = b.HandleRequest(context.Background(), req)

	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("Read err: %s, resp %#v", err, resp)
	}

	// max_versions not provided, should not have changed
	if resp.Data["max_versions"] != expectedMaxVersions {
		t.Fatalf("max_versions mismatch, expected: %d, actual: %d, resp: %#v",
			expectedMaxVersions,
			resp.Data["max_versions"],
			resp)
	}

	// cas_required should be overwritten
	if resp.Data["cas_required"] != expectedCasRequired {
		t.Fatalf("cas_required mismatch, expected: %t, actual: %t, resp: %#v",
			expectedCasRequired,
			resp.Data["cas_required"],
			resp)
	}

	// custom_metadata provided for the first time, should no longer be a nil map
	if diff := deep.Equal(resp.Data["custom_metadata"], expectedCustomMetadata); len(diff) > 0 {
		t.Fatal(diff)
	}

	expectedCustomMetadata = map[string]string{
		"baz": "abc123",
	}

	data = map[string]interface{}{
		"custom_metadata": expectedCustomMetadata,
	}

	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      metadataPath,
		Storage:   storage,
		Data:      data,
	}

	resp, err = b.HandleRequest(context.Background(), req)

	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("Write err: %s, resp: %#v", err, resp)
	}

	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      metadataPath,
		Storage:   storage,
	}

	resp, err = b.HandleRequest(context.Background(), req)

	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("Read err: %s, resp %#v", err, resp)
	}

	// max_versions not provided, should not have changed
	if resp.Data["max_versions"] != expectedMaxVersions {
		t.Fatalf("max_versions mismatch, expected: %d, actual: %d",
			expectedMaxVersions,
			resp.Data["max_versions"])
	}

	// cas_required not provided, should not have changed
	if resp.Data["cas_required"] != expectedCasRequired {
		t.Fatalf("cas_required mismatch, expected: %t, actual: %t,",
			expectedCasRequired,
			resp.Data["cas_required"])
	}

	// custom_metadata should be completely overwritten
	if diff := deep.Equal(resp.Data["custom_metadata"], expectedCustomMetadata); len(diff) > 0 {
		t.Fatal(diff)
	}

	expectedMaxVersions = 20

	data = map[string]interface{}{
		"max_versions": expectedMaxVersions,
	}

	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      metadataPath,
		Storage:   storage,
		Data:      data,
	}

	resp, err = b.HandleRequest(context.Background(), req)

	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("Write err: %s, resp: %#v", err, resp)
	}

	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      metadataPath,
		Storage:   storage,
	}

	resp, err = b.HandleRequest(context.Background(), req)

	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("Read err: %s, resp %#v", err, resp)
	}

	// custom_metadata not provided, should not have changed
	if diff := deep.Equal(resp.Data["custom_metadata"], expectedCustomMetadata); len(diff) > 0 {
		t.Fatal(diff)
	}
}

func TestVersionedKV_Metadata_Patch_MissingPath(t *testing.T) {
	b, storage := getBackend(t)

	req := &logical.Request{
		Operation: logical.PatchOperation,
		Path:      "metadata/",
		Storage:   storage,
		Data: map[string]interface{}{
			"cas_required": true,
		},
	}

	resp, err := b.HandleRequest(context.Background(), req)

	if err != nil || resp == nil {
		t.Fatalf("unexpected patch error, err: %#v, resp: %#v", err, resp)
	}

	expectedErr := "missing path"
	if respErr := resp.Error().Error(); !strings.Contains(respErr, expectedErr) {
		t.Fatalf("expected patch output to contain %s, actual: %s", expectedErr, respErr)
	}
}

func TestVersionedKV_Metadata_Patch_Validation(t *testing.T) {
	t.Parallel()

	unprintableString := "unprint\u200bable"

	longKeyLength := 129
	longValueLength := 513

	longKey := strings.Repeat("a", longKeyLength)
	longValue := strings.Repeat("a", longValueLength)

	cases := []struct {
		name     string
		metadata map[string]interface{}
		output   string
	}{
		{
			"field_conversion_error",
			map[string]interface{}{
				"max_versions": []int{1, 2, 3},
			},
			"Field validation failed: error converting input",
		},
		{
			"custom_metadata_empty_key",
			map[string]interface{}{
				"custom_metadata": map[string]string{
					"": "foo",
				},
			},
			fmt.Sprintf("length of key %q is 0", ""),
		},
		{
			"custom_metadata_unprintable_key",
			map[string]interface{}{
				"custom_metadata": map[string]string{
					unprintableString: "foo",
				},
			},
			fmt.Sprintf("key %q (%s) contains unprintable characters", unprintableString, unprintableString),
		},
		{
			"custom_metadata_unprintable_value",
			map[string]interface{}{
				"custom_metadata": map[string]string{
					"foo": unprintableString,
				},
			},
			fmt.Sprintf("value for key %q contains unprintable characters", "foo"),
		},
		{
			"custom_metadata_key_too_long",
			map[string]interface{}{
				"custom_metadata": map[string]string{
					longKey: "foo",
				},
			},
			fmt.Sprintf("length of key %q is %d", longKey, longKeyLength),
		},
		{
			"custom_metadata_value_too_long",
			map[string]interface{}{
				"custom_metadata": map[string]string{
					"foo": longValue,
				},
			},
			fmt.Sprintf("length of value for key %q is %d", "foo", longValueLength),
		},
		{
			"custom_metadata_invalid_type",
			map[string]interface{}{
				"custom_metadata": map[string]interface{}{
					"foo": map[string]interface{}{
						"bar": "baz",
					},
				},
			},
			"got unconvertible type",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, storage := getBackend(t)
			path := "metadata/" + tc.name

			req := &logical.Request{
				Operation: logical.CreateOperation,
				Path:      path,
				Storage:   storage,
				Data: map[string]interface{}{
					"cas_required": true,
				},
			}

			resp, err := b.HandleRequest(context.Background(), req)

			if err != nil || (resp != nil && resp.IsError()) {
				t.Fatalf("create request failed, err: %#v, resp: %#v", err, resp)
			}

			req = &logical.Request{
				Operation: logical.PatchOperation,
				Path:      path,
				Storage:   storage,
				Data:      tc.metadata,
			}

			resp, err = b.HandleRequest(context.Background(), req)
			if err != nil {
				t.Fatalf("unexpected patch error, err: %#v", err)
			}

			if resp == nil || !resp.IsError() {
				t.Fatalf("expected patch response to be error, actual: %#v", resp)
			}

			respError := resp.Error().Error()

			if !strings.Contains(respError, tc.output) {
				t.Fatalf("expected patch output to contain %s, actual: %s", tc.output, respError)
			}
		})
	}
}

func TestVersionedKV_Metadata_Patch_NotFound(t *testing.T) {
	b, storage := getBackend(t)

	req := &logical.Request{
		Operation: logical.PatchOperation,
		Path:      "metadata/foo",
		Storage:   storage,
		Data: map[string]interface{}{
			"cas_required": true,
		},
	}

	resp, err := b.HandleRequest(context.Background(), req)

	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("request failed, err:%s resp:%#v\n", err, resp)
	}

	if resp.Data["http_status_code"] != 404 {
		t.Fatalf("expected 404 response, resp:%#v", resp)
	}
}

func TestVersionedKV_Metadata_Patch_CasRequiredWarning(t *testing.T) {
	b, storage := getBackend(t)

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"cas_required": true,
		},
	}

	resp, err := b.HandleRequest(context.Background(), req)

	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("config request failed, err:%s resp:%#v\n", err, resp)
	}

	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "metadata/foo",
		Storage:   storage,
		Data: map[string]interface{}{
			"max_versions": 5,
		},
	}

	resp, err = b.HandleRequest(context.Background(), req)

	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("metadata create request failed, err:%s resp:%#v\n", err, resp)
	}

	req = &logical.Request{
		Operation: logical.PatchOperation,
		Path:      "metadata/foo",
		Storage:   storage,
		Data: map[string]interface{}{
			"cas_required": false,
		},
	}

	resp, err = b.HandleRequest(context.Background(), req)

	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("metadata patch request failed, err:%s resp:%#v\n", err, resp)
	}

	if len(resp.Warnings) != 1 ||
		!strings.Contains(resp.Warnings[0], "\"cas_required\" set to false, but is mandated by backend config") {
		t.Fatalf("expected cas_required warning, resp warnings: %#v", resp.Warnings)
	}

	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "metadata/foo",
		Storage:   storage,
	}

	resp, err = b.HandleRequest(context.Background(), req)

	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("metadata create request failed, err:%s resp:%#v\n", err, resp)
	}

	if resp.Data["cas_required"] != false {
		t.Fatal("expected cas_required to be set to false despite warning")
	}
}

func TestVersionedKV_Metadata_Patch_CustomMetadata(t *testing.T) {
	t.Parallel()

	initialCustomMetadata := map[string]string{
		"foo": "abc",
		"bar": "def",
	}

	cases := []struct {
		name   string
		input  map[string]interface{}
		output map[string]string
	}{
		{
			"empty_object",
			map[string]interface{}{},
			map[string]string{
				"foo": "abc",
				"bar": "def",
			},
		},
		{
			"add_a_key",
			map[string]interface{}{
				"baz": "ghi",
			},
			map[string]string{
				"foo": "abc",
				"bar": "def",
				"baz": "ghi",
			},
		},
		{
			"remove_a_key",
			map[string]interface{}{
				"foo": nil,
			},
			map[string]string{
				"bar": "def",
			},
		},
		{
			"replace_a_key",
			map[string]interface{}{
				"foo": "ghi",
			},
			map[string]string{
				"foo": "ghi",
				"bar": "def",
			},
		},
		{
			"mixed",
			map[string]interface{}{
				"foo": "def",
				"bar": nil,
				"baz": "ghi",
			},
			map[string]string{
				"foo": "def",
				"baz": "ghi",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, storage := getBackend(t)
			path := "metadata/" + tc.name

			req := &logical.Request{
				Operation: logical.CreateOperation,
				Path:      path,
				Storage:   storage,
				Data: map[string]interface{}{
					"custom_metadata": initialCustomMetadata,
				},
			}

			resp, err := b.HandleRequest(context.Background(), req)

			if err != nil || (resp != nil && resp.IsError()) {
				t.Fatalf("create request failed, err: %#v, resp: %#v", err, resp)
			}

			req = &logical.Request{
				Operation: logical.PatchOperation,
				Path:      path,
				Storage:   storage,
				Data: map[string]interface{}{
					"custom_metadata": tc.input,
				},
			}

			resp, err = b.HandleRequest(context.Background(), req)

			if err != nil || (resp != nil && resp.IsError()) {
				t.Fatalf("patch request failed, err: %#v, resp: %#v", err, resp)
			}

			req = &logical.Request{
				Operation: logical.ReadOperation,
				Path:      path,
				Storage:   storage,
			}

			resp, err = b.HandleRequest(context.Background(), req)

			if err != nil || (resp != nil && resp.IsError()) {
				t.Fatalf("read request failed, err: %#v, resp: %#v", err, resp)
			}

			var ok bool
			var customMetadata map[string]string

			if customMetadata, ok = resp.Data["custom_metadata"].(map[string]string); !ok {
				t.Fatalf("custom_metadata not included or incorrect type, resp: %#v", resp)
			}

			if diff := deep.Equal(tc.output, customMetadata); len(diff) > 0 {
				t.Fatalf("patched custom metadata does not match, diff: %#v", diff)
			}
		})
	}
}

func TestVersionedKV_Metadata_Patch_Success(t *testing.T) {
	t.Parallel()

	ignoreVal := "ignore_me"
	cases := []struct {
		name            string
		input           map[string]interface{}
		expectedChanges int
	}{
		{
			"ignored_fields",
			map[string]interface{}{
				"foo":             ignoreVal,
				"created_time":    ignoreVal,
				"current_version": ignoreVal,
				"oldest_version":  ignoreVal,
				"updated_time":    ignoreVal,
			},
			0,
		},
		{
			"no_fields_modified",
			map[string]interface{}{},
			0,
		},
		{
			"top_level_fields_replaced",
			map[string]interface{}{
				"cas_required": true,
				"max_versions": uint32(5),
			},
			2,
		},
		{
			"top_level_mixed",
			map[string]interface{}{
				"cas_required":         true,
				"max_versions":         uint32(15),
				"delete_version_after": nil,
				"updated_time":         ignoreVal,
			},
			2,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, storage := getBackend(t)
			path := "metadata/" + tc.name

			req := &logical.Request{
				Operation: logical.CreateOperation,
				Path:      path,
				Storage:   storage,
				Data: map[string]interface{}{
					"max_versions": uint32(10),
				},
			}

			resp, err := b.HandleRequest(context.Background(), req)

			if err != nil || (resp != nil && resp.IsError()) {
				t.Fatalf("create request failed, err: %#v, resp: %#v", err, resp)
			}

			req = &logical.Request{
				Operation: logical.ReadOperation,
				Path:      path,
				Storage:   storage,
			}

			resp, err = b.HandleRequest(context.Background(), req)

			if err != nil || (resp != nil && resp.IsError()) {
				t.Fatalf("read request failed, err: %#v, resp: %#v", err, resp)
			}

			initialMetadata := resp.Data

			req = &logical.Request{
				Operation: logical.PatchOperation,
				Path:      path,
				Storage:   storage,
				Data:      tc.input,
			}

			resp, err = b.HandleRequest(context.Background(), req)

			if err != nil || (resp != nil && resp.IsError()) {
				t.Fatalf("patch request failed, err: %#v, resp: %#v", err, resp)
			}

			req = &logical.Request{
				Operation: logical.ReadOperation,
				Path:      path,
				Storage:   storage,
			}

			resp, err = b.HandleRequest(context.Background(), req)

			if err != nil || (resp != nil && resp.IsError()) {
				t.Fatalf("read request failed, err: %#v, resp: %#v", err, resp)
			}

			patchedMetadata := resp.Data

			if diff := deep.Equal(initialMetadata, patchedMetadata); tc.expectedChanges != len(diff) {
				t.Fatalf("incorrect number of changes to metadata, expected: %d, actual: %d, diff: %#v",
					tc.expectedChanges,
					len(diff),
					diff)
			}

			for k, v := range patchedMetadata {
				var expectedVal interface{}

				if inputVal, ok := tc.input[k]; ok && inputVal != nil && inputVal != ignoreVal {
					expectedVal = inputVal
				} else {
					expectedVal = initialMetadata[k]
				}

				if k == "custom_metadata" || k == "versions" {
					if diff := deep.Equal(expectedVal, v); len(diff) > 0 {
						t.Fatalf("patched %q mismatch, diff: %#v", k, diff)
					}
				} else if expectedVal != v {
					t.Fatalf("patched key %s mismatch, expected: %#v, actual %#v", k, expectedVal, v)
				}
			}
		})
	}
}

func TestVersionedKV_Metadata_Patch_NilsUnset(t *testing.T) {
	b, storage := getBackend(t)
	path := "metadata/nils_unset"

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      path,
		Storage:   storage,
		Data: map[string]interface{}{
			"max_versions": uint32(10),
		},
	}

	resp, err := b.HandleRequest(context.Background(), req)

	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("create request failed, err: %#v, resp: %#v", err, resp)
	}

	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      path,
		Storage:   storage,
	}

	resp, err = b.HandleRequest(context.Background(), req)

	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("read request failed, err: %#v, resp: %#v", err, resp)
	}

	if maxVersions := resp.Data["max_versions"].(uint32); maxVersions != 10 {
		t.Fatal("expected max_versions to be 10")
	}

	req = &logical.Request{
		Operation: logical.PatchOperation,
		Path:      path,
		Storage:   storage,
		Data: map[string]interface{}{
			"max_versions": nil,
		},
	}

	resp, err = b.HandleRequest(context.Background(), req)

	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("patch request failed, err: %#v, resp: %#v", err, resp)
	}

	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      path,
		Storage:   storage,
	}

	resp, err = b.HandleRequest(context.Background(), req)

	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("read request failed, err: %#v, resp: %#v", err, resp)
	}

	if maxVersions := resp.Data["max_versions"].(uint32); maxVersions != 0 {
		t.Fatal("expected max_versions to be unset to zero value")
	}
}

// TestVersionedKV_ListDetailedMetadata ensures that detailed listing in
// KVv2 does not cause a panic due to directories with missing metadata
// entries.
func TestVersionedKV_ListDetailedMetadata(t *testing.T) {
	b, storage := getBackend(t)

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "data/subdir/entry",
		Storage:   storage,
		Data: map[string]interface{}{
			"data": map[string]interface{}{
				"value": 10,
			},
		},
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("create request failed, err: %#v, resp: %#v", err, resp)
	}

	req = &logical.Request{
		Operation: logical.ListOperation,
		Path:      "detailed-metadata/",
		Storage:   storage,
	}

	listResp, err := b.HandleRequest(context.Background(), req)
	if err != nil || listResp == nil || listResp.IsError() {
		t.Fatalf("err:%s resp:%#v\n", err, listResp)
	}

	if len(listResp.Data["keys"].([]string)) != 1 || listResp.Data["keys"].([]string)[0] != "subdir/" {
		t.Fatalf("expected one key (foo) - resp: %#v", listResp)
	}

	value := listResp.Data["key_info"].(map[string]interface{})["subdir"]

	if value != nil && len(value.(map[string]interface{})) != 0 {
		t.Fatalf("unexpected info about directory in detailed list response: %v", listResp.Data)
	}
}
