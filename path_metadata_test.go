package kv

import (
	"context"
	"fmt"
	"github.com/go-test/deep"
	"github.com/hashicorp/vault/sdk/logical"
	"strings"
	"testing"
	"time"
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

	customMetadata := map[string]string{
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
