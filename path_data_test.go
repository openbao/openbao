package kv

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"

	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/helper/logging"
	"github.com/hashicorp/vault/logical"
)

func getBackend(t *testing.T) (logical.Backend, logical.Storage) {
	config := &logical.BackendConfig{
		Logger:      logging.NewVaultLogger(log.Trace),
		System:      &logical.StaticSystemView{},
		StorageView: &logical.InmemStorage{},
		BackendUUID: "test",
	}

	b, err := VersionedKVFactory(context.Background(), config)
	if err != nil {
		t.Fatalf("unable to create backend: %v", err)
	}

	// Wait for the upgrade to finish
	time.Sleep(time.Second)

	return b, config.StorageView
}

func TestVersionedKV_Data_Put(t *testing.T) {
	b, storage := getBackend(t)

	data := map[string]interface{}{
		"data": map[string]interface{}{
			"bar": "baz",
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

	if resp.Data["version"] != uint64(1) {
		t.Fatalf("Bad response: %#v", resp)
	}

	data = map[string]interface{}{
		"data": map[string]interface{}{
			"bar": "baz1",
		},
		"options": map[string]interface{}{
			"cas": float64(1),
		},
	}

	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "data/foo",
		Storage:   storage,
		Data:      data,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	if resp.Data["version"] != uint64(2) {
		t.Fatalf("Bad response: %#v", resp)
	}
}

func TestVersionedKV_Data_Get(t *testing.T) {
	b, storage := getBackend(t)

	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "data/foo",
		Storage:   storage,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	if resp != nil {
		t.Fatalf("Bad response: %#v", resp)
	}

	data := map[string]interface{}{
		"data": map[string]interface{}{
			"bar": "baz",
		},
	}

	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "data/foo",
		Storage:   storage,
		Data:      data,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	if resp.Data["version"] != uint64(1) {
		t.Fatalf("Bad response: %#v", resp)
	}

	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "data/foo",
		Storage:   storage,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	if !reflect.DeepEqual(resp.Data["data"], data["data"]) {
		t.Fatalf("Bad response: %#v", resp)
	}

	if resp.Data["metadata"].(map[string]interface{})["version"].(uint64) != uint64(1) {
		t.Fatalf("Bad response: %#v", resp)
	}

	parsed, err := time.Parse(time.RFC3339Nano, resp.Data["metadata"].(map[string]interface{})["created_time"].(string))
	if err != nil {
		t.Fatal(err)
	}

	if !parsed.After(time.Now().Add(-1*time.Minute)) || !parsed.Before(time.Now()) {
		t.Fatalf("Bad response: %#v", resp)
	}
}

func TestVersionedKV_Data_Delete(t *testing.T) {
	b, storage := getBackend(t)

	data := map[string]interface{}{
		"data": map[string]interface{}{
			"bar": "baz",
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

	if resp.Data["version"] != uint64(1) {
		t.Fatalf("Bad response: %#v", resp)
	}

	req = &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "data/foo",
		Storage:   storage,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "data/foo",
		Storage:   storage,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	var httpResp logical.HTTPResponse
	err = json.Unmarshal(resp.Data["http_raw_body"].([]byte), &httpResp)
	if err != nil {
		t.Fatal(err)
	}

	if uint64(httpResp.Data["metadata"].(map[string]interface{})["version"].(float64)) != uint64(1) {
		t.Fatalf("Bad response: %#v", resp)
	}

	parsed, err := time.Parse(time.RFC3339Nano, httpResp.Data["metadata"].(map[string]interface{})["deletion_time"].(string))
	if err != nil {
		t.Fatal(err)
	}

	if !parsed.After(time.Now().Add(-1*time.Minute)) || !parsed.Before(time.Now()) {
		t.Fatalf("Bad response: %#v", resp)
	}

}

func TestVersionedKV_Data_CleanupOldVersions(t *testing.T) {
	b, storage := getBackend(t)

	// Write 10 versions
	for i := 0; i < 10; i++ {
		data := map[string]interface{}{
			"data": map[string]interface{}{
				"bar": "baz",
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

	// lower max versions
	data := map[string]interface{}{
		"max_versions": 2,
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

	// write another version
	data = map[string]interface{}{
		"data": map[string]interface{}{
			"bar": "baz",
		},
	}

	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "data/foo",
		Storage:   storage,
		Data:      data,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	if resp.Data["version"] != uint64(11) {
		t.Fatalf("Bad response: %#v", resp)
	}

	// Make sure versions 1-9 were cleaned up.
	for i := 1; i <= 9; i++ {
		versionKey, err := b.(*versionedKVBackend).getVersionKey(context.Background(), "foo", uint64(i), storage)
		if err != nil {
			t.Fatal(err)
		}

		v, err := storage.Get(context.Background(), versionKey)
		if err != nil {
			t.Fatal(err)
		}

		if v != nil {
			t.Fatalf("version not cleaned up %d", i)
		}
	}

}

func TestVersionedKV_Reload_Policy(t *testing.T) {
	b, storage := getBackend(t)

	data := map[string]interface{}{
		"data": map[string]interface{}{
			"bar": "baz",
		},
	}

	// Write 10 versions
	for i := 0; i < 10; i++ {

		req := &logical.Request{
			Operation: logical.CreateOperation,
			Path:      fmt.Sprintf("data/%d", i),
			Storage:   storage,
			Data:      data,
		}

		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%s resp:%#v\n", err, resp)
		}
	}

	config := &logical.BackendConfig{
		Logger:      logging.NewVaultLogger(log.Trace),
		System:      &logical.StaticSystemView{},
		StorageView: storage,
		BackendUUID: "test",
	}

	b, err := VersionedKVFactory(context.Background(), config)
	if err != nil {
		t.Fatalf("unable to create backend: %v", err)
	}

	// Read values back out
	for i := 0; i < 10; i++ {
		req := &logical.Request{
			Operation: logical.ReadOperation,
			Path:      fmt.Sprintf("data/%d", i),
			Storage:   storage,
		}

		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%s resp:%#v\n", err, resp)
		}

		if !reflect.DeepEqual(resp.Data["data"], data["data"]) {
			t.Fatalf("Bad response: %#v", resp)
		}

	}

}
