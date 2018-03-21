package kv

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/hashicorp/vault/helper/consts"
	"github.com/hashicorp/vault/logical"
)

func testPassthroughBackendWithStorage() (logical.Backend, logical.Storage) {
	storage := &logical.InmemStorage{}
	b, _ := PassthroughBackendFactory(context.Background(), &logical.BackendConfig{
		Logger: nil,
		System: logical.StaticSystemView{
			DefaultLeaseTTLVal: time.Hour * 24,
			MaxLeaseTTLVal:     time.Hour * 24 * 32,
		},
		StorageView: storage,
	})

	return b, storage
}

func TestPassthroughDowngrader_Data_Put(t *testing.T) {
	b, storage := testPassthroughBackendWithStorage()

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
		Headers: map[string][]string{
			consts.VaultKVCLIClientHeader: []string{"true"},
		},
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
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
		Headers: map[string][]string{
			consts.VaultKVCLIClientHeader: []string{"true"},
		},
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "foo",
		Storage:   storage,
		Data:      data,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	if !reflect.DeepEqual(resp.Data, map[string]interface{}{
		"bar": "baz1",
	}) {
		t.Fatalf("bad response: %#v", resp)
	}
}

func TestPassthroughDowngrader_Data_Get(t *testing.T) {
	b, storage := testPassthroughBackendWithStorage()

	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "data/foo",
		Storage:   storage,
		Headers: map[string][]string{
			consts.VaultKVCLIClientHeader: []string{"true"},
		},
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	if resp != nil {
		t.Fatalf("Bad response: %#v", resp)
	}

	data := map[string]interface{}{
		"bar": "baz",
	}

	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "foo",
		Storage:   storage,
		Data:      data,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "data/foo",
		Storage:   storage,
		Headers: map[string][]string{
			consts.VaultKVCLIClientHeader: []string{"true"},
		},
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	if !reflect.DeepEqual(resp.Data["data"], data) {
		t.Fatalf("Bad response: %#v", resp)
	}

	if !reflect.DeepEqual(resp.Data["metadata"], nil) {
		t.Fatalf("Bad response: %#v", resp)
	}
}

func TestPassthroughDowngrader_Data_Delete(t *testing.T) {
	b, storage := testPassthroughBackendWithStorage()

	data := map[string]interface{}{
		"bar": "baz",
	}

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "foo",
		Storage:   storage,
		Data:      data,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	req = &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "data/foo",
		Storage:   storage,
		Headers: map[string][]string{
			consts.VaultKVCLIClientHeader: []string{"true"},
		},
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "data/foo",
		Storage:   storage,
		Headers: map[string][]string{
			consts.VaultKVCLIClientHeader: []string{"true"},
		},
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}
	if resp != nil {
		t.Fatalf("bad response: %#v", resp)
	}

	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "foo",
		Storage:   storage,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}
	if resp != nil {
		t.Fatalf("bad response: %#v", resp)
	}

}

func TestPassthroughDowngrader_InvalidPaths(t *testing.T) {
	b, storage := testPassthroughBackendWithStorage()

	data := map[string]interface{}{
		"version": "1",
	}

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "metadata/foo",
		Storage:   storage,
		Data:      data,
		Headers: map[string][]string{
			consts.VaultKVCLIClientHeader: []string{"true"},
		},
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if resp.Error().Error() != "path is not supported when versioning is disabled" {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "archive/foo",
		Storage:   storage,
		Data:      data,
		Headers: map[string][]string{
			consts.VaultKVCLIClientHeader: []string{"true"},
		},
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if resp.Error().Error() != "path is not supported when versioning is disabled" {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "unarchive/foo",
		Storage:   storage,
		Data:      data,
		Headers: map[string][]string{
			consts.VaultKVCLIClientHeader: []string{"true"},
		},
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if resp.Error().Error() != "path is not supported when versioning is disabled" {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "destroy/foo",
		Storage:   storage,
		Data:      data,
		Headers: map[string][]string{
			consts.VaultKVCLIClientHeader: []string{"true"},
		},
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if resp.Error().Error() != "path is not supported when versioning is disabled" {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   storage,
		Data:      data,
		Headers: map[string][]string{
			consts.VaultKVCLIClientHeader: []string{"true"},
		},
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if resp.Error().Error() != "path is not supported when versioning is disabled" {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "data/foo",
		Storage:   storage,
		Data:      data,
		Headers: map[string][]string{
			consts.VaultKVCLIClientHeader: []string{"true"},
		},
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if resp.Error().Error() != "retrieving a version is not supported when versioning is disabled" {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}
}
