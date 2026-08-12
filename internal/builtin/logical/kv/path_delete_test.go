package kv

import (
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"
)

func TestVersionedKV_Delete_Put(t *testing.T) {
	b, storage := getBackend(t)

	data := map[string]any{
		"data": map[string]any{
			"bar": "baz",
		},
	}

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "data/foo",
		Storage:   storage,
		Data:      data,
	}

	resp, err := b.HandleRequest(t.Context(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	if resp.Data["version"] != uint64(1) {
		t.Fatalf("Bad response: %#v", resp)
	}

	data = map[string]any{
		"data": map[string]any{
			"bar": "baz1",
		},
		"options": map[string]any{
			"cas": float64(1),
		},
	}

	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "data/foo",
		Storage:   storage,
		Data:      data,
	}

	resp, err = b.HandleRequest(t.Context(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	if resp.Data["version"] != uint64(2) {
		t.Fatalf("Bad response: %#v", resp)
	}

	data = map[string]any{
		"versions": "1,2",
	}

	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "delete/foo",
		Storage:   storage,
		Data:      data,
	}

	resp, err = b.HandleRequest(t.Context(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "metadata/foo",
		Storage:   storage,
		Data:      data,
	}

	resp, err = b.HandleRequest(t.Context(), req)
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	parsed, err := time.Parse(time.RFC3339Nano, resp.Data["versions"].(map[string]any)["1"].(map[string]any)["deletion_time"].(string))
	if err != nil {
		t.Fatal(err)
	}

	if !parsed.After(time.Now().Add(-1*time.Minute)) || !parsed.Before(time.Now()) {
		t.Fatalf("Bad response: %#v", resp)
	}

	parsed, err = time.Parse(time.RFC3339Nano, resp.Data["versions"].(map[string]any)["2"].(map[string]any)["deletion_time"].(string))
	if err != nil {
		t.Fatal(err)
	}

	if !parsed.After(time.Now().Add(-1*time.Minute)) || !parsed.Before(time.Now()) {
		t.Fatalf("Bad response: %#v", resp)
	}
}

func TestVersionedKV_Undelete_Put(t *testing.T) {
	b, storage := getBackend(t)

	data := map[string]any{
		"data": map[string]any{
			"bar": "baz",
		},
	}

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "data/foo",
		Storage:   storage,
		Data:      data,
	}

	resp, err := b.HandleRequest(t.Context(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	if resp.Data["version"] != uint64(1) {
		t.Fatalf("Bad response: %#v", resp)
	}

	data = map[string]any{
		"data": map[string]any{
			"bar": "baz1",
		},
		"options": map[string]any{
			"cas": float64(1),
		},
	}

	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "data/foo",
		Storage:   storage,
		Data:      data,
	}

	resp, err = b.HandleRequest(t.Context(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	if resp.Data["version"] != uint64(2) {
		t.Fatalf("Bad response: %#v", resp)
	}

	data = map[string]any{
		"versions": "1,2",
	}

	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "delete/foo",
		Storage:   storage,
		Data:      data,
	}

	resp, err = b.HandleRequest(t.Context(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	data = map[string]any{
		"versions": "1,2",
	}

	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "undelete/foo",
		Storage:   storage,
		Data:      data,
	}

	resp, err = b.HandleRequest(t.Context(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "metadata/foo",
		Storage:   storage,
		Data:      data,
	}

	resp, err = b.HandleRequest(t.Context(), req)
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	if resp.Data["versions"].(map[string]any)["1"].(map[string]any)["deletion_time"].(string) != "" {
		t.Fatalf("Bad response: %#v", resp)
	}
	if resp.Data["versions"].(map[string]any)["2"].(map[string]any)["deletion_time"].(string) != "" {
		t.Fatalf("Bad response: %#v", resp)
	}
}
