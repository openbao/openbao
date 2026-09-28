// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package framework

import (
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
)

func TestPathStruct(t *testing.T) {
	p := &PathStruct{
		Name: "foo",
		Path: "bar",
		Schema: map[string]*FieldSchema{
			"value": {Type: TypeString},
		},
		Read: true,
	}

	storage := new(logical.InmemStorage)
	var b logical.Backend = &Backend{Paths: p.Paths()}

	ctx := t.Context()

	// Write via HTTP
	_, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "bar",
		Data: map[string]any{
			"value": "baz",
		},
		Storage: storage,
	})
	require.NoError(t, err)

	// Read via HTTP
	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "bar",
		Storage:   storage,
	})
	require.NoError(t, err)
	if resp.Data["value"] != "baz" {
		t.Fatalf("bad: %#v", resp)
	}

	// Read via API
	v, err := p.Get(ctx, storage)
	require.NoError(t, err)
	if v["value"] != "baz" {
		t.Fatalf("bad: %#v", v)
	}

	// Delete via HTTP
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "bar",
		Data:      nil,
		Storage:   storage,
	})
	require.NoError(t, err)
	if resp != nil {
		t.Fatalf("bad: %#v", resp)
	}

	// Re-read via HTTP
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "bar",
		Storage:   storage,
	})
	require.NoError(t, err)
	if _, ok := resp.Data["value"]; ok {
		t.Fatalf("bad: %#v", resp)
	}

	// Re-read via API
	v, err = p.Get(ctx, storage)
	require.NoError(t, err)
	if v != nil {
		t.Fatalf("bad: %#v", v)
	}
}
