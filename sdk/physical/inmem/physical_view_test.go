// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package inmem

import (
	"context"
	"testing"

	log "github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/sdk/v2/helper/logging"
	"github.com/openbao/openbao/sdk/v2/physical"
)

func TestPhysicalView_impl(t *testing.T) {
	var _ physical.Backend = new(physical.View)
}

func newInmemTestBackend() (physical.Backend, error) {
	logger := logging.NewVaultLogger(log.Debug)
	return NewInmem(nil, logger)
}

func TestPhysicalView_BadKeysKeys(t *testing.T) {
	backend, err := newInmemTestBackend()
	if err != nil {
		t.Fatal(err)
	}
	view := physical.NewView(backend, "foo/")

	_, err = view.List(context.Background(), "../")
	if err == nil {
		t.Fatal("expected error")
	}

	_, err = view.Get(context.Background(), "../")
	if err == nil {
		t.Fatal("expected error")
	}

	err = view.Delete(context.Background(), "../foo")
	if err == nil {
		t.Fatal("expected error")
	}

	le := &physical.Entry{
		Key:   "../foo",
		Value: []byte("test"),
	}
	err = view.Put(context.Background(), le)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestPhysicalView(t *testing.T) {
	backend, err := newInmemTestBackend()
	if err != nil {
		t.Fatal(err)
	}

	view := physical.NewView(backend, "foo/")

	// Write a key outside of foo/
	entry := &physical.Entry{Key: "test", Value: []byte("test")}
	if err := backend.Put(context.Background(), entry); err != nil {
		t.Fatalf("bad: %v", err)
	}

	// List should have no visibility
	keys, err := view.List(context.Background(), "")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("bad: %v", err)
	}

	// Get should have no visibility
	out, err := view.Get(context.Background(), "test")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if out != nil {
		t.Fatalf("bad: %v", out)
	}

	// Try to put the same entry via the view
	if err := view.Put(context.Background(), entry); err != nil {
		t.Fatalf("err: %v", err)
	}

	// Check it is nested
	entry, err = backend.Get(context.Background(), "foo/test")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if entry == nil {
		t.Fatal("missing nested foo/test")
	}

	// Delete nested
	if err := view.Delete(context.Background(), "test"); err != nil {
		t.Fatalf("err: %v", err)
	}

	// Check the nested key
	entry, err = backend.Get(context.Background(), "foo/test")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if entry != nil {
		t.Fatal("nested foo/test should be gone")
	}

	// Check the non-nested key
	entry, err = backend.Get(context.Background(), "test")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if entry == nil {
		t.Fatal("root test missing")
	}
}
