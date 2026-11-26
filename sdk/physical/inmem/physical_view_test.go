// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package inmem

import (
	"testing"

	log "github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/sdk/v2/helper/logging"
	"github.com/openbao/openbao/sdk/v2/physical"
	"github.com/stretchr/testify/require"
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
	require.NoError(t, err)
	view := physical.NewView(backend, "foo/")

	_, err = view.List(t.Context(), "../")
	require.Error(t, err)

	_, err = view.Get(t.Context(), "../")
	require.Error(t, err)

	err = view.Delete(t.Context(), "../foo")
	require.Error(t, err)

	le := &physical.Entry{
		Key:   "../foo",
		Value: []byte("test"),
	}
	err = view.Put(t.Context(), le)
	require.Error(t, err)
}

func TestPhysicalView(t *testing.T) {
	backend, err := newInmemTestBackend()
	require.NoError(t, err)

	view := physical.NewView(backend, "foo/")

	// Write a key outside of foo/
	entry := &physical.Entry{Key: "test", Value: []byte("test")}
	require.NoError(t, backend.Put(t.Context(), entry))

	// List should have no visibility
	keys, err := view.List(t.Context(), "")
	require.NoError(t, err)
	if len(keys) != 0 {
		t.Fatalf("bad: %v", err)
	}

	// Get should have no visibility
	out, err := view.Get(t.Context(), "test")
	require.NoError(t, err)
	if out != nil {
		t.Fatalf("bad: %v", out)
	}

	// Try to put the same entry via the view
	require.NoError(t, view.Put(t.Context(), entry))

	// Check it is nested
	entry, err = backend.Get(t.Context(), "foo/test")
	require.NoError(t, err)
	if entry == nil {
		t.Fatal("missing nested foo/test")
	}

	// Delete nested
	require.NoError(t, view.Delete(t.Context(), "test"))

	// Check the nested key
	entry, err = backend.Get(t.Context(), "foo/test")
	require.NoError(t, err)
	if entry != nil {
		t.Fatal("nested foo/test should be gone")
	}

	// Check the non-nested key
	entry, err = backend.Get(t.Context(), "test")
	require.NoError(t, err)
	if entry == nil {
		t.Fatal("root test missing")
	}
}
