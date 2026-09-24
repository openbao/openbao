// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package framework

import (
	"reflect"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
)

func TestWAL(t *testing.T) {
	s := new(logical.InmemStorage)

	ctx := t.Context()

	// WAL should be empty to start
	keys, err := ListWAL(ctx, s)
	require.NoError(t, err)
	if len(keys) > 0 {
		t.Fatalf("bad: %#v", keys)
	}

	// Write an entry to the WAL
	id, err := PutWAL(ctx, s, "foo", "bar")
	require.NoError(t, err)

	// The key should be in the WAL
	keys, err = ListWAL(ctx, s)
	require.NoError(t, err)
	if !reflect.DeepEqual(keys, []string{id}) {
		t.Fatalf("bad: %#v", keys)
	}

	// Should be able to get the value
	entry, err := GetWAL(ctx, s, id)
	require.NoError(t, err)
	if entry.Kind != "foo" {
		t.Fatalf("bad: %#v", entry)
	}
	if entry.Data != "bar" {
		t.Fatalf("bad: %#v", entry)
	}

	// Should be able to delete the value
	if err := DeleteWAL(ctx, s, id); err != nil {
		t.Fatalf("err: %s", err)
	}
	entry, err = GetWAL(ctx, s, id)
	require.NoError(t, err)
	if entry != nil {
		t.Fatalf("bad: %#v", entry)
	}
}
