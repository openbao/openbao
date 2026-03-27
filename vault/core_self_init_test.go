// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
)

// TestMarkSelfInitStarted_WritesFailed verifies that MarkSelfInitStarted
// writes the failed marker to the barrier.
func TestMarkSelfInitStarted_WritesFailed(t *testing.T) {
	c, _, _ := TestCoreUnsealed(t)
	ctx := context.Background()

	err := c.MarkSelfInitStarted(ctx)
	require.NoError(t, err)

	entry, err := c.barrier.Get(ctx, coreStatusSelfInitKey)
	require.NoError(t, err)
	require.NotNil(t, entry)
	require.Equal(t, coreStatusSelfInitFailed, string(entry.Value))
}

// TestMarkSelfInitStarted_Idempotent verifies that calling MarkSelfInitStarted
// twice does not fail.
func TestMarkSelfInitStarted_Idempotent(t *testing.T) {
	c, _, _ := TestCoreUnsealed(t)
	ctx := context.Background()

	require.NoError(t, c.MarkSelfInitStarted(ctx))
	require.NoError(t, c.MarkSelfInitStarted(ctx))

	entry, err := c.barrier.Get(ctx, coreStatusSelfInitKey)
	require.NoError(t, err)
	require.Equal(t, coreStatusSelfInitFailed, string(entry.Value))
}

// TestMarkSelfInitComplete_DeletesMarker verifies that MarkSelfInitComplete
// removes the marker from the barrier.
func TestMarkSelfInitComplete_DeletesMarker(t *testing.T) {
	c, _, _ := TestCoreUnsealed(t)
	ctx := context.Background()

	require.NoError(t, c.MarkSelfInitStarted(ctx))
	require.NoError(t, c.MarkSelfInitComplete(ctx))

	entry, err := c.barrier.Get(ctx, coreStatusSelfInitKey)
	require.NoError(t, err)
	require.Nil(t, entry, "marker must be absent after MarkSelfInitComplete")
}

// TestIsSelfInitComplete_MissingEntry_BackwardCompat verifies that a missing
// marker is treated as success for backward compatibility.
func TestIsSelfInitComplete_MissingEntry_BackwardCompat(t *testing.T) {
	c, _, _ := TestCoreUnsealed(t)
	ctx := context.Background()

	ok, err := c.IsSelfInitComplete(ctx)
	require.NoError(t, err)
	require.True(t, ok)
}

// TestIsSelfInitComplete_FailedEntry_ReturnsCrashError verifies that a failed
// marker produces an error.
func TestIsSelfInitComplete_FailedEntry_ReturnsCrashError(t *testing.T) {
	c, _, _ := TestCoreUnsealed(t)
	ctx := context.Background()

	require.NoError(t, c.MarkSelfInitStarted(ctx))

	ok, err := c.IsSelfInitComplete(ctx)
	require.Error(t, err)
	require.False(t, ok)
}

// TestIsSelfInitComplete_CorruptEntry_ReturnsError verifies that an unknown
// marker value is treated as an error.
func TestIsSelfInitComplete_CorruptEntry_ReturnsError(t *testing.T) {
	c, _, _ := TestCoreUnsealed(t)
	ctx := context.Background()

	err := c.barrier.Put(ctx, &logical.StorageEntry{
		Key:   coreStatusSelfInitKey,
		Value: []byte("GARBAGE_VALUE"),
	})
	require.NoError(t, err)

	ok, err := c.IsSelfInitComplete(ctx)
	require.Error(t, err)
	require.False(t, ok)
	require.Contains(t, err.Error(), "GARBAGE_VALUE")
}

func TestSelfInitStateMachine_FullSequence(t *testing.T) {
	c, _, _ := TestCoreUnsealed(t)
	ctx := context.Background()

	ok, err := c.IsSelfInitComplete(ctx)
	require.NoError(t, err)
	require.True(t, ok, "no marker: backward-compat success")

	require.NoError(t, c.MarkSelfInitStarted(ctx))
	ok, err = c.IsSelfInitComplete(ctx)
	require.Error(t, err)
	require.False(t, ok, "failed marker: crash detection active")

	require.NoError(t, c.MarkSelfInitComplete(ctx))
	ok, err = c.IsSelfInitComplete(ctx)
	require.NoError(t, err)
	require.True(t, ok, "marker deleted: success")
}
