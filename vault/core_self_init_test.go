// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

// Tests for the self-init state machine in core_self_init.go.
//
// Design rationale:
//   - All tests use TestCoreNewSeal(t) + TestCoreInit + unseal to get a Core
//     with an open security barrier, since the state machine now writes to
//     c.barrier (not c.physical). A sealed or uninitialized barrier returns
//     ErrBarrierSealed on any Get/Put.
//   - Tests live in package vault (white-box) because the state machine
//     operates on c.barrier, which is unexported.
//   - Each test exercises exactly one observable behaviour.
//   - Accuracy level 5+: every assertion has a comment explaining the invariant.
//
// NOTE: TestInitialize_SetsCompletedMarker was removed from this file.
// Its coverage is provided by command/server_initialize_test.go which exercises
// the full command.Initialize() path including MarkSelfInitStarted/Complete.
//
// Pattern matches: vault/core_self_init.go (OpenBao MPLv2)
// Test helpers from: vault/testing.go (OpenBao MPLv2)

import (
	"context"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// rootCtx returns the context used throughout the OpenBao core for root-namespace
// operations.
func rootCtx() context.Context {
	return context.Background()
}

// openCore returns a *Core with an initialized, unsealed security barrier.
// All state machine methods require the barrier to be open.
//
// Uses TestCoreNewSeal (auto-unseal capable) + TestCoreInit + UnsealWithStoredKeys.
// TestCoreUnseal is NOT used here because it uses the Shamir path; auto-unseal
// cores must be unsealed via UnsealWithStoredKeys which reads the stored keys
// written by core.Initialize.
func openCore(t *testing.T) *Core {
	t.Helper()
	c := TestCoreNewSeal(t)
	TestCoreInit(t, c)
	err := c.UnsealWithStoredKeys(context.Background())
	require.NoError(t, err, "UnsealWithStoredKeys must not fail after TestCoreInit")
	require.False(t, c.Sealed(), "precondition: core must be unsealed")
	return c
}

// ---------------------------------------------------------------------------
// MarkSelfInitStarted
// ---------------------------------------------------------------------------

// TestMarkSelfInitStarted_WritesStartedMarker verifies that after calling
// MarkSelfInitStarted the barrier contains coreStatusSelfInitKey = "started".
//
// This is the first transition in the state machine (∅ → started).
func TestMarkSelfInitStarted_WritesStartedMarker(t *testing.T) {
	t.Parallel()

	c := openCore(t)
	ctx := rootCtx()

	err := c.MarkSelfInitStarted(ctx)
	require.NoError(t, err, "MarkSelfInitStarted must not return an error on an open barrier")

	// Read directly from barrier to confirm the exact key/value contract
	// that IsSelfInitComplete depends on.
	entry, err := c.barrier.Get(ctx, coreStatusSelfInitKey)
	require.NoError(t, err, "barrier.Get after MarkSelfInitStarted must not fail")
	require.NotNil(t, entry, "barrier entry must exist after MarkSelfInitStarted")
	require.Equal(t, coreStatusSelfInitStarted, string(entry.Value),
		"stored value must be the const coreStatusSelfInitStarted, not a magic string")
}

// TestMarkSelfInitStarted_Idempotent verifies that calling MarkSelfInitStarted
// twice does not fail and leaves the marker at "started".
func TestMarkSelfInitStarted_Idempotent(t *testing.T) {
	t.Parallel()

	c := openCore(t)
	ctx := rootCtx()

	require.NoError(t, c.MarkSelfInitStarted(ctx))
	require.NoError(t, c.MarkSelfInitStarted(ctx), "second call must not fail (Put is idempotent)")

	entry, err := c.barrier.Get(ctx, coreStatusSelfInitKey)
	require.NoError(t, err)
	require.Equal(t, coreStatusSelfInitStarted, string(entry.Value))
}

// ---------------------------------------------------------------------------
// MarkSelfInitComplete
// ---------------------------------------------------------------------------

// TestMarkSelfInitComplete_WritesCompletedMarker verifies the transition
// started → completed.
func TestMarkSelfInitComplete_WritesCompletedMarker(t *testing.T) {
	t.Parallel()

	c := openCore(t)
	ctx := rootCtx()

	require.NoError(t, c.MarkSelfInitStarted(ctx))
	require.NoError(t, c.MarkSelfInitComplete(ctx))

	entry, err := c.barrier.Get(ctx, coreStatusSelfInitKey)
	require.NoError(t, err)
	require.NotNil(t, entry)
	require.Equal(t, coreStatusSelfInitCompleted, string(entry.Value),
		"value must be coreStatusSelfInitCompleted after a successful init")
}

// TestMarkSelfInitComplete_WithoutStarted verifies that MarkSelfInitComplete
// can write "completed" even when MarkSelfInitStarted was never called.
func TestMarkSelfInitComplete_WithoutStarted(t *testing.T) {
	t.Parallel()

	c := openCore(t)
	ctx := rootCtx()

	require.NoError(t, c.MarkSelfInitComplete(ctx),
		"MarkSelfInitComplete must succeed even without a prior MarkSelfInitStarted")

	entry, err := c.barrier.Get(ctx, coreStatusSelfInitKey)
	require.NoError(t, err)
	require.Equal(t, coreStatusSelfInitCompleted, string(entry.Value))
}

// ---------------------------------------------------------------------------
// IsSelfInitComplete
// ---------------------------------------------------------------------------

// TestIsSelfInitComplete_MissingEntry_BackwardCompat verifies that a Core with
// no self-init marker in the barrier is treated as successfully initialised.
//
// This is the backward-compatibility rule: clusters initialised before this
// feature existed have no marker, so we must assume they succeeded.
func TestIsSelfInitComplete_MissingEntry_BackwardCompat(t *testing.T) {
	t.Parallel()

	// Initialized and unsealed core, but no marker written — simulates a
	// cluster that was initialized before this feature existed.
	c := openCore(t)
	ctx := rootCtx()

	ok, err := c.IsSelfInitComplete(ctx)
	require.NoError(t, err, "missing marker must not produce an error")
	require.True(t, ok, "missing marker must return true (backward-compat: assume success)")
}

// TestIsSelfInitComplete_CompletedEntry_ReturnsTrue verifies the normal success
// path: a "completed" marker means the previous init finished cleanly.
func TestIsSelfInitComplete_CompletedEntry_ReturnsTrue(t *testing.T) {
	t.Parallel()

	c := openCore(t)
	ctx := rootCtx()

	require.NoError(t, c.MarkSelfInitStarted(ctx))
	require.NoError(t, c.MarkSelfInitComplete(ctx))

	ok, err := c.IsSelfInitComplete(ctx)
	require.NoError(t, err)
	require.True(t, ok, "completed marker must return (true, nil)")
}

// TestIsSelfInitComplete_StartedEntry_ReturnsCrashError verifies the crash-
// detection logic: a "started" marker without a subsequent "completed" means
// the process was killed during auto-init.
func TestIsSelfInitComplete_StartedEntry_ReturnsCrashError(t *testing.T) {
	t.Parallel()

	c := openCore(t)
	ctx := rootCtx()

	require.NoError(t, c.MarkSelfInitStarted(ctx))

	ok, err := c.IsSelfInitComplete(ctx)
	require.Error(t, err, "started-only marker must produce an error (crash detected)")
	require.False(t, ok, "started-only marker must return false")
}

// TestIsSelfInitComplete_CorruptEntry_ReturnsError verifies that an unknown
// value in the marker key is treated as an error rather than silently accepted.
func TestIsSelfInitComplete_CorruptEntry_ReturnsError(t *testing.T) {
	t.Parallel()

	c := openCore(t)
	ctx := rootCtx()

	// Write a garbage value directly to the barrier, bypassing the public API,
	// to simulate storage corruption or a future schema conflict.
	err := c.barrier.Put(ctx, &logical.StorageEntry{
		Key:   coreStatusSelfInitKey,
		Value: []byte("GARBAGE_VALUE"),
	})
	require.NoError(t, err, "precondition: direct barrier write must not fail")

	ok, err := c.IsSelfInitComplete(ctx)
	require.Error(t, err, "unknown marker value must produce an error")
	require.False(t, ok, "unknown marker value must return false")
	require.Contains(t, err.Error(), "GARBAGE_VALUE",
		"error message must include the offending value for operator diagnostics")
}

// ---------------------------------------------------------------------------
// Full state-machine sequence
// ---------------------------------------------------------------------------

// TestSelfInitStateMachine_FullSequence exercises the complete happy path:
//
//	∅ (no marker)        → IsSelfInitComplete = true  (backward-compat)
//	MarkSelfInitStarted  → IsSelfInitComplete = false (crash would be detected)
//	MarkSelfInitComplete → IsSelfInitComplete = true  (success)
func TestSelfInitStateMachine_FullSequence(t *testing.T) {
	t.Parallel()

	// Core must be initialized and unsealed for all barrier operations.
	c := openCore(t)
	ctx := rootCtx()

	// Step 0: initialized core, no marker written → backward-compat success.
	ok, err := c.IsSelfInitComplete(ctx)
	require.NoError(t, err)
	require.True(t, ok, "step 0: no marker → backward-compat true")

	// Step 1: mark started → crash would now be detected.
	require.NoError(t, c.MarkSelfInitStarted(ctx))
	ok, err = c.IsSelfInitComplete(ctx)
	require.Error(t, err, "step 1: after MarkSelfInitStarted → crash detection active")
	require.False(t, ok)

	// Step 2: mark complete → clean state.
	require.NoError(t, c.MarkSelfInitComplete(ctx))
	ok, err = c.IsSelfInitComplete(ctx)
	require.NoError(t, err)
	require.True(t, ok, "step 2: after MarkSelfInitComplete → success")
}
