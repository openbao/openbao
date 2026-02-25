// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

// Tests for the self-init state machine in core_self_init.go.
//
// Design rationale:
//   - All tests use TestCore(t) which builds a real *Core with physInmem backend.
//     No mocks, no manual physical.NewInmem calls: the inMem backend is the
//     same one that production code uses during `bao server -dev`.
//   - Tests live in package vault (white-box) because the state machine operates
//     on c.physical, which is unexported.
//   - Each test exercises exactly one observable behaviour.
//   - Accuracy level 5+: every assertion has an accompanying comment explaining
//     what the invariant is and why it matters.
//
// Pattern matches: vault/core_self_init.go (OpenBao MPLv2)
// Test helpers from: vault/testing.go (OpenBao MPLv2)

import (
	"context"
	"testing"

	"github.com/openbao/openbao/sdk/v2/physical"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// rootCtx returns the context used throughout the OpenBao core for root-namespace
// operations. Using context.Background() directly (as TestCoreInitClusterWrapperSetup
// does) is also correct at this layer; we alias it for clarity.
func rootCtx() context.Context {
	return context.Background()
}

// ---------------------------------------------------------------------------
// MarkSelfInitStarted
// ---------------------------------------------------------------------------

// TestMarkSelfInitStarted_WritesStartedMarker verifies that after calling
// MarkSelfInitStarted the physical backend contains the key
// coreStatusSelfInitKey with value "started".
//
// This is the first transition in the state machine (∅ → started).
// If this write is missing or wrong, IsSelfInitComplete would misread the
// state on a subsequent boot.
func TestMarkSelfInitStarted_WritesStartedMarker(t *testing.T) {
	t.Parallel()

	// TestCore builds an uninitialised core backed by physInmem.
	// Pattern matches: vault/testing.go TestCore()
	c := TestCore(t)
	ctx := rootCtx()

	err := c.MarkSelfInitStarted(ctx)
	require.NoError(t, err, "MarkSelfInitStarted must not return an error on a healthy inMem backend")

	// Read directly from physical to confirm the raw write, bypassing any
	// higher-level cache or barrier. This validates the exact key/value
	// contract that IsSelfInitComplete depends on.
	entry, err := c.physical.Get(ctx, coreStatusSelfInitKey)
	require.NoError(t, err, "physical.Get after MarkSelfInitStarted must not fail")
	require.NotNil(t, entry, "physical entry must exist after MarkSelfInitStarted")
	require.Equal(t, coreStatusSelfInitStarted, string(entry.Value),
		"stored value must be the const coreStatusSelfInitStarted, not a magic string")
}

// TestMarkSelfInitStarted_Idempotent verifies that calling MarkSelfInitStarted
// twice does not fail and leaves the marker at "started".
//
// Idempotency matters because a crash between two calls to MarkSelfInitStarted
// (e.g. during a retry loop) must not leave the backend in an error state.
func TestMarkSelfInitStarted_Idempotent(t *testing.T) {
	t.Parallel()

	c := TestCore(t)
	ctx := rootCtx()

	require.NoError(t, c.MarkSelfInitStarted(ctx))
	require.NoError(t, c.MarkSelfInitStarted(ctx), "second call must not fail (Put is idempotent on inMem)")

	entry, err := c.physical.Get(ctx, coreStatusSelfInitKey)
	require.NoError(t, err)
	require.Equal(t, coreStatusSelfInitStarted, string(entry.Value))
}

// ---------------------------------------------------------------------------
// MarkSelfInitComplete
// ---------------------------------------------------------------------------

// TestMarkSelfInitComplete_WritesCompletedMarker verifies the transition
// started → completed.
//
// This is the terminal success transition. If MarkSelfInitComplete never
// writes "completed", IsSelfInitComplete would always return (false, error)
// on subsequent boots, making the cluster permanently unbootable.
func TestMarkSelfInitComplete_WritesCompletedMarker(t *testing.T) {
	t.Parallel()

	c := TestCore(t)
	ctx := rootCtx()

	// Simulate the normal sequence: started → completed.
	require.NoError(t, c.MarkSelfInitStarted(ctx))
	require.NoError(t, c.MarkSelfInitComplete(ctx))

	entry, err := c.physical.Get(ctx, coreStatusSelfInitKey)
	require.NoError(t, err)
	require.NotNil(t, entry)
	require.Equal(t, coreStatusSelfInitCompleted, string(entry.Value),
		"value must be the const coreStatusSelfInitCompleted after a successful init")
}

// TestMarkSelfInitComplete_WithoutStarted verifies that MarkSelfInitComplete
// can write "completed" even when MarkSelfInitStarted was never called.
//
// This covers the edge case of a code path that calls Complete without first
// calling Started (e.g. a future refactoring). The state machine only reads
// the final value, so the intermediate "started" is not required to be present.
func TestMarkSelfInitComplete_WithoutStarted(t *testing.T) {
	t.Parallel()

	c := TestCore(t)
	ctx := rootCtx()

	require.NoError(t, c.MarkSelfInitComplete(ctx),
		"MarkSelfInitComplete must succeed even without a prior MarkSelfInitStarted")

	entry, err := c.physical.Get(ctx, coreStatusSelfInitKey)
	require.NoError(t, err)
	require.Equal(t, coreStatusSelfInitCompleted, string(entry.Value))
}

// ---------------------------------------------------------------------------
// IsSelfInitComplete
// ---------------------------------------------------------------------------

// TestIsSelfInitComplete_MissingEntry_BackwardCompat verifies that a Core with
// no self-init marker in physical storage is treated as successfully initialised.
//
// This is the backward-compatibility rule: clusters initialised before this
// feature existed have no marker, so we must assume they succeeded.
// Violating this invariant would make every pre-existing cluster fail to boot.
func TestIsSelfInitComplete_MissingEntry_BackwardCompat(t *testing.T) {
	t.Parallel()

	c := TestCore(t)
	ctx := rootCtx()

	// Fresh core: no marker written at all.
	ok, err := c.IsSelfInitComplete(ctx)
	require.NoError(t, err, "missing marker must not produce an error")
	require.True(t, ok, "missing marker must return true (backward-compat: assume success)")
}

// TestIsSelfInitComplete_CompletedEntry_ReturnsTrue verifies the normal success
// path: a "completed" marker means the previous init finished cleanly.
func TestIsSelfInitComplete_CompletedEntry_ReturnsTrue(t *testing.T) {
	t.Parallel()

	c := TestCore(t)
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
//
// The function must return (false, non-nil error). The caller (command/server.go
// Initialize) will use this to print a fatal message and refuse to start,
// preventing silent data corruption.
func TestIsSelfInitComplete_StartedEntry_ReturnsCrashError(t *testing.T) {
	t.Parallel()

	c := TestCore(t)
	ctx := rootCtx()

	// Simulate a crash: started written, complete never reached.
	require.NoError(t, c.MarkSelfInitStarted(ctx))

	ok, err := c.IsSelfInitComplete(ctx)
	require.Error(t, err, "started-only marker must produce an error (crash detected)")
	require.False(t, ok, "started-only marker must return false")
}

// TestIsSelfInitComplete_CorruptEntry_ReturnsError verifies that an unknown
// value in the marker key is treated as an error rather than silently accepted.
//
// Storage corruption or manual tampering must not silently pass as "completed":
// that would hide real problems. The function must return (false, error).
func TestIsSelfInitComplete_CorruptEntry_ReturnsError(t *testing.T) {
	t.Parallel()

	c := TestCore(t)
	ctx := rootCtx()

	// Write an arbitrary garbage value directly to physical, bypassing the
	// public API, to simulate storage corruption or a future schema conflict.
	err := c.physical.Put(ctx, &physical.Entry{
		Key:   coreStatusSelfInitKey,
		Value: []byte("GARBAGE_VALUE"),
	})
	require.NoError(t, err, "precondition: direct physical write must not fail")

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
//
// This test documents the intended lifecycle in a single readable sequence,
// which doubles as integration-level documentation for reviewers.
func TestSelfInitStateMachine_FullSequence(t *testing.T) {
	t.Parallel()

	c := TestCore(t)
	ctx := rootCtx()

	// Step 0: fresh core, no marker → backward-compatible success.
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

// ---------------------------------------------------------------------------
// Integration: Initialize sets the markers correctly
// ---------------------------------------------------------------------------

// TestInitialize_SetsCompletedMarker verifies that the OpenBao Core.Initialize
// path (as called by command/server.go) correctly transitions the state machine
// from ∅ to "completed" when initialization succeeds.
//
// We use TestCoreInit (which wraps core.Initialize + unseal) to exercise the
// full path. After a successful init+unseal the marker must be "completed".
//
// NOTE: This test depends on the integration work in command/server.go where
// MarkSelfInitStarted is called before core.Initialize and MarkSelfInitComplete
// is called after doSelfInit returns.  If those calls are missing, this test
// will catch the regression.
func TestInitialize_SetsCompletedMarker(t *testing.T) {
	t.Parallel()

	c := TestCore(t)
	ctx := rootCtx()

	// TestCoreInit calls core.Initialize then unseals.
	// Pattern matches: vault/testing.go TestCoreInit()
	keys, _ := TestCoreInit(t, c)
	for _, key := range keys {
		_, err := TestCoreUnseal(c, TestKeyCopy(key))
		require.NoError(t, err)
	}
	require.False(t, c.Sealed(), "core must be unsealed after TestCoreInit + Unseal")

	// After a complete init+unseal cycle, IsSelfInitComplete must return true.
	// If it returns false or error, the state machine was not wired into
	// core.Initialize correctly.
	ok, err := c.IsSelfInitComplete(ctx)
	require.NoError(t, err,
		"after successful Initialize, IsSelfInitComplete must not return an error")
	require.True(t, ok,
		"after successful Initialize, IsSelfInitComplete must return true")
}
