// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package command

// Tests for (*ServerCommand).Initialize in command/server.go.
// Requires a Core with auto-unseal: self-init does not support Shamir seal.
// Does not test doSelfInit internals (profile engine): that is out of scope.

import (
	"context"
	"testing"

	"github.com/openbao/openbao/command/server"
	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/helper/profiles"
	vault "github.com/openbao/openbao/vault"
	"github.com/stretchr/testify/require"
)

// emptyInitConfig returns a server.Config with a non-nil but non-empty
// Initialization slice containing one empty OuterConfig.
// This bypasses the `len(config.Initialization) == 0` fast-path but
// produces zero requests, so doSelfInit is a no-op.
func emptyInitConfig() *server.Config {
	return &server.Config{
		Initialization: []*profiles.OuterConfig{
			{
				Type:     "initialize",
				Requests: nil,
			},
		},
	}
}

// rootCtxCmd returns the root namespace context used throughout the command layer.
func rootCtxCmd() context.Context {
	return namespace.RootContext(context.Background())
}

// ---------------------------------------------------------------------------
// Fast path: empty Initialization
// ---------------------------------------------------------------------------

// TestInitialize_EmptyInitialization verifies that when config.Initialization
// is empty, Initialize returns immediately with nil without touching the Core.
//
// This guards the performance of normal (non-self-init) server starts: the
// function must be a no-op when no initialization profile is configured.
func TestInitialize_EmptyInitialization(t *testing.T) {
	t.Parallel()

	_, cmd := testServerCommand(t)
	core := vault.TestCoreNewSeal(t)

	cfg := &server.Config{
		Initialization: []*profiles.OuterConfig{},
	}

	err := cmd.Initialize(core, cfg)
	require.NoError(t, err, "empty Initialization must return nil immediately")

	// The core must still be uninitialized: Initialize must not have touched it.
	inited, err := core.Initialized(rootCtxCmd())
	require.NoError(t, err)
	require.False(t, inited, "core must remain uninitialized when Initialization is empty")
}

// ---------------------------------------------------------------------------
// Precondition: auto-unseal required
// ---------------------------------------------------------------------------

// TestInitialize_RequiresAutoUnseal verifies that Initialize refuses to run
// when the Core uses Shamir sealing (RecoveryKeySupported == false).
//
// Self-initialization cannot persist Shamir keys, so running it on a Shamir
// cluster would leave the cluster in an unlockable state. The function must
// fail fast with a clear error.
func TestInitialize_RequiresAutoUnseal(t *testing.T) {
	t.Parallel()

	_, cmd := testServerCommand(t)

	// TestCore uses Shamir — RecoveryKeySupported() returns false.
	core := vault.TestCore(t)

	err := cmd.Initialize(core, emptyInitConfig())
	require.Error(t, err, "Initialize must fail when auto-unseal is not available")
	require.Contains(t, err.Error(), "auto-unseal",
		"error must mention auto-unseal so operators understand the requirement")
}

// ---------------------------------------------------------------------------
// Already initialized: consistent state
// ---------------------------------------------------------------------------

// TestInitialize_AlreadyInitialized_Completed verifies that when the Core is
// already initialized AND the self-init marker is "completed", Initialize
// returns nil without re-running initialization.
//
// This is the normal re-start path: the cluster was successfully initialized
// in a previous run and is now coming back up.
func TestInitialize_AlreadyInitialized_Completed(t *testing.T) {
	t.Parallel()

	_, cmd := testServerCommand(t)
	core := vault.TestCoreNewSeal(t)

	// Simulate a previously successful self-init: initialize the core and
	// write the completed marker.
	vault.TestCoreInit(t, core)
	require.NoError(t, core.UnsealWithStoredKeys(rootCtxCmd()))
	require.NoError(t, core.MarkSelfInitComplete(rootCtxCmd()))

	err := cmd.Initialize(core, emptyInitConfig())
	require.NoError(t, err,
		"already-initialized core with completed marker must return nil")
}

// ---------------------------------------------------------------------------
// Already initialized: crash detected
// ---------------------------------------------------------------------------

// TestInitialize_AlreadyInitialized_CrashDetected verifies the crash detection path:
// the Core is initialized (barrier exists) but the self-init marker is
// "started" (never reached "completed").
//
// This means the previous run crashed mid-initialization. IsSelfInitComplete
// returns (false, err) — the non-nil error propagates through Initialize as
// "failed to verify self-init consistency: ...". The cluster must not start.
func TestInitialize_AlreadyInitialized_CrashDetected(t *testing.T) {
	t.Parallel()

	_, cmd := testServerCommand(t)
	core := vault.TestCoreNewSeal(t)
	ctx := rootCtxCmd()

	// Simulate a crashed self-init: barrier exists but marker is "started".
	vault.TestCoreInit(t, core)
	require.NoError(t, core.UnsealWithStoredKeys(ctx))
	require.NoError(t, core.MarkSelfInitStarted(ctx))
	// Intentionally do NOT call MarkSelfInitComplete — simulating a crash.

	err := cmd.Initialize(core, emptyInitConfig())
	require.Error(t, err,
		"initialized core with started-only marker must return an error")
	require.Contains(t, err.Error(), "self-init consistency",
		"error must mention self-init consistency so operators understand the cause")
}

// ---------------------------------------------------------------------------
// Already initialized: missing marker (backward compat)
// ---------------------------------------------------------------------------

// TestInitialize_AlreadyInitialized_NoMarker_BackwardCompat verifies that a
// Core that was initialized before the self-init feature existed (no marker
// in physical storage) is treated as successfully initialized.
//
// Clusters upgraded from older OpenBao versions must not be refused on restart
// just because they lack the new marker.
func TestInitialize_AlreadyInitialized_NoMarker_BackwardCompat(t *testing.T) {
	t.Parallel()

	_, cmd := testServerCommand(t)
	core := vault.TestCoreNewSeal(t)

	// Initialize the core but write NO self-init marker.
	vault.TestCoreInit(t, core)
	require.NoError(t, core.UnsealWithStoredKeys(rootCtxCmd()))

	err := cmd.Initialize(core, emptyInitConfig())
	require.NoError(t, err,
		"initialized core with no marker must return nil (backward compat)")
}

// ---------------------------------------------------------------------------
// First boot: end-to-end with a real profile request
// ---------------------------------------------------------------------------

// TestInitialize_FirstBoot_RealRequest verifies the complete first-boot flow
// with a real initialization profile request: mounting a kv secret engine at
// secret/.
//
// This test goes beyond state machine verification and exercises the full
// doSelfInit → profiles.Evaluate → core.HandleRequest path. After Initialize
// returns, the mount must actually exist in the core's mount table.
//
// This catches regressions where the state machine passes but the profile
// engine fails silently or requests are not routed correctly.
func TestInitialize_FirstBoot_RealRequest(t *testing.T) {
	t.Parallel()

	_, cmd := testServerCommand(t)
	core := vault.TestCoreNewSeal(t)
	ctx := rootCtxCmd()

	cfg := &server.Config{
		Initialization: []*profiles.OuterConfig{
			{
				Type: "initialize",
				Requests: []*profiles.RequestConfig{
					{
						Type:      "mount-kv",
						Operation: "update",
						Path:      "sys/mounts/secret",
						Data: map[string]interface{}{
							"type": "kv",
						},
					},
				},
			},
		},
	}

	err := cmd.Initialize(core, cfg)
	require.NoError(t, err, "first boot with real kv mount request must succeed")

	// State machine must be completed.
	ok, err := core.IsSelfInitComplete(ctx)
	require.NoError(t, err)
	require.True(t, ok, "IsSelfInitComplete must return true after successful Initialize")

	// The kv mount must actually exist in the mount table.
	mounts, err := core.ListMounts()
	require.NoError(t, err, "ListMounts must not error after successful Initialize")
	found := false
	for _, m := range mounts {
		if m.Path == "secret/" && m.Type == "kv" {
			found = true
			break
		}
	}
	require.True(t, found, "kv mount at secret/ must exist after doSelfInit executed the profile request")
}

// TestInitialize_FirstBoot_EmptyProfile verifies the complete first-boot flow
// with an empty (but non-nil) initialization profile:
//
//  1. MarkSelfInitStarted is written before core.Initialize
//  2. core.Initialize succeeds
//  3. doSelfInit succeeds (no-op with empty profile)
//  4. MarkSelfInitComplete is written
//
// After the call, IsSelfInitComplete must return (true, nil).
//
// NOTE: waitForLeader returns true immediately on non-HA inmem backends
// (ErrHANotEnabled path), so no timing issues are expected.
func TestInitialize_FirstBoot_EmptyProfile(t *testing.T) {
	t.Parallel()

	_, cmd := testServerCommand(t)
	core := vault.TestCoreNewSeal(t)
	ctx := rootCtxCmd()

	err := cmd.Initialize(core, emptyInitConfig())
	require.NoError(t, err, "first boot with empty profile must succeed")

	// The state machine must be in "completed" state.
	ok, err := core.IsSelfInitComplete(ctx)
	require.NoError(t, err,
		"IsSelfInitComplete must not error after successful Initialize")
	require.True(t, ok,
		"IsSelfInitComplete must return true after successful Initialize")

	// The core must now be initialized.
	inited, err := core.Initialized(ctx)
	require.NoError(t, err)
	require.True(t, inited, "core must be initialized after successful Initialize")
}

// ---------------------------------------------------------------------------
// Already initialized: sealed (follower/standby node)
// ---------------------------------------------------------------------------

// TestInitialize_AlreadyInitialized_Sealed verifies that when the Core is
// already initialized but still sealed, Initialize returns nil without
// attempting to read the self-init marker through the barrier.
//
// This is the parallel-node path: a follower or standby comes up after
// another node already ran initialization. The barrier exists in shared
// storage (inited == true) but this node has not yet fetched stored keys.
// IsSelfInitComplete would fail with "Vault is sealed"; the guard introduced
// by the ParallelInit fix must short-circuit before reaching that call.
func TestInitialize_AlreadyInitialized_Sealed(t *testing.T) {
	t.Parallel()

	_, cmd := testServerCommand(t)
	core := vault.TestCoreNewSeal(t)

	// Barrier exists in storage but this node is still sealed:
	// do NOT call UnsealWithStoredKeys — simulating a follower coming up.
	vault.TestCoreInit(t, core)

	err := cmd.Initialize(core, emptyInitConfig())
	require.NoError(t, err,
		"initialized but sealed core must return nil: follower nodes must not attempt barrier reads")

	// Sealed state must be unchanged: Initialize must not have touched it.
	require.True(t, core.Sealed(),
		"core must remain sealed after Initialize returns: unseal is not Initialize's responsibility")
}
