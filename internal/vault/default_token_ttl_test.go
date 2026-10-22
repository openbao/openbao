// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"testing"
	"time"

	"github.com/openbao/openbao/v2/internal/helper/namespace"
	"github.com/openbao/openbao/v2/internal/vault/routing"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
)

// tuneTokenMountMaxLeaseTTL applies a mount tune to the default token mount
// via the real handleAuthTuneWrite path (POST sys/auth/token/tune, the
// internal counterpart of "bao secrets tune auth/token/") and returns the
// resulting mount entry.
func tuneTokenMountMaxLeaseTTL(t *testing.T, c *Core, root, maxLeaseTTL string) *routing.MountEntry {
	t.Helper()
	ctx := namespace.RootContext(t.Context())
	// The SystemBackend is reachable via sys/..., so tune the token mount
	// through sys/mounts/auth/token/tune -> handleMountTuneWrite (the same
	// internal target as "bao secrets tune auth/token/").
	req := logical.TestRequest(t, logical.UpdateOperation, "sys/mounts/auth/token/tune")
	req.Data["max_lease_ttl"] = maxLeaseTTL
	req.ClientToken = root
	resp, err := c.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.False(t, resp.IsError(), "tune of token mount failed: %v", resp.Error())

	entry := c.router.MatchingMountEntry(ctx, routing.CredentialRoutePrefix+"token/")
	require.NotNil(t, entry, "expected default token mount to be registered")
	return entry
}

// TestTokenStore_MountMaxLeaseTTL verifies the documented operator mechanism
// for capping the token store: a mount tune of max_lease_ttl on the token
// mount sets the mount-level ceiling that the token store's system view
// honors (fetchTTLs in dynamic_system_view.go prefers the mount value over
// the system default). This is the documented "stolen key should not survive
// days" floor operators apply on a fresh install.
func TestTokenStore_MountMaxLeaseTTL(t *testing.T) {
	c, _, root := TestCoreUnsealed(t)
	entry := tuneTokenMountMaxLeaseTTL(t, c, root, "72h")
	require.Equal(t, 72*time.Hour, entry.Config.MaxLeaseTTL,
		"mount tune should set the token mount max lease TTL")
}

// TestTokenStore_MountMaxLeaseTTL_Preserved verifies that a subsequent tune
// with an explicit value replaces the previous one; the documented override
// path never silently re-applies an old value.
func TestTokenStore_MountMaxLeaseTTL_Preserved(t *testing.T) {
	c, _, root := TestCoreUnsealed(t)
	tuneTokenMountMaxLeaseTTL(t, c, root, "72h")
	entry := tuneTokenMountMaxLeaseTTL(t, c, root, "48h")
	require.Equal(t, 48*time.Hour, entry.Config.MaxLeaseTTL,
		"an explicitly tuned max lease TTL must not be overridden")
}

// TestTokenStore_MountMaxLeaseTTL_System verifies that tuning
// max_lease_ttl back to "system" restores the system-wide ceiling
// (32 days) instead of leaving a mount-level value in place.
func TestTokenStore_MountMaxLeaseTTL_System(t *testing.T) {
	c, _, root := TestCoreUnsealed(t)
	tuneTokenMountMaxLeaseTTL(t, c, root, "72h")
	entry := tuneTokenMountMaxLeaseTTL(t, c, root, "system")
	require.Equal(t, time.Duration(0), entry.Config.MaxLeaseTTL,
		"`system` tune must clear the mount-level max lease TTL")
	require.Equal(t, 32*24*time.Hour, c.tokenStore.System().MaxLeaseTTL(),
		"token store system view must fall back to the system max lease TTL")
}

// TestTokenStore_MountMaxLeaseTTL_NoDefault verifies that a fresh install
// carries NO mount-level max_lease_ttl on the default token mount: the
// token store clamps to the system ceiling (32 days) and operators opt in
// to a tighter cap explicitly via mount tune. This guards against
// regressions where a mount-level default leaks into every mount's
// System().MaxLeaseTTL() and defeats per-core system ceilings.
func TestTokenStore_MountMaxLeaseTTL_NoDefault(t *testing.T) {
	c, _, _ := TestCoreUnsealed(t)
	entry := c.router.MatchingMountEntry(namespace.RootContext(t.Context()), routing.CredentialRoutePrefix+"token/")
	require.NotNil(t, entry)
	require.Equal(t, time.Duration(0), entry.Config.MaxLeaseTTL,
		"fresh install must not carry a mount-level max lease TTL")
	require.Equal(t, 32*24*time.Hour, c.tokenStore.System().MaxLeaseTTL(),
		"fresh install token store must clamp to the system max lease TTL")
}
