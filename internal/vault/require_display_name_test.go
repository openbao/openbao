// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"testing"

	"github.com/openbao/openbao/v2/internal/helper/namespace"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
)

// setTokenMountRequireDisplayName toggles the require_display_name option on the
// default token mount used by TestCoreUnsealed.
func setTokenMountRequireDisplayName(t *testing.T, c *Core, enabled bool) {
	t.Helper()
	ctx := namespace.RootContext(t.Context())
	entry := c.router.MatchingMountEntry(ctx, "auth/token/")
	require.NotNil(t, entry)
	if entry.Options == nil {
		entry.Options = map[string]string{}
	}
	if enabled {
		entry.Options["require_display_name"] = "true"
	} else {
		delete(entry.Options, "require_display_name")
	}
}

// TestTokenStore_RequireDisplayName_RejectsEmpty verifies that when the
// require_display_name mount option is enabled, a display-name-less mint is
// rejected with a 400-class error and no token entry is persisted.
func TestTokenStore_RequireDisplayName_RejectsEmpty(t *testing.T) {
	c, _, root := TestCoreUnsealed(t)
	ts := c.tokenStore

	setTokenMountRequireDisplayName(t, c, true)

	req := logical.TestRequest(t, logical.UpdateOperation, "create")
	req.ClientToken = root
	// no display_name

	resp, err := ts.HandleRequest(namespace.RootContext(t.Context()), req)
	require.Error(t, err)
	require.NotNil(t, resp)
	require.True(t, resp.IsError())
	require.Contains(t, resp.Error().Error(), "require_display_name")
}

// TestTokenStore_RequireDisplayName_AllowsNamed verifies that with the option
// enabled, a mint that supplies a display_name succeeds and records it.
func TestTokenStore_RequireDisplayName_AllowsNamed(t *testing.T) {
	c, _, root := TestCoreUnsealed(t)
	ts := c.tokenStore

	setTokenMountRequireDisplayName(t, c, true)

	req := logical.TestRequest(t, logical.UpdateOperation, "create")
	req.ClientToken = root
	req.Data["display_name"] = "svc-x"

	resp, err := ts.HandleRequest(namespace.RootContext(t.Context()), req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.False(t, resp.IsError())
	out, err := ts.Lookup(namespace.RootContext(t.Context()), resp.Auth.ClientToken)
	require.NoError(t, err)
	require.Equal(t, "token-svc-x", out.DisplayName)
}

// TestTokenStore_RequireDisplayName_DefaultOff verifies the disabled path: a
// display-name-less mint on a mount without the option succeeds and records the
// "token" default.
func TestTokenStore_RequireDisplayName_DefaultOff(t *testing.T) {
	c, _, root := TestCoreUnsealed(t)
	ts := c.tokenStore

	setTokenMountRequireDisplayName(t, c, false)

	req := logical.TestRequest(t, logical.UpdateOperation, "create")
	req.ClientToken = root
	// no display_name, option off

	resp, err := ts.HandleRequest(namespace.RootContext(t.Context()), req)
	require.NoError(t, err)
	require.False(t, resp.IsError())
	out, err := ts.Lookup(namespace.RootContext(t.Context()), resp.Auth.ClientToken)
	require.NoError(t, err)
	require.Equal(t, "token", out.DisplayName)
}

// TestTokenStore_RequireDisplayName_MountOptionRoundTrip verifies the mount
// option is visible on the mount-entry accessor (read side).
func TestTokenStore_RequireDisplayName_MountOptionRoundTrip(t *testing.T) {
	c, _, _ := TestCoreUnsealed(t)
	ctx := namespace.RootContext(t.Context())
	setTokenMountRequireDisplayName(t, c, true)
	entry := c.router.MatchingMountEntry(ctx, "auth/token/")
	require.Equal(t, "true", entry.Options["require_display_name"])
}
