// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"testing"

	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
)

func TestNamespaceBackend_KeyStatus(t *testing.T) {
	t.Parallel()
	b := testSystemBackend(t)
	rootCtx := namespace.RootContext(context.Background())

	t.Run("returns error for non-existent namespace", func(t *testing.T) {
		req := logical.TestRequest(t, logical.ReadOperation, "namespaces/noop/key-status")
		resp, err := b.HandleRequest(rootCtx, req)
		require.ErrorContains(t, err, "namespace \"noop/\" doesn't exist")
		require.Empty(t, resp)
	})

	t.Run("returns error for non-sealable namespace", func(t *testing.T) {
		testCreateNamespace(t, rootCtx, b, "foo", nil)
		req := logical.TestRequest(t, logical.ReadOperation, "namespaces/foo/key-status")
		resp, err := b.HandleRequest(rootCtx, req)
		require.ErrorContains(t, err, "namespace \"foo/\" doesn't have a barrier setup")
		require.Empty(t, resp)
	})

	t.Run("returns key info for sealable namespace", func(t *testing.T) {
		sealConfig := map[string]interface{}{"type": "shamir", "secret_shares": 3, "secret_threshold": 2}
		testCreateNamespace(t, rootCtx, b, "bar", map[string]interface{}{"seals": sealConfig})
		req := logical.TestRequest(t, logical.ReadOperation, "namespaces/bar/key-status")
		resp, err := b.HandleRequest(rootCtx, req)

		require.NoError(t, err)
		require.Equal(t, resp.Data["term"], 1)
		require.NotEmpty(t, resp.Data["encryptions"])
		require.NotEmpty(t, resp.Data["install_time"])
	})
}

func TestNamespaceBackend_SealStatus(t *testing.T) {
	t.Parallel()
	b := testSystemBackend(t)
	rootCtx := namespace.RootContext(context.Background())

	t.Run("returns nil seal status of seal-less namespace", func(t *testing.T) {
		testCreateNamespace(t, rootCtx, b, "foo", nil)

		req := logical.TestRequest(t, logical.ReadOperation, "namespaces/foo/seal-status")
		res, err := b.HandleRequest(rootCtx, req)
		require.NoError(t, err)
		require.Empty(t, res)
	})

	t.Run("can read seal status", func(t *testing.T) {
		req := logical.TestRequest(t, logical.UpdateOperation, "namespaces/bar")
		req.Data["seals"] = map[string]interface{}{"type": "shamir", "secret_shares": 3, "secret_threshold": 2}
		res, err := b.HandleRequest(rootCtx, req)
		require.NoError(t, err)

		req = logical.TestRequest(t, logical.ReadOperation, "namespaces/bar/seal-status")
		res, err = b.HandleRequest(rootCtx, req)
		require.NoError(t, err)
		require.Equal(t, "shamir", res.Data["seal_status"].(*SealStatusResponse).Type)
		require.Equal(t, false, res.Data["seal_status"].(*SealStatusResponse).Sealed)
		require.Equal(t, 2, res.Data["seal_status"].(*SealStatusResponse).T)
		require.Equal(t, 3, res.Data["seal_status"].(*SealStatusResponse).N)
		require.Equal(t, 0, res.Data["seal_status"].(*SealStatusResponse).Progress)
	})
}

func TestNamespaceBackend_SealUnseal(t *testing.T) {
	t.Parallel()
	c, _, _ := TestCoreUnsealed(t)
	b := c.systemBackend

	rootCtx := namespace.RootContext(context.Background())
	t.Run("can seal namespace created with seal config", func(t *testing.T) {
		req := logical.TestRequest(t, logical.UpdateOperation, "namespaces/foo")
		req.Data["seals"] = map[string]interface{}{"type": "shamir", "secret_shares": 3, "secret_threshold": 2}
		res, err := b.HandleRequest(rootCtx, req)
		require.NoError(t, err)

		require.NotEmpty(t, res.Data["uuid"].(string), "namespace has no UUID")
		require.NotEmpty(t, res.Data["id"].(string), "namespace has no ID")
		require.Equal(t, res.Data["path"].(string), "foo/")
		require.Equal(t, res.Data["tainted"].(bool), false)
		require.Len(t, res.Data["key_shares"].(map[string][]string)["default"], 3)

		req = logical.TestRequest(t, logical.UpdateOperation, "namespaces/foo/seal")
		res, err = b.HandleRequest(rootCtx, req)
		require.NoError(t, err)

		// any call using the namespace will now fail
		req = logical.TestRequest(t, logical.CreateOperation, "auth/token/create/foo")
		res, err = b.HandleRequest(rootCtx, req)
		require.Error(t, err)
		require.Empty(t, res)

		// nothing happens - no op
		req = logical.TestRequest(t, logical.UpdateOperation, "namespaces/foo/seal")
		res, err = b.HandleRequest(rootCtx, req)
		require.NoError(t, err)
		require.Empty(t, res)
	})

	t.Run("cannot seal non-existent namespace", func(t *testing.T) {
		req := logical.TestRequest(t, logical.UpdateOperation, "namespaces/bar/seal")
		res, err := b.HandleRequest(rootCtx, req)
		require.Error(t, err)
		require.Equal(t, res.Data["error"], "namespace doesn't exist")
	})

	t.Run("can unseal namespace with required number of keyshares", func(t *testing.T) {
		req := logical.TestRequest(t, logical.UpdateOperation, "namespaces/baz")
		req.Data["seals"] = map[string]interface{}{"type": "shamir", "secret_shares": 3, "secret_threshold": 2}
		res, err := b.HandleRequest(rootCtx, req)
		require.NoError(t, err)

		keyshares := res.Data["key_shares"].(map[string][]string)["default"]

		req = logical.TestRequest(t, logical.UpdateOperation, "namespaces/baz/seal")
		res, err = b.HandleRequest(rootCtx, req)
		require.NoError(t, err)

		// calls using the namespace will now fail
		ns, err := c.namespaceStore.GetNamespaceByPath(rootCtx, "baz")
		require.NoError(t, err)

		nsCtx := namespace.ContextWithNamespace(rootCtx, ns)
		req = logical.TestRequest(t, logical.UpdateOperation, "namespaces/child")
		res, err = b.HandleRequest(nsCtx, req)
		require.Error(t, err)
		require.Contains(t, res.Data["error"], "Barrier is sealed")

		req = logical.TestRequest(t, logical.UpdateOperation, "namespaces/baz/unseal")
		req.Data["key"] = keyshares[0]
		res, err = b.HandleRequest(rootCtx, req)
		require.NoError(t, err)
		require.Equal(t, 1, res.Data["seal_status"].(*SealStatusResponse).Progress)
		require.Equal(t, true, res.Data["seal_status"].(*SealStatusResponse).Sealed)

		req = logical.TestRequest(t, logical.UpdateOperation, "namespaces/baz/unseal")
		req.Data["key"] = keyshares[1]
		res, err = b.HandleRequest(rootCtx, req)
		require.NoError(t, err)
		// progress reset
		require.Equal(t, 0, res.Data["seal_status"].(*SealStatusResponse).Progress)
		require.Equal(t, false, res.Data["seal_status"].(*SealStatusResponse).Sealed)

		// call succedes
		req = logical.TestRequest(t, logical.UpdateOperation, "namespaces/child")
		res, err = b.HandleRequest(nsCtx, req)
		require.NoError(t, err)
	})
}

func TestNamespaceBackend_Rotate(t *testing.T) {
	t.Parallel()
	c, _, _ := TestCoreUnsealed(t)
	b := c.systemBackend
	rootCtx := namespace.RootContext(context.Background())

	t.Run("cannot rotate keys on non-existent namespace", func(t *testing.T) {
		req := logical.TestRequest(t, logical.UpdateOperation, "namespaces/bar/rotate")
		res, err := b.HandleRequest(rootCtx, req)
		require.Error(t, err)
		require.ErrorContains(t, err, "namespace \"bar/\" doesn't exist")
		require.Empty(t, res)
	})

	t.Run("returns error for non-sealable namespace", func(t *testing.T) {
		testCreateNamespace(t, rootCtx, b, "foo", nil)
		req := logical.TestRequest(t, logical.UpdateOperation, "namespaces/foo/rotate")
		res, err := b.HandleRequest(rootCtx, req)
		require.ErrorContains(t, err, "namespace \"foo/\" is not a sealable namespace")
		require.Empty(t, res)
	})

	t.Run("rotates the barrier key for a sealable namespace", func(t *testing.T) {
		sealConfig := map[string]any{"type": "shamir", "secret_shares": 3, "secret_threshold": 2}
		testCreateNamespace(t, rootCtx, b, "foobar", map[string]any{"seals": sealConfig})

		req := logical.TestRequest(t, logical.ReadOperation, "namespaces/foobar/key-status")
		res, err := b.HandleRequest(rootCtx, req)
		require.NoError(t, err)
		require.Equal(t, res.Data["term"], 1)
		require.NotEmpty(t, res.Data["encryptions"])
		require.NotEmpty(t, res.Data["install_time"])

		req = logical.TestRequest(t, logical.UpdateOperation, "namespaces/foobar/rotate")
		res, err = b.HandleRequest(rootCtx, req)
		require.NoError(t, err)
		require.Empty(t, res)

		req = logical.TestRequest(t, logical.ReadOperation, "namespaces/foobar/key-status")
		res, err = b.HandleRequest(rootCtx, req)
		require.NoError(t, err)
		require.Equal(t, res.Data["term"], 2)
		require.Empty(t, res.Data["encryptions"])
		require.NotEmpty(t, res.Data["install_time"])
	})
}

func TestNamespaceBackend_RotateConfig(t *testing.T) {
	t.Parallel()
	c, _, _ := TestCoreUnsealed(t)
	b := c.systemBackend
	rootCtx := namespace.RootContext(context.Background())

	t.Run("cannot configure automatic key rotation on non-existent namespace", func(t *testing.T) {
		req := logical.TestRequest(t, logical.UpdateOperation, "namespaces/bar/rotate/config")
		res, err := b.HandleRequest(rootCtx, req)
		require.Error(t, err)
		require.ErrorContains(t, err, "namespace \"bar/\" doesn't exist")
		require.Empty(t, res)

		req = logical.TestRequest(t, logical.ReadOperation, "namespaces/bar/rotate/config")
		res, err = b.HandleRequest(rootCtx, req)
		require.Error(t, err)
		require.ErrorContains(t, err, "namespace \"bar/\" doesn't exist")
		require.Empty(t, res)
	})

	t.Run("returns error for non-sealable namespace", func(t *testing.T) {
		testCreateNamespace(t, rootCtx, b, "foo", nil)
		req := logical.TestRequest(t, logical.UpdateOperation, "namespaces/foo/rotate/config")
		res, err := b.HandleRequest(rootCtx, req)
		require.ErrorContains(t, err, "namespace \"foo/\" is not a sealable namespace")
		require.Empty(t, res)

		req = logical.TestRequest(t, logical.ReadOperation, "namespaces/foo/rotate/config")
		res, err = b.HandleRequest(rootCtx, req)
		require.ErrorContains(t, err, "namespace \"foo/\" is not a sealable namespace")
		require.Empty(t, res)
	})

	t.Run("update the key rotation config for a sealable namespace", func(t *testing.T) {
		sealConfig := map[string]any{"type": "shamir", "secret_shares": 3, "secret_threshold": 2}
		testCreateNamespace(t, rootCtx, b, "foobar", map[string]any{"seals": sealConfig})

		req := logical.TestRequest(t, logical.UpdateOperation, "namespaces/foobar/rotate/config")
		req.Data["max_operations"] = 1_234_567
		req.Data["interval"] = "25h"
		req.Data["enabled"] = false
		res, err := b.HandleRequest(rootCtx, req)
		require.NoError(t, err)
		require.Empty(t, res)

		req = logical.TestRequest(t, logical.ReadOperation, "namespaces/foobar/rotate/config")
		res, err = b.HandleRequest(rootCtx, req)
		require.NoError(t, err)
		require.Equal(t, int64(1_234_567), res.Data["max_operations"])
		require.Equal(t, "25h0m0s", res.Data["interval"])
		require.Equal(t, false, res.Data["enabled"])
	})
}
