// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
)

func TestNamespaceBackend_Rotate(t *testing.T) {
	t.Parallel()
	c, _, _ := TestCoreUnsealed(t)
	b := c.systemBackend
	rootCtx := namespace.RootContext(context.Background())

	t.Run("cannot rotate keys on non-existent namespace", func(t *testing.T) {
		req := logical.TestRequest(t, logical.UpdateOperation, "namespaces/bar/rotate/keyring")
		res, err := b.HandleRequest(rootCtx, req)
		require.Error(t, err)
		require.ErrorContains(t, res.Error(), "namespace \"bar/\" doesn't exist")
	})

	t.Run("returns error for non-sealable namespace", func(t *testing.T) {
		testCreateNamespace(t, rootCtx, b, "foo", nil)
		req := logical.TestRequest(t, logical.UpdateOperation, "namespaces/foo/rotate/keyring")
		res, err := b.HandleRequest(rootCtx, req)
		require.Error(t, err)
		require.ErrorContains(t, res.Error(), ErrNotSealable.Error())
	})

	t.Run("rotates the barrier key for a sealable namespace", func(t *testing.T) {
		sealConfig := map[string]any{"type": "shamir", "secret_shares": 3, "secret_threshold": 2}
		testCreateNamespace(t, rootCtx, b, "foobar", map[string]any{"seals": sealConfig})

		req := logical.TestRequest(t, logical.ReadOperation, "namespaces/foobar/key-status")
		res, err := b.HandleRequest(rootCtx, req)
		require.NoError(t, err)
		require.Equal(t, 1, res.Data["term"])
		require.NotEmpty(t, res.Data["encryptions"])
		require.NotEmpty(t, res.Data["install_time"])

		req = logical.TestRequest(t, logical.UpdateOperation, "namespaces/foobar/rotate/keyring")
		res, err = b.HandleRequest(rootCtx, req)
		require.NoError(t, err)
		require.Empty(t, res)

		req = logical.TestRequest(t, logical.ReadOperation, "namespaces/foobar/key-status")
		res, err = b.HandleRequest(rootCtx, req)
		require.NoError(t, err)
		require.Equal(t, 2, res.Data["term"])
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
		req := logical.TestRequest(t, logical.UpdateOperation, "namespaces/bar/rotate/keyring/config")
		res, err := b.HandleRequest(rootCtx, req)
		require.Error(t, err)
		require.ErrorContains(t, res.Error(), "namespace \"bar/\" doesn't exist")

		req = logical.TestRequest(t, logical.ReadOperation, "namespaces/bar/rotate/keyring/config")
		res, err = b.HandleRequest(rootCtx, req)
		require.Error(t, err)
		require.ErrorContains(t, res.Error(), "namespace \"bar/\" doesn't exist")
	})

	t.Run("returns error for non-sealable namespace", func(t *testing.T) {
		testCreateNamespace(t, rootCtx, b, "foo", nil)
		req := logical.TestRequest(t, logical.UpdateOperation, "namespaces/foo/rotate/keyring/config")
		res, err := b.HandleRequest(rootCtx, req)
		require.Error(t, err)
		require.ErrorContains(t, res.Error(), ErrNotSealable.Error())

		req = logical.TestRequest(t, logical.ReadOperation, "namespaces/foo/rotate/keyring/config")
		res, err = b.HandleRequest(rootCtx, req)
		require.Error(t, err)
		require.ErrorContains(t, res.Error(), ErrNotSealable.Error())
	})

	t.Run("update the key rotation config for a sealable namespace", func(t *testing.T) {
		sealConfig := map[string]any{"type": "shamir", "secret_shares": 3, "secret_threshold": 2}
		testCreateNamespace(t, rootCtx, b, "foobar", map[string]any{"seals": sealConfig})

		req := logical.TestRequest(t, logical.UpdateOperation, "namespaces/foobar/rotate/keyring/config")
		req.Data["max_operations"] = 1_234_567
		req.Data["interval"] = "25h"
		req.Data["enabled"] = false
		res, err := b.HandleRequest(rootCtx, req)
		require.NoError(t, err)
		require.Empty(t, res)

		req = logical.TestRequest(t, logical.ReadOperation, "namespaces/foobar/rotate/keyring/config")
		res, err = b.HandleRequest(rootCtx, req)
		require.NoError(t, err)
		require.Equal(t, int64(1_234_567), res.Data["max_operations"])
		require.Equal(t, "25h0m0s", res.Data["interval"])
		require.Equal(t, false, res.Data["enabled"])
	})
}

func TestNamespaceBackend_RotateInitStatus(t *testing.T) {
	t.Parallel()
	c, _, _ := TestCoreUnsealed(t)
	b := c.systemBackend
	rootCtx := namespace.RootContext(context.Background())

	t.Run("rotate init status fails for non-existent or non-sealable namespaces", func(t *testing.T) {
		TestCoreCreateNamespaces(t, c, &namespace.Namespace{Path: "nonsealable/"})

		// try to read root rotation status of non-existent namespace
		req := logical.TestRequest(t, logical.ReadOperation, "namespaces/nonexistent/rotate/root/init")
		res, err := b.HandleRequest(rootCtx, req)

		require.Error(t, err)
		require.ErrorContains(t, res.Error(), `namespace "nonexistent/" doesn't exist`)

		// try to read root rotation status of non-sealable namespace
		req = logical.TestRequest(t, logical.ReadOperation, "namespaces/nonsealable/rotate/root/init")
		res, err = b.HandleRequest(rootCtx, req)

		require.Error(t, err)
		require.ErrorContains(t, res.Error(), "namespace is not sealable")
	})

	t.Run("rotate init responds with rotation status", func(t *testing.T) {
		_ = TestCoreCreateSealedNamespaces(t, c, &namespace.Namespace{Path: "foo/"})

		// read root rotation status without initializing beforehand
		req := logical.TestRequest(t, logical.ReadOperation, "namespaces/foo/rotate/root/init")
		res, err := b.HandleRequest(rootCtx, req)

		require.NoError(t, err)
		require.Equal(t, "foo/", res.Data["namespace"])
		require.Equal(t, false, res.Data["started"])
		require.Equal(t, 0, res.Data["n"])
		require.Equal(t, 0, res.Data["t"])
		require.Equal(t, 3, res.Data["seal_threshold"])

		// initialize rotation
		req = logical.TestRequest(t, logical.UpdateOperation, "namespaces/foo/rotate/root/init")
		req.Data["secret_shares"] = 5
		req.Data["secret_threshold"] = 3
		res, err = b.HandleRequest(rootCtx, req)

		require.NoError(t, err)
		require.Equal(t, "foo/", res.Data["namespace"])
		require.Equal(t, true, res.Data["started"])
		require.Equal(t, 5, res.Data["n"])
		require.Equal(t, 3, res.Data["t"])
		require.Equal(t, 3, res.Data["seal_threshold"])
		require.Equal(t, 0, res.Data["progress"])
		require.Equal(t, false, res.Data["verification_required"])
		require.Empty(t, res.Data["verification_nonce"])
		require.NotEmpty(t, res.Data["nonce"])
	})
}

func TestNamespaceBackend_RotateInitDispatch(t *testing.T) {
	t.Parallel()
	c, _, _ := TestCoreUnsealed(t)
	b := c.systemBackend
	rootCtx := namespace.RootContext(context.Background())

	t.Run("rotate init dispatch fails for non-existent or non-sealable namespaces", func(t *testing.T) {
		TestCoreCreateNamespaces(t, c, &namespace.Namespace{Path: "nonsealable/"})

		// try to init root rotation of non-existent namespace
		req := logical.TestRequest(t, logical.UpdateOperation, "namespaces/nonexistent/rotate/root/init")
		res, err := b.HandleRequest(rootCtx, req)

		require.Error(t, err)
		require.ErrorContains(t, res.Error(), `namespace "nonexistent/" doesn't exist`)

		// try to init root rotation of non-sealable namespace
		req = logical.TestRequest(t, logical.UpdateOperation, "namespaces/nonsealable/rotate/root/init")
		res, err = b.HandleRequest(rootCtx, req)

		require.Error(t, err)
		require.ErrorContains(t, res.Error(), "namespace is not sealable")
	})

	t.Run("only one rotation can be in progress at a time", func(t *testing.T) {
		_ = TestCoreCreateSealedNamespaces(t, c, &namespace.Namespace{Path: "foo/"})

		// initialize rotation
		req := logical.TestRequest(t, logical.UpdateOperation, "namespaces/foo/rotate/root/init")
		req.Data["secret_shares"] = 5
		req.Data["secret_threshold"] = 3
		res, err := b.HandleRequest(rootCtx, req)

		require.NoError(t, err)
		require.NotEmpty(t, res)

		// cannot initialize when there's one in progress
		req = logical.TestRequest(t, logical.UpdateOperation, "namespaces/foo/rotate/root/init")
		res, err = b.HandleRequest(rootCtx, req)
		require.Error(t, err)
		require.ErrorContains(t, res.Error(), "rotation already in progress")
	})

	t.Run("can cancel the rotation and dispatch again", func(t *testing.T) {
		_ = TestCoreCreateSealedNamespaces(t, c, &namespace.Namespace{Path: "bar/"})

		// initialize rotation
		req := logical.TestRequest(t, logical.UpdateOperation, "namespaces/bar/rotate/root/init")
		req.Data["secret_shares"] = 5
		req.Data["secret_threshold"] = 3
		res, err := b.HandleRequest(rootCtx, req)

		require.NoError(t, err)
		require.NotEmpty(t, res)

		// cancel rotation
		req = logical.TestRequest(t, logical.DeleteOperation, "namespaces/bar/rotate/root/init")
		res, err = b.HandleRequest(rootCtx, req)
		require.NoError(t, err)
		require.Empty(t, res)

		// dispatch rotation again
		req = logical.TestRequest(t, logical.UpdateOperation, "namespaces/bar/rotate/root/init")
		req.Data["secret_shares"] = 5
		req.Data["secret_threshold"] = 3
		res, err = b.HandleRequest(rootCtx, req)

		require.NoError(t, err)
		require.NotEmpty(t, res)
	})
}

func TestNamespaceBackend_RotateUpdate(t *testing.T) {
	t.Parallel()
	c, _, _ := TestCoreUnsealed(t)
	b := c.systemBackend
	rootCtx := namespace.RootContext(context.Background())

	t.Run("rotate update missing required data", func(t *testing.T) {
		unsealShares := TestCoreCreateSealedNamespaces(t, c, &namespace.Namespace{Path: "foo/"})

		// init root rotation
		req := logical.TestRequest(t, logical.UpdateOperation, "namespaces/foo/rotate/root/init")
		req.Data["secret_shares"] = 1
		req.Data["secret_threshold"] = 1
		res, err := b.HandleRequest(rootCtx, req)

		require.NoError(t, err)
		require.NotEmpty(t, res)
		nonce := res.Data["nonce"].(string)

		// try to progress rotation without nonce and key
		req = logical.TestRequest(t, logical.UpdateOperation, "namespaces/foo/rotate/root/update")
		res, err = b.HandleRequest(rootCtx, req)

		require.Error(t, err)
		require.ErrorContains(t, res.Error(), "missing required field 'key'")

		// try to progress rotation without nonce
		req.Data["key"] = base64.RawStdEncoding.EncodeToString(unsealShares["foo/"][0])
		res, err = b.HandleRequest(rootCtx, req)

		require.Error(t, err)
		require.ErrorContains(t, res.Error(), "missing required field 'nonce'")

		// try to progress rotation with invalid key
		req.Data["nonce"] = nonce
		req.Data["key"] = "invalid key" // test with invalid key
		res, err = b.HandleRequest(rootCtx, req)
		require.Error(t, err)
		require.ErrorContains(t, res.Error(), "'key' must be a valid hex or base64 string")
	})

	t.Run("rotate update complete", func(t *testing.T) {
		unsealShares := TestCoreCreateSealedNamespaces(t, c, &namespace.Namespace{Path: "bar/"})

		// init root rotation
		req := logical.TestRequest(t, logical.UpdateOperation, "namespaces/bar/rotate/root/init")
		req.Data["secret_shares"] = 1
		req.Data["secret_threshold"] = 1
		res, err := b.HandleRequest(rootCtx, req)

		require.NoError(t, err)
		require.NotEmpty(t, res)
		nonce := res.Data["nonce"].(string)

		// progress rotation
		req = logical.TestRequest(t, logical.UpdateOperation, "namespaces/bar/rotate/root/update")
		req.Data["nonce"] = nonce

		for i := range len(unsealShares["bar/"]) {
			req.Data["key"] = base64.StdEncoding.EncodeToString(unsealShares["bar/"][i])
			res, err = b.HandleRequest(rootCtx, req)
			require.NoError(t, err)

			if i == len(unsealShares["bar/"])-1 {
				break
			}

			require.Equal(t, "bar/", res.Data["namespace"])
			require.Equal(t, true, res.Data["started"])
			require.Equal(t, 1, res.Data["n"])
			require.Equal(t, 1, res.Data["t"])
			require.Equal(t, 3, res.Data["seal_threshold"])
			require.Equal(t, i+1, res.Data["progress"])
		}

		require.Equal(t, true, res.Data["complete"])
		require.Len(t, res.Data["keys"], 1)
	})
}
