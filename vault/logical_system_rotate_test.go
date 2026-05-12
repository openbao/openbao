// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
)

func TestBackend_Rotate(t *testing.T) {
	t.Parallel()
	c, _, _ := TestCoreUnsealed(t)
	b := c.systemBackend
	ctx := namespace.RootContext(t.Context())

	t.Run("returns error for non-sealable namespace", func(t *testing.T) {
		ns := testCreateNamespace(t, ctx, b, "foo", nil)
		req := logical.TestRequest(t, logical.UpdateOperation, "rotate/keyring")
		res, err := b.HandleRequest(namespace.ContextWithNamespace(ctx, ns), req)
		require.Error(t, err)
		require.ErrorContains(t, res.Error(), ErrNotSealable.Error())
	})

	ns := &namespace.Namespace{Path: "foobar/"}
	_ = TestCoreCreateUnsealedNamespaces(t, b.Core, ns)
	namespaces := []*namespace.Namespace{namespace.RootNamespace, ns}
	for _, ns := range namespaces {
		t.Run(fmt.Sprintf("rotates the barrier key for namespace: %s", ns.ID), func(t *testing.T) {
			nsCtx := namespace.ContextWithNamespace(ctx, ns)

			req := logical.TestRequest(t, logical.ReadOperation, "key-status")
			res, err := b.HandleRequest(nsCtx, req)
			require.NoError(t, err)
			require.Equal(t, 1, res.Data["term"])
			require.NotEmpty(t, res.Data["encryptions"])
			require.NotEmpty(t, res.Data["install_time"])

			req = logical.TestRequest(t, logical.UpdateOperation, "rotate/keyring")
			res, err = b.HandleRequest(nsCtx, req)
			require.NoError(t, err)
			require.Empty(t, res)

			req = logical.TestRequest(t, logical.ReadOperation, "key-status")
			res, err = b.HandleRequest(nsCtx, req)
			require.NoError(t, err)
			require.Equal(t, 2, res.Data["term"])
			require.Equal(t, int64(0), res.Data["encryptions"])
			require.NotEmpty(t, res.Data["install_time"])
		})
	}
}

func TestBackend_RotateRoot(t *testing.T) {
	t.Parallel()
	c, _, _ := TestCoreUnsealed(t)
	b := c.systemBackend
	ctx := namespace.RootContext(t.Context())

	ns := &namespace.Namespace{Path: "foobar/"}
	_ = TestCoreCreateUnsealedNamespaces(t, b.Core, ns)
	namespaces := []*namespace.Namespace{namespace.RootNamespace, ns}
	for _, ns := range namespaces {
		t.Run(fmt.Sprintf("rotates the barrier root key for namespace: %s", ns.ID), func(t *testing.T) {
			nsCtx := namespace.ContextWithNamespace(ctx, ns)

			prevKeyring, err := b.Core.sealManager.NamespaceBarrier(ns.Path).Keyring()
			require.NoError(t, err)

			req := logical.TestRequest(t, logical.UpdateOperation, "rotate/root")
			res, err := b.HandleRequest(nsCtx, req)
			require.NoError(t, err)
			require.Empty(t, res)

			curKeyring, err := b.Core.sealManager.NamespaceBarrier(ns.Path).Keyring()
			require.NoError(t, err)
			require.NotEqual(t, prevKeyring, curKeyring)
		})
	}
}

func TestBackend_RotateConfig(t *testing.T) {
	t.Parallel()
	c, _, _ := TestCoreUnsealed(t)
	b := c.systemBackend
	ctx := namespace.RootContext(t.Context())

	t.Run("returns error for non-sealable namespace", func(t *testing.T) {
		ns := &namespace.Namespace{Path: "nonsealable/"}
		nsCtx := namespace.ContextWithNamespace(ctx, ns)
		TestCoreCreateNamespaces(t, c, ns)

		req := logical.TestRequest(t, logical.UpdateOperation, "rotate/keyring/config")
		res, err := b.HandleRequest(nsCtx, req)
		require.Error(t, err)
		require.ErrorContains(t, res.Error(), ErrNotSealable.Error())

		req = logical.TestRequest(t, logical.ReadOperation, "rotate/keyring/config")
		res, err = b.HandleRequest(nsCtx, req)
		require.Error(t, err)
		require.ErrorContains(t, res.Error(), ErrNotSealable.Error())
	})

	ns := &namespace.Namespace{Path: "foobar/"}
	_ = TestCoreCreateUnsealedNamespaces(t, b.Core, ns)
	namespaces := []*namespace.Namespace{namespace.RootNamespace, ns}
	for _, ns := range namespaces {
		t.Run(fmt.Sprintf("updates the key rotation config for namespace: %s", ns.ID), func(t *testing.T) {
			nsCtx := namespace.ContextWithNamespace(ctx, ns)
			req := logical.TestRequest(t, logical.UpdateOperation, "rotate/keyring/config")
			req.Data["max_operations"] = 1_234_567
			req.Data["interval"] = "25h"
			req.Data["enabled"] = false
			res, err := b.HandleRequest(nsCtx, req)
			require.NoError(t, err)
			require.Empty(t, res)

			req = logical.TestRequest(t, logical.ReadOperation, "rotate/keyring/config")
			res, err = b.HandleRequest(nsCtx, req)
			require.NoError(t, err)
			require.Equal(t, int64(1_234_567), res.Data["max_operations"])
			require.Equal(t, "25h0m0s", res.Data["interval"])
			require.Equal(t, false, res.Data["enabled"])
		})
	}
}

func TestBackend_RotateInitStatus(t *testing.T) {
	t.Parallel()
	c, _, _ := TestCoreUnsealed(t)
	b := c.systemBackend
	ctx := namespace.RootContext(t.Context())

	t.Run("rotate init status fails for non-sealable namespaces", func(t *testing.T) {
		ns := &namespace.Namespace{Path: "nonsealable/"}
		nsCtx := namespace.ContextWithNamespace(ctx, ns)
		TestCoreCreateNamespaces(t, c, ns)

		// try to read root rotation status of non-sealable namespace
		req := logical.TestRequest(t, logical.ReadOperation, "rotate/root/init")
		res, err := b.HandleRequest(nsCtx, req)

		require.Error(t, err)
		require.ErrorContains(t, res.Error(), ErrNotSealable.Error())
	})

	ns := &namespace.Namespace{Path: "foo/"}
	_ = TestCoreCreateUnsealedNamespaces(t, b.Core, ns)
	namespaces := []*namespace.Namespace{namespace.RootNamespace, ns}
	for _, ns := range namespaces {
		t.Run(fmt.Sprintf("rotates init responds with rotation status for namespace: %s", ns.ID), func(t *testing.T) {
			nsCtx := namespace.ContextWithNamespace(ctx, ns)

			// read root rotation status without initializing beforehand
			req := logical.TestRequest(t, logical.ReadOperation, "rotate/root/init")
			res, err := b.HandleRequest(nsCtx, req)

			require.NoError(t, err)
			require.Equal(t, false, res.Data["started"])
			require.Equal(t, 0, res.Data["n"])
			require.Equal(t, 0, res.Data["t"])
			require.Equal(t, 3, res.Data["required"])

			// initialize rotation
			req = logical.TestRequest(t, logical.UpdateOperation, "rotate/root/init")
			req.Data["secret_shares"] = 5
			req.Data["secret_threshold"] = 3
			res, err = b.HandleRequest(nsCtx, req)

			require.NoError(t, err)
			require.Equal(t, true, res.Data["started"])
			require.Equal(t, 5, res.Data["n"])
			require.Equal(t, 3, res.Data["t"])
			require.Equal(t, 3, res.Data["required"])
			require.Equal(t, 0, res.Data["progress"])
			require.Equal(t, false, res.Data["verification_required"])
			require.Empty(t, res.Data["verification_nonce"])
			require.NotEmpty(t, res.Data["nonce"])
		})
	}
}

func TestBackend_RotateInitDispatch(t *testing.T) {
	t.Parallel()
	c, _, _ := TestCoreUnsealed(t)
	b := c.systemBackend
	ctx := namespace.RootContext(t.Context())

	t.Run("rotate init dispatch fails for non-sealable namespaces", func(t *testing.T) {
		ns := &namespace.Namespace{Path: "nonsealable/"}
		nsCtx := namespace.ContextWithNamespace(ctx, ns)
		TestCoreCreateNamespaces(t, c, ns)

		// try to init root rotation of non-sealable namespace
		req := logical.TestRequest(t, logical.UpdateOperation, "rotate/root/init")
		res, err := b.HandleRequest(nsCtx, req)

		require.Error(t, err)
		require.ErrorContains(t, res.Error(), ErrNotSealable.Error())
	})

	t.Run("only one rotation can be in progress at a time", func(t *testing.T) {
		ns := &namespace.Namespace{Path: "foo/"}
		nsCtx := namespace.ContextWithNamespace(ctx, ns)
		_ = TestCoreCreateUnsealedNamespaces(t, c, ns)

		// initialize rotation
		req := logical.TestRequest(t, logical.UpdateOperation, "rotate/root/init")
		req.Data["secret_shares"] = 5
		req.Data["secret_threshold"] = 3
		res, err := b.HandleRequest(nsCtx, req)

		require.NoError(t, err)
		require.NotEmpty(t, res)

		// cannot initialize when there's one in progress
		req = logical.TestRequest(t, logical.UpdateOperation, "rotate/root/init")
		res, err = b.HandleRequest(nsCtx, req)
		require.Error(t, err)
		require.ErrorContains(t, res.Error(), "rotation already in progress")
	})

	t.Run("can cancel the rotation and dispatch again", func(t *testing.T) {
		ns := &namespace.Namespace{Path: "bar/"}
		nsCtx := namespace.ContextWithNamespace(ctx, ns)
		_ = TestCoreCreateUnsealedNamespaces(t, c, ns)

		// initialize rotation
		req := logical.TestRequest(t, logical.UpdateOperation, "rotate/root/init")
		req.Data["secret_shares"] = 5
		req.Data["secret_threshold"] = 3
		res, err := b.HandleRequest(nsCtx, req)

		require.NoError(t, err)
		require.NotEmpty(t, res)

		// cancel rotation
		req = logical.TestRequest(t, logical.DeleteOperation, "rotate/root/init")
		res, err = b.HandleRequest(nsCtx, req)
		require.NoError(t, err)
		require.Empty(t, res)

		// dispatch rotation again
		req = logical.TestRequest(t, logical.UpdateOperation, "rotate/root/init")
		req.Data["secret_shares"] = 5
		req.Data["secret_threshold"] = 3
		res, err = b.HandleRequest(nsCtx, req)

		require.NoError(t, err)
		require.NotEmpty(t, res)
	})
}

func TestBackend_RotateUpdate(t *testing.T) {
	t.Parallel()
	c, _, _ := TestCoreUnsealed(t)
	b := c.systemBackend
	ctx := namespace.RootContext(t.Context())

	t.Run("rotate update missing required data", func(t *testing.T) {
		ns := &namespace.Namespace{Path: "foo/"}
		nsCtx := namespace.ContextWithNamespace(ctx, ns)
		unsealShares := TestCoreCreateUnsealedNamespaces(t, c, ns)

		// init root rotation
		req := logical.TestRequest(t, logical.UpdateOperation, "rotate/root/init")
		req.Data["secret_shares"] = 1
		req.Data["secret_threshold"] = 1
		res, err := b.HandleRequest(nsCtx, req)
		require.NoError(t, err)
		require.NotEmpty(t, res.Data)
		nonce := res.Data["nonce"].(string)

		// try to progress rotation without nonce and key
		req = logical.TestRequest(t, logical.UpdateOperation, "rotate/root/update")
		res, err = b.HandleRequest(nsCtx, req)

		require.Error(t, err)
		require.ErrorContains(t, res.Error(), "missing required field 'key'")

		// try to progress rotation without nonce
		req.Data["key"] = base64.RawStdEncoding.EncodeToString(unsealShares["foo/"][0])
		res, err = b.HandleRequest(nsCtx, req)

		require.Error(t, err)
		require.ErrorContains(t, res.Error(), "missing required field 'nonce'")

		// try to progress rotation with invalid key
		req.Data["nonce"] = nonce
		req.Data["key"] = "invalid key" // test with invalid key
		res, err = b.HandleRequest(nsCtx, req)
		require.Error(t, err)
		require.ErrorContains(t, res.Error(), "'key' must be a valid hex or base64 string")
	})

	t.Run("rotate update complete", func(t *testing.T) {
		ns := &namespace.Namespace{Path: "bar/"}
		nsCtx := namespace.ContextWithNamespace(ctx, ns)
		unsealShares := TestCoreCreateUnsealedNamespaces(t, c, ns)

		// init root rotation
		req := logical.TestRequest(t, logical.UpdateOperation, "rotate/root/init")
		req.Data["secret_shares"] = 1
		req.Data["secret_threshold"] = 1
		res, err := b.HandleRequest(nsCtx, req)

		require.NoError(t, err)
		require.NotEmpty(t, res)
		nonce := res.Data["nonce"].(string)

		// progress rotation
		req = logical.TestRequest(t, logical.UpdateOperation, "rotate/root/update")
		req.Data["nonce"] = nonce

		for i := range len(unsealShares["bar/"]) {
			req.Data["key"] = base64.StdEncoding.EncodeToString(unsealShares["bar/"][i])
			res, err = b.HandleRequest(nsCtx, req)
			require.NoError(t, err)

			if i == len(unsealShares["bar/"])-1 {
				break
			}

			require.Equal(t, true, res.Data["started"])
			require.Equal(t, 1, res.Data["n"])
			require.Equal(t, 1, res.Data["t"])
			require.Equal(t, 3, res.Data["required"])
			require.Equal(t, i+1, res.Data["progress"])
		}

		require.Equal(t, true, res.Data["complete"])
		require.Len(t, res.Data["keys"], 1)
	})
}
