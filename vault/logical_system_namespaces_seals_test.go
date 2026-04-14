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

func TestNamespaceBackend_SealUnseal(t *testing.T) {
	t.Parallel()
	c, _, _ := TestCoreUnsealed(t)
	b := c.systemBackend

	rootCtx := namespace.RootContext(context.Background())
	t.Run("namespaces created with seal config are sealed by default", func(t *testing.T) {
		TestCoreCreateSealedNamespaces(t, c, &namespace.Namespace{Path: "foo/"})

		req := logical.TestRequest(t, logical.CreateOperation, "auth/token/create/foo")
		res, err := b.HandleRequest(rootCtx, req)
		require.Error(t, err)
		require.Empty(t, res)

		req = logical.TestRequest(t, logical.UpdateOperation, "namespaces/foo/seal")
		res, err = b.HandleRequest(rootCtx, req)
		require.NoError(t, err)
		require.Empty(t, res)
	})

	t.Run("cannot seal non-existent namespace", func(t *testing.T) {
		req := logical.TestRequest(t, logical.UpdateOperation, "namespaces/bar/seal")
		_, err := b.HandleRequest(rootCtx, req)
		require.Error(t, err)
		require.Equal(t, "invalid request", err.Error())
	})

	t.Run("can unseal namespace with required number of keyshares", func(t *testing.T) {
		req := logical.TestRequest(t, logical.UpdateOperation, "namespaces/baz")
		req.Data["seal"] = map[string]any{"type": "shamir", "secret_shares": 3, "secret_threshold": 2}
		res, err := b.HandleRequest(rootCtx, req)
		require.NoError(t, err)

		keyShares := res.Data["key_shares"].([]string)
		require.Len(t, keyShares, 3)

		ns, err := c.namespaceStore.GetNamespaceByPath(rootCtx, "baz")
		require.NoError(t, err)
		require.NotNil(t, ns)
		nsCtx := namespace.ContextWithNamespace(rootCtx, ns)

		// call to sealed namespace should fail
		req = logical.TestRequest(t, logical.UpdateOperation, "namespaces/child")
		res, err = b.HandleRequest(nsCtx, req)
		require.Error(t, err)
		require.NotNil(t, res.Error())

		req = logical.TestRequest(t, logical.UpdateOperation, "namespaces/baz/unseal")
		req.Data["key"] = keyShares[0]
		res, err = b.HandleRequest(rootCtx, req)
		require.NoError(t, err)
		require.Equal(t, 1, res.Data["progress"])
		require.Equal(t, true, res.Data["sealed"])

		req = logical.TestRequest(t, logical.UpdateOperation, "namespaces/baz/unseal")
		req.Data["key"] = keyShares[1]
		res, err = b.HandleRequest(rootCtx, req)
		require.NoError(t, err)

		// progress reset
		require.Equal(t, 0, res.Data["progress"])
		require.Equal(t, false, res.Data["sealed"])

		// call to unsealed namespace should succeed
		req = logical.TestRequest(t, logical.UpdateOperation, "namespaces/child")
		res, err = b.HandleRequest(nsCtx, req)
		require.NotNil(t, res)
		require.NoError(t, err)
	})

	t.Run("preserve mounts after unsealing namespaces", func(t *testing.T) {
		keyshares := TestCoreCreateUnsealedNamespaces(t, c, &namespace.Namespace{Path: "foobar/"})
		ns, err := c.namespaceStore.GetNamespaceByPath(rootCtx, "foobar")
		require.NoError(t, err)
		nsCtx := namespace.ContextWithNamespace(rootCtx, ns)

		// mount a kv engine
		req := logical.TestRequest(t, logical.UpdateOperation, "mounts/my_secrets")
		req.Data["type"] = "kv"
		_, err = b.HandleRequest(nsCtx, req)
		require.NoError(t, err)

		// mount should appear
		req = logical.TestRequest(t, logical.ReadOperation, "mounts")
		res, err := b.HandleRequest(nsCtx, req)
		require.NoError(t, err)
		require.NotNil(t, res.Data["my_secrets/"])

		// store something to the mount
		req = logical.TestRequest(t, logical.UpdateOperation, "my_secrets/abc")
		req.Data["test_key"] = "test_value"
		_, err = c.router.Route(nsCtx, req)
		require.NoError(t, err)

		// mount an auth and use it
		req = logical.TestRequest(t, logical.UpdateOperation, "auth/my_approle")
		req.Data["type"] = "approle"
		_, err = b.HandleRequest(nsCtx, req)
		require.NoError(t, err)

		req = logical.TestRequest(t, logical.ReadOperation, "auth")
		res, err = b.HandleRequest(nsCtx, req)
		require.NoError(t, err)
		require.NotNil(t, res.Data["my_approle/"])

		req = logical.TestRequest(t, logical.CreateOperation, "auth/my_approle/role/myrole")
		req.Data["token_policies"] = []string{"default"}
		_, err = c.router.Route(nsCtx, req)
		require.NoError(t, err)

		// then seal the namespace
		req = logical.TestRequest(t, logical.UpdateOperation, "namespaces/foobar/seal")
		_, err = b.HandleRequest(rootCtx, req)
		require.NoError(t, err)

		// unseal the namespace
		req = logical.TestRequest(t, logical.UpdateOperation, "namespaces/foobar/unseal")
		req.Data["key"] = base64.RawStdEncoding.EncodeToString(keyshares["foobar/"][0])
		res, err = b.HandleRequest(rootCtx, req)
		require.NoError(t, err)
		require.Equal(t, 1, res.Data["progress"])
		require.Equal(t, true, res.Data["sealed"])

		req = logical.TestRequest(t, logical.UpdateOperation, "namespaces/foobar/unseal")
		req.Data["key"] = base64.RawStdEncoding.EncodeToString(keyshares["foobar/"][1])
		res, err = b.HandleRequest(rootCtx, req)
		require.NoError(t, err)
		require.Equal(t, 2, res.Data["progress"])
		require.Equal(t, true, res.Data["sealed"])

		req = logical.TestRequest(t, logical.UpdateOperation, "namespaces/foobar/unseal")
		req.Data["key"] = base64.RawStdEncoding.EncodeToString(keyshares["foobar/"][2])
		res, err = b.HandleRequest(rootCtx, req)
		require.NoError(t, err)

		// progress reset
		require.Equal(t, 0, res.Data["progress"])
		require.Equal(t, false, res.Data["sealed"])

		// mount should appear
		req = logical.TestRequest(t, logical.ReadOperation, "mounts")
		res, err = b.HandleRequest(nsCtx, req)
		require.NoError(t, err)
		require.NotNil(t, res.Data["my_secrets/"])

		// reading from mount should work
		req = logical.TestRequest(t, logical.ReadOperation, "my_secrets/abc")
		res, err = c.router.Route(nsCtx, req)
		require.NoError(t, err)
		require.NotNil(t, res)
		require.Equal(t, "test_value", res.Data["test_key"])

		// auth should appear
		req = logical.TestRequest(t, logical.ReadOperation, "auth")
		res, err = b.HandleRequest(nsCtx, req)
		require.NoError(t, err)
		require.NotNil(t, res.Data["my_approle/"])

		// reading from auth should work
		req = logical.TestRequest(t, logical.ReadOperation, "auth/my_approle/role/myrole")
		res, err = c.router.Route(nsCtx, req)
		require.NoError(t, err)
		require.NotNil(t, res)
	})
}
