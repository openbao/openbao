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

func TestNamespaceBackend_Unseal(t *testing.T) {
	t.Parallel()
	c, _, _ := TestCoreUnsealed(t)
	b := c.systemBackend

	rootCtx := namespace.RootContext(context.Background())
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

	// TODO(wslabosz): add additional tests with seal operation
}
