// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"maps"
	"path"
	"testing"

	"github.com/mitchellh/mapstructure"
	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
)

func testCreateNamespace(t *testing.T, b logical.Backend, name string, customMetadata map[string]string) {
	t.Helper()
	req := logical.TestRequest(t, logical.UpdateOperation, path.Join("namespaces", name))
	if customMetadata != nil {
		req.Data["custom_metadata"] = customMetadata
	}
	_, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
}

func TestNamespaceBackend_Set(t *testing.T) {
	t.Parallel()
	b := testSystemBackend(t)

	t.Run("create namespace", func(t *testing.T) {
		customMetadata := map[string]string{"abc": "def"}
		req := logical.TestRequest(t, logical.UpdateOperation, "namespaces/foo")
		req.Data["custom_metadata"] = customMetadata
		res, err := b.HandleRequest(context.Background(), req)
		require.NoError(t, err)

		require.NotEmpty(t, res.Data["uuid"].(string), "namespace has no UUID")
		require.NotEmpty(t, res.Data["id"].(string), "namespace has no ID")
		require.Equal(t, res.Data["path"].(string), "foo/")
		require.Equal(t, res.Data["custom_metadata"], customMetadata,
			"read custom_metadata does not match original custom_metadata")
	})

	t.Run("update namespace metadata", func(t *testing.T) {
		customMetadata := map[string]string{"abc": "def"}
		testCreateNamespace(t, b, "bar", customMetadata)

		newMetadata := map[string]string{"testing": "hello"}
		req := logical.TestRequest(t, logical.UpdateOperation, "namespaces/foo")
		req.Data["custom_metadata"] = newMetadata
		res, err := b.HandleRequest(context.Background(), req)
		require.NoError(t, err)

		require.NotEmpty(t, res.Data["uuid"].(string), "namespace has no UUID")
		require.NotEmpty(t, res.Data["id"].(string), "namespace has no ID")
		require.Equal(t, res.Data["path"].(string), "foo/")
		require.Equal(t, res.Data["custom_metadata"], newMetadata,
			"read custom_metadata does not match original custom_metadata")
	})
}

func TestNamespaceBackend_Read(t *testing.T) {
	t.Parallel()
	b := testSystemBackend(t)

	t.Run("reads existing namespace as expected", func(t *testing.T) {
		customMetadata := map[string]string{"abc": "def"}
		testCreateNamespace(t, b, "foo", customMetadata)

		req := logical.TestRequest(t, logical.ReadOperation, "namespaces/foo")
		res, err := b.HandleRequest(context.Background(), req)
		require.NoError(t, err)

		require.NotEmpty(t, res.Data["uuid"].(string), "namespace has no UUID")
		require.NotEmpty(t, res.Data["id"].(string), "namespace has no ID")
		require.Equal(t, res.Data["path"].(string), "foo/")
		require.Equal(t, res.Data["custom_metadata"], customMetadata,
			"read custom_metadata does not match original custom_metadata")
	})

	t.Run("returns empty response for non-existing namespace", func(t *testing.T) {
		req := logical.TestRequest(t, logical.ReadOperation, "namespaces/bar")
		res, err := b.HandleRequest(context.Background(), req)
		require.NoError(t, err)
		require.Empty(t, res, "expected empty response")
	})
}

func TestNamespaceBackend_Patch(t *testing.T) {
	t.Parallel()
	b := testSystemBackend(t)

	t.Run("add metadata keys", func(t *testing.T) {
		testCreateNamespace(t, b, "foo", nil)

		req := logical.TestRequest(t, logical.PatchOperation, "namespaces/foo")
		patch := map[string]string{"abc": "def"}
		req.Data["custom_metadata"] = patch
		res, err := b.HandleRequest(context.Background(), req)
		require.NoError(t, err)
		outputMetadata := res.Data["custom_metadata"].(map[string]string)
		require.Equal(t, outputMetadata, patch, "returned metadata does not match metadata patch")

		req = logical.TestRequest(t, logical.PatchOperation, "namespaces/foo")
		patch = map[string]string{"testing": "hello"}
		req.Data["custom_metadata"] = patch
		res, err = b.HandleRequest(context.Background(), req)
		require.NoError(t, err)
		outputMetadata = res.Data["custom_metadata"].(map[string]string)
		expected := map[string]string{"abc": "def"}
		maps.Copy(expected, patch)
		require.Equal(t, outputMetadata, expected, "returned metadata does not match expected updated metadata")

		req = logical.TestRequest(t, logical.PatchOperation, "namespaces/foo")
		illegalPatch := map[string]interface{}{"illegal": 1337}
		req.Data["custom_metadata"] = illegalPatch
		res, err = b.HandleRequest(context.Background(), req)
		require.ErrorContains(t, err, "custom_metadata values must be strings", "got unwanted error")
		require.Empty(t, res, "patch failure should have empty response")
	})

	t.Run("remove metadata keys", func(t *testing.T) {
		customMetadata := map[string]string{"abc": "def"}
		testCreateNamespace(t, b, "bar", customMetadata)

		req := logical.TestRequest(t, logical.PatchOperation, "namespaces/bar")
		patch := map[string]interface{}{"abc": nil}
		req.Data["custom_metadata"] = patch
		res, err := b.HandleRequest(context.Background(), req)
		require.NoError(t, err)
		outputMetadata := res.Data["custom_metadata"].(map[string]string)
		require.Equal(t, outputMetadata, map[string]string{},
			"expected custom_metadata to be empty after patching out only key")

		req = logical.TestRequest(t, logical.PatchOperation, "namespaces/bar")
		patch = map[string]interface{}{"abc": nil}
		req.Data["custom_metadata"] = patch
		res, err = b.HandleRequest(context.Background(), req)
		require.NoError(t, err)
		outputMetadata = res.Data["custom_metadata"].(map[string]string)
		require.Equal(t, outputMetadata, map[string]string{},
			"expected custom_metadata to stay empty after patching out non-existing key")
	})

	t.Run("add and remove keys in one shot", func(t *testing.T) {
		customMetadata := map[string]string{"abc": "def"}
		testCreateNamespace(t, b, "baz", customMetadata)

		req := logical.TestRequest(t, logical.PatchOperation, "namespaces/baz")
		patch := map[string]interface{}{"abc": nil, "testing": "hello"}
		req.Data["custom_metadata"] = patch
		res, err := b.HandleRequest(context.Background(), req)
		require.NoError(t, err)
		outputMetadata := res.Data["custom_metadata"].(map[string]string)
		require.Equal(t, outputMetadata, map[string]string{"testing": "hello"},
			"expected old key to be removed and new key to be added")
	})
}

func TestNamespaceBackend_Delete(t *testing.T) {
	t.Parallel()
	b := testSystemBackend(t)

	t.Run("delete existing namespace", func(t *testing.T) {
		testCreateNamespace(t, b, "foo", nil)

		req := logical.TestRequest(t, logical.DeleteOperation, "namespaces/foo")
		_, err := b.HandleRequest(context.Background(), req)
		require.NoError(t, err)

		req = logical.TestRequest(t, logical.ReadOperation, "namespaces/foo")
		res, err := b.HandleRequest(context.Background(), req)
		require.NoError(t, err)
		require.Empty(t, res, "expected emtpy response to read after deleting namespace")
	})

	t.Run("delete non-existent namespace", func(t *testing.T) {
		req := logical.TestRequest(t, logical.DeleteOperation, "namespaces/bar")
		_, err := b.HandleRequest(context.Background(), req)
		require.NoError(t, err)
	})
}

func TestNamespaceBackend_List(t *testing.T) {
	b := testSystemBackend(t)

	t.Run("list is empty if root is only namespace", func(t *testing.T) {
		req := logical.TestRequest(t, logical.ListOperation, "namespaces")
		res, err := b.HandleRequest(context.Background(), req)
		require.NoError(t, err)
		require.Equal(t, res.Data, map[string]interface{}{}, "list data has unexpected elements")
	})

	t.Run("list includes non-root namespaces", func(t *testing.T) {
		testCreateNamespace(t, b, "foo", nil)
		testCreateNamespace(t, b, "bar", nil)

		req := logical.TestRequest(t, logical.ListOperation, "namespaces")
		res, err := b.HandleRequest(context.Background(), req)

		require.NoError(t, err)
		require.NotEmpty(t, res.Data["keys"], "keys is empty")
		require.NotEmpty(t, res.Data["key_info"], "key_info is empty")

		keys, ok := res.Data["keys"].([]string)
		require.True(t, ok, "keys is not a list")
		keyInfo, ok := res.Data["key_info"].(map[string]interface{})
		require.True(t, ok, "key_info is not a map")

		require.Equal(t, len(keys), 2, "expected two entries in keys")
		require.Equal(t, len(keyInfo), 2, "expected two entries in key_info")

		for _, path := range keys {
			info, ok := keyInfo[path]
			require.True(t, ok, fmt.Sprintf("key_info does not have path %q which is present in keys", path))
			var ns namespace.Namespace
			require.NoError(t, mapstructure.Decode(info, &ns), "key_info entry is not a namespace")
			require.Equal(t, ns.Path, path, "path in key does not match path in namespace struct")
			require.NotEmpty(t, ns.ID, "namespace ID should not be empty")
			require.NotEqual(t, ns.ID, namespace.RootNamespaceID, "list should not include root namespace")
		}
	})
}

func TestNamespaceBackend_Scan(t *testing.T) {
	// TODO(satoqz): Implement scan once a clear API is available from NamespaceStore.
}
