// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"maps"
	"path"
	"testing"
	"time"

	"github.com/go-viper/mapstructure/v2"
	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
)

func testCreateNamespace(t *testing.T, ctx context.Context, b logical.Backend, name string, customMetadata map[string]string) *namespace.Namespace {
	t.Helper()
	req := logical.TestRequest(t, logical.UpdateOperation, path.Join("namespaces", name))
	if customMetadata != nil {
		req.Data["custom_metadata"] = customMetadata
	}
	res, err := b.HandleRequest(ctx, req)
	require.NoError(t, err)

	return &namespace.Namespace{
		ID:             res.Data["id"].(string),
		UUID:           res.Data["uuid"].(string),
		Path:           res.Data["path"].(string),
		Tainted:        res.Data["tainted"].(bool),
		Locked:         res.Data["locked"].(bool),
		CustomMetadata: res.Data["custom_metadata"].(map[string]string),
	}
}

func TestNamespaceBackend_Set(t *testing.T) {
	t.Parallel()
	b := testSystemBackend(t)
	rootCtx := namespace.RootContext(context.Background())

	t.Run("create namespace", func(t *testing.T) {
		customMetadata := map[string]string{"abc": "def"}
		req := logical.TestRequest(t, logical.UpdateOperation, "namespaces/foo")
		req.Data["custom_metadata"] = customMetadata
		res, err := b.HandleRequest(rootCtx, req)
		require.NoError(t, err)

		require.NotEmpty(t, res.Data["uuid"].(string), "namespace has no UUID")
		require.NotEmpty(t, res.Data["id"].(string), "namespace has no ID")
		require.Equal(t, res.Data["path"].(string), "foo/")
		require.Equal(t, res.Data["tainted"].(bool), false)
		require.Equal(t, res.Data["locked"].(bool), false)
		require.Equal(t, res.Data["custom_metadata"], customMetadata,
			"read custom_metadata does not match original custom_metadata")
	})

	t.Run("create namespace name validation", func(t *testing.T) {
		nsTeam1 := testCreateNamespace(t, rootCtx, b, "team_1", map[string]string{})
		tcases := []struct {
			path      string
			wantPath  string
			namespace *namespace.Namespace
			wantError bool
		}{
			{
				// this works as ultimately extra '/' get stripped
				path:     "test////",
				wantPath: "test/",
			},
			{
				path:      "test/child",
				wantError: true,
			},
			{
				path:      "root",
				wantError: true,
			},
			{
				path:      "cubbyhole",
				wantError: true,
			},
			{
				path:      "cubbyhole",
				wantError: true,
			},
			{
				namespace: nsTeam1,
				path:      "team_1.1",
				wantPath:  "team_1/team_1.1/",
			},
			{
				namespace: nsTeam1,
				path:      "cubbyhole",
				wantError: true,
			},
			{
				namespace: nsTeam1,
				path:      "team_1 1",
				wantError: true,
			},
		}

		for _, tc := range tcases {
			ctx := namespace.RootContext(context.Background())
			if tc.namespace != nil {
				ctx = namespace.ContextWithNamespace(ctx, tc.namespace)
			}

			req := logical.TestRequest(t, logical.UpdateOperation, "namespaces/"+tc.path)
			res, err := b.HandleRequest(ctx, req)

			if tc.wantError {
				require.Error(t, err)
			} else {
				require.Equal(t, tc.wantPath, res.Data["path"].(string))
				require.Equal(t, res.Data["tainted"].(bool), false)
				require.Equal(t, res.Data["locked"].(bool), false)
				require.NotEmpty(t, res.Data["uuid"].(string), "namespace has no UUID")
				require.NotEmpty(t, res.Data["id"].(string), "namespace has no ID")
			}
		}
	})

	t.Run("update namespace metadata", func(t *testing.T) {
		customMetadata := map[string]string{"abc": "def"}
		testCreateNamespace(t, rootCtx, b, "bar", customMetadata)

		newMetadata := map[string]string{"testing": "hello"}
		req := logical.TestRequest(t, logical.UpdateOperation, "namespaces/foo")
		req.Data["custom_metadata"] = newMetadata
		res, err := b.HandleRequest(rootCtx, req)
		require.NoError(t, err)

		require.NotEmpty(t, res.Data["uuid"].(string), "namespace has no UUID")
		require.NotEmpty(t, res.Data["id"].(string), "namespace has no ID")
		require.Equal(t, res.Data["path"].(string), "foo/")
		require.Equal(t, res.Data["tainted"].(bool), false)
		require.Equal(t, res.Data["locked"].(bool), false)
		require.Equal(t, res.Data["custom_metadata"], newMetadata,
			"read custom_metadata does not match original custom_metadata")
	})
}

func TestNamespaceBackend_Read(t *testing.T) {
	t.Parallel()
	b := testSystemBackend(t)
	rootCtx := namespace.RootContext(context.Background())

	t.Run("reads existing namespace as expected", func(t *testing.T) {
		customMetadata := map[string]string{"abc": "def"}
		testCreateNamespace(t, rootCtx, b, "foo", customMetadata)

		req := logical.TestRequest(t, logical.ReadOperation, "namespaces/foo")
		res, err := b.HandleRequest(rootCtx, req)
		require.NoError(t, err)

		require.NotEmpty(t, res.Data["uuid"].(string), "namespace has no UUID")
		require.NotEmpty(t, res.Data["id"].(string), "namespace has no ID")
		require.Equal(t, res.Data["path"].(string), "foo/")
		require.Equal(t, res.Data["tainted"].(bool), false)
		require.Equal(t, res.Data["locked"].(bool), false)
		require.Equal(t, res.Data["custom_metadata"], customMetadata,
			"read custom_metadata does not match original custom_metadata")
	})

	t.Run("reads nested namespace via context and path", func(t *testing.T) {
		customMetadata := map[string]string{"abc": "def"}
		fooNs := testCreateNamespace(t, rootCtx, b, "foo", nil)
		nestedCtx := namespace.ContextWithNamespace(rootCtx, fooNs)
		testCreateNamespace(t, nestedCtx, b, "bar", customMetadata)

		req := logical.TestRequest(t, logical.ReadOperation, "namespaces/bar")
		res, err := b.HandleRequest(nestedCtx, req)
		require.NoError(t, err)

		require.NotEmpty(t, res.Data["uuid"].(string), "namespace has no UUID")
		require.NotEmpty(t, res.Data["id"].(string), "namespace has no ID")
		require.Equal(t, res.Data["path"].(string), "foo/bar/")
		require.Equal(t, res.Data["tainted"].(bool), false)
		require.Equal(t, res.Data["locked"].(bool), false)
		require.Equal(t, res.Data["custom_metadata"], customMetadata,
			"read custom_metadata does not match original custom_metadata")
	})

	t.Run("returns empty response for non-existing namespace", func(t *testing.T) {
		req := logical.TestRequest(t, logical.ReadOperation, "namespaces/bar")
		res, err := b.HandleRequest(rootCtx, req)
		require.NoError(t, err)
		require.Empty(t, res, "expected empty response")
	})
}

func TestNamespaceBackend_Patch(t *testing.T) {
	t.Parallel()
	b := testSystemBackend(t)
	rootCtx := namespace.RootContext(context.Background())

	t.Run("add metadata keys", func(t *testing.T) {
		testCreateNamespace(t, rootCtx, b, "foo", nil)

		req := logical.TestRequest(t, logical.PatchOperation, "namespaces/foo")
		patch := map[string]string{"abc": "def"}
		req.Data["custom_metadata"] = patch
		res, err := b.HandleRequest(rootCtx, req)
		require.NoError(t, err)
		outputMetadata := res.Data["custom_metadata"].(map[string]string)
		require.Equal(t, outputMetadata, patch, "returned metadata does not match metadata patch")

		req = logical.TestRequest(t, logical.PatchOperation, "namespaces/foo")
		patch = map[string]string{"testing": "hello"}
		req.Data["custom_metadata"] = patch
		res, err = b.HandleRequest(rootCtx, req)
		require.NoError(t, err)
		outputMetadata = res.Data["custom_metadata"].(map[string]string)
		expected := map[string]string{"abc": "def"}
		maps.Copy(expected, patch)
		require.Equal(t, outputMetadata, expected, "returned metadata does not match expected updated metadata")

		req = logical.TestRequest(t, logical.PatchOperation, "namespaces/foo")
		illegalPatch := map[string]interface{}{"illegal": 1337}
		req.Data["custom_metadata"] = illegalPatch
		res, err = b.HandleRequest(rootCtx, req)
		require.ErrorContains(t, err, "custom_metadata values must be strings", "got unwanted error")
		require.Empty(t, res, "patch failure should have empty response")
	})

	t.Run("remove metadata keys", func(t *testing.T) {
		customMetadata := map[string]string{"abc": "def"}
		testCreateNamespace(t, rootCtx, b, "bar", customMetadata)

		req := logical.TestRequest(t, logical.PatchOperation, "namespaces/bar")
		patch := map[string]interface{}{"abc": nil}
		req.Data["custom_metadata"] = patch
		res, err := b.HandleRequest(rootCtx, req)
		require.NoError(t, err)
		outputMetadata := res.Data["custom_metadata"].(map[string]string)
		require.Equal(t, outputMetadata, map[string]string{},
			"expected custom_metadata to be empty after patching out only key")

		req = logical.TestRequest(t, logical.PatchOperation, "namespaces/bar")
		patch = map[string]interface{}{"abc": nil}
		req.Data["custom_metadata"] = patch
		res, err = b.HandleRequest(rootCtx, req)
		require.NoError(t, err)
		outputMetadata = res.Data["custom_metadata"].(map[string]string)
		require.Equal(t, outputMetadata, map[string]string{},
			"expected custom_metadata to stay empty after patching out non-existing key")
	})

	t.Run("add and remove keys in one shot", func(t *testing.T) {
		customMetadata := map[string]string{"abc": "def"}
		testCreateNamespace(t, rootCtx, b, "baz", customMetadata)

		req := logical.TestRequest(t, logical.PatchOperation, "namespaces/baz")
		patch := map[string]interface{}{"abc": nil, "testing": "hello"}
		req.Data["custom_metadata"] = patch
		res, err := b.HandleRequest(rootCtx, req)
		require.NoError(t, err)
		outputMetadata := res.Data["custom_metadata"].(map[string]string)
		require.Equal(t, outputMetadata, map[string]string{"testing": "hello"},
			"expected old key to be removed and new key to be added")
	})

	t.Run("patch nested namespace", func(t *testing.T) {
		fooNs := testCreateNamespace(t, rootCtx, b, "foo", nil)
		nestedCtx := namespace.ContextWithNamespace(rootCtx, fooNs)
		testCreateNamespace(t, nestedCtx, b, "bar", map[string]string{"abc": "def"})

		// ctx ns = /, path = foo/bar
		req := logical.TestRequest(t, logical.PatchOperation, "namespaces/foo/bar")
		patch := map[string]string{"abc": "fed"}
		req.Data["custom_metadata"] = patch
		res, err := b.HandleRequest(rootCtx, req)
		require.Error(t, err)
		require.Empty(t, res)

		// ctx ns = foo, path = bar
		req = logical.TestRequest(t, logical.PatchOperation, "namespaces/bar")
		patch = map[string]string{"testing": "hello"}
		req.Data["custom_metadata"] = patch
		res, err = b.HandleRequest(nestedCtx, req)
		require.NoError(t, err)
		outputMetadata := res.Data["custom_metadata"].(map[string]string)
		expected := map[string]string{"abc": "def"}
		maps.Copy(expected, patch)
		require.Equal(t, outputMetadata, expected, "returned metadata does not match expected updated metadata")

		// ctx ns = foo, path = bar
		req = logical.TestRequest(t, logical.PatchOperation, "namespaces/bar")
		illegalPatch := map[string]interface{}{"illegal": 1337}
		req.Data["custom_metadata"] = illegalPatch
		res, err = b.HandleRequest(nestedCtx, req)
		require.ErrorContains(t, err, "custom_metadata values must be strings", "got unwanted error")
		require.Empty(t, res, "patch failure should have empty response")
	})
}

func TestNamespaceBackend_Delete(t *testing.T) {
	t.Parallel()
	b := testSystemBackend(t)
	rootCtx := namespace.RootContext(context.Background())

	t.Run("delete namespace", func(t *testing.T) {
		testCreateNamespace(t, rootCtx, b, "foo", nil)

		maxRetries := 50
		for range maxRetries {
			req := logical.TestRequest(t, logical.DeleteOperation, "namespaces/foo")
			res, err := b.HandleRequest(rootCtx, req)
			require.NoError(t, err)
			val, ok := res.Data["status"]
			if ok {
				require.Equal(t, "in-progress", val)
				time.Sleep(1 * time.Millisecond)
				continue
			}
			require.Empty(t, res.Data, "data should be empty when deleting already deleted namespace")
			break
		}
	})

	t.Run("delete nested namespace", func(t *testing.T) {
		fooNs := testCreateNamespace(t, rootCtx, b, "foobar", nil)
		nestedCtx := namespace.ContextWithNamespace(rootCtx, fooNs)
		testCreateNamespace(t, nestedCtx, b, "bar", nil)
		testCreateNamespace(t, nestedCtx, b, "baz", nil)

		// three namespaces: "foobar", "foobar/bar" and "foobar/baz"
		req := logical.TestRequest(t, logical.DeleteOperation, "namespaces/foobar")
		res, err := b.HandleRequest(rootCtx, req)
		// fails as foobar contains child namespaces
		require.Error(t, err)

		req = logical.TestRequest(t, logical.DeleteOperation, "namespaces/baz")
		res, err = b.HandleRequest(nestedCtx, req)
		require.NoError(t, err)
		require.Equal(t, "in-progress", res.Data["status"])

		maxRetries := 50
		for range maxRetries {
			req = logical.TestRequest(t, logical.ReadOperation, "namespaces/baz")
			res, err = b.HandleRequest(nestedCtx, req)
			require.NoError(t, err)

			if res != nil {
				val, ok := res.Data["tainted"].(bool)
				if ok {
					require.Equal(t, true, val)
					time.Sleep(1 * time.Millisecond)
					continue
				}
			}

			require.Empty(t, res, "expected empty response")
			break
		}

		req = logical.TestRequest(t, logical.ReadOperation, "namespaces/foobar")
		res, err = b.HandleRequest(rootCtx, req)
		require.NoError(t, err)
		require.NotEmpty(t, res, "expected non-empty response")
	})

	t.Run("delete non-existent namespace", func(t *testing.T) {
		req := logical.TestRequest(t, logical.DeleteOperation, "namespaces/does-not-exist")
		_, err := b.HandleRequest(rootCtx, req)
		require.NoError(t, err)
	})
}

func TestNamespaceBackend_List(t *testing.T) {
	b := testSystemBackend(t)
	rootCtx := namespace.RootContext(context.Background())

	t.Run("list is empty if root is only namespace", func(t *testing.T) {
		req := logical.TestRequest(t, logical.ListOperation, "namespaces")
		res, err := b.HandleRequest(rootCtx, req)
		require.NoError(t, err)
		require.Equal(t, res.Data, map[string]interface{}{}, "list data has unexpected elements")
	})

	t.Run("list includes non-root namespaces", func(t *testing.T) {
		testCreateNamespace(t, rootCtx, b, "foo", nil)
		testCreateNamespace(t, rootCtx, b, "bar", nil)

		req := logical.TestRequest(t, logical.ListOperation, "namespaces")
		res, err := b.HandleRequest(rootCtx, req)

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
			require.False(t, ns.Tainted, "tainted in key should be false")
			require.False(t, ns.Locked, "locked in key should be false")
			require.NotEmpty(t, ns.ID, "namespace ID should not be empty")
			require.NotEqual(t, ns.ID, namespace.RootNamespaceID, "list should not include root namespace")
		}
	})

	t.Run("list only includes one level of namespaces", func(t *testing.T) {
		fooNs := testCreateNamespace(t, rootCtx, b, "foo", nil)
		nestedCtx := namespace.ContextWithNamespace(rootCtx, fooNs)
		testCreateNamespace(t, rootCtx, b, "bar", nil)
		testCreateNamespace(t, nestedCtx, b, "baz", nil)

		req := logical.TestRequest(t, logical.ListOperation, "namespaces")
		res, err := b.HandleRequest(rootCtx, req)

		require.NoError(t, err)
		require.NotEmpty(t, res.Data["keys"], "keys is empty")
		require.NotEmpty(t, res.Data["key_info"], "key_info is empty")

		keys, ok := res.Data["keys"].([]string)
		require.True(t, ok, "keys is not a list")
		keyInfo, ok := res.Data["key_info"].(map[string]interface{})
		require.True(t, ok, "key_info is not a map")

		require.Equal(t, 2, len(keys), "expected two entries in keys")
		require.Equal(t, 2, len(keyInfo), "expected two entries in key_info")
		require.Subset(t, keys, []string{"foo/", "bar/"})

		for _, path := range keys {
			info, ok := keyInfo[path]
			require.True(t, ok, fmt.Sprintf("key_info does not have path %q which is present in keys", path))
			var ns namespace.Namespace
			require.NoError(t, mapstructure.Decode(info, &ns), "key_info entry is not a namespace")
			require.Equal(t, ns.Path, path, "path in key does not match path in namespace struct")
			require.False(t, ns.Tainted, "tainted in key should be false")
			require.False(t, ns.Locked, "locked in key should be false")
			require.NotEmpty(t, ns.ID, "namespace ID should not be empty")
			require.NotEqual(t, ns.ID, namespace.RootNamespaceID, "list should not include root namespace")
		}
	})

	t.Run("list nested namespaces", func(t *testing.T) {
		testCreateNamespace(t, rootCtx, b, "unrelated", nil)
		fooNs := testCreateNamespace(t, rootCtx, b, "foo", nil)
		nestedCtx := namespace.ContextWithNamespace(rootCtx, fooNs)
		testCreateNamespace(t, nestedCtx, b, "bar", nil)
		testCreateNamespace(t, nestedCtx, b, "baz", nil)

		req := logical.TestRequest(t, logical.ListOperation, "namespaces")
		res, err := b.HandleRequest(nestedCtx, req)

		require.NoError(t, err)
		require.NotEmpty(t, res.Data["keys"], "keys is empty")
		require.NotEmpty(t, res.Data["key_info"], "key_info is empty")

		keys, ok := res.Data["keys"].([]string)
		require.True(t, ok, "keys is not a list")
		keyInfo, ok := res.Data["key_info"].(map[string]interface{})
		require.True(t, ok, "key_info is not a map")

		require.Equal(t, 2, len(keys), "expected two entries in keys")
		require.Equal(t, 2, len(keyInfo), "expected two entries in key_info")

		t.Log(res.Data)
		for _, path := range keys {
			info, ok := keyInfo[path]
			require.True(t, ok, fmt.Sprintf("key_info does not have path %q which is present in keys", path))
			var ns namespace.Namespace
			require.NoError(t, mapstructure.Decode(info, &ns), "key_info entry is not a namespace")
			require.False(t, ns.Tainted, "tainted in key should be false")
			require.False(t, ns.Locked, "locked in key should be false")
			require.NotEmpty(t, ns.ID, "namespace ID should not be empty")
			require.NotEqual(t, ns.ID, namespace.RootNamespaceID, "list should not include root namespace")
			require.Subset(t, []string{"bar/", "baz/"}, []string{path})
		}
	})
}

func TestNamespaceBackend_Scan(t *testing.T) {
	b := testSystemBackend(t)
	rootCtx := namespace.RootContext(context.Background())

	t.Run("scan is empty if root is only namespace", func(t *testing.T) {
		req := logical.TestRequest(t, logical.ScanOperation, "namespaces")
		res, err := b.HandleRequest(rootCtx, req)
		require.NoError(t, err)
		require.Equal(t, res.Data, map[string]interface{}{}, "scan data has unexpected elements")
	})

	t.Run("scan includes non-root namespaces", func(t *testing.T) {
		testCreateNamespace(t, rootCtx, b, "foo", nil)
		testCreateNamespace(t, rootCtx, b, "bar", nil)

		req := logical.TestRequest(t, logical.ScanOperation, "namespaces")
		res, err := b.HandleRequest(rootCtx, req)

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
			require.False(t, ns.Tainted, "tainted in key should be false")
			require.False(t, ns.Locked, "locked in key should be false")
			require.NotEmpty(t, ns.ID, "namespace ID should not be empty")
			require.NotEqual(t, ns.ID, namespace.RootNamespaceID, "list should not include root namespace")
		}
	})

	t.Run("scan includes multiple levels of namespaces", func(t *testing.T) {
		fooNs := testCreateNamespace(t, rootCtx, b, "foo", nil)
		nestedCtx := namespace.ContextWithNamespace(rootCtx, fooNs)
		testCreateNamespace(t, rootCtx, b, "bar", nil)
		testCreateNamespace(t, nestedCtx, b, "baz", nil)

		req := logical.TestRequest(t, logical.ScanOperation, "namespaces")
		res, err := b.HandleRequest(rootCtx, req)

		require.NoError(t, err)
		require.NotEmpty(t, res.Data["keys"], "keys is empty")
		require.NotEmpty(t, res.Data["key_info"], "key_info is empty")

		keys, ok := res.Data["keys"].([]string)
		require.True(t, ok, "keys is not a list")
		keyInfo, ok := res.Data["key_info"].(map[string]interface{})
		require.True(t, ok, "key_info is not a map")

		require.Equal(t, 3, len(keys), "expected two entries in keys")
		require.Equal(t, 3, len(keyInfo), "expected two entries in key_info")
		require.Subset(t, keys, []string{"foo/", "bar/", "foo/baz/"})

		for _, path := range keys {
			info, ok := keyInfo[path]
			require.True(t, ok, fmt.Sprintf("key_info does not have path %q which is present in keys", path))
			var ns namespace.Namespace
			require.NoError(t, mapstructure.Decode(info, &ns), "key_info entry is not a namespace")
			require.Equal(t, ns.Path, path, "path in key does not match path in namespace struct")
			require.False(t, ns.Tainted, "tainted in key should be false")
			require.False(t, ns.Locked, "locked in key should be false")
			require.NotEmpty(t, ns.ID, "namespace ID should not be empty")
			require.NotEqual(t, ns.ID, namespace.RootNamespaceID, "list should not include root namespace")
		}
	})

	t.Run("scan nested namespaces", func(t *testing.T) {
		testCreateNamespace(t, rootCtx, b, "unrelated", nil)
		fooNs := testCreateNamespace(t, rootCtx, b, "foo", nil)
		fooCtx := namespace.ContextWithNamespace(rootCtx, fooNs)
		bazNs := testCreateNamespace(t, fooCtx, b, "baz", nil)
		bazCtx := namespace.ContextWithNamespace(rootCtx, bazNs)
		testCreateNamespace(t, bazCtx, b, "bar", nil)

		req := logical.TestRequest(t, logical.ScanOperation, "namespaces")
		res, err := b.HandleRequest(fooCtx, req)

		require.NoError(t, err)
		require.NotEmpty(t, res.Data["keys"], "keys is empty")
		require.NotEmpty(t, res.Data["key_info"], "key_info is empty")

		keys, ok := res.Data["keys"].([]string)
		require.True(t, ok, "keys is not a list")
		keyInfo, ok := res.Data["key_info"].(map[string]interface{})
		require.True(t, ok, "key_info is not a map")

		require.Equal(t, 2, len(keys), "expected two entries in keys: %v", keys)
		require.Equal(t, 2, len(keyInfo), "expected two entries in key_info")

		for _, path := range keys {
			info, ok := keyInfo[path]
			require.True(t, ok, fmt.Sprintf("key_info does not have path %q which is present in keys", path))
			var ns namespace.Namespace
			require.NoError(t, mapstructure.Decode(info, &ns), "key_info entry is not a namespace")
			require.Equal(t, ns.Path, info.(map[string]any)["path"], "path in key does not match path in info struct")
			require.False(t, ns.Tainted, "tainted in key should be false")
			require.False(t, ns.Locked, "locked in key should be false")
			require.NotEmpty(t, ns.ID, "namespace ID should not be empty")
			require.NotEqual(t, ns.ID, namespace.RootNamespaceID, "list should not include root namespace")
			require.Subset(t, []string{"baz/", "baz/bar/"}, []string{path})
		}
	})
}

// TestNamespaceBackend_Lock tests the Lock namespace operation on logical request level
func TestNamespaceBackend_Lock(t *testing.T) {
	b := testSystemBackend(t)
	rootCtx := namespace.RootContext(context.Background())

	t.Run("cannot lock nonexistent, root or already locked namespaces", func(t *testing.T) {
		testNamespace := testCreateNamespace(t, rootCtx, b, "test", nil)

		req := logical.TestRequest(t, logical.UpdateOperation, "namespaces/api-lock/lock/idontexist")
		res, err := b.HandleRequest(rootCtx, req)
		require.Error(t, err)
		require.Equal(t, "requested namespace does not exist", res.Data["error"])

		req = logical.TestRequest(t, logical.UpdateOperation, "namespaces/api-lock/lock")
		res, err = b.HandleRequest(rootCtx, req)
		require.Error(t, err)
		require.Equal(t, "root namespace cannot be locked/unlocked", res.Data["error"])

		req = logical.TestRequest(t, logical.UpdateOperation, "namespaces/api-lock/lock/test")
		res, err = b.HandleRequest(rootCtx, req)
		require.NoError(t, err)
		require.NotEmpty(t, res.Data["unlock_key"], "unlock_key is missing")

		req = logical.TestRequest(t, logical.UpdateOperation, "namespaces/api-lock/lock/test")
		res, err = b.HandleRequest(rootCtx, req)
		require.Error(t, err)
		require.Equal(t, fmt.Sprintf("cannot lock namespace %q: is already locked", testNamespace.Path), res.Data["error"])
	})

	t.Run("cannot lock child namespace when ancestor is locked", func(t *testing.T) {
		nsCompanyA := testCreateNamespace(t, rootCtx, b, "company_a", nil)
		companyACtx := namespace.ContextWithNamespace(rootCtx, nsCompanyA)
		testCreateNamespace(t, companyACtx, b, "team_a", nil)

		req := logical.TestRequest(t, logical.UpdateOperation, "namespaces/api-lock/lock/company_a")
		res, err := b.HandleRequest(rootCtx, req)
		require.NoError(t, err)
		require.NotEmpty(t, res.Data["unlock_key"], "unlock_key is missing")

		req = logical.TestRequest(t, logical.UpdateOperation, "namespaces/api-lock/lock/company_a/team_a")
		res, err = b.HandleRequest(rootCtx, req)
		require.Error(t, err)
		require.Equal(t, fmt.Sprintf("cannot lock namespace %q: ancestor namespace %q is already locked", "company_a/team_a/", "company_a/"), res.Data["error"])
	})

	t.Run("can lock parent namespace when child is locked", func(t *testing.T) {
		nsCompanyB := testCreateNamespace(t, rootCtx, b, "company_b", nil)
		companyBCtx := namespace.ContextWithNamespace(rootCtx, nsCompanyB)
		testCreateNamespace(t, companyBCtx, b, "team_b", nil)

		req := logical.TestRequest(t, logical.UpdateOperation, "namespaces/api-lock/lock/company_b/team_b")
		res, err := b.HandleRequest(rootCtx, req)
		require.NoError(t, err)
		require.NotEmpty(t, res.Data["unlock_key"], "unlock_key is missing")

		req = logical.TestRequest(t, logical.UpdateOperation, "namespaces/api-lock/lock/company_b")
		res, err = b.HandleRequest(rootCtx, req)
		require.NoError(t, err)
		require.NotEmpty(t, res.Data["unlock_key"], "unlock_key is missing")
	})

	t.Run("locked namespace, and its children do not accept any requests", func(t *testing.T) {
		company := testCreateNamespace(t, rootCtx, b, "company", nil)
		companyCtx := namespace.ContextWithNamespace(rootCtx, company)
		team := testCreateNamespace(t, companyCtx, b, "team", nil)
		teamCtx := namespace.ContextWithNamespace(rootCtx, team)

		req := logical.TestRequest(t, logical.UpdateOperation, "namespaces/api-lock/lock/company")
		res, err := b.HandleRequest(rootCtx, req)
		require.NoError(t, err)
		require.NotEmpty(t, res.Data["unlock_key"], "unlock_key is missing")

		req = logical.TestRequest(t, logical.CreateOperation, "auth/token/create")
		res, err = b.HandleRequest(companyCtx, req)
		require.Error(t, err)
		require.Empty(t, res, "response is not empty")

		req = logical.TestRequest(t, logical.CreateOperation, "auth/token/create")
		res, err = b.HandleRequest(teamCtx, req)
		require.Error(t, err)
		require.Empty(t, res, "response is not empty")

		req = logical.TestRequest(t, logical.ReadOperation, "cubbyhole/foo")
		res, err = b.HandleRequest(companyCtx, req)
		require.Error(t, err)
		require.Empty(t, res, "response is not empty")

		req = logical.TestRequest(t, logical.ReadOperation, "cubbyhole/foo")
		res, err = b.HandleRequest(teamCtx, req)
		require.Error(t, err)
		require.Empty(t, res, "response is not empty")
	})
}

// TestNamespaceBackend_Unlock tests the Unlock namespace operation on logical request level
func TestNamespaceBackend_Unlock(t *testing.T) {
	core, _, rootToken := TestCoreUnsealed(t)
	b := core.systemBackend
	rootCtx := namespace.RootContext(context.Background())

	t.Run("cannot unlock namespace with missing request details", func(t *testing.T) {
		testNS := testCreateNamespace(t, rootCtx, b, "test", nil)

		// invalid token
		req := logical.TestRequest(t, logical.UpdateOperation, "namespaces/api-lock/unlock/test")
		res, err := b.HandleRequest(rootCtx, req)
		require.Error(t, err)
		require.Empty(t, res, "response is not empty")

		// empty unlock key
		req = logical.TestRequest(t, logical.UpdateOperation, "namespaces/api-lock/unlock/test")
		req.ClientToken = "token"
		res, err = b.HandleRequest(rootCtx, req)
		require.ErrorContains(t, err, "provided empty key")
		require.Empty(t, res, "response is not empty")

		// namespace doesn't exist
		req = logical.TestRequest(t, logical.UpdateOperation, "namespaces/api-lock/unlock/nonexistent")
		req.Data["unlock_key"] = "key"
		req.ClientToken = "token"
		res, err = b.HandleRequest(rootCtx, req)
		require.Error(t, err)
		require.Equal(t, "requested namespace does not exist", res.Data["error"])

		// namespace not locked
		req = logical.TestRequest(t, logical.UpdateOperation, "namespaces/api-lock/unlock/test")
		req.Data["unlock_key"] = "key"
		req.ClientToken = "token"
		res, err = b.HandleRequest(rootCtx, req)
		require.Error(t, err)
		require.Equal(t, fmt.Sprintf("namespace %q is not locked", testNS.Path), res.Data["error"])
	})

	t.Run("cannot unlock namespace with locked ancestor", func(t *testing.T) {
		parentNS := testCreateNamespace(t, rootCtx, b, "parent", nil)
		parentNSCtx := namespace.ContextWithNamespace(rootCtx, parentNS)
		childNS := testCreateNamespace(t, parentNSCtx, b, "child", nil)

		req := logical.TestRequest(t, logical.UpdateOperation, "namespaces/api-lock/lock/parent/child")
		_, err := b.HandleRequest(rootCtx, req)
		require.NoError(t, err)

		req = logical.TestRequest(t, logical.UpdateOperation, "namespaces/api-lock/lock/parent")
		_, err = b.HandleRequest(rootCtx, req)
		require.NoError(t, err)

		req = logical.TestRequest(t, logical.UpdateOperation, "namespaces/api-lock/unlock/parent/child")
		req.Data["unlock_key"] = "placeholder"
		req.ClientToken = "token"
		res, err := b.HandleRequest(rootCtx, req)
		require.Error(t, err)
		require.Equal(t, fmt.Sprintf("cannot unlock %q with namespace %q being locked", childNS.Path, parentNS.Path), res.Data["error"])
	})

	t.Run("namespace can be unlocked with unlock key", func(t *testing.T) {
		companyA := testCreateNamespace(t, rootCtx, b, "company_a", nil)
		companyACtx := namespace.ContextWithNamespace(rootCtx, companyA)
		testCreateNamespace(t, companyACtx, b, "team_a", nil)

		req := logical.TestRequest(t, logical.UpdateOperation, "namespaces/api-lock/lock/company_a/team_a")
		res, err := b.HandleRequest(rootCtx, req)
		require.NoError(t, err)
		teamALock := res.Data["unlock_key"].(string)

		req = logical.TestRequest(t, logical.UpdateOperation, "namespaces/api-lock/lock/company_a")
		res, err = b.HandleRequest(rootCtx, req)
		require.NoError(t, err)
		companyALock := res.Data["unlock_key"].(string)

		req = logical.TestRequest(t, logical.UpdateOperation, "namespaces/api-lock/unlock/company_a")
		req.Data["unlock_key"] = companyALock
		req.ClientToken = "team_a"
		res, err = b.HandleRequest(rootCtx, req)
		require.NoError(t, err)
		require.Empty(t, res)

		req = logical.TestRequest(t, logical.UpdateOperation, "namespaces/api-lock/unlock/company_a/team_a")
		req.Data["unlock_key"] = teamALock
		req.ClientToken = "team_a"
		res, err = b.HandleRequest(rootCtx, req)
		require.NoError(t, err)
		require.Empty(t, res)
	})

	t.Run("namespace can be unlocked by root", func(t *testing.T) {
		companyB := testCreateNamespace(t, rootCtx, b, "company_b", nil)
		companyBCtx := namespace.ContextWithNamespace(rootCtx, companyB)
		testCreateNamespace(t, companyBCtx, b, "team_b", nil)

		req := logical.TestRequest(t, logical.UpdateOperation, "namespaces/api-lock/lock/company_b/team_b")
		_, err := b.HandleRequest(rootCtx, req)
		require.NoError(t, err)

		req = logical.TestRequest(t, logical.UpdateOperation, "namespaces/api-lock/lock/company_b")
		_, err = b.HandleRequest(rootCtx, req)
		require.NoError(t, err)

		// root can unlock any namespace without providing the unlock key
		req = logical.TestRequest(t, logical.UpdateOperation, "namespaces/api-lock/unlock/company_b")
		req.ClientToken = rootToken
		res, err := b.HandleRequest(rootCtx, req)
		require.NoError(t, err)
		require.Equal(t, "Namespace unlocked using sudo capabilities", res.Warnings[0])

		req = logical.TestRequest(t, logical.UpdateOperation, "namespaces/api-lock/unlock/company_b/team_b")
		req.ClientToken = rootToken
		res, err = b.HandleRequest(rootCtx, req)
		require.NoError(t, err)
		require.Equal(t, "Namespace unlocked using sudo capabilities", res.Warnings[0])
	})
}
