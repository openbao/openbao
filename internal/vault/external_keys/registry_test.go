// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package ek

import (
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/v2/internal/command/server"
	"github.com/openbao/openbao/v2/internal/helper/kmsplugin"
	"github.com/openbao/openbao/v2/internal/helper/namespace"
	"github.com/stretchr/testify/require"
)

// newTestRegistry constructs a Registry for testing.
func newTestRegistry(t *testing.T) *Registry {
	logger := hclog.New(hclog.DefaultOptions)

	// This is an empty plugin catalog that only handles builtins.
	plugins, err := kmsplugin.NewCatalog(logger, &server.Config{})
	require.NoError(t, err)

	return NewRegistry(plugins, logger)
}

// TestCache tests that KMS clients are cached between calls and correctly
// removed from cache when invalidated through various means.
func TestCache(t *testing.T) {
	ctx := t.Context()

	r := newTestRegistry(t)
	defer r.Stop(ctx)

	ns1 := &namespace.Namespace{ID: "ns1"}
	ns2 := &namespace.Namespace{ID: "ns2"}

	// This is a bit special but works well for the purpose of this test: We
	// use the same storage or for each namespace. This means that any config
	// we write is immediately mirrored between namespaces, but cache entries
	// should remain separate.
	storage := &logical.InmemStorage{}

	// verify=false, so no cache insert expected.
	require.NoError(t, r.ModifyConfig(
		namespace.ContextWithNamespace(ctx, ns1),
		storage, "test",
		false,
		func(ce *ConfigEntry, exists bool) error {
			ce.Plugin = "transit"
			ce.Values = map[string]any{"token": "dummy"}
			return nil
		},
	))

	require.Empty(t, r.cache)

	touch := func(t *testing.T, ns *namespace.Namespace, verify bool) {
		t.Helper()
		require.NoError(t, r.ModifyConfig(
			namespace.ContextWithNamespace(ctx, ns),
			storage, "test",
			verify,
			func(ce *ConfigEntry, exists bool) error { return nil },
		))
	}

	// Now touch the config again, but verify.
	touch(t, ns1, true)

	// There should be a cache entry for ns1.
	require.Len(t, r.cache, 1)
	require.Len(t, r.cache[ns1.ID], 1)
	require.Len(t, r.cache[ns2.ID], 0)

	// Now also touch it in ns2:
	touch(t, ns2, true)

	// Caches in both namespaces now.
	require.Len(t, r.cache, 2)
	require.Len(t, r.cache[ns1.ID], 1)
	require.Len(t, r.cache[ns2.ID], 1)

	// Clear cache via invalidation:
	require.NoError(t, r.InvalidateConfig(namespace.ContextWithNamespace(ctx, ns1), "test"))
	require.NoError(t, r.InvalidateConfig(namespace.ContextWithNamespace(ctx, ns1), "bogus"))

	// Just ns2 is left.
	require.Len(t, r.cache, 1)
	require.Len(t, r.cache[ns2.ID], 1)

	// Clear cache via namespace removal:
	r.CleanupNamespace(ctx, ns2)

	// All gone:
	require.Empty(t, r.cache)

	// Re-establish cache:
	client1, err := r.GetClient(ctx, storage, ns1, "test")
	require.NoError(t, err)

	// Then fetch it once more:
	client2, err := r.GetClient(ctx, storage, ns1, "test")
	require.NoError(t, err)

	// Should get the same client:
	require.Equal(t, client1, client2)

	// Invalidate and try again:
	touch(t, ns1, false)
	client3, err := r.GetClient(ctx, storage, ns1, "test")
	require.NoError(t, err)
	require.NotEqual(t, client1, client3)
}

// TestGrants tests that a matching grant is required to access a key via
// GetExternalKey.
func TestGrants(t *testing.T) {
	storage := &logical.InmemStorage{}
	ctx := namespace.RootContext(t.Context())

	r := newTestRegistry(t)
	defer r.Stop(ctx)

	// Create a config:
	require.NoError(t, r.ModifyConfig(ctx, storage, "test", false, func(ce *ConfigEntry, exists bool) error {
		ce.Plugin = "transit"
		ce.Values = map[string]any{"token": "dummy"}
		return nil
	}))

	// Create a key with no grants:
	require.NoError(t, r.ModifyKey(ctx, storage, "test", "test", false, func(ke *KeyEntry, exists bool) error {
		ke.Values = map[string]any{"name": "test"}
		return nil
	}))

	var err error

	// In the beginning, there was nothing:
	_, err = r.GetExternalKey(ctx, storage, namespace.RootNamespace, "", "test:test")
	require.Error(t, err)
	_, err = r.GetExternalKey(ctx, storage, namespace.RootNamespace, "foo/", "test:test")
	require.Error(t, err)
	_, err = r.GetExternalKey(ctx, storage, namespace.RootNamespace, "bar/", "test:test")
	require.Error(t, err)

	// Now add a grant on "foo/":
	require.NoError(t, r.ModifyKey(ctx, storage, "test", "test", false, func(ke *KeyEntry, exists bool) error {
		ke.Grants = map[string]struct{}{"foo/": {}}
		return nil
	}))

	// "bar/" still shouldn't have access:
	_, err = r.GetExternalKey(ctx, storage, namespace.RootNamespace, "bar/", "test:test")
	require.Error(t, err)

	// But "foo/" should:
	key, err := r.GetExternalKey(ctx, storage, namespace.RootNamespace, "foo/", "test:test")
	require.NoError(t, err)
	require.NoError(t, key.Close(ctx))
}

// TestParseRef tests that key references are parsed correctly.
func TestParseRef(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		config, key, err := ParseRef("foo:bar")
		require.NoError(t, err)
		require.Equal(t, []string{"foo", "bar"}, []string{config, key})
	})

	bad := []string{
		"",
		":", "::", ":::",
		"foo", ":foo", "foo:",
		"/:/", "foo/bar:foo/bar",
	}

	t.Run("bad", func(t *testing.T) {
		for _, ref := range bad {
			_, _, err := ParseRef(ref)
			require.Error(t, err)
		}
	})
}
