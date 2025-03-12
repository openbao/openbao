package vault

import (
	"context"
	"testing"

	"github.com/openbao/openbao/helper/namespace"
	"github.com/stretchr/testify/require"
)

func TestNamespaceStore(t *testing.T) {
	t.Parallel()

	c, keys, root := TestCoreUnsealed(t)
	s := c.namespaceStore

	ctx := namespace.RootContext(context.TODO())

	// Initial store should be empty.
	ns, err := s.ListAllNamespaceEntries(ctx, false)
	require.NoError(t, err)
	require.Empty(t, ns)

	// Creating an item should save it, set IDs, and canonicalize path.
	item := &NamespaceEntry{
		Namespace: &namespace.Namespace{
			Path: "ns1",
		},
	}

	err = s.SetNamespace(ctx, item)
	require.NoError(t, err)
	require.NotEmpty(t, item.UUID)
	require.NotEmpty(t, item.Namespace.ID)
	require.Equal(t, item.Namespace.Path, namespace.Canonicalize("ns1"))
	require.Equal(t, item.Namespace.Path, "ns1/")

	itemUUID := item.UUID
	itemAccessor := item.Namespace.ID
	itemPath := item.Namespace.Path

	// We should now have one item.
	ns, err = s.ListAllNamespaceEntries(ctx, false)
	require.NoError(t, err)
	require.NotEmpty(t, ns)
	require.Equal(t, ns[0].UUID, item.UUID)

	// Modifying our copy shouldn't affect anything.
	item.Namespace.CustomMetadata = map[string]string{"openbao": "true"}
	item.Namespace.Path = "modified"
	item.Namespace.ID = "modified"
	item.UUID = "modified"

	fetched, err := s.GetNamespace(ctx, itemUUID)
	require.NoError(t, err)
	require.NotNil(t, fetched)
	require.Equal(t, fetched.UUID, itemUUID)
	require.Equal(t, fetched.Namespace.ID, itemAccessor)
	require.Equal(t, fetched.Namespace.Path, itemPath)
	require.Empty(t, fetched.Namespace.CustomMetadata)

	// Fetching the modified ID should fail.
	fetched, err = s.GetNamespace(ctx, item.UUID)
	require.NoError(t, err)
	require.Nil(t, fetched)

	// Sealing the core and unsealing it should yield the same result.
	err = c.Seal(root)
	require.NoError(t, err)

	for i, key := range keys {
		unseal, err := TestCoreUnseal(c, key)
		require.NoError(t, err)

		if i+1 == len(keys) && !unseal {
			t.Fatal("err: should be unsealed")
		}
	}

	// After sealing and unsealing, the namespace stored in the core is replaced with a new one.
	// however, the s.SetNamespace function is still using the previous namespace.
	s = c.namespaceStore

	// We should still have one item.
	ns, err = s.ListAllNamespaceEntries(ctx, false)
	require.NoError(t, err)
	require.NotEmpty(t, ns)
	require.Equal(t, ns[0].UUID, itemUUID)

	// Delete that item.
	err = s.DeleteNamespace(ctx, itemUUID)
	require.NoError(t, err)

	// Store should be empty.
	ns, err = s.ListAllNamespaceEntries(ctx, false)
	require.NoError(t, err)
	require.Empty(t, ns)

	// Sealing the core and unsealing it should yield the same result.
	err = c.Seal(root)
	require.NoError(t, err)

	for i, key := range keys {
		unseal, err := TestCoreUnseal(c, key)
		require.NoError(t, err)

		if i+1 == len(keys) && !unseal {
			t.Fatal("err: should be unsealed")
		}
	}

	// After sealing and unsealing, the namespace stored in the core is replaced with a new one,
	// however, the s.SetNamespace function is still using the previous namespace.
	s = c.namespaceStore

	ns, err = s.ListAllNamespaceEntries(ctx, false)
	require.NoError(t, err)
	require.Empty(t, ns)

	// Creating a new version of item should yield a new id even though the
	// path is the same.
	item = &NamespaceEntry{
		Namespace: &namespace.Namespace{
			Path: "ns1/",
		},
	}

	err = s.SetNamespace(ctx, item)
	require.NoError(t, err)
	require.NotEmpty(t, item.UUID)
	require.NotEqual(t, item.UUID, itemUUID)
	require.NotEmpty(t, item.Namespace.ID)
	require.NotEqual(t, item.Namespace.ID, itemAccessor)
	require.Equal(t, item.Namespace.Path, namespace.Canonicalize("ns1"))
	require.Equal(t, item.Namespace.Path, "ns1/")
	require.Equal(t, item.Namespace.Path, itemPath)
}

func TestNamespaceHierarchy(t *testing.T) {
	t.Parallel()

	c, _, _ := TestCoreUnsealed(t)
	s := c.namespaceStore

	ctx := namespace.RootContext(context.TODO())

	// Initial store should be empty.
	ns, err := s.ListAllNamespaceEntries(ctx, false)
	require.NoError(t, err)
	require.Empty(t, ns)

	// Creating an item should save it, set IDs, and canonicalize path.
	namespaces := []struct {
		context.Context
		*NamespaceEntry
	}{
		{
			namespace.ContextWithNamespace(ctx, namespace.RootNamespace),
			&NamespaceEntry{Namespace: &namespace.Namespace{Path: "ns1"}},
		},
		{
			namespace.ContextWithNamespace(ctx, namespace.RootNamespace),
			&NamespaceEntry{Namespace: &namespace.Namespace{Path: "ns2"}},
		},
		{
			namespace.ContextWithNamespace(ctx, namespace.RootNamespace),
			&NamespaceEntry{Namespace: &namespace.Namespace{Path: "ns1/ns3"}},
		},
	}

	for idx, ns := range namespaces {
		err := s.SetNamespace(ns.Context, ns.NamespaceEntry)
		require.NoError(t, err)
		require.NotEmpty(t, ns.UUID)
		require.NotEmpty(t, ns.Namespace.ID)
		require.Equal(t, ns.Namespace.Path, namespace.Canonicalize(namespaces[idx].Namespace.Path))
	}

	t.Run("ListNamespaces", func(t *testing.T) {
		t.Run("no root namespace", func(t *testing.T) {
			nsList, err := s.ListAllNamespaces(ctx, false)
			require.NoError(t, err)
			containsRoot := false
			for _, nss := range nsList {
				if (nss.Path == "") || (nss.Path == namespace.RootNamespaceID) {
					containsRoot = true
					break
				}
			}
			require.Falsef(t, containsRoot, "ListAllNamespaces must not contain root namespace")
			require.Equal(t, len(namespaces), len(nsList), "ListAllNamespaces must return all namespaces, excluding root")
		})
		t.Run("with root namespace", func(t *testing.T) {
			nsList, err := s.ListAllNamespaces(ctx, true)
			require.NoError(t, err)
			containsRoot := false
			for _, nss := range nsList {
				if (nss.Path == "") || (nss.Path == namespace.RootNamespaceID) {
					containsRoot = true
					break
				}
			}
			require.Truef(t, containsRoot, "ListAllNamespaces must contain root namespace")
			require.Equal(t, len(namespaces)+1, len(nsList), "ListAllNamespaces must return all namespaces")
		})
		t.Run("list child namespaces", func(t *testing.T) {
			ctx := namespace.ContextWithNamespace(ctx, namespaces[0].Namespace)
			nsList, err := s.ListNamespaces(ctx, false, false)
			require.NoError(t, err)
			for _, nss := range nsList {
				t.Logf("> ID  : %s\n", nss.ID)
				t.Logf("> Path: %s\n", nss.Path)
			}
			require.Equal(t, 1, len(nsList))

			ctx = namespace.ContextWithNamespace(ctx, namespaces[1].Namespace)
			nsList, err = s.ListNamespaces(ctx, false, false)
			require.NoError(t, err)
			require.Equal(t, 0, len(nsList))
		})
	})
}
