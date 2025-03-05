package vault

import (
	"context"
	"math/rand"
	"strconv"
	"testing"

	"github.com/openbao/openbao/helper/benchhelpers"
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

func randomNamespace(ns *NamespaceStore) *NamespaceEntry {
	// make use of random map iteration order
	for _, item := range ns.namespacesByUUID {
		return item
	}
	return nil
}

func BenchmarkNamespaceStore(b *testing.B) {
	c, _, _ := TestCoreUnsealed(benchhelpers.TBtoT(b))
	s := c.namespaceStore

	ctx := namespace.RootContext(context.Background())

	n := 1_000

	for i := range n {
		parent := randomNamespace(s)
		ctx := namespace.ContextWithNamespace(ctx, parent.Namespace)
		item := &NamespaceEntry{
			Namespace: &namespace.Namespace{
				Path: parent.Namespace.Path + "ns" + strconv.Itoa(i) + "/",
			},
		}
		s.SetNamespace(ctx, item)
	}

	require.Equal(b, n+1, len(s.namespaces))

	b.Run("GetNamespace", func(b *testing.B) {
		n := len(s.namespaces)
		for b.Loop() {
			idx := rand.Intn(n)
			uuid := s.namespaces[idx].UUID
			s.GetNamespace(ctx, uuid)
		}
	})

	b.Run("GetNamespaceByAccessor", func(b *testing.B) {
		n := len(s.namespaces)
		for b.Loop() {
			idx := rand.Intn(n)
			accessor := s.namespaces[idx].Namespace.ID
			s.GetNamespaceByAccessor(ctx, accessor)
		}
	})

	b.Run("GetNamespaceByPath", func(b *testing.B) {
		n := len(s.namespaces)
		for b.Loop() {
			idx := rand.Intn(n)
			path := s.namespaces[idx].Namespace.Path
			s.GetNamespaceByPath(ctx, path)
		}
	})

	b.Run("ModifyNamespaceByPath", func(b *testing.B) {
		n := len(s.namespaces)
		for b.Loop() {
			idx := rand.Intn(n)
			path := s.namespaces[idx].Namespace.Path
			s.ModifyNamespaceByPath(ctx, path, testModifyNamespace)
		}
	})

	b.Run("ListAllNamespaces", func(b *testing.B) {
		for b.Loop() {
			s.ListAllNamespaces(ctx, false)
		}
	})

	b.Run("ListNamespaces non-recursive", func(b *testing.B) {
		for b.Loop() {
			parent := randomNamespace(s).Namespace
			ctx = namespace.ContextWithNamespace(ctx, parent)
			s.ListNamespaces(ctx, false, false)
		}
	})

	b.Run("ListNamespaces recursive", func(b *testing.B) {
		for b.Loop() {
			parent := randomNamespace(s).Namespace
			ctx = namespace.ContextWithNamespace(ctx, parent)
			s.ListNamespaces(ctx, false, true)
		}
	})

	b.Run("ResolveNamespaceFromRequest", func(b *testing.B) {
		rootCtx := namespace.RootContext(context.TODO())
		n := len(s.namespaces)
		for b.Loop() {
			idx := rand.Intn(n)
			ns := s.namespaces[idx].Namespace
			ctx := namespace.ContextWithNamespace(rootCtx, ns)
			s.ResolveNamespaceFromRequest(rootCtx, ctx, "/sys/namespaces")
		}
	})

	b.Run("DeleteNamespace", func(b *testing.B) {
		for b.Loop() {
			n := len(s.namespaces)
			idx := rand.Intn(n)
			uuid := s.namespaces[idx].UUID
			s.DeleteNamespace(ctx, uuid)
		}
	})
}

func testModifyNamespace(_ context.Context, ns *NamespaceEntry) (*NamespaceEntry, error) {
	uuid := ns.UUID
	accessor := ns.Namespace.ID
	ns.Namespace.CustomMetadata["uuid"] = uuid
	ns.Namespace.CustomMetadata["accessor"] = accessor

	return ns, nil
}

func BenchmarkNamespaceSet(b *testing.B) {
	c, _, _ := TestCoreUnsealed(benchhelpers.TBtoT(b))
	s := c.namespaceStore

	ctx := namespace.RootContext(context.Background())

	item := &NamespaceEntry{
		Namespace: &namespace.Namespace{},
	}

	var i int
	for b.Loop() {
		item.Namespace.Path = "ns" + strconv.Itoa(i)
		s.SetNamespace(ctx, item)
		i += 1
	}
}

func BenchmarkNamespaceSetLocked(b *testing.B) {
	c, _, _ := TestCoreUnsealed(benchhelpers.TBtoT(b))
	s := c.namespaceStore

	ctx := namespace.RootContext(context.Background())

	item := &NamespaceEntry{
		Namespace: &namespace.Namespace{},
	}

	var i int
	for b.Loop() {
		item.Namespace.Path = "ns" + strconv.Itoa(i)
		s.lock.Lock()
		s.setNamespaceLocked(ctx, item)
		i += 1
	}
}
