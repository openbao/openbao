package vault

import (
	"context"
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
	require.NotEmpty(t, item.Namespace.UUID)
	require.NotEmpty(t, item.Namespace.ID)
	require.Equal(t, item.Namespace.Path, namespace.Canonicalize("ns1"))
	require.Equal(t, item.Namespace.Path, "ns1/")

	itemUUID := item.Namespace.UUID
	itemAccessor := item.Namespace.ID
	itemPath := item.Namespace.Path

	// We should now have one item.
	ns, err = s.ListAllNamespaceEntries(ctx, false)
	require.NoError(t, err)
	require.NotEmpty(t, ns)
	require.Equal(t, ns[0].Namespace.UUID, item.Namespace.UUID)

	// Modifying our copy shouldn't affect anything.
	item.Namespace.CustomMetadata = map[string]string{"openbao": "true"}
	item.Namespace.Path = "modified"
	item.Namespace.ID = "modified"
	item.Namespace.UUID = "modified"

	fetched, err := s.GetNamespace(ctx, itemUUID)
	require.NoError(t, err)
	require.NotNil(t, fetched)
	require.Equal(t, fetched.Namespace.UUID, itemUUID)
	require.Equal(t, fetched.Namespace.ID, itemAccessor)
	require.Equal(t, fetched.Namespace.Path, itemPath)
	require.Empty(t, fetched.Namespace.CustomMetadata)

	// Fetching the modified ID should fail.
	fetched, err = s.GetNamespace(ctx, item.Namespace.UUID)
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
	require.Equal(t, ns[0].Namespace.UUID, itemUUID)

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
	require.NotEmpty(t, item.Namespace.UUID)
	require.NotEqual(t, item.Namespace.UUID, itemUUID)
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
		require.NotEmpty(t, ns.Namespace.UUID)
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

func TestNamespaceTree(t *testing.T) {
	rootNs := &NamespaceEntry{Namespace: namespace.RootNamespace}
	tree := newNamespaceTree(rootNs)

	namespaces1 := []*NamespaceEntry{
		{Namespace: &namespace.Namespace{Path: "ns1/", ID: "00001", UUID: "00001"}},
		{Namespace: &namespace.Namespace{Path: "ns1/ns2/", ID: "00002", UUID: "00002"}},
		{Namespace: &namespace.Namespace{Path: "ns3/ns4/", ID: "00004", UUID: "00004"}},
		{Namespace: &namespace.Namespace{Path: "ns3/", ID: "00003", UUID: "00003"}},
	}

	for _, entry := range namespaces1 {
		tree.unsafeInsert(entry)
	}
	err := tree.validate()
	require.NoError(t, err)

	namespaces2 := []*NamespaceEntry{
		{Namespace: &namespace.Namespace{Path: "ns3/ns6/ns7/", ID: "00007", UUID: "00007"}},
		{Namespace: &namespace.Namespace{Path: "ns3/ns8/ns9/", ID: "00009", UUID: "00009"}},
	}

	for _, entry := range namespaces2 {
		tree.unsafeInsert(entry)
	}
	err = tree.validate()
	require.Error(t, err)

	namespaces3 := []*NamespaceEntry{
		{Namespace: &namespace.Namespace{Path: "ns3/ns6/", ID: "00006", UUID: "00006"}},
		{Namespace: &namespace.Namespace{Path: "ns3/ns8/", ID: "00008", UUID: "00008"}},
		{Namespace: &namespace.Namespace{Path: "ns9/ns10/", ID: "00010", UUID: "00010"}},
	}

	err = tree.Insert(namespaces3[0])
	require.NoError(t, err)
	err = tree.Insert(namespaces3[1])
	require.NoError(t, err)
	err = tree.Insert(namespaces3[2])
	require.Error(t, err)

	err = tree.validate()
	require.NoError(t, err)

	beforeSize := tree.size
	err = tree.Delete("ns9/ns10/")
	require.NoError(t, err)
	require.Equal(t, beforeSize, tree.size)

	err = tree.Delete("ns3/")
	require.Error(t, err)
	require.Equal(t, beforeSize, tree.size)

	err = tree.Delete("ns1/ns2/")
	require.NoError(t, err)
	require.Equal(t, beforeSize-1, tree.size)

	entries, err := tree.List("", false, false)
	require.NoError(t, err)
	require.Equal(t, 2, len(entries))

	entries, err = tree.List("", false, true)
	require.NoError(t, err)
	require.Equal(t, tree.size, len(entries))

	entry := tree.Get("ns1/")
	require.NotNil(t, entry)
	require.Equal(t, namespaces1[0], entry)

	entry = tree.Get("ns3/ns4/foobar")
	require.Nil(t, entry)

	namespacePrefix, entry, pathSuffix := tree.LongestPrefix("ns3/ns4/foobar")
	require.NotNil(t, entry)
	require.Equal(t, "ns3/ns4/", namespacePrefix)
	require.Equal(t, "foobar", pathSuffix)
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
		err := s.SetNamespace(ctx, item)
		require.NoError(b, err)
	}

	require.Equal(b, n+1, len(s.namespacesByUUID))

	b.Run("GetNamespace", func(b *testing.B) {
		for b.Loop() {
			uuid := randomNamespace(s).Namespace.UUID
			s.GetNamespace(ctx, uuid)
		}
	})

	b.Run("GetNamespaceByAccessor", func(b *testing.B) {
		for b.Loop() {
			accessor := randomNamespace(s).Namespace.ID
			s.GetNamespaceByAccessor(ctx, accessor)
		}
	})

	b.Run("GetNamespaceByPath", func(b *testing.B) {
		for b.Loop() {
			path := randomNamespace(s).Namespace.Path
			s.GetNamespaceByPath(ctx, path)
		}
	})

	b.Run("ModifyNamespaceByPath", func(b *testing.B) {
		for b.Loop() {
			path := randomNamespace(s).Namespace.Path
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
		for b.Loop() {
			ns := randomNamespace(s).Namespace
			ctx := namespace.ContextWithNamespace(rootCtx, ns)
			s.ResolveNamespaceFromRequest(rootCtx, ctx, "/sys/namespaces")
		}
	})

	b.Run("DeleteNamespace", func(b *testing.B) {
		for b.Loop() {
			uuid := randomNamespace(s).Namespace.UUID
			s.DeleteNamespace(ctx, uuid)
		}
	})
}

func testModifyNamespace(_ context.Context, ns *NamespaceEntry) (*NamespaceEntry, error) {
	uuid := ns.Namespace.UUID
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

// TestNamespaces_ResolveNamespaceFromRequest verifies namespace resolution logic from request.
func TestNamespaces_ResolveNamespaceFromRequest(t *testing.T) {
	core, _, _ := TestCoreUnsealed(t)
	nsStore := core.namespaceStore

	// Setup only necessary namespaces
	ns1Entry := &NamespaceEntry{Namespace: &namespace.Namespace{Path: "ns1/"}}
	ns2Entry := &NamespaceEntry{Namespace: &namespace.Namespace{Path: "ns1/ns2/"}}

	ns3Entry := &NamespaceEntry{Namespace: &namespace.Namespace{Path: "ns1/ns2/namespaces/ns3/"}}

	// Create namespaces
	rootCtx := namespace.RootContext(nil)
	// Set namespaces in root
	require.NoError(t, nsStore.SetNamespace(rootCtx, ns1Entry))

	// Set child into ns1
	ns1Ctx := namespace.ContextWithNamespace(rootCtx, ns1Entry.Namespace)
	require.NoError(t, nsStore.SetNamespace(ns1Ctx, ns2Entry))

	// Set child into ns1/ns2
	ns2Ctx := namespace.ContextWithNamespace(ns1Ctx, ns2Entry.Namespace)
	require.NoError(t, nsStore.SetNamespace(ns2Ctx, ns3Entry))

	// Define test cases
	testCases := []struct {
		name            string
		reqPath         string
		expectedFinalNS *namespace.Namespace
		expectedRelPath string
	}{
		{
			name:            "NS in path",
			reqPath:         "ns1/secret/foo",
			expectedFinalNS: ns1Entry.Namespace,
			expectedRelPath: "secret/foo",
		},
		{
			name:            "Nested NS in path",
			reqPath:         "ns1/ns2/secret/foo",
			expectedFinalNS: ns2Entry.Namespace,
			expectedRelPath: "secret/foo",
		},
		{
			name:            "Route to existing namespace ns2 with sys in path",
			reqPath:         "ns1/sys/namespaces/ns2",
			expectedFinalNS: ns1Entry.Namespace,
			expectedRelPath: "sys/namespaces/ns2",
		},
		{
			name:            "Route to existing namespace ns3 with ns1/ns2/sys in path",
			reqPath:         "ns1/ns2/sys/namespaces/ns3",
			expectedFinalNS: ns2Entry.Namespace,
			expectedRelPath: "sys/namespaces/ns3",
		},
	}

	// Execute test cases
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			baseCtx := namespace.RootContext(context.Background())
			httpCtx := namespace.RootContext(context.Background())

			finalCtx, finalNS, finalPath, err := nsStore.ResolveNamespaceFromRequest(baseCtx, httpCtx, tc.reqPath)

			require.NoError(t, err)
			require.Equal(t, tc.expectedFinalNS.Path, finalNS.Path)
			require.Equal(t, tc.expectedRelPath, finalPath)
			require.NotNil(t, finalCtx)
		})
	}
}
