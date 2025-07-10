package vault

import (
	"context"
	"fmt"
	"path"
	"strconv"
	"testing"
	"time"

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
	ns, err := s.ListAllNamespaces(ctx, false)
	require.NoError(t, err)
	require.Empty(t, ns)

	// Creating an item should save it, set IDs, and canonicalize path.
	item := &namespace.Namespace{
		Path: "ns1",
	}

	err = s.SetNamespace(ctx, item)
	require.NoError(t, err)
	require.NotEmpty(t, item.UUID)
	require.NotEmpty(t, item.ID)
	require.Equal(t, item.Path, namespace.Canonicalize("ns1"))
	require.Equal(t, item.Path, "ns1/")

	itemUUID := item.UUID
	itemAccessor := item.ID
	itemPath := item.Path

	// We should now have one item.
	ns, err = s.ListAllNamespaces(ctx, false)
	require.NoError(t, err)
	require.NotEmpty(t, ns)
	require.Equal(t, ns[0].UUID, item.UUID)

	// Modifying our copy shouldn't affect anything.
	item.CustomMetadata = map[string]string{"openbao": "true"}
	item.Path = "modified"
	item.ID = "modified"
	item.UUID = "modified"

	fetched, err := s.GetNamespace(ctx, itemUUID)
	require.NoError(t, err)
	require.NotNil(t, fetched)
	require.Equal(t, fetched.UUID, itemUUID)
	require.Equal(t, fetched.ID, itemAccessor)
	require.Equal(t, fetched.Path, itemPath)
	require.Empty(t, fetched.CustomMetadata)

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
	ns, err = s.ListAllNamespaces(ctx, false)
	require.NoError(t, err)
	require.NotEmpty(t, ns)
	require.Equal(t, ns[0].UUID, itemUUID)

	// Delete that item.
	status, err := s.DeleteNamespace(ctx, itemPath)
	require.NoError(t, err)
	require.Equal(t, "in-progress", status)

	// Wait until deletion has finished.
	maxRetries := 50
	for range maxRetries {
		ns, err = s.ListAllNamespaces(ctx, false)
		require.NoError(t, err)
		if len(ns) > 0 {
			time.Sleep(1 * time.Millisecond)
			continue
		}
		break
	}

	// Store should be empty.
	ns, err = s.ListAllNamespaces(ctx, false)
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

	ns, err = s.ListAllNamespaces(ctx, false)
	require.NoError(t, err)
	require.Empty(t, ns)

	// Creating a new version of item should yield a new id even though the
	// path is the same.
	item = &namespace.Namespace{
		Path: "ns1/",
	}

	err = s.SetNamespace(ctx, item)
	require.NoError(t, err)
	require.NotEmpty(t, item.UUID)
	require.NotEqual(t, item.UUID, itemUUID)
	require.NotEmpty(t, item.ID)
	require.NotEqual(t, item.ID, itemAccessor)
	require.Equal(t, item.Path, namespace.Canonicalize("ns1"))
	require.Equal(t, item.Path, "ns1/")
	require.Equal(t, item.Path, itemPath)
}

func TestNamespaceStore_DeleteNamespace(t *testing.T) {
	t.Parallel()

	c, _, _ := TestCoreUnsealed(t)
	s := c.namespaceStore
	ctx := namespace.RootContext(context.Background())

	// create namespace
	testNamespace := &namespace.Namespace{Path: "test"}
	err := s.SetNamespace(ctx, testNamespace)
	require.NoError(t, err)

	// delete namespace
	status, err := s.DeleteNamespace(ctx, "test")
	require.NoError(t, err)
	require.Equal(t, "in-progress", status)

	maxRetries := 50
	for range maxRetries {
		status, err := s.DeleteNamespace(ctx, "test")
		require.NoError(t, err)
		if status == "in-progress" {
			time.Sleep(1 * time.Millisecond)
			continue
		}
		break
	}

	// verify namespace deletion
	nsList, err := s.ListAllNamespaces(ctx, false)
	require.NoError(t, err)
	require.Empty(t, nsList)

	keys, err := s.storage.List(ctx, namespaceStoreSubPath)
	require.NoError(t, err)
	require.Empty(t, keys, "Expected empty namespace store on storage level")

	// all have to be of length 1 due to root existing
	require.Len(t, s.namespacesByAccessor, 1)
	require.Len(t, s.namespacesByUUID, 1)
	require.Equal(t, s.namespacesByPath.size, 1)

	// try to delete root
	_, err = s.DeleteNamespace(ctx, "")
	require.Error(t, err)

	// try to delete namespace with child namespaces
	parentNamespace := &namespace.Namespace{Path: "parent/"}
	childNamespace := &namespace.Namespace{Path: "parent/child/"}
	err = s.SetNamespace(ctx, parentNamespace)
	require.NoError(t, err)

	parentCtx := namespace.ContextWithNamespace(ctx, parentNamespace)
	err = s.SetNamespace(ctx, childNamespace)
	require.NoError(t, err)

	// failed to delete as it contains a child namespace
	_, err = s.DeleteNamespace(ctx, "parent")
	require.Error(t, err)

	// delete the child namespace
	status, err = s.DeleteNamespace(parentCtx, "child")
	require.NoError(t, err)
	require.Equal(t, "in-progress", status)

	for range maxRetries {
		status, err := s.DeleteNamespace(parentCtx, "child")
		require.NoError(t, err)
		if status == "in-progress" {
			time.Sleep(1 * time.Millisecond)
			continue
		}
		break
	}

	keys, err = s.storage.List(ctx, path.Join(namespaceBarrierPrefix, parentNamespace.UUID, namespaceStoreSubPath)+"/")
	require.NoError(t, err)
	require.Empty(t, keys, "Expected empty namespace store on storage level")
}

// TestNamespaceStore_LockNamespace tests the lock namespace method of the namespace store
func TestNamespaceStore_LockNamespace(t *testing.T) {
	t.Parallel()

	c, keys, _ := TestCoreUnsealed(t)
	s := c.namespaceStore
	ctx := namespace.RootContext(context.Background())

	testNamespace := &namespace.Namespace{Path: "test"}
	err := s.SetNamespace(ctx, testNamespace)
	require.NoError(t, err)
	testNamespaceCtx := namespace.ContextWithNamespace(ctx, testNamespace)

	childNamespace := &namespace.Namespace{Path: "test/child"}
	err = s.SetNamespace(testNamespaceCtx, childNamespace)
	require.NoError(t, err)

	// nonexistent path will return err and empty unlock key
	unlockKey, err := s.LockNamespace(ctx, "nonexistent")
	require.ErrorContains(t, err, "requested namespace does not exist")
	require.Empty(t, unlockKey)

	// root path will return err and empty unlock key
	unlockKey, err = s.LockNamespace(ctx, "")
	require.ErrorContains(t, err, "root namespace cannot be locked/unlocked")
	require.Empty(t, unlockKey)

	// lock parent namespace
	unlockKey, err = s.LockNamespace(ctx, testNamespace.Path)
	require.NoError(t, err)
	require.NotEmpty(t, unlockKey)

	// verify the 'locked' flag
	require.Equal(t, true, s.namespacesByAccessor[testNamespace.ID].Locked)
	require.Equal(t, true, s.namespacesByUUID[testNamespace.UUID].Locked)
	require.Equal(t, true, s.namespacesByPath.Get(testNamespace.Path).Locked)

	// verify that you cannot lock already locked namespace
	unlockKey, err = s.LockNamespace(ctx, testNamespace.Path)
	require.ErrorContains(t, err, fmt.Sprintf("cannot lock namespace %q: is already locked", testNamespace.Path))
	require.Empty(t, unlockKey)

	// verify that you cannot lock children of a locked namespace
	unlockKey, err = s.LockNamespace(ctx, childNamespace.Path)
	require.ErrorContains(t, err, fmt.Sprintf("cannot lock namespace %q: ancestor namespace %q is already locked", childNamespace.Path, testNamespace.Path))
	require.Empty(t, unlockKey)

	err = TestCoreSeal(c)
	require.NoError(t, err)

	for _, key := range keys {
		if _, err := TestCoreUnseal(c, TestKeyCopy(key)); err != nil {
			t.Fatalf("unseal err: %s", err)
		}
	}

	// verify the persistence of the lock and ensure unlock key is not
	// returned outside of the store.
	ret, err := c.namespaceStore.GetNamespace(ctx, testNamespace.UUID)
	require.NoError(t, err)
	require.Equal(t, true, ret.Locked)
	require.Empty(t, ret.UnlockKey)

	// verify that modifying a locked namespace does not affect lock
	// status.
	ret, err = c.namespaceStore.ModifyNamespaceByPath(ctx, testNamespace.Path, func(ctx context.Context, ns *namespace.Namespace) (*namespace.Namespace, error) {
		ns.CustomMetadata["testing"] = "pass"

		// Ensure we do not see the unlock key during modification either.
		require.Empty(t, ret.UnlockKey)

		return ns, nil
	})
	require.NoError(t, err)
	require.Equal(t, true, ret.Locked)
	require.Contains(t, ret.CustomMetadata, "testing")
	require.Empty(t, ret.UnlockKey)

	// Verify that listing does not return locks.
	all, err := c.namespaceStore.ListAllNamespaces(ctx, true)
	require.NoError(t, err)
	for index, ns := range all {
		require.Empty(t, ns.UnlockKey, "namespace: %v / index: %v", ns, index)
	}

	all, err = c.namespaceStore.ListNamespaces(ctx, true, true)
	require.NoError(t, err)
	for index, ns := range all {
		require.Empty(t, ns.UnlockKey, "namespace: %v / index: %v", ns, index)
	}
}

// TestNamespaceStore_UnlockNamespace tests the unlock namespace method of the namespace store
func TestNamespaceStore_UnlockNamespace(t *testing.T) {
	t.Parallel()

	c, _, _ := TestCoreUnsealed(t)
	s := c.namespaceStore
	ctx := namespace.RootContext(context.Background())

	testNamespace := &namespace.Namespace{Path: "test"}
	err := s.SetNamespace(ctx, testNamespace)
	require.NoError(t, err)
	testNamespaceCtx := namespace.ContextWithNamespace(ctx, testNamespace)

	childNamespace := &namespace.Namespace{Path: "test/child"}
	err = s.SetNamespace(testNamespaceCtx, childNamespace)
	require.NoError(t, err)

	anotherNamespace := &namespace.Namespace{Path: "another"}
	err = s.SetNamespace(ctx, anotherNamespace)
	require.NoError(t, err)

	// lock namespace
	unlockKeyChild, err := s.LockNamespace(ctx, childNamespace.Path)
	require.NoError(t, err)
	require.NotEmpty(t, unlockKeyChild)

	unlockKeyParent, err := s.LockNamespace(ctx, testNamespace.Path)
	require.NoError(t, err)
	require.NotEmpty(t, unlockKeyParent)

	// verify locked status
	require.Equal(t, true, s.namespacesByAccessor[testNamespace.ID].Locked)
	require.Equal(t, true, s.namespacesByUUID[testNamespace.UUID].Locked)
	require.Equal(t, true, s.namespacesByPath.Get(testNamespace.Path).Locked)

	// nonexistent path will return err
	err = s.UnlockNamespace(ctx, "key", "nonexistent")
	require.ErrorContains(t, err, "requested namespace does not exist")

	// cannot unlock root as it cannot be locked
	err = s.UnlockNamespace(ctx, "key", "")
	require.ErrorContains(t, err, "root namespace cannot be locked/unlocked")

	// unlocking not locked namespace will return err
	err = s.UnlockNamespace(ctx, "key", anotherNamespace.Path)
	require.ErrorContains(t, err, fmt.Sprintf("namespace %q is not locked", anotherNamespace.Path))

	// cannot unlock child namespace of a locked namespace
	err = s.UnlockNamespace(ctx, unlockKeyChild, childNamespace.Path)
	require.ErrorContains(t, err, fmt.Sprintf("cannot unlock %q with namespace %q being locked", childNamespace.Path, testNamespace.Path))

	// try to unlock with wrong key
	err = s.UnlockNamespace(ctx, "key", testNamespace.Path)
	require.ErrorContains(t, err, "e")

	// unlock with correct key
	err = s.UnlockNamespace(ctx, unlockKeyParent, testNamespace.Path)
	require.NoError(t, err)

	// verify the locked status
	require.Equal(t, false, s.namespacesByAccessor[testNamespace.ID].Locked)
	require.Equal(t, false, s.namespacesByUUID[testNamespace.UUID].Locked)
	require.Equal(t, false, s.namespacesByPath.Get(testNamespace.Path).Locked)

	// force unlock of child namespace using empty key (parent is already unlocked)
	err = s.UnlockNamespace(ctx, "", childNamespace.Path)
	require.NoError(t, err)

	// verify the locked status
	require.Equal(t, false, s.namespacesByAccessor[childNamespace.ID].Locked)
	require.Equal(t, false, s.namespacesByUUID[childNamespace.UUID].Locked)
	require.Equal(t, false, s.namespacesByPath.Get(childNamespace.Path).Locked)
}

func TestNamespaceStore_ExternalKeyTypeAllowed(t *testing.T) {
	t.Parallel()

	c, _, _ := TestCoreUnsealed(t)
	s := c.namespaceStore

	foo := &namespace.Namespace{Path: "foo/", ExternalKeyTypes: []string{"softhsm"}}
	bar := &namespace.Namespace{Path: "foo/bar/", ExternalKeyTypes: []string{"softhsm", "awskms"}}
	baz := &namespace.Namespace{Path: "foo/bar/baz/", ExternalKeyTypes: []string{"awskms"}}
	TestCoreCreateNamespaces(t, c, foo, bar, baz)

	tcs := []struct {
		namespace *namespace.Namespace
		ty        string
		wantErr   bool
	}{
		{namespace.RootNamespace, "softhsm", true},
		{namespace.RootNamespace, "awskms", true},

		{foo, "softhsm", true},
		{bar, "softhsm", true},
		{baz, "softhsm", false},

		{foo, "awskms", false},
		{bar, "awskms", false},
		{baz, "awskms", false},
	}

	for _, tc := range tcs {
		err := s.ExternalKeyTypeAllowed(tc.namespace, tc.ty)
		if tc.wantErr {
			require.NoError(t, err, fmt.Sprintf(
				"Type %q should not be allowed in namespace %q, but was", tc.ty, tc.namespace.Path))
		} else {
			require.Error(t, err, fmt.Sprintf(
				"Type %q should be allowed in namespace %q, but wasn't", tc.ty, tc.namespace.Path))
		}
	}
}

func TestNamespaceHierarchy(t *testing.T) {
	t.Parallel()

	c, _, _ := TestCoreUnsealed(t)
	s := c.namespaceStore

	ctx := namespace.RootContext(context.TODO())

	// Initial store should be empty.
	ns, err := s.ListAllNamespaces(ctx, false)
	require.NoError(t, err)
	require.Empty(t, ns)

	// Creating an item should save it, set IDs, and canonicalize path.
	namespaces := []struct {
		context.Context
		*namespace.Namespace
	}{
		{
			namespace.ContextWithNamespace(ctx, namespace.RootNamespace),
			&namespace.Namespace{Path: "ns1"},
		},
		{
			namespace.ContextWithNamespace(ctx, namespace.RootNamespace),
			&namespace.Namespace{Path: "ns2"},
		},
		{
			namespace.ContextWithNamespace(ctx, namespace.RootNamespace),
			&namespace.Namespace{Path: "ns1/ns3"},
		},
	}

	for idx, ns := range namespaces {
		err := s.SetNamespace(ns.Context, ns.Namespace)
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
	rootNs := namespace.RootNamespace
	tree := newNamespaceTree(rootNs)

	namespaces1 := []*namespace.Namespace{
		{Path: "ns1/", ID: "00001", UUID: "00001"},
		{Path: "ns1/ns2/", ID: "00002", UUID: "00002"},
		{Path: "ns3/", ID: "00003", UUID: "00003"},
		{Path: "ns3/ns4/", ID: "00004", UUID: "00004"},
	}

	for _, entry := range namespaces1 {
		err := tree.Insert(entry)
		require.NoError(t, err)
	}
	err := tree.validate()
	require.NoError(t, err)

	namespaces2 := []*namespace.Namespace{
		{Path: "ns3/ns6/ns7/", ID: "00007", UUID: "00007"},
		{Path: "ns3/ns8/ns9/", ID: "00009", UUID: "00009"},
	}

	for _, entry := range namespaces2 {
		err := tree.Insert(entry)
		require.Error(t, err)
	}

	namespaces3 := []*namespace.Namespace{
		{Path: "ns3/ns6/", ID: "00006", UUID: "00006"},
		{Path: "ns3/ns8/", ID: "00008", UUID: "00008"},
		{Path: "ns9/ns10/", ID: "00010", UUID: "00010"},
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

	entries, err = tree.List("", true, true)
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

func randomNamespace(ns *NamespaceStore) *namespace.Namespace {
	// make use of random map iteration order
	for _, item := range ns.namespacesByUUID {
		return item
	}
	return nil
}

func testModifyNamespace(_ context.Context, ns *namespace.Namespace) (*namespace.Namespace, error) {
	uuid := ns.UUID
	accessor := ns.ID
	ns.CustomMetadata["uuid"] = uuid
	ns.CustomMetadata["accessor"] = accessor

	return ns, nil
}

func BenchmarkNamespaceStore(b *testing.B) {
	c, _, _ := TestCoreUnsealed(benchhelpers.TBtoT(b))
	s := c.namespaceStore

	ctx := namespace.RootContext(context.Background())

	n := 1_000

	for i := range n {
		parent := randomNamespace(s)
		ctx := namespace.ContextWithNamespace(ctx, parent)
		item := &namespace.Namespace{
			Path: parent.Path + "ns" + strconv.Itoa(i) + "/",
		}
		err := s.SetNamespace(ctx, item)
		require.NoError(b, err)
	}

	require.Equal(b, n+1, len(s.namespacesByUUID))

	b.Run("GetNamespace", func(b *testing.B) {
		for b.Loop() {
			uuid := randomNamespace(s).UUID
			s.GetNamespace(ctx, uuid)
		}
	})

	b.Run("GetNamespaceByAccessor", func(b *testing.B) {
		for b.Loop() {
			accessor := randomNamespace(s).ID
			s.GetNamespaceByAccessor(ctx, accessor)
		}
	})

	b.Run("GetNamespaceByPath", func(b *testing.B) {
		for b.Loop() {
			path := randomNamespace(s).Path
			s.GetNamespaceByPath(ctx, path)
		}
	})

	b.Run("ModifyNamespaceByPath", func(b *testing.B) {
		for b.Loop() {
			path := randomNamespace(s).Path
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
			parent := randomNamespace(s)
			ctx = namespace.ContextWithNamespace(ctx, parent)
			s.ListNamespaces(ctx, false, false)
		}
	})

	b.Run("ListNamespaces recursive", func(b *testing.B) {
		for b.Loop() {
			parent := randomNamespace(s)
			ctx = namespace.ContextWithNamespace(ctx, parent)
			s.ListNamespaces(ctx, false, true)
		}
	})

	b.Run("ResolveNamespaceFromRequest", func(b *testing.B) {
		for b.Loop() {
			ns := randomNamespace(s)
			c.ResolveNamespaceFromRequest(ns.Path, "/sys/namespaces")
		}
	})
}

// can be later on expanded with non-empty namespaces
func BenchmarkClearNamespaceResources(b *testing.B) {
	c, _, _ := TestCoreUnsealed(benchhelpers.TBtoT(b))
	s := c.namespaceStore
	ctx := namespace.RootContext(context.Background())

	n := 1_000

	for i := range n {
		ctx := namespace.ContextWithNamespace(ctx, namespace.RootNamespace)
		item := &namespace.Namespace{
			Path: "ns" + strconv.Itoa(i) + "/",
		}
		err := s.SetNamespace(ctx, item)
		require.NoError(b, err)
	}

	require.Equal(b, n+1, len(s.namespacesByUUID))

	for b.Loop() {
		ns := randomNamespace(s)
		s.clearNamespaceResources(ctx, ns)
	}
}

func BenchmarkNamespace_Set(b *testing.B) {
	c, _, _ := TestCoreUnsealed(benchhelpers.TBtoT(b))
	s := c.namespaceStore
	ctx := namespace.RootContext(context.Background())

	item := &namespace.Namespace{}

	b.Run("SetNamespace", func(b *testing.B) {
		var i int
		for b.Loop() {
			item.Path = "ns" + strconv.Itoa(i)
			s.SetNamespace(ctx, item)
			i += 1
		}
	})

	b.Run("SetNamespaceLocked", func(b *testing.B) {
		var i int
		for b.Loop() {
			item.Path = "ns" + strconv.Itoa(i)
			s.lock.Lock()
			s.setNamespaceLocked(ctx, item)
			i += 1
		}
	})
}

// TestNamespaces_ResolveNamespaceFromRequest verifies namespace resolution logic from request.
func TestNamespaces_ResolveNamespaceFromRequest(t *testing.T) {
	core, _, _ := TestCoreUnsealed(t)
	nsStore := core.namespaceStore

	// Setup only necessary namespaces
	ns1Entry := &namespace.Namespace{Path: "ns1/"}
	ns2Entry := &namespace.Namespace{Path: "ns1/ns2/"}
	ns3Entry := &namespace.Namespace{Path: "ns1/ns2/ns3/"}

	// Create namespaces
	rootCtx := namespace.RootContext(nil)

	// Set child into root
	require.NoError(t, nsStore.SetNamespace(rootCtx, ns1Entry))

	// Set child into ns1
	ns1Ctx := namespace.ContextWithNamespace(rootCtx, ns1Entry)
	require.NoError(t, nsStore.SetNamespace(ns1Ctx, ns2Entry))

	// Set child into ns1/ns2
	ns2Ctx := namespace.ContextWithNamespace(ns1Ctx, ns2Entry)
	require.NoError(t, nsStore.SetNamespace(ns2Ctx, ns3Entry))

	// Define test cases
	testCases := []struct {
		name                string
		nsHeader            string
		reqPath             string
		expectedNamespace   *namespace.Namespace
		expectedTrimmedPath string
		wantError           bool
	}{
		{
			name:                "Single namespace in header",
			nsHeader:            "ns1",
			reqPath:             "secret/foo",
			expectedNamespace:   ns1Entry,
			expectedTrimmedPath: "secret/foo",
		},
		{
			name:                "Nested namespace in header",
			nsHeader:            "ns1/ns2",
			reqPath:             "secret/foo",
			expectedNamespace:   ns2Entry,
			expectedTrimmedPath: "secret/foo",
		},
		{
			name:                "Single namespace in request path",
			reqPath:             "ns1/secret/foo",
			expectedNamespace:   ns1Entry,
			expectedTrimmedPath: "secret/foo",
		},
		{
			name:                "Nested namespace in request path",
			reqPath:             "ns1/ns2/secret/foo",
			expectedNamespace:   ns2Entry,
			expectedTrimmedPath: "secret/foo",
		},
		{
			name:                "Route to existing namespace ns2 with sys in path",
			reqPath:             "ns1/sys/namespaces/ns2",
			expectedNamespace:   ns1Entry,
			expectedTrimmedPath: "sys/namespaces/ns2",
		},
		{
			name:                "Route to existing namespace ns3 with ns1/ns2/sys in path",
			reqPath:             "ns1/ns2/sys/namespaces/ns3",
			expectedNamespace:   ns2Entry,
			expectedTrimmedPath: "sys/namespaces/ns3",
		},
		{
			name:                "Namespace in both header and request path",
			nsHeader:            "ns1/ns2",
			reqPath:             "ns3/secret/foo",
			expectedNamespace:   ns3Entry,
			expectedTrimmedPath: "secret/foo",
		},
		{
			name:              "Invalid namespace in header and request path combination",
			nsHeader:          "ns1/ns3",
			reqPath:           "ns2/secret/foo",
			expectedNamespace: nil,
		},
		{
			name:              "Header cannot spill into path",
			nsHeader:          "ns1/secret",
			reqPath:           "foo",
			expectedNamespace: nil,
		},
		{
			name:                "Header and path don't deduplicate",
			nsHeader:            "ns1",
			reqPath:             "ns1/secret/foo",
			expectedNamespace:   ns1Entry,
			expectedTrimmedPath: "ns1/secret/foo",
		},
	}

	// Execute test cases
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ns, trimmedPath := nsStore.ResolveNamespaceFromRequest(tc.nsHeader, tc.reqPath)
			if tc.expectedNamespace == nil {
				require.Nil(t, ns)
			} else {
				require.NotNil(t, ns)
				require.Equal(t, tc.expectedNamespace.Path, ns.Path)
				require.Equal(t, tc.expectedTrimmedPath, trimmedPath)
			}
		})
	}
}

func TestNamespaceStorage(t *testing.T) {
	c, keys, root := TestCoreUnsealed(t)
	s := c.namespaceStore

	namespaces := []*namespace.Namespace{
		{Path: "ns1/"},
		{Path: "ns2/"},
		{Path: "ns1/ns3/"},
		{Path: "ns1/ns3/ns4/"},
	}
	TestCoreCreateNamespaces(t, c, namespaces...)

	ctx := namespace.RootContext(nil)

	nsKeys, err := s.storage.List(ctx, namespaceStoreSubPath)
	require.NoError(t, err)
	require.Len(t, nsKeys, 2)
	require.ElementsMatch(t, nsKeys, []string{namespaces[0].UUID, namespaces[1].UUID})

	nsKeys, err = s.storage.List(ctx, path.Join(namespaceBarrierPrefix, namespaces[0].UUID, namespaceStoreSubPath)+"/")
	require.NoError(t, err)
	require.Len(t, nsKeys, 1)
	require.ElementsMatch(t, nsKeys, []string{namespaces[2].UUID})

	nsKeys, err = s.storage.List(ctx, path.Join(namespaceBarrierPrefix, namespaces[1].UUID, namespaceStoreSubPath)+"/")
	require.NoError(t, err)
	require.Len(t, nsKeys, 0)

	nsKeys, err = s.storage.List(ctx, path.Join(namespaceBarrierPrefix, namespaces[2].UUID, namespaceStoreSubPath)+"/")
	require.NoError(t, err)
	require.Len(t, nsKeys, 1)
	require.ElementsMatch(t, nsKeys, []string{namespaces[3].UUID})

	nsKeys, err = s.storage.List(ctx, path.Join(namespaceBarrierPrefix, namespaces[3].UUID, namespaceStoreSubPath)+"/")
	require.NoError(t, err)
	require.Len(t, nsKeys, 0)

	// Loading structure back into memory on seal -> unseal
	err = c.Seal(root)
	require.NoError(t, err)

	for i, key := range keys {
		unseal, err := TestCoreUnseal(c, key)
		require.NoError(t, err)

		if i+1 == len(keys) && !unseal {
			t.Fatal("err: should be unsealed")
		}
	}

	for _, ns := range namespaces {
		ns, err := s.GetNamespace(ctx, ns.UUID)
		require.NoError(t, err)
		require.NotNil(t, ns)
	}
}
