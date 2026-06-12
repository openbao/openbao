package vault

import (
	"context"
	"fmt"
	"path"
	"strconv"
	"testing"
	"time"

	credAppRole "github.com/openbao/openbao/builtin/credential/approle"
	"github.com/openbao/openbao/helper/benchhelpers"
	"github.com/openbao/openbao/helper/identity/mfa"
	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/sdk/v2/logical"
	be "github.com/openbao/openbao/vault/backend"
	"github.com/openbao/openbao/vault/barrier"
	ident "github.com/openbao/openbao/vault/identity"
	"github.com/openbao/openbao/vault/policy"
	"github.com/openbao/openbao/vault/routing"
	"github.com/openbao/openbao/vault/seal"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNamespaceStore(t *testing.T) {
	t.Parallel()

	c, keys, root := TestCoreUnsealed(t)
	s := c.namespaceStore

	ctx := namespace.RootContext(t.Context())

	// Initial store should be empty.
	ns, err := s.ListNamespaces(ctx, ListNamespaceOpts{
		Recursive:     true,
		IncludeSealed: true,
	})
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
	ns, err = s.ListNamespaces(ctx, ListNamespaceOpts{
		Recursive: true,
	})
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
	ns, err = s.ListNamespaces(ctx, ListNamespaceOpts{
		Recursive: true,
	})
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
		ns, err = s.ListNamespaces(ctx, ListNamespaceOpts{})
		require.NoError(t, err)
		if len(ns) > 0 {
			time.Sleep(1 * time.Millisecond)
			continue
		}
		break
	}

	// Store should be empty.
	ns, err = s.ListNamespaces(ctx, ListNamespaceOpts{
		Recursive: true,
	})
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

	ns, err = s.ListNamespaces(ctx, ListNamespaceOpts{
		Recursive: true,
	})
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
	ctx := namespace.RootContext(t.Context())

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
	nsList, err := s.ListNamespaces(ctx, ListNamespaceOpts{
		Recursive:     true,
		IncludeSealed: true,
	})
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

	keys, err = s.storage.List(ctx, path.Join(barrier.NamespacePrefix, parentNamespace.UUID, namespaceStoreSubPath)+"/")
	require.NoError(t, err)
	require.Empty(t, keys, "Expected empty namespace store on storage level")
}

func TestNamespaceStore_DeleteSealedNamespace(t *testing.T) {
	t.Parallel()

	c, _, _ := TestCoreUnsealed(t)
	s := c.namespaceStore
	ctx := namespace.RootContext(t.Context())

	_ = TestCoreCreateUnsealedNamespaces(
		t, c,
		&namespace.Namespace{Path: "a/"},
		&namespace.Namespace{Path: "b/"},
		&namespace.Namespace{Path: "c/"},
		&namespace.Namespace{Path: "tree/"},
	)
	TestCoreCreateNamespaces(
		t, c,
		&namespace.Namespace{Path: "tree/a/"},
		&namespace.Namespace{Path: "tree/b/"},
		&namespace.Namespace{Path: "tree/a/b/"},
	)

	type test struct {
		path  string
		force bool
	}

	// Inputs that should all fail while namespaces are unsealed.
	tests := map[string]test{
		"root":       {"/", false},
		"root+force": {"/", true},
		"a":          {"a/", false},
		"a+force":    {"a/", true},
		"tree":       {"tree/", false},
		"tree+force": {"tree/", true},
	}

	for name, tt := range tests {
		t.Run(fmt.Sprintf("unsealed+%s", name), func(t *testing.T) {
			_, err := s.DeleteSealedNamespace(ctx, tt.path, tt.force)
			require.Error(t, err)
		})
	}

	// Seal the world:
	require.NoError(t, s.SealNamespace(ctx, "a/"))
	require.NoError(t, s.SealNamespace(ctx, "b/"))
	require.NoError(t, s.SealNamespace(ctx, "tree/"))

	// Inputs that should all fail even after sealing the namespaces.
	tests = map[string]test{
		"root":       {"/", false},
		"root+force": {"/", true},
		"tree":       {"tree/", false},
	}

	for name, tt := range tests {
		t.Run(fmt.Sprintf("sealed+%s", name), func(t *testing.T) {
			_, err := s.DeleteSealedNamespace(ctx, tt.path, tt.force)
			require.Error(t, err)
		})
	}

	// Inputs that should all wipe namespaces down to the last bit.
	tests = map[string]test{
		// We have single-level "a" and "b" in this test just so one can be
		// force deleted while the other isn't.
		"a":          {"a/", false},
		"b+force":    {"b/", true},
		"tree+force": {"tree/", true},
	}

	for name, tt := range tests {
		t.Run(fmt.Sprintf("sealed+%s", name), func(t *testing.T) {
			status, err := s.DeleteSealedNamespace(ctx, tt.path, tt.force)
			require.NoError(t, err)
			require.Equal(t, "in-progress", status)
			// Wait for the deletion to finish asynchronously.
			require.EventuallyWithT(t, func(t *assert.CollectT) {
				status, err := s.DeleteSealedNamespace(ctx, tt.path, tt.force)
				require.Equal(t, "", status)
				require.NoError(t, err)
			}, time.Second*10, time.Millisecond*10)
		})
	}

	// Check that the namespace store no longer knows of any namespaces, except
	// for "c/", which we never touched:
	namespaces, err := s.ListNamespaces(ctx, ListNamespaceOpts{
		Recursive:     true,
		IncludeSealed: true,
	})
	require.Len(t, namespaces, 1)
	require.Equal(t, namespaces[0].Path, "c/")
	require.NoError(t, err)

	// Check that namespace storage is entirely empty, except for c's UUID.
	keys, err := c.barrier.List(ctx, barrier.NamespacePrefix)
	require.Len(t, keys, 1)
	require.Equal(t, keys[0], namespaces[0].UUID+"/")
	require.NoError(t, err)
}

// TestNamespaceStore_LockNamespace tests the lock namespace method of the namespace store
func TestNamespaceStore_LockNamespace(t *testing.T) {
	t.Parallel()

	c, keys, _ := TestCoreUnsealed(t)
	s := c.namespaceStore
	ctx := namespace.RootContext(t.Context())

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
	ret, _, err = c.namespaceStore.ModifyNamespaceByPath(ctx, testNamespace.Path, nil, func(ctx context.Context, ns *namespace.Namespace) (*namespace.Namespace, error) {
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
	all, err := c.namespaceStore.ListNamespaces(ctx, ListNamespaceOpts{
		Recursive:     true,
		IncludeParent: true,
	})
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
	ctx := namespace.RootContext(t.Context())

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

func TestNamespaceHierarchy(t *testing.T) {
	t.Parallel()

	c, _, _ := TestCoreUnsealed(t)
	s := c.namespaceStore

	ctx := namespace.RootContext(t.Context())

	// Initial store should be empty.
	ns, err := s.ListNamespaces(ctx, ListNamespaceOpts{
		Recursive: true,
	})
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
		require.NotEmpty(t, ns.UUID)
		require.NotEmpty(t, ns.ID)
		require.Equal(t, ns.Path, namespace.Canonicalize(namespaces[idx].Path))
	}

	t.Run("ListNamespaces", func(t *testing.T) {
		t.Run("no root namespace", func(t *testing.T) {
			nsList, err := s.ListNamespaces(ctx, ListNamespaceOpts{
				Recursive: true,
			})
			require.NoError(t, err)
			containsRoot := false
			for _, nss := range nsList {
				if (nss.Path == "") || (nss.Path == namespace.RootNamespaceID) {
					containsRoot = true
					break
				}
			}
			require.Falsef(t, containsRoot, "must not contain root namespace")
			require.Equal(t, len(namespaces), len(nsList), "must return all namespaces, excluding root")
		})
		t.Run("with root namespace", func(t *testing.T) {
			nsList, err := s.ListNamespaces(ctx, ListNamespaceOpts{
				IncludeParent: true,
				Recursive:     true,
			})
			require.NoError(t, err)
			containsRoot := false
			for _, nss := range nsList {
				if (nss.Path == "") || (nss.Path == namespace.RootNamespaceID) {
					containsRoot = true
					break
				}
			}
			require.Truef(t, containsRoot, "must contain root namespace")
			require.Equal(t, len(namespaces)+1, len(nsList), "must return all namespaces")
		})
		t.Run("list child namespaces", func(t *testing.T) {
			ctx := namespace.ContextWithNamespace(ctx, namespaces[0].Namespace)
			nsList, err := s.ListNamespaces(ctx, ListNamespaceOpts{
				IncludeParent: true,
			})
			require.NoError(t, err)
			for _, nss := range nsList {
				t.Logf("> ID  : %s\n", nss.ID)
				t.Logf("> Path: %s\n", nss.Path)
			}
			require.Equal(t, 2, len(nsList))

			ctx = namespace.ContextWithNamespace(ctx, namespaces[1].Namespace)
			nsList, err = s.ListNamespaces(ctx, ListNamespaceOpts{})
			require.NoError(t, err)
			require.Equal(t, 0, len(nsList))
		})
	})
}

func TestNamespaceTree(t *testing.T) {
	t.Parallel()

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

	count := 0
	require.NoError(t, tree.Walk("", false, func(n *namespace.Namespace) {
		count++
	}))
	require.Equal(t, 2, count)

	count = 0
	require.NoError(t, tree.Walk("", true, func(n *namespace.Namespace) {
		count++
	}))
	require.Equal(t, tree.size, count+1)

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

	ctx := namespace.RootContext(b.Context())

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
			_, _ = s.GetNamespace(ctx, uuid)
		}
	})

	b.Run("GetNamespaceByAccessor", func(b *testing.B) {
		for b.Loop() {
			accessor := randomNamespace(s).ID
			_, _ = s.GetNamespaceByAccessor(ctx, accessor)
		}
	})

	b.Run("GetNamespaceByPath", func(b *testing.B) {
		for b.Loop() {
			path := randomNamespace(s).Path
			_, _ = s.GetNamespaceByPath(ctx, path)
		}
	})

	b.Run("ModifyNamespaceByPath", func(b *testing.B) {
		for b.Loop() {
			path := randomNamespace(s).Path
			_, _, _ = s.ModifyNamespaceByPath(ctx, path, nil, testModifyNamespace)
		}
	})

	b.Run("ListNamespaces non-recursive", func(b *testing.B) {
		for b.Loop() {
			parent := randomNamespace(s)
			ctx = namespace.ContextWithNamespace(ctx, parent)
			_, _ = s.ListNamespaces(ctx, ListNamespaceOpts{})
		}
	})

	b.Run("ListNamespaces recursive", func(b *testing.B) {
		for b.Loop() {
			parent := randomNamespace(s)
			ctx = namespace.ContextWithNamespace(ctx, parent)
			_, _ = s.ListNamespaces(ctx, ListNamespaceOpts{
				Recursive: true,
			})
		}
	})

	b.Run("ResolveNamespaceFromRequest", func(b *testing.B) {
		for b.Loop() {
			ns := randomNamespace(s)
			_, _ = c.ResolveNamespaceFromRequest(ns.Path, "/sys/namespaces")
		}
	})
}

// can be later on expanded with non-empty namespaces
func BenchmarkClearNamespaceResources(b *testing.B) {
	c, _, _ := TestCoreUnsealed(benchhelpers.TBtoT(b))
	s := c.namespaceStore
	ctx := namespace.RootContext(b.Context())

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
		err := s.clearNamespaceResources(ctx, ns, true)
		require.NoError(b, err)
	}
}

func BenchmarkNamespace_Set(b *testing.B) {
	c, _, _ := TestCoreUnsealed(benchhelpers.TBtoT(b))
	s := c.namespaceStore
	ctx := namespace.RootContext(b.Context())

	defaultSealConfig := &SealConfig{Type: seal.WrapperTypeShamir.String(), SecretShares: 5, SecretThreshold: 3}
	item := &namespace.Namespace{}

	b.Run("SetNamespace", func(b *testing.B) {
		var i int
		for b.Loop() {
			item.Path = "ns" + strconv.Itoa(i)
			_ = s.SetNamespace(ctx, item)
			i += 1
		}
	})

	b.Run("SetNamespaceLocked", func(b *testing.B) {
		var i int
		for b.Loop() {
			item.Path = "ns" + strconv.Itoa(i)
			s.lock.Lock()
			_, _ = s.setNamespaceLocked(ctx, item, nil)
			i += 1
		}
	})

	b.Run("SetNamespaceLockedWithSealConfig", func(b *testing.B) {
		var i int
		for b.Loop() {
			item.Path = "ns" + strconv.Itoa(i)
			s.lock.Lock()
			_, _ = s.setNamespaceLocked(ctx, item, defaultSealConfig)
			i += 1
		}
	})
}

// TestNamespaces_ResolveNamespaceFromRequest verifies namespace resolution logic from request.
func TestNamespaces_ResolveNamespaceFromRequest(t *testing.T) {
	t.Parallel()

	core, _, _ := TestCoreUnsealed(t)
	nsStore := core.namespaceStore

	// Setup only necessary namespaces
	ns1Entry := &namespace.Namespace{Path: "ns1/"}
	ns2Entry := &namespace.Namespace{Path: "ns1/ns2/"}
	ns3Entry := &namespace.Namespace{Path: "ns1/ns2/ns3/"}

	// Create namespaces
	rootCtx := namespace.RootContext(t.Context())

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
	t.Parallel()

	c, keys, root := TestCoreUnsealed(t)
	s := c.namespaceStore

	namespaces := []*namespace.Namespace{
		{Path: "ns1/"},
		{Path: "ns2/"},
		{Path: "ns1/ns3/"},
		{Path: "ns1/ns3/ns4/"},
	}
	TestCoreCreateNamespaces(t, c, namespaces...)

	ctx := namespace.RootContext(t.Context())

	nsKeys, err := s.storage.List(ctx, namespaceStoreSubPath)
	require.NoError(t, err)
	require.Len(t, nsKeys, 2)
	require.ElementsMatch(t, nsKeys, []string{namespaces[0].UUID, namespaces[1].UUID})

	nsKeys, err = s.storage.List(ctx, path.Join(barrier.NamespacePrefix, namespaces[0].UUID, namespaceStoreSubPath)+"/")
	require.NoError(t, err)
	require.Len(t, nsKeys, 1)
	require.ElementsMatch(t, nsKeys, []string{namespaces[2].UUID})

	nsKeys, err = s.storage.List(ctx, path.Join(barrier.NamespacePrefix, namespaces[1].UUID, namespaceStoreSubPath)+"/")
	require.NoError(t, err)
	require.Len(t, nsKeys, 0)

	nsKeys, err = s.storage.List(ctx, path.Join(barrier.NamespacePrefix, namespaces[2].UUID, namespaceStoreSubPath)+"/")
	require.NoError(t, err)
	require.Len(t, nsKeys, 1)
	require.ElementsMatch(t, nsKeys, []string{namespaces[3].UUID})

	nsKeys, err = s.storage.List(ctx, path.Join(barrier.NamespacePrefix, namespaces[3].UUID, namespaceStoreSubPath)+"/")
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

func TestNamespaceDeletionSealingInteraction(t *testing.T) {
	t.Parallel()

	c, keys, _ := TestCoreUnsealed(t)
	s := c.namespaceStore
	ctx := namespace.RootContext(t.Context())

	namespaces := []*namespace.Namespace{
		{Path: "ns1/"},
		{Path: "ns2/"},
		{Path: "ns3/"},
	}
	nsKeys := TestCoreCreateUnsealedNamespaces(t, c, namespaces...)

	t.Run("cannot seal tainted namespace", func(t *testing.T) {
		_, err := s.DeleteNamespace(ctx, "ns1")
		require.NoError(t, err)

		require.Error(t, s.SealNamespace(ctx, "ns1"))
		ns, err := s.GetNamespaceByPath(ctx, "ns1")
		require.NoError(t, err)
		require.NotNil(t, ns)
		require.True(t, ns.Tainted)
		require.False(t, c.NamespaceSealed(ns))

		require.EventuallyWithT(t, func(collect *assert.CollectT) {
			status, err := s.DeleteNamespace(ctx, "ns1")
			require.NoError(collect, err)
			require.Empty(collect, status)
		}, time.Second, 100*time.Millisecond)
	})

	t.Run("seal core while deleting namespace", func(t *testing.T) {
		_, err := s.DeleteNamespace(ctx, "ns2")
		require.NoError(t, err)

		require.NoError(t, TestCoreSeal(c))
		for _, key := range keys {
			unsealed, err := TestCoreUnseal(c, key)
			require.NoError(t, err)
			if unsealed {
				break
			}
		}
		require.False(t, c.Sealed())

		s = c.namespaceStore
		ns, err := s.GetNamespaceByPath(ctx, "ns2")
		require.NoError(t, err)
		require.True(t, ns.Tainted)

		_, err = s.DeleteNamespace(ctx, "ns2")
		require.Error(t, err)

		for _, key := range nsKeys["ns2/"] {
			unsealed, err := TestNamespaceUnseal(c, ns, key)
			require.NoError(t, err)
			if unsealed {
				break
			}
		}
		require.False(t, c.NamespaceSealed(ns))

		require.EventuallyWithT(t, func(collect *assert.CollectT) {
			status, err := s.DeleteNamespace(ctx, "ns2")
			require.NoError(collect, err)
			require.Empty(collect, status)
		}, time.Second, 100*time.Millisecond)
	})

	t.Run("cannot delete currently sealed namespace", func(t *testing.T) {
		require.NoError(t, s.SealNamespace(ctx, "ns3"))

		_, err := s.DeleteNamespace(ctx, "ns3")
		require.ErrorContains(t, err, "namespace is sealed")
	})
}

func TestNamespaceSealResourcesLifecycle(t *testing.T) {
	t.Parallel()

	c, _, rootToken := TestCoreUnsealed(t)
	c.credentialBackends["approle"] = credAppRole.Factory
	c.logicalBackends["noop"] = func(ctx context.Context, config *logical.BackendConfig) (logical.Backend, error) {
		return &be.Noop{
			BackendType: logical.TypeLogical,
		}, nil
	}

	s := c.namespaceStore
	ctx := namespace.RootContext(t.Context())

	ns := &namespace.Namespace{Path: "ns1/"}
	nsCtx := namespace.ContextWithNamespace(ctx, ns)
	nsKeys := TestCoreCreateUnsealedNamespaces(t, c, ns)

	ns2, _, err := c.namespaceStore.ModifyNamespaceByPath(nsCtx, "ns2/", nil, func(ctx context.Context, obj *namespace.Namespace) (*namespace.Namespace, error) {
		return obj, nil
	})
	require.NoError(t, err)
	require.NotNil(t, ns2)

	tPolicy := `
		name = "tPolicy"
		path "ns1/*" {
			policy = "sudo"
		}
	`
	p, err := policy.ParseACLPolicy(ns, tPolicy)
	require.NoError(t, err)
	require.NoError(t, c.policyStore.SetPolicy(nsCtx, p, nil))

	approleMe := &routing.MountEntry{
		Table: routing.CredentialTableType,
		Path:  "approle/",
		Type:  "approle",
	}
	require.NoError(t, c.enableCredential(nsCtx, approleMe))

	require.NoError(t, c.mount(nsCtx, &routing.MountEntry{
		Table: routing.MountTableType,
		Path:  "foo",
		Type:  "noop",
	}))

	alias := &logical.Alias{
		MountType:     "approle",
		MountAccessor: approleMe.Accessor,
		Name:          "approleuser",
	}

	entity, _, err := c.identityStore.CreateOrFetchEntity(nsCtx, alias)
	require.NoError(t, err)
	require.NotNil(t, entity)

	mConfig := &mfa.Config{Name: "mConfig", NamespaceID: ns.ID, ID: "mConfigID", Type: ident.MfaMethodTypeTOTP, Config: &mfa.Config_TOTPConfig{
		TOTPConfig: &mfa.TOTPConfig{},
	}}
	require.NoError(t, c.loginMFABackend.PutMFAConfigByID(nsCtx, mConfig))
	require.NoError(t, c.loginMFABackend.MemDBUpsertMFAConfig(nsCtx, mConfig))

	eConfig := &mfa.MFAEnforcementConfig{Name: "eConfig", NamespaceID: ns.ID, ID: "eConfigID"}
	require.NoError(t, c.loginMFABackend.PutMFALoginEnforcementConfig(nsCtx, eConfig, ns))
	require.NoError(t, c.loginMFABackend.MemDBUpsertMFALoginEnforcementConfig(nsCtx, eConfig))

	resp, err := c.HandleRequest(nsCtx, &logical.Request{
		Path:        "auth/approle/role/testing",
		Operation:   logical.CreateOperation,
		ClientToken: rootToken,
	})
	require.NoError(t, err)
	require.Nil(t, resp)

	resp, err = c.HandleRequest(nsCtx, &logical.Request{
		Path:        "auth/approle/role/testing/role-id",
		Operation:   logical.ReadOperation,
		ClientToken: rootToken,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Contains(t, resp.Data, "role_id")
	roleId := resp.Data["role_id"].(string)

	resp, err = c.HandleRequest(nsCtx, &logical.Request{
		Path:        "auth/approle/role/testing/secret-id",
		Operation:   logical.CreateOperation,
		ClientToken: rootToken,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Contains(t, resp.Data, "secret_id")
	secretId := resp.Data["secret_id"].(string)

	authResp, err := c.HandleRequest(nsCtx, &logical.Request{
		Path:      "auth/approle/login",
		Operation: logical.CreateOperation,
		Data: map[string]any{
			"role_id":   roleId,
			"secret_id": secretId,
		},
	})
	require.NoError(t, err)
	require.NotNil(t, authResp)

	t.Logf("\n\nauth: %#v\n\n", authResp)

	checkState := func() {
		// policies
		policies, err := c.policyStore.ListPolicies(nsCtx, policy.TypeACL, false)
		require.NoError(t, err)
		require.Len(t, policies, 3)

		// auth mounts
		authMounts, err := c.auth.FindAllNamespaceMounts(nsCtx)
		require.NoError(t, err)
		require.Len(t, authMounts, 2)

		// mounts
		mounts, err := c.mounts.FindAllNamespaceMounts(nsCtx)
		require.NoError(t, err)
		require.Len(t, mounts, 4)

		// identity
		counts, err := c.identityStore.CountEntitiesByNamespace(nsCtx)
		require.NoError(t, err)
		require.Equal(t, 2, counts[ns.ID])

		// mfa
		mfaMethods, err := c.loginMFABackend.MfaMethodList(nsCtx, "")
		require.NoError(t, err)
		require.Len(t, mfaMethods, 1)
		enfConfigs, err := c.loginMFABackend.MfaLoginEnforcementList(nsCtx)
		require.NoError(t, err)
		require.Len(t, enfConfigs, 1)

		// namespaces
		childNs, err := c.namespaceStore.ListNamespaces(nsCtx, ListNamespaceOpts{
			Recursive: true,
		})
		require.NoError(t, err)
		require.Equal(t, 1, len(childNs))

		// leases
		require.EventuallyWithT(t, func(collect *assert.CollectT) {
			found := false
			c.expiration.pending.Range(func(keyRaw any, _ any) bool {
				key := keyRaw.(string)
				if ns.MatchesID(key) {
					found = true
				}

				return true
			})
			require.True(collect, found)
		}, time.Second, 100*time.Millisecond)
	}

	checkState()

	// verify after seal
	require.NoError(t, s.SealNamespace(ctx, ns.Path))
	baseView := NamespaceScopedView(c.barrier, ns)

	_, err = c.policyStore.ListPolicies(nsCtx, policy.TypeACL, false)
	require.Error(t, err)
	keys, err := baseView.SubView(barrier.SystemBarrierPrefix+policy.ACLSubPath).List(ctx, "")
	require.NoError(t, err)
	require.Len(t, keys, 3)

	authMounts, err := c.auth.FindAllNamespaceMounts(nsCtx)
	require.NoError(t, err)
	require.Len(t, authMounts, 0)

	mounts, err := c.mounts.FindAllNamespaceMounts(nsCtx)
	require.NoError(t, err)
	require.Len(t, mounts, 0)

	require.Nil(t, c.identityStore.View(nsCtx))
	counts, err := c.identityStore.CountEntitiesByNamespace(nsCtx)
	require.NoError(t, err)
	require.Equal(t, 0, counts[ns.ID])

	mfaMethods, err := c.loginMFABackend.MfaMethodList(ctx, "")
	require.NoError(t, err)
	require.Len(t, mfaMethods, 0)

	mfaEnfConfigs, err := c.loginMFABackend.MfaLoginEnforcementList(nsCtx)
	require.NoError(t, err)
	require.Len(t, mfaEnfConfigs, 0)

	for _, key := range nsKeys[ns.Path] {
		unsealed, err := TestNamespaceUnseal(c, ns, key)
		require.NoError(t, err)
		if unsealed {
			break
		}
	}

	require.False(t, c.NamespaceSealed(ns))

	// verify after unseal
	checkState()
}
