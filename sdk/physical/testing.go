// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package physical

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func sortaEqualSlice(t testing.TB, expected []string, actual []string, msg string, args ...interface{}) {
	if len(expected) == 0 {
		require.Equal(t, len(expected), len(actual), msg, args)
	} else {
		require.Equal(t, expected, actual, msg, args)
	}
}

func testListAndPage(t testing.TB, b Backend, prefix string, expected []string) {
	keys, err := b.List(context.Background(), prefix)
	require.NoError(t, err, "initial list failed")
	sortaEqualSlice(t, expected, keys, "expected list to match")

	page, err := b.ListPage(context.Background(), prefix, "", -100)
	require.NoError(t, err, "initial list page failed")
	sortaEqualSlice(t, expected, page, "expected list page to match")

	page, err = b.ListPage(context.Background(), prefix, ".", -100)
	require.NoError(t, err, "initial list page failed")
	sortaEqualSlice(t, expected, page, "expected list page with after=. to match bare list")

	page, err = b.ListPage(context.Background(), prefix, "", -1)
	require.NoError(t, err, "initial list page failed")
	sortaEqualSlice(t, expected, page, "expected list page to match")

	page, err = b.ListPage(context.Background(), prefix, "", 0)
	require.NoError(t, err, "initial list page failed")
	sortaEqualSlice(t, expected, page, "expected list page to match")

	page, err = b.ListPage(context.Background(), prefix, "", len(expected))
	require.NoError(t, err, "initial list page failed")
	sortaEqualSlice(t, expected, page, "expected list page to match")

	page, err = b.ListPage(context.Background(), prefix, "", len(expected)+1)
	require.NoError(t, err, "initial list page failed")
	sortaEqualSlice(t, expected, page, "expected list page to match")

	if len(expected) > 0 {
		// Fetch pages one at a time.
		page, err = b.ListPage(context.Background(), prefix, "", 1)
		require.NoError(t, err, "list page failed")
		require.Equal(t, 1, len(page), "expected only a single entry")
		require.Equal(t, expected[0], page[0], "expected list page to match first entry")

		for index, after := range expected {
			entry := ""
			if index+1 < len(expected) {
				entry = expected[index+1]
			}

			page, err = b.ListPage(context.Background(), prefix, after, 1)
			require.NoError(t, err, "list page failed")
			if entry != "" {
				require.Equal(t, 1, len(page), "expected only a single entry")
				require.Equal(t, entry, page[0], "expected list page to match entry at index %v", index+1)

				// Now fetch all subsequent entries and ensure subset matches.
				page, err = b.ListPage(context.Background(), prefix, after, -1)
				require.NoError(t, err, "list page failed")
				sortaEqualSlice(t, expected[index+1:], page, "expected contents of pages to match")

				page, err = b.ListPage(context.Background(), prefix, after, len(expected))
				require.NoError(t, err, "list page failed")
				sortaEqualSlice(t, expected[index+1:], page, "expected contents of pages to match")

				page, err = b.ListPage(context.Background(), prefix, after, len(expected)-index-1)
				require.NoError(t, err, "list page failed")
				sortaEqualSlice(t, expected[index+1:], page, "expected contents of pages to match")
			} else {
				require.Equal(t, 0, len(page), "expected no entries: page=%v / index=%v / after=%v / entry=%v / expected=%v", page, index, after, entry, expected)
			}

			// Then fetch all previous entries and ensure subset matches.
			page, err = b.ListPage(context.Background(), prefix, "", index+1)
			require.NoError(t, err, "list page failed")
			require.Equal(t, expected[:index+1], page, "expected prefix contents to match")
		}

		// Creating a fake reference point before the current
		// one should yield everything.
		if len(expected[0]) > 1 {
			basis := string(expected[0][0])
			page, err = b.ListPage(context.Background(), prefix, basis, -1)
			require.NoError(t, err, "list page failed")
			require.Equal(t, expected, page, "expected previous basis to yield everything")
		} else if expected[0] >= "\x02" {
			basis := "\x01"
			page, err = b.ListPage(context.Background(), prefix, basis, -1)
			require.NoError(t, err, "list page failed")
			require.Equal(t, expected, page, "expected previous basis to yield everything")
		}

		// Creating a fake reference point after the last result
		// should yield nothing.
		basis := expected[len(expected)-1] + "z"
		page, err = b.ListPage(context.Background(), prefix, basis, -1)
		require.NoError(t, err, "list page failed")
		sortaEqualSlice(t, nil, page, "expected list page to be empty with later reference")
	} else {
		// Make sure giving a bogus after entry doesn't change the result.
		page, err = b.ListPage(context.Background(), prefix, "bogus", -1)
		require.NoError(t, err, "initial list page failed")
		sortaEqualSlice(t, expected, page, "expected list page to match")

		page, err = b.ListPage(context.Background(), prefix, "bogus", 2)
		require.NoError(t, err, "initial list page failed")
		sortaEqualSlice(t, expected, page, "expected list page to match")
	}
}

func ExerciseBackend(t testing.TB, b Backend) {
	t.Helper()

	// Initial list should be empty
	testListAndPage(t, b, "", nil)

	// Delete should work if it does not exist
	err := b.Delete(context.Background(), "foo")
	if err != nil {
		t.Fatalf("idempotent delete: %v", err)
	}

	// Get should not fail, but be nil
	out, err := b.Get(context.Background(), "foo")
	if err != nil {
		t.Fatalf("initial get failed: %v", err)
	}
	if out != nil {
		t.Errorf("initial get was not nil: %v", out)
	}

	// Make an entry
	e := &Entry{Key: "foo", Value: []byte("test")}
	err = b.Put(context.Background(), e)
	if err != nil {
		t.Fatalf("put failed: %v", err)
	}

	// Get should work
	out, err = b.Get(context.Background(), "foo")
	if err != nil {
		t.Fatalf("get failed: %v", err)
	}
	if !reflect.DeepEqual(out, e) {
		t.Errorf("bad: %v expected: %v", out, e)
	}

	// List should not be empty
	testListAndPage(t, b, "", []string{"foo"})

	// Delete should work
	err = b.Delete(context.Background(), "foo")
	if err != nil {
		t.Fatalf("delete: %v", err)
	}

	// List should be empty
	testListAndPage(t, b, "", nil)

	// Get should not fail, but be nil again
	out, err = b.Get(context.Background(), "foo")
	if err != nil {
		t.Fatalf("get after delete: %v", err)
	}
	if out != nil {
		t.Errorf("get after delete not nil: %v", out)
	}

	// Multiple Puts should work; GH-189
	e = &Entry{Key: "foo", Value: []byte("test")}
	err = b.Put(context.Background(), e)
	if err != nil {
		t.Fatalf("multi put 1 failed: %v", err)
	}
	e = &Entry{Key: "foo", Value: []byte("test")}
	err = b.Put(context.Background(), e)
	if err != nil {
		t.Fatalf("multi put 2 failed: %v", err)
	}

	// Make a nested entry
	e = &Entry{Key: "foo/bar", Value: []byte("baz")}
	err = b.Put(context.Background(), e)
	if err != nil {
		t.Fatalf("nested put failed: %v", err)
	}

	// Get should work
	out, err = b.Get(context.Background(), "foo/bar")
	if err != nil {
		t.Fatalf("get failed: %v", err)
	}
	if !reflect.DeepEqual(out, e) {
		t.Errorf("bad: %v expected: %v", out, e)
	}

	// List should have both a key and a subtree.
	testListAndPage(t, b, "", []string{"foo", "foo/"})

	// Delete with children should work
	err = b.Delete(context.Background(), "foo")
	if err != nil {
		t.Fatalf("delete after multi: %v", err)
	}

	// Get should return the child
	out, err = b.Get(context.Background(), "foo/bar")
	if err != nil {
		t.Fatalf("get after multi delete: %v", err)
	}
	if out == nil {
		t.Errorf("get after multi delete not nil: %v", out)
	}

	// Removal of nested secret should not leave artifacts
	e = &Entry{Key: "foo/nested1/nested2/nested3", Value: []byte("baz")}
	err = b.Put(context.Background(), e)
	if err != nil {
		t.Fatalf("deep nest: %v", err)
	}

	err = b.Delete(context.Background(), "foo/nested1/nested2/nested3")
	if err != nil {
		t.Fatalf("failed to remove deep nest: %v", err)
	}

	testListAndPage(t, b, "foo/", []string{"bar"})

	// Make a second nested entry to test prefix removal
	e = &Entry{Key: "foo/zip", Value: []byte("zap")}
	err = b.Put(context.Background(), e)
	if err != nil {
		t.Fatalf("failed to create second nested: %v", err)
	}

	// Delete should not remove the prefix
	err = b.Delete(context.Background(), "foo/bar")
	if err != nil {
		t.Fatalf("failed to delete nested prefix: %v", err)
	}

	testListAndPage(t, b, "", []string{"foo/"})

	// Delete should remove the prefix
	err = b.Delete(context.Background(), "foo/zip")
	if err != nil {
		t.Fatalf("failed to delete second prefix: %v", err)
	}

	testListAndPage(t, b, "", nil)

	// When the root path is empty, adding and removing deep nested values should not break listing
	e = &Entry{Key: "foo/nested1/nested2/value1", Value: []byte("baz")}
	err = b.Put(context.Background(), e)
	if err != nil {
		t.Fatalf("deep nest: %v", err)
	}

	e = &Entry{Key: "foo/nested1/nested2/value2", Value: []byte("baz")}
	err = b.Put(context.Background(), e)
	if err != nil {
		t.Fatalf("deep nest: %v", err)
	}

	err = b.Delete(context.Background(), "foo/nested1/nested2/value2")
	if err != nil {
		t.Fatalf("failed to remove deep nest: %v", err)
	}

	keys, err := b.List(context.Background(), "")
	if err != nil {
		t.Fatalf("listing of root failed after deletion: %v", err)
	}
	if len(keys) == 0 {
		t.Errorf("root is returning empty after deleting a single nested value, expected nested1/: %v", keys)
		keys, err = b.List(context.Background(), "foo/nested1")
		if err != nil {
			t.Fatalf("listing of expected nested path 'foo/nested1' failed: %v", err)
		}
		// prove that the root should not be empty and that foo/nested1 exists
		if len(keys) != 0 {
			t.Logf("  keys can still be listed from nested1/ so it's not empty, expected nested2/: %v", keys)
		}
	}
	testListAndPage(t, b, "", []string{"foo/"})

	// cleanup left over listing bug test value
	err = b.Delete(context.Background(), "foo/nested1/nested2/value1")
	if err != nil {
		t.Fatalf("failed to remove deep nest: %v", err)
	}

	testListAndPage(t, b, "", nil)

	// Create multiple items in a path iteratively and ensure
	// paginated lists work as expected.
	var created []string
	for i := 0; i < 10; i++ {
		name := fmt.Sprintf("key-%d", i)
		e = &Entry{Key: "foo/" + name, Value: []byte("baz")}
		err = b.Put(context.Background(), e)
		if err != nil {
			t.Fatalf("deep nest: %v", err)
		}

		created = append(created, name)
		testListAndPage(t, b, "foo/", created)
	}
	for _, name := range created {
		err = b.Delete(context.Background(), "foo/"+name)
		if err != nil {
			t.Fatalf("failed to remove deep nest: %v", err)
		}
	}
}

func ExerciseBackend_ListPrefix(t testing.TB, b Backend) {
	t.Helper()

	e1 := &Entry{Key: "foo", Value: []byte("test")}
	e2 := &Entry{Key: "foo/bar", Value: []byte("test")}
	e3 := &Entry{Key: "foo/bar/baz", Value: []byte("test")}

	defer func() {
		b.Delete(context.Background(), "foo")
		b.Delete(context.Background(), "foo/bar")
		b.Delete(context.Background(), "foo/bar/baz")
	}()

	err := b.Put(context.Background(), e1)
	if err != nil {
		t.Fatalf("failed to put entry 1: %v", err)
	}
	err = b.Put(context.Background(), e2)
	if err != nil {
		t.Fatalf("failed to put entry 2: %v", err)
	}
	err = b.Put(context.Background(), e3)
	if err != nil {
		t.Fatalf("failed to put entry 3: %v", err)
	}

	// Scan the root
	keys, err := b.List(context.Background(), "")
	if err != nil {
		t.Fatalf("list root: %v", err)
	}
	sort.Strings(keys)
	if len(keys) != 2 || keys[0] != "foo" || keys[1] != "foo/" {
		t.Errorf("root expected [foo foo/]: %v", keys)
	}

	// Scan foo/
	keys, err = b.List(context.Background(), "foo/")
	if err != nil {
		t.Fatalf("list level 1: %v", err)
	}
	sort.Strings(keys)
	if len(keys) != 2 || keys[0] != "bar" || keys[1] != "bar/" {
		t.Errorf("level 1 expected [bar bar/]: %v", keys)
	}

	// Scan foo/bar/
	keys, err = b.List(context.Background(), "foo/bar/")
	if err != nil {
		t.Fatalf("list level 2: %v", err)
	}
	sort.Strings(keys)
	if len(keys) != 1 || keys[0] != "baz" {
		t.Errorf("level 1 expected [baz]: %v", keys)
	}
}

func ExerciseHABackend(t testing.TB, b HABackend, b2 HABackend) {
	t.Helper()

	// Get the lock
	lock, err := b.LockWith("foo", "bar")
	if err != nil {
		t.Fatalf("initial lock: %v", err)
	}

	// Attempt to lock
	leaderCh, err := lock.Lock(nil)
	if err != nil {
		t.Fatalf("lock attempt 1: %v", err)
	}
	if leaderCh == nil {
		t.Fatalf("missing leaderCh")
	}

	// Check the value
	held, val, err := lock.Value()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !held {
		t.Errorf("should be held")
	}
	if val != "bar" {
		t.Errorf("expected value bar: %v", err)
	}

	// Check if it's fencing that we can register the lock
	if fba, ok := b.(FencingHABackend); ok {
		require.NoError(t, fba.RegisterActiveNodeLock(lock))
	}

	// Second acquisition should fail
	lock2, err := b2.LockWith("foo", "baz")
	if err != nil {
		t.Fatalf("lock 2: %v", err)
	}

	// Checking the lock from b2 should discover that the lock is held since held
	// implies only that there is _some_ leader not that b2 is leader (this was
	// not clear before so we make it explicit with this assertion).
	held2, val2, err := lock2.Value()
	require.NoError(t, err)
	require.Equal(t, "bar", val2)
	require.True(t, held2)

	// Cancel attempt in 50 msec
	stopCh := make(chan struct{})
	time.AfterFunc(50*time.Millisecond, func() {
		close(stopCh)
	})

	// Attempt to lock
	leaderCh2, err := lock2.Lock(stopCh)
	if err != nil {
		t.Fatalf("stop lock 2: %v", err)
	}
	if leaderCh2 != nil {
		t.Errorf("should not have gotten leaderCh: %v", leaderCh2)
	}

	// Release the first lock
	lock.Unlock()

	// Attempt to lock should work
	leaderCh2, err = lock2.Lock(nil)
	if err != nil {
		t.Fatalf("lock 2 lock: %v", err)
	}
	if leaderCh2 == nil {
		t.Errorf("should get leaderCh")
	}

	// Check if it's fencing that we can register the lock
	if fba2, ok := b2.(FencingHABackend); ok {
		require.NoError(t, fba2.RegisterActiveNodeLock(lock))
	}

	// Check the value
	held, val, err = lock2.Value()
	if err != nil {
		t.Fatalf("value: %v", err)
	}
	if !held {
		t.Errorf("should still be held")
	}
	if val != "baz" {
		t.Errorf("expected: baz, got: %v", val)
	}

	// Cleanup
	lock2.Unlock()
}

func ExerciseTransactionalBackend(t testing.TB, b TransactionalBackend) {
	t.Helper()

	// Creating a transaction and committing or rolling it back without doing
	// anything should succeed, regardless of type of transaction. Doing the
	// same operation twice should fail as the transaction was already
	// finished.
	txn, err := b.BeginTx(context.Background())
	require.NoError(t, err, "failed to begin read-write transaction")
	err = txn.Commit(context.Background())
	require.NoError(t, err, "failed to commit transaction with no entries")
	err = txn.Commit(context.Background())
	require.Error(t, err, "expected double commit of transaction to fail")

	txn, err = b.BeginReadOnlyTx(context.Background())
	require.NoError(t, err, "failed to begin read-only transaction")
	err = txn.Commit(context.Background())
	require.NoError(t, err, "failed to commit read-only transaction with no entries")
	err = txn.Commit(context.Background())
	require.Error(t, err, "expected double commit of read-only transaction to fail")

	txn, err = b.BeginTx(context.Background())
	require.NoError(t, err, "failed to begin second read-write transaction")
	err = txn.Rollback(context.Background())
	require.NoError(t, err, "failed to rollback transaction with no entries")
	err = txn.Rollback(context.Background())
	require.Error(t, err, "expected double rollback of transaction to fail")

	txn, err = b.BeginReadOnlyTx(context.Background())
	require.NoError(t, err, "failed to begin second read-only transaction")
	err = txn.Rollback(context.Background())
	require.NoError(t, err, "failed to rollback read-only transaction with no entries")
	err = txn.Rollback(context.Background())
	require.Error(t, err, "expected double rollback of read-only transaction to fail")

	// This should also be true if we swap types (commit->rollback and
	// visa-versa).
	txn, err = b.BeginTx(context.Background())
	require.NoError(t, err, "failed to begin read-write transaction")
	err = txn.Commit(context.Background())
	require.NoError(t, err, "failed to commit transaction with no entries")
	err = txn.Rollback(context.Background())
	require.Error(t, err, "expected subsequent rollback of transaction to fail")

	txn, err = b.BeginReadOnlyTx(context.Background())
	require.NoError(t, err, "failed to begin read-only transaction")
	err = txn.Commit(context.Background())
	require.NoError(t, err, "failed to commit read-only transaction with no entries")
	err = txn.Rollback(context.Background())
	require.Error(t, err, "expected subsequent rollback of read-only transaction to fail")

	txn, err = b.BeginTx(context.Background())
	require.NoError(t, err, "failed to begin second read-write transaction")
	err = txn.Rollback(context.Background())
	require.NoError(t, err, "failed to rollback transaction with no entries")
	err = txn.Commit(context.Background())
	require.Error(t, err, "expected subsequent commit of transaction to fail")

	txn, err = b.BeginReadOnlyTx(context.Background())
	require.NoError(t, err, "failed to begin second read-only transaction")
	err = txn.Rollback(context.Background())
	require.NoError(t, err, "failed to rollback read-only transaction with no entries")
	err = txn.Commit(context.Background())
	require.Error(t, err, "expected subsequent commit of read-only transaction to fail")

	// Empty transactions can be interwoven.
	txn1, err := b.BeginTx(context.Background())
	require.NoError(t, err, "failed to begin first interwoven transaction")
	txn2, err := b.BeginTx(context.Background())
	require.NoError(t, err, "failed to begin second interwoven transaction")
	err = txn2.Commit(context.Background())
	require.NoError(t, err, "failed to commit second interwoven transaction")
	err = txn1.Commit(context.Background())
	require.NoError(t, err, "failed to commit second interwoven transaction")

	// Writing to a read-only transaction should fail; committing this
	// transaction should have no impact on storage.
	entry := &Entry{Key: "foo", Value: []byte("test")}

	rtx, err := b.BeginReadOnlyTx(context.Background())
	require.NoError(t, err, "failed to create read-only transaction for writing")
	err = rtx.Put(context.Background(), entry)
	require.Error(t, err, "expected failure to put in read-only transaction")
	err = rtx.Delete(context.Background(), "foo")
	require.Error(t, err, "expected failure to delete in read-only transaction")

	err = rtx.Commit(context.Background())
	require.NoError(t, err, "failed to commit empty read-only transaction")

	entries, err := b.List(context.Background(), "")
	require.NoError(t, err, "failed to list storage entries")
	require.Empty(t, entries, "expected nothing in storage")

	// Creating the same entry in two transactions should conflict the
	// second committed one, even though they have the same contents.

	txn1, err = b.BeginTx(context.Background())
	require.NoError(t, err, "failed to begin first conflicting transaction")
	txn2, err = b.BeginTx(context.Background())
	require.NoError(t, err, "failed to begin second conflicting transaction")

	err = txn1.Put(context.Background(), entry)
	require.NoError(t, err, "unexpected failure writing to first transaction")
	err = txn2.Put(context.Background(), entry)
	require.NoError(t, err, "unexpected failure writing to second transaction")

	err = txn1.Commit(context.Background())
	require.NoError(t, err, "failed to commit first conflicting transaction")
	err = txn2.Commit(context.Background())
	require.Error(t, err, "expected failure to commit second conflicting transaction")

	result, err := b.Get(context.Background(), "foo")
	require.NoError(t, err, "failed to read storage entry")
	require.Equal(t, result.Value, []byte("test"))

	bazEntry := &Entry{Key: "foo", Value: []byte("baz")}

	txn1, err = b.BeginTx(context.Background())
	require.NoError(t, err, "failed to begin first conflicting transaction (round 2)")
	txn2, err = b.BeginTx(context.Background())
	require.NoError(t, err, "failed to begin second conflicting transaction (round 2)")

	err = txn1.Put(context.Background(), bazEntry)
	require.NoError(t, err, "unexpected failure writing to first transaction (round 2)")
	err = txn2.Put(context.Background(), bazEntry)
	require.NoError(t, err, "unexpected failure writing to second transaction (round 2)")

	err = txn2.Commit(context.Background())
	require.NoError(t, err, "failed to commit second conflicting transaction")
	err = txn1.Commit(context.Background())
	require.Error(t, err, "expected failure to commit first conflicting transaction")

	result, err = b.Get(context.Background(), "foo")
	require.NoError(t, err, "failed to read storage entry")
	require.Equal(t, result.Value, []byte("baz"))

	// Creating different entries in two transactions should be fine.

	txn1, err = b.BeginTx(context.Background())
	require.NoError(t, err, "failed to begin first parallel transaction")
	txn2, err = b.BeginTx(context.Background())
	require.NoError(t, err, "failed to begin second parallel transaction")

	barEntry := &Entry{Key: "bar", Value: []byte("baz")}
	err = txn1.Put(context.Background(), entry)
	require.NoError(t, err, "unexpected failure writing to first transaction")
	err = txn2.Put(context.Background(), barEntry)
	require.NoError(t, err, "unexpected failure writing to second transaction")

	err = txn1.Commit(context.Background())
	require.NoError(t, err, "failed to commit first parallel transaction")
	err = txn2.Commit(context.Background())
	require.NoError(t, err, "failed to commit second parallel transaction")

	result, err = b.Get(context.Background(), "foo")
	require.NoError(t, err, "failed to read storage entry")
	require.Equal(t, result.Value, []byte("test"))

	result, err = b.Get(context.Background(), "bar")
	require.NoError(t, err, "failed to read storage entry")
	require.Equal(t, result.Value, []byte("baz"))

	// Getting an item and writing to the same item in different transactions
	// should fail one of the two.

	txn1, err = b.BeginTx(context.Background())
	require.NoError(t, err, "failed to begin first parallel transaction")
	txn2, err = b.BeginTx(context.Background())
	require.NoError(t, err, "failed to begin second parallel transaction")

	result, err = txn1.Get(context.Background(), "bar")
	require.NoError(t, err, "failed to read storage entry in first transaction")
	require.Equal(t, result.Value, []byte("baz"))
	err = txn1.Put(context.Background(), bazEntry)
	require.NoError(t, err, "failed to put storage entry in first transaction")

	result, err = txn2.Get(context.Background(), "foo")
	require.NoError(t, err, "failed to read storage entry in second transaction")
	require.Equal(t, result.Value, []byte("test"))
	barTestEntry := &Entry{Key: "bar", Value: []byte("test")}
	err = txn2.Put(context.Background(), barTestEntry)
	require.NoError(t, err, "failed to put storage entry in second transaction")

	err = txn1.Commit(context.Background())
	require.NoError(t, err, "failed to commit first conflicting read transaction")
	err = txn2.Commit(context.Background())
	require.Error(t, err, "expected failure to commit second conflicting read transaction")

	result, err = b.Get(context.Background(), "foo")
	require.NoError(t, err, "failed to read storage entry")
	require.Equal(t, result.Value, []byte("baz"))

	result, err = b.Get(context.Background(), "bar")
	require.NoError(t, err, "failed to read storage entry")
	require.Equal(t, result.Value, []byte("baz"))

	// Try again, with delete this time, committing in a different order.

	txn1, err = b.BeginTx(context.Background())
	require.NoError(t, err, "failed to begin first parallel transaction")
	txn2, err = b.BeginTx(context.Background())
	require.NoError(t, err, "failed to begin second parallel transaction")

	result, err = txn1.Get(context.Background(), "bar")
	require.NoError(t, err, "failed to read storage entry in first transaction")
	require.Equal(t, result.Value, []byte("baz"))
	err = txn1.Delete(context.Background(), "foo")
	require.NoError(t, err, "failed to delete storage entry in first transaction")

	result, err = txn2.Get(context.Background(), "foo")
	require.NoError(t, err, "failed to read storage entry in second transaction")
	require.Equal(t, result.Value, []byte("baz"))
	err = txn2.Delete(context.Background(), "bar")
	require.NoError(t, err, "failed to delete storage entry in second transaction")

	err = txn2.Commit(context.Background())
	require.NoError(t, err, "failed to commit second conflicting read transaction")
	err = txn1.Commit(context.Background())
	require.Error(t, err, "expected failure to commit first conflicting read transaction")

	result, err = b.Get(context.Background(), "foo")
	require.NoError(t, err, "failed to read storage entry")
	require.Equal(t, result.Value, []byte("baz"))

	entries, err = b.List(context.Background(), "")
	require.NoError(t, err, "failed to list storage entries")
	require.Equal(t, entries, []string{"foo"}, "expected only a single entry in storage")

	// Reading entries that don't exist shouldn't cause issues.
	txn, err = b.BeginTx(context.Background())
	require.NoError(t, err, "failed to begin empty-read transaction")

	result, err = txn.Get(context.Background(), "bar")
	require.NoError(t, err, "failed to read storage entry in first transaction")
	if result != nil {
		require.Equal(t, len(result.Value), 0, "expected empty storage entry `bar`")
	}

	result, err = txn.Get(context.Background(), "foo")
	require.NoError(t, err, "failed to read storage entry in second transaction")
	require.Equal(t, result.Value, []byte("baz"))

	err = txn.Delete(context.Background(), "foo")
	require.NoError(t, err, "failed to delete entry in transaction")

	err = txn.Commit(context.Background())
	require.NoError(t, err, "failed to commit deletion transaction")

	// Ensure we left it as we found it.
	entries, err = b.List(context.Background(), "")
	require.NoError(t, err, "failed to list storage entries")
	require.Empty(t, entries, "expected nothing in storage")
}
