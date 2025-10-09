// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package physical

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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
		t.Fatal("missing leaderCh")
	}

	// Check the value
	held, val, err := lock.Value()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !held {
		t.Error("should be held")
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
		t.Error("should get leaderCh")
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
		t.Error("should still be held")
	}
	if val != "baz" {
		t.Errorf("expected: baz, got: %v", val)
	}

	// Cleanup
	lock2.Unlock()
}

func ExerciseTransactionalBackend(t testing.TB, b TransactionalBackend) {
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

	// Ensure writes issued before reads commit OK.
	foo := &Entry{Key: "foo", Value: []byte("foo")}
	txn, err = b.BeginTx(context.Background())
	require.NoError(t, err, "failed to start new transaction")
	err = txn.Put(context.Background(), foo)
	require.NoError(t, err, "failed to write entry")
	entry, err := txn.Get(context.Background(), "foo")
	require.NoError(t, err, "failed to read entry")
	require.NotNil(t, entry, "expected to get a non-empty entry")
	require.Equal(t, string(entry.Value), "foo", "expected written value")
	entries, err := txn.List(context.Background(), "")
	require.NoError(t, err, "failed to list entries")
	require.Equal(t, entries, []string{"foo"}, "expected one entry in storage")
	err = txn.Commit(context.Background())
	require.NoError(t, err, "failed to commit transaction")

	// Ensure reads before writes commit OK.
	txn, err = b.BeginTx(context.Background())
	require.NoError(t, err, "failed to start new transaction")
	entries, err = txn.List(context.Background(), "")
	require.NoError(t, err, "failed to list entries")
	require.Equal(t, entries, []string{"foo"}, "expected one entry in storage")
	entry, err = txn.Get(context.Background(), "foo")
	require.NoError(t, err, "failed to read entry")
	require.NotNil(t, entry, "expected to get a non-empty entry")
	require.Equal(t, string(entry.Value), "foo", "expected written value")
	err = txn.Delete(context.Background(), "foo")
	require.NoError(t, err, "failed to delete entry")
	err = txn.Commit(context.Background())
	require.NoError(t, err, "failed to commit transaction")

	// Ensure we have an empty storage
	entries, err = b.List(context.Background(), "")
	require.NoError(t, err, "failed to list storage entries")
	require.Empty(t, entries, "expected nothing in storage")

	// Run tests which ensure exclusive writers behave correctly (those which
	// only write, with no reads).
	testTransactionalExclusiveWriters(t, b)

	// Run tests which ensure mixed writers behave correctly (those execute
	// both reads and writes).
	testTransactionalMixedWriters(t, b)

	// Ensure we left it as we found it.
	entries, err = b.List(context.Background(), "")
	require.NoError(t, err, "failed to list storage entries")
	require.Empty(t, entries, "expected nothing in storage")
}

func testTransactionalExclusiveWriters(t testing.TB, b TransactionalBackend) {
	// Now do functionality tests: we have a few readers and writers inside of
	// transactions plus a lister outside of transactions (which should still
	// be atomic relative to the transactions that are occurring). When the
	// writers are done, signal the readers/listers to finish up.
	var wgWriters sync.WaitGroup
	var wgReaders sync.WaitGroup
	var wgListers sync.WaitGroup
	var done atomic.Bool
	var numFiles int = 25
	var numWriters int = 100
	var numWrites int = 25
	var writeBreak int = 50
	var numReaders int = 25
	var readBreak int = 5
	var numListers int = 5
	var listBreak int = 10
	var numErrors atomic.Int32
	for i := 1; i <= numWriters; i++ {
		wgWriters.Add(1)
		go func(worker int) {
			defer wgWriters.Done()
			for write := 1; write <= numWrites; write++ {
				time.Sleep(time.Duration(worker) * time.Millisecond)

				// Write files
				ctx := context.Background()
				txn, err := b.BeginTx(ctx)
				if err != nil {
					t.Logf("[%d/%d] write begin tx failed: %v", worker, write, err)
					numErrors.Add(1)
					return
				}

				for file := 1; file <= numFiles; file++ {
					key := fmt.Sprintf("%d-%d", worker, file)
					value := fmt.Sprintf("%d-%d-%d", worker, write, file)
					entry := &Entry{Key: key, Value: []byte(value)}
					err = txn.Put(ctx, entry)
					if err != nil {
						t.Logf("[%d/%d] write put failed: %v", worker, write, err)
						numErrors.Add(1)
						return
					}
				}

				err = txn.Commit(ctx)
				if err != nil {
					t.Logf("[%d/%d] write commit failed: %v", worker, write, err)
					numErrors.Add(1)
					return
				}

				time.Sleep(time.Duration(writeBreak) * time.Millisecond)

				// Delete files
				txn, err = b.BeginTx(ctx)
				if err != nil {
					t.Logf("[%d/%d] write begin tx failed: %v", worker, write, err)
					numErrors.Add(1)
					return
				}

				for file := 1; file <= numFiles; file++ {
					key := fmt.Sprintf("%d-%d", worker, file)
					err = txn.Delete(ctx, key)
					if err != nil {
						t.Logf("[%d/%d] write put failed: %v", worker, write, err)
						numErrors.Add(1)
						return
					}
				}

				err = txn.Commit(ctx)
				if err != nil {
					t.Logf("[%d/%d] write commit failed: %v", worker, write, err)
					numErrors.Add(1)
					return
				}
			}
		}(i)
	}

	// Validate reads within a transaction are consistent.
	for i := 1; i <= numReaders; i++ {
		wgReaders.Add(1)
		go func(worker int) {
			defer wgReaders.Done()
			var read int = 1
			time.Sleep(time.Duration(worker) * time.Millisecond)

			for {
				switch {
				case done.Load():
					t.Log("shutting down reader")
					return
				default:
					ctx := context.Background()

					txn, err := b.BeginReadOnlyTx(ctx)
					if err != nil {
						t.Logf("[%d/%d] read begin tx failed: %v", worker, read, err)
						numErrors.Add(1)
						return
					}

					list, err := txn.List(ctx, "")
					if err != nil {
						t.Logf("[%d/%d] read list failed: %v", worker, read, err)
						numErrors.Add(1)
						return
					}

					workerFileValueMap := make(map[int]map[int]string)
					for index, key := range list {
						split := strings.Split(key, "-")
						if len(split) != 2 {
							t.Logf("[%d/%d/%d] list item %v had %d components; expected 2", worker, read, index, key, len(split))
							numErrors.Add(1)
							return
						}

						keyWorker, _ := strconv.Atoi(split[0])
						keyFile, _ := strconv.Atoi(split[1])
						if _, ok := workerFileValueMap[keyWorker]; !ok {
							workerFileValueMap[keyWorker] = make(map[int]string)
						}

						entry, err := txn.Get(ctx, key)
						if err != nil {
							t.Logf("[%d/%d/%d] read entry %v failed: %v", worker, read, index, key, err)
							numErrors.Add(1)
							return
						}

						if entry == nil {
							t.Logf("[%d/%d/%d] read entry %v failed: was unexpectedly nil", worker, read, index, key)
							numErrors.Add(1)
							return
						}

						expectedValue, present := workerFileValueMap[keyWorker][keyFile]
						if present {
							if string(entry.Value) != expectedValue {
								t.Logf("[%d/%d/%d] read entry %v failed: different value: expected=%v / actual=%v", worker, read, index, key, expectedValue, string(entry.Value))
								numErrors.Add(1)
								return
							}
						} else {
							workerFileValueMap[keyWorker][keyFile] = string(entry.Value)
						}
					}

					for keyWorker, keyFiles := range workerFileValueMap {
						if len(keyFiles) != 0 && len(keyFiles) != numFiles {
							t.Logf("[%d/%d] read list files failed: expected 0 or %v files due to transaction consistency; got %v for worker %v: %v", worker, read, numFiles, len(keyFiles), keyWorker, keyFiles)
							numErrors.Add(1)
							return
						}
					}

					err = txn.Rollback(ctx)
					if err != nil {
						t.Logf("[%d/%d] read rollback failed: %v", worker, read, err)
						numErrors.Add(1)
						return
					}
				}

				time.Sleep(time.Duration(readBreak) * time.Millisecond)
				read += 1
			}
		}(i)
	}

	// Validate lists outside of a transaction are consistent.
	for i := 1; i <= numListers; i++ {
		wgListers.Add(1)
		go func(worker int) {
			defer wgListers.Done()
			var list int = 1
			time.Sleep(time.Duration(worker) * time.Millisecond)

			for {
				switch {
				case done.Load():
					t.Log("shutting down lister")
					return
				default:
					ctx := context.Background()

					entries, err := b.List(ctx, "")
					if err != nil {
						t.Logf("[%d/%d] list failed: %v", worker, list, err)
					}

					workerFileMap := make(map[int]int)
					for index, key := range entries {
						split := strings.Split(key, "-")
						if len(split) != 2 {
							t.Logf("[%d/%d/%d] list item %v had %d components; expected 2", worker, list, index, key, len(split))
							numErrors.Add(1)
							return
						}

						keyWorker, _ := strconv.Atoi(split[0])
						workerFileMap[keyWorker] += 1
					}

					for keyWorker, keyFiles := range workerFileMap {
						if keyFiles != 0 && keyFiles != numFiles {
							t.Logf("[%d/%d] list files inconsistent: expected 0 or %v files due to transaction consistency; got %v for worker %v: %v", worker, list, numFiles, keyFiles, keyWorker, entries)
							numErrors.Add(1)
							return
						}
					}
				}

				time.Sleep(time.Duration(listBreak) * time.Millisecond)
				list += 1
			}
		}(i)
	}

	// Wait for writers to finish
	wgWriters.Wait()

	// Signal readers and listeners to finish
	done.Store(true)

	// Wait for readers and listers to finish in parallel
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		wgReaders.Wait()
	}()
	go func() {
		defer wg.Done()
		wgListers.Wait()
	}()
	wg.Wait()

	// Handle cleanup
	if numErrors.Load() > 0 {
		t.Fatalf("got %v errors while running test; see log messages for more info", numErrors.Load())
	}
}

func testTransactionalMixedWriters(t testing.TB, b TransactionalBackend) {
	// We have a few readers and writers inside of transactions
	var wgWriters sync.WaitGroup
	var wgReaders sync.WaitGroup
	var done atomic.Bool
	var numFiles int = 25
	var numWriters int = 100
	var numWrites int = 25
	var numReaders int = 25
	var readBreak int = 5
	var numErrors atomic.Int32
	for i := 1; i <= numWriters; i++ {
		wgWriters.Add(1)
		go func(worker int) {
			defer wgWriters.Done()
			for write := 1; write <= numWrites; write++ {
				time.Sleep(time.Duration(worker) * time.Millisecond)

				// Write files
				ctx := context.Background()
				txn, err := b.BeginTx(ctx)
				if err != nil {
					t.Logf("[%d/%d] write begin tx failed: %v", worker, write, err)
					numErrors.Add(1)
					return
				}

				// List files that exist; there should be numFiles of them if
				// write > 1.
				prefix := fmt.Sprintf("%d/", worker)
				results, err := txn.List(context.Background(), prefix)
				if err != nil {
					t.Logf("[%d/%d] write list failed: %v", worker, write, err)
					numErrors.Add(1)
					return
				}

				if write > 1 {
					if len(results) != numFiles {
						t.Logf("[%d/%d] write list failed: expected %v but saw %v entries: %#v", worker, write, numFiles, len(results), results)
						numErrors.Add(1)
						return
					}
				}

				for file := 1; file <= numFiles; file++ {
					// Read files before writing them.
					key := fmt.Sprintf("%d/%d", worker, file)
					expectedValue := fmt.Sprintf("%d-%d-%d", worker, write-1, file)
					existingEntry, err := txn.Get(context.Background(), key)
					if err != nil {
						t.Logf("[%d/%d] write read failed: %v", worker, write, err)
						numErrors.Add(1)
						return
					}

					if existingEntry != nil && string(existingEntry.Value) != expectedValue {
						t.Logf("[%d/%d] write read failed: expected %v ; saw %v in entry %v", worker, write, expectedValue, string(existingEntry.Value), key)
						numErrors.Add(1)
						return
					}

					value := fmt.Sprintf("%d-%d-%d", worker, write, file)
					entry := &Entry{Key: key, Value: []byte(value)}
					err = txn.Put(ctx, entry)
					if err != nil {
						t.Logf("[%d/%d] write put failed: %v", worker, write, err)
						numErrors.Add(1)
						return
					}
				}

				err = txn.Commit(ctx)
				if err != nil {
					t.Logf("[%d/%d] write commit failed: %v", worker, write, err)
					numErrors.Add(1)
					return
				}
			}
		}(i)
	}

	// Validate reads within a transaction are consistent.
	for i := 1; i <= numReaders; i++ {
		wgReaders.Add(1)
		go func(worker int) {
			defer wgReaders.Done()
			var read int = 1
			time.Sleep(time.Duration(worker) * time.Millisecond)

			for {
				switch {
				case done.Load():
					t.Log("shutting down reader")
					return
				default:
					ctx := context.Background()

					txn, err := b.BeginReadOnlyTx(ctx)
					if err != nil {
						t.Logf("[%d/%d] read begin tx failed: %v", worker, read, err)
						numErrors.Add(1)
						return
					}

					list, err := txn.List(ctx, "")
					if err != nil {
						t.Logf("[%d/%d] read list failed: %v", worker, read, err)
						numErrors.Add(1)
						return
					}

					workerFileValueMap := make(map[int]map[int]string)
					for workerIndex, workerDir := range list {
						keyWorker, _ := strconv.Atoi(workerDir[0 : len(workerDir)-1])
						if _, ok := workerFileValueMap[keyWorker]; !ok {
							workerFileValueMap[keyWorker] = make(map[int]string)
						}

						workerList, err := txn.List(ctx, workerDir)
						if err != nil {
							t.Logf("[%d/%d/%d] read list worker %v failed: %v", worker, read, workerIndex, keyWorker, err)
							numErrors.Add(1)
							return

						}

						for entryIndex, entryName := range workerList {
							keyFile, _ := strconv.Atoi(entryName)
							key := fmt.Sprintf("%v%v", workerDir, entryName)

							entry, err := txn.Get(ctx, key)
							if err != nil {
								t.Logf("[%d/%d/%d (%v)/%d (%v)] read entry %v failed: %v", worker, read, workerIndex, workerDir, entryIndex, entryName, key, err)
								numErrors.Add(1)
								return
							}

							if entry == nil {
								t.Logf("[%d/%d/%d (%v)/%d (%v)] read entry %v failed: was unexpectedly nil", worker, read, workerIndex, workerDir, entryIndex, entryName, key)
								numErrors.Add(1)
								return
							}

							expectedValue, present := workerFileValueMap[keyWorker][keyFile]
							if present {
								if string(entry.Value) != expectedValue {
									t.Logf("[%d/%d/%d (%v)/%d (%v)] read entry %v failed: different value: expected=%v / actual=%v", worker, read, workerIndex, workerDir, entryIndex, entryName, key, expectedValue, string(entry.Value))
									numErrors.Add(1)
									return
								}
							} else {
								workerFileValueMap[keyWorker][keyFile] = string(entry.Value)
							}
						}
					}

					for keyWorker, keyFiles := range workerFileValueMap {
						if len(keyFiles) != 0 && len(keyFiles) != numFiles {
							t.Logf("[%d/%d] read list files failed: expected 0 or %v files due to transaction consistency; got %v for worker %v: %v", worker, read, numFiles, len(keyFiles), keyWorker, keyFiles)
							numErrors.Add(1)
							return
						}
					}

					err = txn.Rollback(ctx)
					if err != nil {
						t.Logf("[%d/%d] read rollback failed: %v", worker, read, err)
						numErrors.Add(1)
						return
					}
				}

				time.Sleep(time.Duration(readBreak) * time.Millisecond)
				read += 1
			}
		}(i)
	}

	// Wait for writers to finish
	wgWriters.Wait()

	// Signal readers to stop
	done.Store(true)

	// Wait for readers to finish
	wgReaders.Wait()

	// Handle cleanup
	if numErrors.Load() > 0 {
		t.Fatalf("got %v errors while running test; see log messages for more info", numErrors.Load())
	}

	// Remove remaining files.
	for i := 1; i <= numWriters; i++ {
		for write := 1; write <= numWrites; write++ {
			key := fmt.Sprintf("%d/%d", i, write)
			if err := b.Delete(context.Background(), key); err != nil {
				t.Fatalf("unable to perform cleanup of %v: %v", key, err)
			}
		}
	}
}
