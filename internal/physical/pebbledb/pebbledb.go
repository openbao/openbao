// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package pebbledb

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync"
	"uuid"
	"weak"

	"github.com/openbao/openbao/sdk/v2/physical"

	"github.com/cockroachdb/pebble"
	"github.com/cockroachdb/pebble/vfs"
	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-secure-stdlib/parseutil"
)

/*

The pebble package alone does not implement full read/write interactive
transactions, so we need to build our own transactions similar to the Raft
model, using Snapshots (read-only interactive transactions).

We use an invalidation-checking model; this pushes all in-flight parallel
writes into transactions, notifying whether or not the transaction has
conflicted. This list is checked while holding the write lock one last time
prior to committing. Notably, we need to retain record of these previous
writes so that a later operation within a transaction can conflict
appropriately.

The alternative to this design is re-implementing the check-and-set design
of Raft, though, as PebbleDB doesn't implement interactive write transactions,
this would necessitate holding and grabbing a global write lock for this.

*/

type Backend struct {
	logger log.Logger

	db *pebble.DB

	lock sync.RWMutex
	txns map[string]weak.Pointer[Transaction]
}

var (
	_ physical.Backend              = &Backend{}
	_ physical.TransactionalBackend = &Backend{}
)

// NewBackend constructs a PebbleDB backend using the given
// path. Optionally it can be marked read-only.
func NewBackend(conf map[string]string, logger log.Logger) (physical.Backend, error) {
	var err error

	path, ok := conf["path"]
	if !ok || path == "" {
		return nil, errors.New("missing or empty parameter 'path'")
	}

	readOnly := false
	readOnlyRaw, ok := conf["read_only"]
	if ok {
		readOnly, err = parseutil.ParseBool(readOnlyRaw)
		if err != nil {
			return nil, fmt.Errorf("failed to parse 'read_only' parameter: %w", err)
		}
	}

	var fs vfs.FS
	if path == ":memory:" {
		path = ""
		fs = vfs.NewMem()
	} else {
		if err := os.MkdirAll(path, 0o700); err != nil {
			return nil, fmt.Errorf("failed to create 'path': %w", err)
		}
	}

	db, err := pebble.Open(path, &pebble.Options{
		ReadOnly: readOnly,
		FS:       fs,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	pdb := &Backend{
		logger: logger,
		db:     db,
		txns:   map[string]weak.Pointer[Transaction]{},
	}

	return pdb, nil
}

func (b *Backend) Get(ctx context.Context, key string) (*physical.Entry, error) {
	return b.getInternal(ctx, b.db, key)
}

func (b *Backend) getInternal(ctx context.Context, view pebble.Reader, key string) (*physical.Entry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	data, closer, err := view.Get([]byte(key))
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, nil
		}

		return nil, fmt.Errorf("failed to get entry: %w", err)
	}

	defer closer.Close() //nolint:errcheck // nothing we can do here

	return &physical.Entry{
		Key:   key,
		Value: slices.Clone(data),
	}, nil
}

func (b *Backend) Put(ctx context.Context, entry *physical.Entry) error {
	b.lock.RLock()
	defer b.lock.RUnlock()

	if err := b.putInternal(ctx, b.db, entry); err != nil {
		return err
	}

	return b.notifyWrite(entry.Key, true)
}

func (b *Backend) putInternal(ctx context.Context, view pebble.Writer, entry *physical.Entry) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	if err := view.Set([]byte(entry.Key), entry.Value, &pebble.WriteOptions{
		Sync: true,
	}); err != nil {
		return err
	}

	return nil
}

func (b *Backend) List(ctx context.Context, prefix string) ([]string, error) {
	return b.ListPage(ctx, prefix, "", 0)
}

func newLister(view pebble.Reader, prefix string, after string, limit int) (*pebble.Iterator, *physical.Lister, error) {
	var cursor *pebble.Iterator
	var err error

	lister := &physical.Lister{
		Prefix: prefix,
		After:  after,
		Limit:  limit,
		Start: func(_ []byte) error {
			cursor.First()
			return cursor.Error()
		},
		Next: func() error {
			cursor.Next()
			return cursor.Error()
		},
		Key: func() (string, bool, error) {
			if !cursor.Valid() {
				return "", false, cursor.Error()
			}

			key := cursor.Key()
			return string(key), true, nil
		},
	}

	opts := &pebble.IterOptions{
		LowerBound: lister.SeekPrefix(),
	}

	cursor, err = view.NewIter(opts)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating iterator: %w", err)
	}

	return cursor, lister, nil
}

func (b *Backend) ListPage(ctx context.Context, prefix string, after string, limit int) ([]string, error) {
	cursor, lister, err := newLister(b.db, prefix, after, limit)
	if err != nil {
		return nil, err
	}
	defer func() {
		if cursor != nil {
			cursor.Close() //nolint:errcheck // nothing we can do here.
		}
	}()

	results, _, err := lister.ListPage(ctx)
	return results, err
}

func (b *Backend) Delete(ctx context.Context, key string) error {
	b.lock.RLock()
	defer b.lock.RUnlock()

	if err := b.deleteInternal(ctx, b.db, key); err != nil {
		return err
	}

	return b.notifyWrite(key, true)
}

func (b *Backend) deleteInternal(ctx context.Context, view pebble.Writer, key string) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	if err := view.Delete([]byte(key), &pebble.WriteOptions{
		Sync: true,
	}); err != nil {
		return err
	}

	return nil
}

type Transaction struct {
	parent *Backend
	id     string

	snapshot *pebble.Snapshot
	writable bool

	// The remaining fields need to be read using this lock.

	lock sync.Mutex

	committed  bool
	conflicted bool

	updates map[string]*physical.Entry
	reads   map[string]struct{}
	lists   map[string]map[string]map[int][]string

	parallelWrites map[string][]bool

	cleanup runtime.Cleanup
}

func (b *Backend) BeginTx(ctx context.Context) (physical.Transaction, error) {
	return b.beginTx(ctx, true /* writable */)
}

func (b *Backend) BeginReadOnlyTx(ctx context.Context) (physical.Transaction, error) {
	return b.beginTx(ctx, false /* writable */)
}

func (b *Backend) beginTx(ctx context.Context, writable bool) (physical.Transaction, error) {
	b.lock.Lock()
	defer b.lock.Unlock()

	id := uuid.NewV4().String()

	snapshot := b.db.NewSnapshot()
	txn := &Transaction{
		parent:   b,
		id:       id,
		snapshot: snapshot,
		writable: writable,

		updates:        make(map[string]*physical.Entry),
		reads:          make(map[string]struct{}),
		lists:          make(map[string]map[string]map[int][]string),
		parallelWrites: make(map[string][]bool),
	}

	b.txns[id] = weak.Make(txn)

	txn.cleanup = runtime.AddCleanup(txn, func(_ any) {
		b.lock.Lock()
		delete(b.txns, id)
		b.lock.Unlock()

		_ = snapshot.Close()
	}, true)

	return txn, nil
}

func (t *Transaction) Get(ctx context.Context, key string) (*physical.Entry, error) {
	t.lock.Lock()
	defer t.lock.Unlock()

	if t.committed {
		return nil, physical.ErrTransactionAlreadyCommitted
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if value, present := t.updates[key]; present {
		return value.Clone(), nil
	}

	value, err := t.parent.getInternal(ctx, t.snapshot, key)
	if err != nil {
		return nil, err
	}

	if t.writable {
		t.reads[key] = struct{}{}
	}

	return value, nil
}

func (t *Transaction) Put(ctx context.Context, entry *physical.Entry) error {
	if !t.writable {
		return physical.ErrTransactionReadOnly
	}

	t.lock.Lock()
	defer t.lock.Unlock()

	if t.committed {
		return physical.ErrTransactionAlreadyCommitted
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	cloned := entry.Clone()

	t.updates[cloned.Key] = cloned

	return nil
}

func (t *Transaction) List(ctx context.Context, prefix string) ([]string, error) {
	return t.ListPage(ctx, prefix, "", 0)
}

func (t *Transaction) ListPage(ctx context.Context, prefix string, after string, limit int) ([]string, error) {
	t.lock.Lock()
	defer t.lock.Unlock()

	cursor, lister, err := newLister(t.snapshot, prefix, after, limit)
	if err != nil {
		return nil, err
	}
	defer func() {
		if cursor != nil {
			cursor.Close() //nolint:errcheck // nothing we can do here.
		}
	}()

	lister.Deleted = func(path string) bool {
		entry, present := t.updates[path]
		if !present {
			return false
		}

		return entry == nil
	}

	lister.Inserted = func() iter.Seq[string] {
		return func(yield func(K string) bool) {
			for key, entry := range t.updates {
				if entry == nil {
					// Skip deletes.
					continue
				}

				if !yield(key) {
					return
				}
			}
		}
	}

	keys, presentKeys, err := lister.ListPage(ctx)
	if err != nil {
		return nil, err
	}

	// Now that we have the results, create a fake version for conflict
	// detection.
	afterMap, present := t.lists[lister.Prefix]
	if !present {
		afterMap = map[string]map[int][]string{}
		t.lists[lister.Prefix] = afterMap
	}
	limitMap, present := afterMap[after]
	if !present {
		limitMap = map[int][]string{}
		afterMap[after] = limitMap
	}
	_, haveZero := limitMap[0]

	// Only insert this entry if we don't have a zero-value containing all
	// entries.
	if _, present := limitMap[lister.Limit]; !present && lister.Limit != 0 && !haveZero {
		limitMap[limit] = presentKeys
	}

	// If we don't have a zero value and we are the zero value, reset this
	// map to a new one with just a single entry. This compacts the map.
	if !haveZero && lister.Limit == 0 {
		afterMap[after] = map[int][]string{
			0: presentKeys,
		}
	}

	// TODO(ascheel): if necessary in the future, consider more advanced
	// afterMap compaction: overlaps could be detected and duplicate values
	// removed. Alternatively, if this proves too memory heavy, we could
	// move to a check-and-set style semantic.

	return keys, nil
}

func (t *Transaction) Delete(ctx context.Context, key string) error {
	if !t.writable {
		return physical.ErrTransactionReadOnly
	}

	t.lock.Lock()
	defer t.lock.Unlock()

	if t.committed {
		return physical.ErrTransactionAlreadyCommitted
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	t.updates[key] = nil

	return nil
}

func (t *Transaction) finishTxn() {
	t.committed = true

	// Clear state so we don't hog resources.
	delete(t.parent.txns, t.id)
	t.updates = nil
	t.lists = nil
	t.reads = nil
	t.parallelWrites = nil
}

func (t *Transaction) Commit(ctx context.Context) error {
	// We need to preserve lock ordering: grab the lock on the parent
	// opportunistically, even though we might not need it if we're already
	// committed or conflicted.
	t.parent.lock.Lock()
	defer t.parent.lock.Unlock()

	t.lock.Lock()
	defer t.lock.Unlock()

	if t.committed {
		return physical.ErrTransactionAlreadyCommitted
	}

	// Prevent manual cleanup from running.
	t.cleanup.Stop()

	// Now handle cleanup.
	defer t.finishTxn()

	// Release the snapshot early; we don't need it any more.
	if err := t.snapshot.Close(); err != nil {
		return err
	}

	// Double check all previous writes now that we're committing and have an
	// exclusive lock.
	t.confirmParallelWrites()

	if t.conflicted {
		// No need to do anything else.
		return physical.ErrTransactionCommitFailure
	}

	if len(t.updates) == 0 {
		// Nothing to do; no sense creating an empty batch and applying it.
		return nil
	}

	// Perform all writes in a giant batch.
	batch := t.parent.db.NewBatch()
	for path, entry := range t.updates {
		if entry == nil {
			if err := t.parent.deleteInternal(ctx, batch, path); err != nil {
				return fmt.Errorf("error during batch delete: %w", err)
			}
		} else {
			if err := t.parent.putInternal(ctx, batch, entry); err != nil {
				return fmt.Errorf("error during batch put: %w", err)
			}
		}
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	if err := batch.Commit(&pebble.WriteOptions{
		Sync: true,
	}); err != nil {
		return fmt.Errorf("error during commit: %w", err)
	}

	// Notify all other transactions of this commit.
	if err := t.parent.notifyCommit(ctx, t.id, t.updates); err != nil {
		return fmt.Errorf("error during notify: %w", err)
	}

	return nil
}

func (t *Transaction) Rollback(ctx context.Context) error {
	// We need to preserve lock ordering: grab the lock on the parent
	// opportunistically, even though we might not need it if we're already
	// committed or conflicted.
	t.parent.lock.Lock()
	defer t.parent.lock.Unlock()

	t.lock.Lock()
	defer t.lock.Unlock()

	if t.committed {
		return physical.ErrTransactionAlreadyCommitted
	}

	// Prevent manual cleanup from running.
	t.cleanup.Stop()

	// Now handle cleanup.
	defer t.finishTxn()

	// Release the snapshot early; we don't need it any more.
	if err := t.snapshot.Close(); err != nil {
		return err
	}

	return nil
}

// notifyWrite must be called while holding at least a read lock. It notifies all
// outstanding transactions that a write (update or delete) on the given entry
// has occurred.
func (b *Backend) notifyWrite(key string, deleted bool) error {
	for _, txnWeak := range b.txns {
		if txn := txnWeak.Value(); txn != nil {
			txn.notifyWrite(key, deleted)
		}
	}

	return nil
}

// notifyCommit is like notifyWrite but notifying other transactions that a
// transaction has committed. In flight transaction writes are not notified
// until the transaction has been committed.
func (b *Backend) notifyCommit(ctx context.Context, id string, writes map[string]*physical.Entry) error {
	for path, entry := range writes {
		for txnId, txnWeak := range b.txns {
			if id == txnId {
				continue
			}

			// While we hold a write lock in this case, we maintain that
			// runtime.Cleanup should actually do the deletion of the
			// reference from b.txns, so we let it instead.
			if txn := txnWeak.Value(); txn != nil {
				txn.notifyWrite(path, entry == nil)
			}
		}
	}

	return nil
}

// notifyWrite in a transaction accepts the inbound write and validates
// whether or not it conflicts.
func (t *Transaction) notifyWrite(written string, deleted bool) {
	t.lock.Lock()
	defer t.lock.Unlock()

	// Already conflicted; ignore future writes.
	if t.conflicted {
		return
	}

	values := t.parallelWrites[written]
	if slices.Contains(values, deleted) {
		// Similar write already occurred; no need to process.
		return
	}

	t.parallelWrites[written] = append(t.parallelWrites[written], deleted)
	t.notifyWriteWithLock(written, deleted)
}

// confirmParallelWrites re-confirms every write issued against our update
// set, ensuring we haven't yet conflicted.
func (t *Transaction) confirmParallelWrites() {
	for path, statuses := range t.parallelWrites {
		for _, deleted := range statuses {
			t.notifyWriteWithLock(path, deleted)

			if t.conflicted {
				return
			}
		}
	}
}

// notifyWriteWithLock checks whether this write operation (from another
// transaction or direct write) causes a conflict.
func (t *Transaction) notifyWriteWithLock(written string, deleted bool) {
	var conflicted bool
	defer func() {
		if conflicted {
			t.conflicted = conflicted
		}
	}()

	// Easy part: check reads and updates.
	for path := range t.reads {
		if path == written {
			conflicted = true
			return
		}
	}

	for path := range t.updates {
		if path == written {
			conflicted = true
			return
		}
	}

	// We need to know if the written entry conflicts with a list. This
	// involves checking if the parent directory of this written entry
	// has a list operation (performed within this transaction) that
	// would've included this entry. We can't use path.Base(...) because
	// we don't want to implicitly call path.Clean(...) and deal with its
	// semantics.
	base, suffix, found := strings.CutLast(written, "/")
	if !found {
		suffix = written
	}

	// Ensure we have a trailing slash on base as CutLast will have removed
	// it and compliant list calls will have it.
	base += "/"

	afterMap, present := t.lists[base]
	if !present {
		return
	}

	for after, limitMap := range afterMap {
		if after >= suffix {
			// This list starts after what we care about.
			continue
		}

		if listResults, present := limitMap[0]; present {
			// We'll always be present in a complete list unless we already
			// existed and this is a write, or we did not exist and this was
			// a delete.
			//
			// Either way, we should be safe to skip the rest of these lists,
			// as the others should be consistent with this one: even if we've
			// modified the value of this entry, we haven't changed its status
			// as present in this list and we're not otherwise dependent on
			// its value as we've already checked read/writes for conflicts
			// above.
			inList := slices.Contains(listResults, suffix)
			conflicted = (inList && deleted) || (!inList && !deleted)
			return
		}

		var haveBefore bool
		var haveAfter bool

		for limit, results := range limitMap {
			for _, result := range results {
				if result == suffix {
					if deleted {
						conflicted = true
					}

					// See above about why this is safe.
					return
				}

				if result < suffix {
					haveBefore = true
				} else if result > suffix {
					haveAfter = true
				}
			}

			// If we're here, that means the entry did not exist in the
			// list.
			if deleted {
				// No point complicating the logic: this entry was not seen
				// and was deleted, so it doesn't matter if we re-delete it
				// from the PoV of this list.
				continue
			}

			if haveBefore && haveAfter {
				// We saw entries on either side of this write, so we'd
				// definitively be in the write.
				conflicted = true
				return
			}

			if len(results) < limit && haveBefore {
				// If we had seen this write, we had space to include it in
				// this list that would've included us, so call this a
				// conflict.
				conflicted = true
				return
			}
		}

		return
	}
}
