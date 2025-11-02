// Copyright (c) 2024 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package raft

import (
	"bytes"
	"context"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"hash"
	"maps"
	"math"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/armon/go-metrics"
	"github.com/openbao/openbao/sdk/v2/helper/pointerutil"
	"github.com/openbao/openbao/sdk/v2/physical"
	bolt "go.etcd.io/bbolt"
)

// Hashes used to perform verification operations.
const (
	sha384VerifyHash byte = 1 + iota
)

// The default hash function is chosen to be SHA-384 as it should be
// moderately performant but also resistant to length extension attacks.
// When more hardware implements fast SHA-3 intrinsics, we could consider
// switching to SHA-3-256 instead for lower wire overhead.
var defaultVerifyHash = sha384VerifyHash

// Bytes of overhead a single Put entry has versus a transaction, excluding
// the size of the path. Verified by TestRaft_Backend_PutTxnMargin.
const maxEntrySizeMultipleTxnOverhead = 11

// Parameters to send on the beginTxOp
type beginTxOpParams struct {
	// Index prior to start of the underlying transaction: this allows fast
	// application of transactions if no subsequent WAL entries modified any
	// entries verified by this transaction.
	Index uint64 `json:"i"`
}

func createBeginTxOpValue(index uint64) ([]byte, error) {
	s := beginTxOpParams{
		Index: index,
	}
	return json.Marshal(s)
}

func parseBeginTxOpValue(data []byte) (*beginTxOpParams, error) {
	var s beginTxOpParams

	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("failed to unmarshal begin tx op value: %w", err)
	}

	return &s, nil
}

type verifyListOpParams struct {
	Prefix string `json:"p"`
	After  string `json:"a"`
	Limit  int    `json:"l"`
}

func createVerificationEntry(key string, value []byte) ([]byte, error) {
	return createVerificationEntryOfType(defaultVerifyHash, key, value)
}

func createListVerificationEntry(prefix string, after string, limit int, items []string) (string, []byte, error) {
	params := verifyListOpParams{
		Prefix: prefix,
		After:  after,
		Limit:  limit,
	}
	repr, err := json.Marshal(&params)
	if err != nil {
		return "", nil, err
	}
	sRepr := string(repr)

	sItems := strings.Join(items, "\n")

	hashValue, err := createVerificationEntryOfType(defaultVerifyHash, sRepr, []byte(sItems))
	if err != nil {
		return "", nil, err
	}

	return sRepr, hashValue, nil
}

func createVerificationEntryOfType(hashType byte, key string, value []byte) ([]byte, error) {
	result := []byte{hashType}

	var h hash.Hash
	switch hashType {
	case sha384VerifyHash:
		h = sha512.New384()
	default:
		return nil, fmt.Errorf("unknown hash selected for verify op: %v: %w", hashType, physical.ErrTransactionCommitFailure)
	}

	// Per https://pkg.go.dev/hash#Hash, h.Write never returns an error.
	h.Write([]byte("{"))
	h.Write([]byte(key))
	h.Write([]byte("}"))
	h.Write(value)
	result = h.Sum(result)
	return result, nil
}

func doVerifyEntry(key string, value []byte, expected []byte) error {
	if len(expected) < 1 {
		return fmt.Errorf("truncated verification hash: %w", physical.ErrTransactionCommitFailure)
	}

	hashType := expected[0]

	actual, err := createVerificationEntryOfType(hashType, key, value)
	if err != nil {
		return err
	}

	if subtle.ConstantTimeCompare(actual, expected) == 0 {
		return physical.ErrTransactionCommitFailure
	}

	return nil
}

func parseListVerifyParams(repr string) (*verifyListOpParams, error) {
	var params verifyListOpParams
	if err := json.Unmarshal([]byte(repr), &params); err != nil {
		return nil, err
	}

	return &params, nil
}

func doVerifyList(repr string, items []string, expected []byte) error {
	hashType := expected[0]

	sItems := strings.Join(items, "\n")

	actual, err := createVerificationEntryOfType(hashType, repr, []byte(sItems))
	if err != nil {
		return err
	}

	if subtle.ConstantTimeCompare(actual, expected) == 0 {
		return physical.ErrTransactionCommitFailure
	}

	return nil
}

func cloneBytes(val []byte) []byte {
	ret := make([]byte, len(val))
	copy(ret, val)
	return ret
}

type raftTxnUpdateRecord struct {
	// If this record exists but Contents is nil, the entry was deleted.
	OpType   uint32
	Contents *physical.Entry
}

type RaftTransaction struct {
	b              *RaftBackend
	l              sync.Mutex
	tx             *bolt.Tx
	updates        map[string]*raftTxnUpdateRecord
	reads          map[string]*LogOperation
	lists          map[string]map[string]map[int]*LogOperation
	writable       bool
	haveWritten    bool
	haveFinishedTx bool
	index          uint64
	started        time.Time
}

var _ physical.Transaction = &RaftTransaction{}

func (b *RaftBackend) newTransaction(ctx context.Context, writable bool) (*RaftTransaction, error) {
	// Grab a transaction permit pool entry so that we can limit the number of
	// concurrent transactions. Also grab a read lock in the underlying FSM
	// to prevent key changes from occurring while a transaction is ongoing.
	// These will be released when we finish this transaction.
	b.txnPermitPool.Acquire()
	b.fsm.l.RLock()

	// Grab the last seen WAL index prior to starting the transaction for
	// correctness: this ensures everything in this WAL is seen in the
	// underlying transaction, versus the other ordering (in which, the
	// WAL could be incremented and we could be missing items not present
	// in the transaction).
	index := b.AppliedIndex()

	// All underlying bbolt transactions are read-only; this gives us a
	// consistent view of storage but means we need to track writes ourselves.
	tx, err := b.fsm.db.Begin(false)
	if err != nil {
		return nil, fmt.Errorf("failed to start underlying bbolt transaction: %w", err)
	}

	if writable {
		b.fsm.fastTxnTracker.trackTransaction(index)
	}

	return &RaftTransaction{
		b:        b,
		tx:       tx,
		updates:  make(map[string]*raftTxnUpdateRecord),
		reads:    make(map[string]*LogOperation),
		lists:    make(map[string]map[string]map[int]*LogOperation),
		writable: writable,
		index:    index,
		started:  time.Now(),
	}, nil
}

func (t *RaftTransaction) Put(ctx context.Context, entry *physical.Entry) error {
	t.l.Lock()
	defer t.l.Unlock()

	if !t.writable {
		return physical.ErrTransactionReadOnly
	}
	if t.haveFinishedTx {
		return physical.ErrTransactionAlreadyCommitted
	}

	// Check if we exceed the size of a regular put entry.
	valueSize := len(entry.Value)
	keySize := len(entry.Key)
	if keySize > bolt.MaxKeySize {
		return fmt.Errorf("%s, max key size for integrated storage is %d", physical.ErrKeyTooLarge, bolt.MaxKeySize)
	}

	if valueSize >= (int(t.b.maxEntrySize) - keySize - maxEntrySizeMultipleTxnOverhead) {
		return fmt.Errorf("%v; got %d bytes, max %d bytes", physical.ErrValueTooLarge, keySize, t.b.maxEntrySize)
	}

	t.haveWritten = true

	// If we haven't modified this entry within the scope of this
	// transaction, read the value of this entry so we can hash it.
	if _, present := t.updates[entry.Key]; !present {
		// We could've alternatively performed a read on this entry before
		// attempting to update it; don't create a verification entry if
		// we have.
		if _, present := t.reads[entry.Key]; !present {
			// It is safe to go to the underlying transaction here as we
			// hold an exclusive write lock here and so there's no parallel
			// writers to the same key.
			value := t.tx.Bucket(dataBucketName).Get([]byte(entry.Key))
			contentsHash, err := createVerificationEntry(entry.Key, value)
			if err != nil {
				return err
			}

			// Add it to the list of reads to be performed when it comes time
			// to generate the Raft log.
			t.reads[entry.Key] = &LogOperation{
				OpType: verifyReadOp,
				Key:    entry.Key,
				Value:  contentsHash,
			}
		}
	}

	// Do the update in the transaction, adding it to updates for when we
	// generate the log.
	update := &raftTxnUpdateRecord{
		// Caller may mutate their entry after we accept it, so create a new
		// one for the cache.
		OpType: putOp,
		Contents: &physical.Entry{
			Key:   entry.Key,
			Value: cloneBytes(entry.Value),
		},
	}
	t.updates[entry.Key] = update

	return nil
}

func (t *RaftTransaction) Get(ctx context.Context, key string) (*physical.Entry, error) {
	t.l.Lock()
	defer t.l.Unlock()
	if t.haveFinishedTx {
		return nil, physical.ErrTransactionAlreadyCommitted
	}

	if t.writable {
		// Check if the record has been modified already and return its last
		// value.
		//
		// If this is true, we were the last writer to this key, so we know
		// what the contents are (given we verify the contents prior to write
		// and we're executing inside a transaction), so there's no need to
		// queue another verifyReadOp.
		if updateEntry, present := t.updates[key]; present {
			if updateEntry.Contents == nil {
				return nil, nil
			}

			// Caller may mutate their entry after we return it, so create a
			// new one for them.
			return &physical.Entry{
				Key:   updateEntry.Contents.Key,
				Value: cloneBytes(updateEntry.Contents.Value),
			}, nil
		}
	}

	// Otherwise, ask the underlying transaction for this value.
	value := t.tx.Bucket(dataBucketName).Get([]byte(key))

	if _, present := t.reads[key]; !present {
		// Hash the contents so that we can add a verify operation.
		contentsHash, err := createVerificationEntry(key, value)
		if err != nil {
			return nil, err
		}

		// Add it to the list of reads to be performed when it comes time
		// to generate the Raft log.
		t.reads[key] = &LogOperation{
			OpType: verifyReadOp,
			Key:    key,
			Value:  contentsHash,
		}
	}

	// If we have no value, return nil.
	if value == nil {
		return nil, nil
	}

	return &physical.Entry{
		Key:   key,
		Value: cloneBytes(value),
	}, nil
}

func (t *RaftTransaction) Delete(ctx context.Context, key string) error {
	t.l.Lock()
	defer t.l.Unlock()
	if !t.writable {
		return physical.ErrTransactionReadOnly
	}
	if t.haveFinishedTx {
		return physical.ErrTransactionAlreadyCommitted
	}

	t.haveWritten = true

	// If we haven't modified this entry within the scope of this
	// transaction, read the value of this entry so we can hash it.
	if _, present := t.updates[key]; !present {
		// We could've alternatively performed a read on this entry before
		// attempting to update it; don't create a verification entry if
		// we have.
		if _, present := t.reads[key]; !present {
			// See notes above in Put(...) for why this is safe.
			value := t.tx.Bucket(dataBucketName).Get([]byte(key))
			contentsHash, err := createVerificationEntry(key, value)
			if err != nil {
				return err
			}

			// Verify the entry prior to deleting it, when it comes time for raft
			// application.
			t.reads[key] = &LogOperation{
				OpType: verifyReadOp,
				Key:    key,
				Value:  contentsHash,
			}
		}
	}

	// Do the delete in the transaction, adding it to the future raft log.
	update := &raftTxnUpdateRecord{
		OpType: deleteOp,
	}
	t.updates[key] = update

	return nil
}

func (t *RaftTransaction) List(ctx context.Context, prefix string) ([]string, error) {
	return t.ListPage(ctx, prefix, "", -1)
}

// returns (entryName, isFolder, shouldVisit)
func listShouldIncludeEntry(prefix string, after string, key string) (string, bool, bool) {
	subKey := strings.TrimPrefix(key, prefix)
	i := strings.Index(subKey, "/")
	if i == -1 {
		// Not a folder; check if we can skip this entry by suffix.
		if after != "" && subKey <= after {
			return subKey, false, false
		}

		return subKey, false, true
	}

	// Check if we need to visit the truncated folder path.
	folder := string(subKey[:i+1])
	if after != "" && folder <= after {
		return folder, true, false
	}

	return folder, true, true
}

func (t *RaftTransaction) ListPage(ctx context.Context, prefix string, after string, limit int) ([]string, error) {
	// List differs from Get in that the latter is a single entry: if an
	// put or delete has occurred in the transaction, it supersedes the
	// value we would've gotten from the underlying data store. Here however,
	// we always want to execute the list and remove entries if there have
	// been writes that affect it.
	//
	// This is complex to do efficiently. We might have deleted an entire
	// subtree that might show up in a list. We could've also added more
	// entries, such that the list is unnecessary.
	//
	// We do this in two steps: perform the underlying list, ignoring results
	// that have been deleted and merging any new writes that occur prior to
	// a given iteration's entry.. Finally after the loop, we merge in results
	// that have been added after the last key in the pending list, trimming
	// it down to size.
	t.l.Lock()
	defer t.l.Unlock()
	if t.haveFinishedTx {
		return nil, physical.ErrTransactionAlreadyCommitted
	}

	prefixBytes := []byte(prefix)
	fullAfter := filepath.Join(prefix, after)
	seekPrefix := []byte(fullAfter)
	if after == "" {
		seekPrefix = prefixBytes
	}

	// Assume the bucket exists and has keys.
	c := t.tx.Bucket(dataBucketName).Cursor()

	// Build a map of updates and deletions (in the prefix!) for fast lookup.
	deletions := map[string]struct{}{}
	updates := map[string]struct{}{}
	for key := range t.updates {
		// Modified key is not in the correct path prefix.
		if !strings.HasPrefix(key, prefix) {
			continue
		}

		// Check whether we should visit this entry.
		entry, _, visit := listShouldIncludeEntry(prefix, after, key)
		if !visit {
			continue
		}

		// If we'd keep this entry, track it appropriately.
		if t.updates[key].Contents == nil {
			deletions[key] = struct{}{}
		} else {
			updates[entry] = struct{}{}
		}
	}

	// We do verifications off of the contents actually in the underlying
	// storage, not from pre-commit writes. This means we need two entries:
	//
	// 1. Things we've seen in the course of this list.
	// 2. The immediate next list entry, if any.
	var presentKeys []string
	var nextPresentEntry string

	// Iterate through the results of list and see if the underlying data
	// store already had entries for this list operation. Merge in any
	// updated keys in the process.
	var keys []string
	for k, _ := c.Seek(seekPrefix); k != nil && bytes.HasPrefix(k, prefixBytes); k, _ = c.Next() {
		key := string(k)
		entry, isFolder, shouldVisit := listShouldIncludeEntry(prefix, after, key)

		if limit > 0 && len(keys) >= limit {
			// We've seen enough entries; exit.
			nextPresentEntry = entry
			break
		}

		if _, deleted := deletions[key]; deleted {
			// This key was deleted; we don't need to include it in our list,
			// but because it was deleted, it will show up in our underlying
			// list.
			presentKeys = append(presentKeys, key)
			continue
		}

		if !shouldVisit {
			// Skip this entry.
			continue
		}

		// Before we add this entry, see if there's any updates to add instead.
		lastKey := ""
		if len(keys) > 0 {
			lastKey = keys[len(keys)-1]
		}
		var mergedEntries []string
		for updateEntry := range updates {
			if updateEntry < entry && updateEntry > lastKey {
				mergedEntries = append(mergedEntries, updateEntry)
				delete(updates, updateEntry)
			}
		}
		sort.Strings(mergedEntries)
		keys = append(keys, mergedEntries...)
		if len(keys) > 0 {
			lastKey = keys[len(keys)-1]
		}

		if isFolder && len(keys) > 0 && lastKey == entry {
			// This folder was already seen; don't revisit it.
			if len(presentKeys) > 0 && presentKeys[len(presentKeys)-1] != key {
				presentKeys = append(presentKeys, key)
			}
			continue
		}

		// Otherwise, include the entry.
		keys = append(keys, entry)
		presentKeys = append(presentKeys, entry)
		delete(updates, entry)
	}

	// Finally, attempt to merge newly added entries one more time. This
	// handles the case when there were no on-disk entries, or when there
	// were too few and subsequent entries were added here.
	lastKey := ""
	if len(keys) > 0 {
		lastKey = keys[len(keys)-1]
	}
	var mergedEntries []string
	for updateEntry := range updates {
		if updateEntry > lastKey {
			mergedEntries = append(mergedEntries, updateEntry)
			delete(updates, updateEntry)
		}
	}
	sort.Strings(mergedEntries)
	keys = append(keys, mergedEntries...)

	// We may end up with extra keys as a result of adding all locally
	// updated ones; if we have too many, trim it down.
	if limit > 0 && len(keys) > limit {
		keys = keys[:limit]
	}

	// Now that we have the results, create a fake version for verification:
	// we append the next key (in storage) to the iterated list for iteration,
	// to ensure we didn't miss any entries. This is guaranteed to be at most
	// one more than the requested entries, if no writes occurred within this
	// transaction.
	if nextPresentEntry != "" {
		presentKeys = append(presentKeys, nextPresentEntry)
	}
	verifyLimit := len(presentKeys)
	listParams, contentsHash, err := createListVerificationEntry(prefix, after, verifyLimit, presentKeys)
	if err != nil {
		return nil, err
	}

	// Add the list to the verification log, to ensure nobody else has written
	// to it while the transaction was operating. While it is technically
	// possible to collapse operations across values for after (sharing the
	// same prefix), we only collapse to a single log operation if we have
	// a higher limit than the existing entry.
	if _, present := t.lists[prefix]; !present {
		t.lists[prefix] = make(map[string]map[int]*LogOperation, 1)
		t.lists[prefix][after] = make(map[int]*LogOperation, 1)
	} else if _, present := t.lists[prefix][after]; !present {
		t.lists[prefix][after] = make(map[int]*LogOperation, 1)
	}
	existingLimit := -1
	for existingVerifyLimit := range t.lists[prefix][after] {
		existingLimit = existingVerifyLimit
	}
	if verifyLimit > existingLimit {
		delete(t.lists[prefix][after], existingLimit)
		t.lists[prefix][after][verifyLimit] = &LogOperation{
			OpType: verifyListOp,
			Key:    listParams,
			Value:  contentsHash,
		}
	}

	return keys, nil
}

func (t *RaftTransaction) Commit(ctx context.Context) error {
	t.l.Lock()
	defer t.l.Unlock()

	if t.haveFinishedTx {
		return physical.ErrTransactionAlreadyCommitted
	}

	commitRuntimeStart := time.Now()

	// The transaction is done; release the permit pool entry now that we're
	// mostly done with the underlying transaction.
	//
	// Also unlock the read lock on the underlying fsm.
	defer func() {
		if t.writable {
			t.b.fsm.fastTxnTracker.completeTransaction(t.index)

			// in "Rollback" we call fastTxnTracker.clearOldEntries(...) at this
			// We don't do this in "Commit" because it will be called from the fsm.
			// This ensures the cleanup also happens on standby nodes
		}

		t.b.fsm.l.RUnlock()
		t.b.txnPermitPool.Release()
		t.haveFinishedTx = true

		// Clear our state.
		t.updates = make(map[string]*raftTxnUpdateRecord)
		t.reads = make(map[string]*LogOperation)
		t.lists = make(map[string]map[string]map[int]*LogOperation)

		// Emit a metric for the duration of the transaction.
		metrics.MeasureSince([]string{"raft-storage", "txn-commit"}, t.started)
		metrics.MeasureSince([]string{"raft-storage", "txn-commit-runtime"}, commitRuntimeStart)
	}()

	// Always rollback the underlying transaction.
	if err := t.tx.Rollback(); err != nil {
		return err
	}

	// If no writes have occurred, we don't need to send a log to Raft. We
	// might have conflicted on a verification, but we won't negatively impact
	// an other writer (due to not causing a conflict ourselves). Our state of
	// reads were guaranteed to be consistent, so it would be no different than
	// having executed in a read-only transaction.
	if !t.writable || !t.haveWritten {
		return nil
	}

	// Build the log from its component parts. This is:
	//
	// 1. The initial header containing the index.
	// 2. Any read verifications
	// 3. Any list verifications
	// 4. All writes
	// 5. The final sentinel
	beginValue, err := createBeginTxOpValue(t.index)
	if err != nil {
		return err
	}

	log := &LogData{
		// While list operations may contribute more (if the list was issued
		// with the same prefix with different after and limit values), this
		// is a good approximation as to the size of the operation log and
		// saves us from continually allocating in future appends.
		Operations: make([]*LogOperation, 0, 2+len(t.reads)+len(t.lists)+len(t.updates)),
	}
	log.Operations = append(log.Operations, &LogOperation{
		OpType: beginTxOp,
		Value:  beginValue,
	})
	for _, op := range t.reads {
		log.Operations = append(log.Operations, op)
	}
	for _, afterLimitMap := range t.lists {
		for _, limits := range afterLimitMap {
			for _, op := range limits {
				log.Operations = append(log.Operations, op)
			}
		}
	}
	for key, updateInfo := range t.updates {
		switch updateInfo.OpType {
		case deleteOp:
			log.Operations = append(log.Operations, &LogOperation{
				OpType: deleteOp,
				Key:    key,
			})
		case putOp:
			log.Operations = append(log.Operations, &LogOperation{
				OpType: putOp,
				Key:    key,
				Value:  updateInfo.Contents.Value,
			})
		}
	}
	log.Operations = append(log.Operations, &LogOperation{
		OpType: commitTxOp,
	})

	lowestActiveIndex := t.b.fsm.fastTxnTracker.lowestActiveIndexAfterCommit(t.index)

	// Acquire a regular operation permit pool entry to let us access the
	// underlying storage.
	t.b.permitPool.Acquire()
	defer t.b.permitPool.Release()

	// Now apply all of these transaction entries. If an error occurs during
	// the transaction application in Raft, applyLog will gather it for us
	// and return it as a proper error.
	t.b.l.RLock()
	log.LowestActiveIndex = pointerutil.Ptr(min(lowestActiveIndex, t.b.raft.AppliedIndex()-1)) // we need to cap the lowest active index, otherwise we might miss transaction started later
	err = t.b.applyLog(ctx, log)
	t.b.l.RUnlock()

	return err
}

func (t *RaftTransaction) Rollback(ctx context.Context) error {
	t.l.Lock()
	defer t.l.Unlock()

	if t.haveFinishedTx {
		return physical.ErrTransactionAlreadyCommitted
	}

	// The transaction is done; release the permit pool entry when we're done
	// here.
	//
	// Also unlock the read lock on the underlying fsm.
	defer func() {
		if t.writable {
			lowestActiveIndex := t.b.fsm.fastTxnTracker.lowestActiveIndexAfterCommit(t.index)
			t.b.l.RLock()
			lowestActiveIndex = min(lowestActiveIndex, t.b.raft.AppliedIndex()-1) // we need to cap the lowest active index, otherwise we might miss transaction started later
			t.b.l.RUnlock()

			t.b.fsm.fastTxnTracker.clearOldEntries(lowestActiveIndex)
			t.b.fsm.fastTxnTracker.completeTransaction(t.index)
		}

		t.b.fsm.l.RUnlock()
		t.b.txnPermitPool.Release()
		t.haveFinishedTx = true

		// Clear our state.
		t.updates = make(map[string]*raftTxnUpdateRecord)
		t.reads = make(map[string]*LogOperation)
		t.lists = make(map[string]map[string]map[int]*LogOperation)

		// Emit a metric for the duration of the transaction.
		metrics.MeasureSince([]string{"raft-storage", "txn-rollback"}, t.started)
	}()

	// Rollback the underlying transaction.
	if err := t.tx.Rollback(); err != nil {
		return err
	}

	return nil
}

// fsmTxnCommitIndexTracker allows fast application of transactions by
// tracking certain state about outstanding and finished operations:
// which entries transactions started at and all modifications which
// were applied by subsequent indices.
type fsmTxnCommitIndexTracker struct {
	l sync.Mutex

	// sourceIndexMap tracks the number of write transactions started at a given
	// application log index, so we can keep track of writes between them.
	sourceIndexMap map[uint64]int

	// indexModifiedMap keeps track of which storage entries were modified at
	// given points, letting us fast commit additional entries if the new
	// transaction's verified reads and lists do not conflict with earlier
	// writes. This is slightly non-trivial to track as we need to ensure that
	// verified list operations correctly invalidate on writes to subkeys
	// which are net-new to a list.
	//
	// For example, on an empty storage tree, writing to /foo/bar/fud should
	// invalidate the list on /foo (as it adds /bar in). Luckily, we can use
	// paginated lists to see if bar is contained in foo/'s tree already.
	indexModifiedMap map[uint64]map[string]struct{}
}

func FsmTxnCommitIndexTracker() *fsmTxnCommitIndexTracker {
	return &fsmTxnCommitIndexTracker{
		sourceIndexMap:   make(map[uint64]int, physical.DefaultParallelTransactions),
		indexModifiedMap: make(map[uint64]map[string]struct{}, physical.DefaultParallelTransactions),
	}
}

// lowestActiveIndexAfterCommit returns what will be the lowest starting index
// of among active transactions after the given transaction has been committed
// (or rolled-back).
func (t *fsmTxnCommitIndexTracker) lowestActiveIndexAfterCommit(transactionStartIndex uint64) uint64 {
	t.l.Lock()
	defer t.l.Unlock()

	lowestActiveIndex := uint64(math.MaxUint64)
	for index, activeCount := range t.sourceIndexMap {
		if index == transactionStartIndex && activeCount == 1 { // ignore given transaction, iff it is the only transaction at this index
			continue
		}
		lowestActiveIndex = min(lowestActiveIndex, index)
	}
	return lowestActiveIndex
}

func (t *fsmTxnCommitIndexTracker) clearOldEntries(lowestActiveIndex uint64) {
	t.l.Lock()
	defer t.l.Unlock()

	maps.DeleteFunc(t.indexModifiedMap, func(key uint64, _ map[string]struct{}) bool {
		return key < lowestActiveIndex
	})
}

func (t *fsmTxnCommitIndexTracker) trackTransaction(index uint64) {
	t.l.Lock()
	defer t.l.Unlock()

	t.sourceIndexMap[index] += 1
}

func (t *fsmTxnCommitIndexTracker) completeTransaction(index uint64) {
	t.l.Lock()
	defer t.l.Unlock()

	existing := t.sourceIndexMap[index]
	if existing > 1 {
		t.sourceIndexMap[index] -= 1
	} else {
		delete(t.sourceIndexMap, index)
	}
}

// Logs a single, non-transactional write.
func (t *fsmTxnCommitIndexTracker) logWrite(index uint64, key string) {
	t.l.Lock()
	defer t.l.Unlock()

	t.indexModifiedMap[index] = make(map[string]struct{}, 1)
	t.indexModifiedMap[index][key] = struct{}{}
}

// Logs all writes occurring in a transaction.
func (t *fsmTxnCommitIndexTracker) logTxnWrites(index uint64, writes map[string]struct{}) {
	t.l.Lock()
	defer t.l.Unlock()

	t.indexModifiedMap[index] = writes
}

// Checks whether a given entry was modified within the transaction window.
func (t *fsmTxnCommitIndexTracker) hasModifiedEntry(minIndex uint64, maxIndex uint64, key string) (uint64, bool) {
	t.l.Lock()
	defer t.l.Unlock()

	for index, modifications := range t.indexModifiedMap {
		if index <= minIndex {
			continue
		}

		if index > maxIndex {
			// Raft WALs should be strictly monotonic and thus this shouldn't
			// trigger.
			panic(fmt.Sprintf("saw later index in fast txn cache: %v > %v\n%#v", index, maxIndex, t))
		}

		if _, ok := modifications[key]; ok {
			return index, true
		}
	}

	return 0, false
}

// Checks whether any child of key was modified within the transaction window.
func (t *fsmTxnCommitIndexTracker) hasModifiedListEntry(minIndex uint64, maxIndex uint64, key string) (uint64, bool) {
	t.l.Lock()
	defer t.l.Unlock()

	normKey := key
	if len(key) > 0 && key[len(key)-1] != '/' {
		normKey += "/"
	}

	for index, modifications := range t.indexModifiedMap {
		if index <= minIndex {
			continue
		}

		if index > maxIndex {
			// Raft WALs should be strictly monotonic and thus this shouldn't
			// trigger.
			panic(fmt.Sprintf("saw later index in entry: %v > %v\n%#v", index, maxIndex, t))
		}

		for modified := range modifications {
			if key == "" || key == "/" {
				return index, true
			}

			if strings.HasPrefix(modified, normKey) {
				return index, true
			}
		}
	}

	return 0, false
}

// fsmTxnCommitIndexApplicationState is created by fsmTxnCommitIndexTracker,
// to handle the application of a single WAL entry to storage. This allows
// us to check if the transaction satisfies fast application rules and batch
// updates to the committer.
type fsmTxnCommitIndexApplicationState struct {
	// parent access
	parent *fsmTxnCommitIndexTracker

	// Last index applied prior to stating batch application.
	latestAppliedIndex uint64

	// Index of this transaction within the batch.
	commandOffset int

	// Actual index of this transaction within the full Raft log.
	commandIndex uint64

	// Latest applied index at the time of this transaction.
	txnStartIndex uint64

	// Whether we're in a transaction
	inTx bool

	// List of writes from this transaction.
	modifiedMap map[string]struct{}
}

func (t *fsmTxnCommitIndexTracker) applyState(latestAppliedIndex uint64, commandOffset int, commandIndex uint64) *fsmTxnCommitIndexApplicationState {
	return &fsmTxnCommitIndexApplicationState{
		parent:             t,
		latestAppliedIndex: latestAppliedIndex,
		commandOffset:      commandOffset,
		commandIndex:       commandIndex,
		inTx:               false,
		modifiedMap:        make(map[string]struct{}, 1),
	}
}

func (s *fsmTxnCommitIndexApplicationState) setStartIndex(index uint64) {
	s.txnStartIndex = index
}

func (s *fsmTxnCommitIndexApplicationState) setInTx() {
	s.inTx = true
}

func (s *fsmTxnCommitIndexApplicationState) getInTx() bool {
	return s.inTx
}

func (s *fsmTxnCommitIndexApplicationState) logWrite(key string) {
	if s.inTx {
		s.modifiedMap[key] = struct{}{}
	} else {
		s.parent.logWrite(s.commandIndex, key)
	}
}

func (s *fsmTxnCommitIndexApplicationState) finishTxn() {
	s.parent.logTxnWrites(s.commandIndex, s.modifiedMap)
}

// canFastWrite holds true if this is the first entry in a batch of logs and
// the index when we started the transaction was the same as the index when
// we applied the WAL: nothing has happened in storage.
func (s *fsmTxnCommitIndexApplicationState) canFastWrite() bool {
	return s.inTx && s.commandOffset == 0 && s.latestAppliedIndex == s.txnStartIndex
}

func (s *fsmTxnCommitIndexApplicationState) indexDelta() uint64 {
	return s.latestAppliedIndex - s.txnStartIndex
}

// canFastWriteBypassRead holds true if no subsequent WALs (from when the
// transaction was started) modified this entry. All WALs did not affect
// this verified read operation.
//
// Note that having a counter example is not sufficient to conflict the
// transaction: it only states that it might have been modified, but the
// modification could be reverted in a later WAL or it could have been a
// write of the same value.
func (s *fsmTxnCommitIndexApplicationState) canFastWriteBypassRead(key string) bool {
	// If we found a modifying entry, we can't fast-write: we need to
	// validate that the corresponding write didn't modify our entry
	// and cause the verification to fail.
	_, found := s.parent.hasModifiedEntry(s.txnStartIndex, s.commandIndex, key)
	return !found
}

// canFastWriteBypassList holds true if no subsequent WALs (from when the
// transaction was started) modified any child entries which might have
// affected this list operation.
//
// Note that having a counter example is not sufficient to conflict the
// transaction: it only states that the list results might have been modified,
// but the modification could be reverted in a later WAL or it could have been
// a write of an existing storage entry already visible in the list.
func (s *fsmTxnCommitIndexApplicationState) canFastWriteBypassList(key string) bool {
	_, found := s.parent.hasModifiedListEntry(s.txnStartIndex, s.commandIndex, key)
	return !found
}

func (s *fsmTxnCommitIndexApplicationState) doVerifyRead(b *bolt.Bucket, op *LogOperation) error {
	if s.canFastWrite() || s.canFastWriteBypassRead(op.Key) {
		metrics.IncrCounter([]string{"raft-storage", "txn_fast_apply_read_hit"}, 1)
		return nil
	}

	metrics.AddSample([]string{"raft-storage", "txn_applied_index_delta"}, float32(s.indexDelta()))
	metrics.IncrCounter([]string{"raft-storage", "txn_fast_apply_miss"}, 1)
	val := b.Get([]byte(op.Key))
	err := doVerifyEntry(op.Key, val, op.Value)

	return err
}

func (s *fsmTxnCommitIndexApplicationState) doVerifyList(tx *bolt.Tx, b *bolt.Bucket, op *LogOperation) error {
	params, err := parseListVerifyParams(op.Key)
	if err != nil {
		return err
	}

	if s.canFastWrite() || s.canFastWriteBypassList(params.Prefix) {
		metrics.IncrCounter([]string{"raft-storage", "txn_fast_apply_list_hit"}, 1)
		return nil
	}

	metrics.AddSample([]string{"raft-storage", "txn_applied_index_delta"}, float32(s.indexDelta()))
	metrics.IncrCounter([]string{"raft-storage", "txn_fast_apply_miss"}, 1)

	var keys []string
	keys, err = listPageInner(context.Background(), tx, params.Prefix, params.After, params.Limit)
	if err == nil {
		err = doVerifyList(op.Key, keys, op.Value)
	}

	return err
}
