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
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/armon/go-metrics"
	log "github.com/hashicorp/go-hclog"
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

type beginTxOpParams struct {
	Index uint64 `json:"i"`
}

func (b *RaftBackend) createBeginTxOpValue() (uint64, []byte, error) {
	s := beginTxOpParams{
		Index: b.AppliedIndex(),
	}

	data, err := json.Marshal(s)
	return s.Index, data, err
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
	Contents *physical.Entry
}

type RaftTransaction struct {
	b              *RaftBackend
	l              sync.Mutex
	tx             *bolt.Tx
	updates        map[string]*raftTxnUpdateRecord
	log            *LogData
	writable       bool
	haveWritten    bool
	haveFinishedTx bool
	index          uint64
}

var _ physical.Transaction = &RaftTransaction{}

func (b *RaftBackend) newTransaction(ctx context.Context, writable bool) (*RaftTransaction, error) {
	// Grab a transaction permit pool entry so that we can limit the number of
	// concurrent transactions. Also grab a read lock in the underlying FSM
	// to prevent key changes from occurring while a transaction is ongoing.
	// These will be released when we finish this transaction.
	b.txnPermitPool.Acquire()
	b.fsm.l.RLock()

	// All underlying bbolt transactions are read-only; this gives us a
	// consistent view of storage but means we need to track writes ourselves.
	tx, err := b.fsm.db.Begin(false)
	if err != nil {
		return nil, fmt.Errorf("failed to start underlying bbolt transaction: %w", err)
	}

	index, beginValue, err := b.createBeginTxOpValue()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal begin tx value: %w", err)
	}

	if writable {
		b.fsm.fastTxnTracker.trackWrite(index)
	}

	return &RaftTransaction{
		b:       b,
		tx:      tx,
		updates: make(map[string]*raftTxnUpdateRecord),
		log: &LogData{
			Operations: []*LogOperation{
				{
					OpType: beginTxOp,
					Value:  beginValue,
				},
			},
		},
		writable: writable,
		index:    index,
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
		// It is safe to go to the underlying transaction here as we
		// hold an exclusive write lock here and so there's no parallel
		// writers to the same key.
		value := t.tx.Bucket(dataBucketName).Get([]byte(entry.Key))
		contentsHash, err := createVerificationEntry(entry.Key, value)
		if err != nil {
			return err
		}

		// Verify the entry prior to updating it, when it comes time for raft
		// application.
		t.log.Operations = append(t.log.Operations, &LogOperation{
			OpType: verifyReadOp,
			Key:    entry.Key,
			Value:  contentsHash,
		})
	}

	update := &raftTxnUpdateRecord{
		// Caller may mutate their entry after we accept it, so create a new
		// one for the cache.
		Contents: &physical.Entry{
			Key:   entry.Key,
			Value: cloneBytes(entry.Value),
		},
	}

	// Do the update in the transaction, adding it to the future raft log.
	t.updates[entry.Key] = update
	t.log.Operations = append(t.log.Operations, &LogOperation{
		OpType: putOp,
		Key:    entry.Key,
		Value:  entry.Value,
	})

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

	// Hash the contents so that we can add a verify operation.
	contentsHash, err := createVerificationEntry(key, value)
	if err != nil {
		return nil, err
	}

	// Add the read to the verification log, to ensure nobody else has written
	// to it while the transaction was operating.
	t.log.Operations = append(t.log.Operations, &LogOperation{
		OpType: verifyReadOp,
		Key:    key,
		Value:  contentsHash,
	})

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
		// See notes above in Put(...) for why this is safe.
		value := t.tx.Bucket(dataBucketName).Get([]byte(key))
		contentsHash, err := createVerificationEntry(key, value)
		if err != nil {
			return err
		}

		// Verify the entry prior to deleting it, when it comes time for raft
		// application.
		t.log.Operations = append(t.log.Operations, &LogOperation{
			OpType: verifyReadOp,
			Key:    key,
			Value:  contentsHash,
		})
	}

	// Empty Contents signifies delete.
	update := &raftTxnUpdateRecord{}

	// Do the delete in the transaction, adding it to the future raft log.
	t.updates[key] = update
	t.log.Operations = append(t.log.Operations, &LogOperation{
		OpType: deleteOp,
		Key:    key,
	})

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

	// Iterate through the results of list and see if the underlying data
	// store already had entries for this list operation. Merge in any
	// updated keys in the process.
	var keys []string
	for k, _ := c.Seek(seekPrefix); k != nil && bytes.HasPrefix(k, prefixBytes); k, _ = c.Next() {
		if limit > 0 && len(keys) >= limit {
			// We've seen enough entries; exit.
			break
		}

		key := string(k)
		if _, deleted := deletions[key]; deleted {
			// This key was deleted; we don't need to include it in our list.
			continue
		}

		entry, isFolder, shouldVisit := listShouldIncludeEntry(prefix, after, key)
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
			continue
		}

		// Otherwise, include the entry.
		keys = append(keys, entry)
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

	// Now that we have our result, save the operation in the log
	// for verification. To do so, we hash the results.
	listParams, contentsHash, err := createListVerificationEntry(prefix, after, limit, keys)
	if err != nil {
		return nil, err
	}

	// Add the list to the verification log, to ensure nobody else has written
	// to it while the transaction was operating.
	t.log.Operations = append(t.log.Operations, &LogOperation{
		OpType: verifyListOp,
		Key:    listParams,
		Value:  contentsHash,
	})

	return keys, nil
}

func (t *RaftTransaction) Commit(ctx context.Context) error {
	t.l.Lock()
	defer t.l.Unlock()

	if t.haveFinishedTx {
		return physical.ErrTransactionAlreadyCommitted
	}

	// The transaction is done; release the permit pool entry now that we're
	// mostly done with the underlying transaction.
	//
	// Also unlock the read lock on the underlying fsm.
	defer func() {
		if t.writable {
			t.b.fsm.fastTxnTracker.completeWrite(t.index)
		}

		t.b.fsm.l.RUnlock()
		t.b.txnPermitPool.Release()
		t.haveFinishedTx = true

		// Clear our state
		t.updates = make(map[string]*raftTxnUpdateRecord)
		t.log = &LogData{}
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

	// Append the commit message to the log.
	t.log.Operations = append(t.log.Operations, &LogOperation{
		OpType: commitTxOp,
	})

	// Acquire a regular operation permit pool entry to let us access the
	// underlying storage.
	t.b.permitPool.Acquire()
	defer t.b.permitPool.Release()

	// Now apply all of these transaction entries. If an error occurs during
	// the transaction application in Raft, applyLog will gather it for us
	// and return it as a proper error.
	t.b.l.RLock()
	err := t.b.applyLog(ctx, t.log)
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
			t.b.fsm.fastTxnTracker.completeWrite(t.index)
		}
		t.haveFinishedTx = true

		// Clear our state.
		t.updates = make(map[string]*raftTxnUpdateRecord)
		t.log = &LogData{}

		t.b.fsm.l.RUnlock()
		t.b.txnPermitPool.Release()
	}()

	// Rollback the underlying transaction.
	if err := t.tx.Rollback(); err != nil {
		return err
	}

	return nil
}

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

func (t *fsmTxnCommitIndexTracker) trackWrite(index uint64) {
	t.l.Lock()
	defer t.l.Unlock()

	t.sourceIndexMap[index] += 1
}

func (t *fsmTxnCommitIndexTracker) completeWrite(index uint64) {
	t.l.Lock()
	defer t.l.Unlock()

	existing := t.sourceIndexMap[index]
	if existing >= 1 {
		t.sourceIndexMap[index] -= 1
	}

	if existing == 1 {
		// See if we invalidated the smallest entry; if so, find the next
		// smallest entry and invalidate all earlier indexModifiedMap
		// entries as a result.
		minIndex := index
		for key := range t.sourceIndexMap {
			if key < minIndex {
				minIndex = key
			}
		}

		if minIndex < index {
			return
		}

		deletedIndices := make([]uint64, 0, physical.DefaultParallelTransactions/2)
		for key := range t.indexModifiedMap {
			if key <= minIndex {
				deletedIndices = append(deletedIndices, key)
			}
		}

		for _, index := range deletedIndices {
			delete(t.indexModifiedMap, index)
		}
	}
}

// Logs a single, non-transactional write.
func (t *fsmTxnCommitIndexTracker) logWrite(index uint64, key string) {
	t.l.Lock()
	defer t.l.Unlock()

	t.indexModifiedMap[index] = make(map[string]struct{}, 1)
	t.indexModifiedMap[index][key] = struct{}{}
}

func (t *fsmTxnCommitIndexTracker) logTxnWrites(index uint64, writes map[string]struct{}) {
	t.l.Lock()
	defer t.l.Unlock()

	t.indexModifiedMap[index] = writes
}

func (t *fsmTxnCommitIndexTracker) hasModifiedEntry(minIndex uint64, maxIndex uint64, key string) (uint64, bool) {
	t.l.Lock()
	defer t.l.Unlock()

	for index, modifications := range t.indexModifiedMap {
		if index <= minIndex || index > maxIndex {
			continue
		}

		if _, ok := modifications[key]; ok {
			return index, true
		}
	}

	return 0, false
}

func (t *fsmTxnCommitIndexTracker) hasModifiedListEntry(minIndex uint64, maxIndex uint64, key string) (uint64, bool) {
	t.l.Lock()
	defer t.l.Unlock()

	normKey := key
	if len(key) > 0 && key[len(key)-1] != '/' {
		normKey += "/"
	}

	for index, modifications := range t.indexModifiedMap {
		if index <= minIndex || index > maxIndex {
			continue
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

type fsmTxnCommitIndexApplicationState struct {
	// parent access
	parent *fsmTxnCommitIndexTracker

	// logger
	logger log.Logger

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

func (t *fsmTxnCommitIndexTracker) applyState(logger log.Logger, latestAppliedIndex uint64, commandOffset int, commandIndex uint64) *fsmTxnCommitIndexApplicationState {
	return &fsmTxnCommitIndexApplicationState{
		parent:             t,
		logger:             logger,
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

func (s *fsmTxnCommitIndexApplicationState) canFastWrite() bool {
	return s.inTx && s.commandOffset == 0 && s.latestAppliedIndex == s.txnStartIndex
}

func (s *fsmTxnCommitIndexApplicationState) indexDelta() uint64 {
	return s.latestAppliedIndex - s.txnStartIndex
}

func (s *fsmTxnCommitIndexApplicationState) canFastWriteBypassRead(key string) bool {
	// If we found a modifying entry, we can't fast-write: we need to
	// validate that the corresponding write didn't modify our entry
	// and cause the verification to fail.
	_, found := s.parent.hasModifiedEntry(s.txnStartIndex, s.commandIndex, key)
	return !found
}

func (s *fsmTxnCommitIndexApplicationState) canFastWriteBypassList(key string) bool {
	_, found := s.parent.hasModifiedListEntry(s.txnStartIndex, s.commandIndex, key)
	return !found
}

func (s *fsmTxnCommitIndexApplicationState) doVerifyRead(b *bolt.Bucket, op *LogOperation) error {
	if s.canFastWrite() || s.canFastWriteBypassRead(op.Key) {
		metrics.IncrCounter([]string{"raft-storage", "txn_fast_apply_read_hit"}, 1)
		// return nil
	}

	metrics.AddSample([]string{"raft-storage", "txn_applied_index_delta"}, float32(s.indexDelta()))
	metrics.IncrCounter([]string{"raft-storage", "txn_fast_apply_miss"}, 1)
	val := b.Get([]byte(op.Key))
	err := doVerifyEntry(op.Key, val, op.Value)

	if err != nil && (s.canFastWrite() || s.canFastWriteBypassRead(op.Key)) {
		panic(fmt.Sprintf("expected to be able to fast write (%v / %v) but err'd=%v", s.canFastWrite(), s.canFastWriteBypassRead(op.Key), err))
	}

	return err
}

func (s *fsmTxnCommitIndexApplicationState) doVerifyList(tx *bolt.Tx, b *bolt.Bucket, op *LogOperation) error {
	if s.canFastWrite() {
		metrics.IncrCounter([]string{"raft-storage", "txn_fast_apply_list_hit"}, 1)
		return nil
	}

	metrics.AddSample([]string{"raft-storage", "txn_applied_index_delta"}, float32(s.indexDelta()))
	metrics.IncrCounter([]string{"raft-storage", "txn_fast_apply_miss"}, 1)

	params, err := parseListVerifyParams(op.Key)
	if err == nil {
		var keys []string
		keys, err = listPageInner(context.Background(), tx, params.Prefix, params.After, params.Limit)
		if err == nil {
			err = doVerifyList(op.Key, keys, op.Value)
		}
	}

	if err != nil && (s.canFastWrite() || s.canFastWriteBypassList(op.Key)) {
		panic(fmt.Sprintf("expected to be able to fast write (%v / %v) but err'd=%v", s.canFastWrite(), s.canFastWriteBypassList(op.Key), err))
	}

	return err
}
