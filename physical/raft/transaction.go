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

	"github.com/openbao/openbao/sdk/v2/physical"
	"go.etcd.io/bbolt"
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
	tx             *bbolt.Tx
	updates        map[string]*raftTxnUpdateRecord
	log            *LogData
	writable       bool
	haveWritten    bool
	haveFinishedTx bool
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

	return &RaftTransaction{
		b:       b,
		tx:      tx,
		updates: make(map[string]*raftTxnUpdateRecord),
		log: &LogData{
			Operations: []*LogOperation{
				{
					OpType: beginTxOp,
				},
			},
		},
		writable: writable,
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
		t.b.fsm.l.RUnlock()
		t.b.txnPermitPool.Release()
		t.haveFinishedTx = true

		// Restore ourselves to the initial state.
		t.updates = make(map[string]*raftTxnUpdateRecord)
		t.log = &LogData{
			Operations: []*LogOperation{
				{
					OpType: beginTxOp,
				},
			},
		}
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
		t.b.fsm.l.RUnlock()
		t.b.txnPermitPool.Release()

		t.haveFinishedTx = true

		// Restore ourselves to the initial state.
		t.updates = make(map[string]*raftTxnUpdateRecord)
		t.log = &LogData{
			Operations: []*LogOperation{
				{
					OpType: beginTxOp,
				},
			},
		}
	}()

	// Rollback the underlying transaction.
	if err := t.tx.Rollback(); err != nil {
		return err
	}

	return nil
}
