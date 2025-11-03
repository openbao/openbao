// Copyright (c) 2024 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package raft

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/physical"
	"github.com/stretchr/testify/require"
)

// TestRaft_NonTransactional_MemoryLeak tests that non-transactional Put/Delete
// operations properly set lowestActiveIndex and clean up indexModifiedMap,
// preventing memory leaks.
func TestRaft_NonTransactional_MemoryLeak(t *testing.T) {
	b, dir := GetRaft(t, true, true)
	defer os.RemoveAll(dir)

	ctx := context.Background()

	// Perform several non-transactional writes
	numOps := 100
	for i := 0; i < numOps; i++ {
		key := fmt.Sprintf("key-%d", i)
		value := []byte(fmt.Sprintf("value-%d", i))

		err := b.Put(ctx, &physical.Entry{
			Key:   key,
			Value: value,
		})
		require.NoError(t, err, "Put operation %d should succeed", i)

		// Give raft time to apply
		time.Sleep(10 * time.Millisecond)
	}

	// Wait for all operations to be applied
	time.Sleep(100 * time.Millisecond)

	// Check the size of both tracking maps - they should be cleaned up
	b.fsm.fastTxnTracker.l.Lock()
	indexModifiedMapSize := len(b.fsm.fastTxnTracker.indexModifiedMap)
	sourceIndexMapSize := len(b.fsm.fastTxnTracker.sourceIndexMap)
	b.fsm.fastTxnTracker.l.Unlock()

	// Both maps should be empty or very small since there are no active transactions
	// and cleanup should have occurred
	t.Logf("indexModifiedMap size after %d operations: %d", numOps, indexModifiedMapSize)
	t.Logf("sourceIndexMap size after %d operations: %d", numOps, sourceIndexMapSize)

	// With the fix, the maps should be cleaned up (empty or near-empty).
	// Without the fix, they would grow to numOps entries.
	require.Less(t, indexModifiedMapSize, 10, "indexModifiedMap should be cleaned up, but has %d entries", indexModifiedMapSize)
	require.Equal(t, 0, sourceIndexMapSize, "sourceIndexMap should be empty (no active transactions), but has %d entries", sourceIndexMapSize)
}

// TestRaft_NonTransactional_LowestActiveIndex tests that non-transactional
// operations correctly set lowestActiveIndex in their log entries.
func TestRaft_NonTransactional_LowestActiveIndex(t *testing.T) {
	b, dir := GetRaft(t, true, true)
	defer os.RemoveAll(dir)

	ctx := context.Background()

	// Perform a non-transactional write
	err := b.Put(ctx, &physical.Entry{
		Key:   "test-key",
		Value: []byte("test-value"),
	})
	require.NoError(t, err, "Put operation should succeed")

	// Wait for the operation to be applied
	time.Sleep(100 * time.Millisecond)

	// The lowestActiveIndex should have been set (not nil) in the log entry
	// We can verify this indirectly by checking that cleanup happened
	b.fsm.fastTxnTracker.l.Lock()
	indexModifiedMapSize := len(b.fsm.fastTxnTracker.indexModifiedMap)
	sourceIndexMapSize := len(b.fsm.fastTxnTracker.sourceIndexMap)
	b.fsm.fastTxnTracker.l.Unlock()

	t.Logf("indexModifiedMap size after single operation: %d", indexModifiedMapSize)
	t.Logf("sourceIndexMap size after single operation: %d", sourceIndexMapSize)

	// With the fix, lowestActiveIndex is set, so cleanup occurs
	// The maps should be empty or have very few entries
	require.LessOrEqual(t, indexModifiedMapSize, 1, "indexModifiedMap should be cleaned up")
	require.Equal(t, 0, sourceIndexMapSize, "sourceIndexMap should be empty (no active transactions)")
}

// TestRaft_NonTransactional_MixedWithTransactions tests that non-transactional
// operations correctly handle lowestActiveIndex when transactions are active.
func TestRaft_NonTransactional_MixedWithTransactions(t *testing.T) {
	b, dir := GetRaft(t, true, true)
	defer os.RemoveAll(dir)

	ctx := context.Background()

	// Perform a non-transactional write first to establish a baseline
	err := b.Put(ctx, &physical.Entry{
		Key:   "baseline-key",
		Value: []byte("baseline-value"),
	})
	require.NoError(t, err, "Baseline Put should succeed")
	time.Sleep(100 * time.Millisecond)

	// Start a transaction
	tx, err := b.BeginTx(ctx)
	require.NoError(t, err, "BeginTx should succeed")

	// The transaction tracks its start index
	raftTx := tx.(*RaftTransaction)
	txStartIndex := raftTx.index
	t.Logf("Transaction started at index: %d", txStartIndex)

	// Perform some writes in the transaction
	err = tx.Put(ctx, &physical.Entry{
		Key:   "tx-key-1",
		Value: []byte("tx-value-1"),
	})
	require.NoError(t, err, "Transaction Put should succeed")

	// Check that the transaction is tracked
	lowestIndex := b.fsm.fastTxnTracker.lowestActiveIndex()

	b.fsm.fastTxnTracker.l.Lock()
	_, txActive := b.fsm.fastTxnTracker.sourceIndexMap[txStartIndex]
	b.fsm.fastTxnTracker.l.Unlock()

	t.Logf("Transaction active: %v", txActive)
	t.Logf("Lowest active index: %d", lowestIndex)

	require.True(t, txActive, "Transaction should be tracked")
	require.Equal(t, txStartIndex, lowestIndex, "Lowest active index should be the transaction start index")

	// Commit the transaction
	err = tx.Commit(ctx)
	require.NoError(t, err, "Transaction commit should succeed")

	// Wait for commit to be applied
	time.Sleep(200 * time.Millisecond)

	// After commit, the transaction should no longer be active
	b.fsm.fastTxnTracker.l.Lock()
	_, txStillActive := b.fsm.fastTxnTracker.sourceIndexMap[txStartIndex]
	indexModifiedMapSize := len(b.fsm.fastTxnTracker.indexModifiedMap)
	sourceIndexMapSize := len(b.fsm.fastTxnTracker.sourceIndexMap)
	b.fsm.fastTxnTracker.l.Unlock()

	t.Logf("Transaction still active after commit: %v", txStillActive)
	t.Logf("indexModifiedMap size after commit: %d", indexModifiedMapSize)
	t.Logf("sourceIndexMap size after commit: %d", sourceIndexMapSize)

	require.False(t, txStillActive, "Transaction should no longer be tracked after commit")

	// Both maps should be cleaned up after the transaction completes
	require.Less(t, indexModifiedMapSize, 5, "indexModifiedMap should be cleaned up after transaction commit")
	require.Equal(t, 0, sourceIndexMapSize, "sourceIndexMap should be empty after transaction commit")
} // TestRaft_LowestActiveIndex_NoTransactions tests the lowestActiveIndex method
// when there are no active transactions.
func TestRaft_LowestActiveIndex_NoTransactions(t *testing.T) {
	b, dir := GetRaft(t, true, true)
	defer os.RemoveAll(dir)

	// Check lowestActiveIndex when no transactions are active
	lowestIndex := b.fsm.fastTxnTracker.lowestActiveIndex()

	// Should return math.MaxUint64 when there are no active transactions
	t.Logf("Lowest active index (no transactions): %d", lowestIndex)
	require.Equal(t, uint64(1<<64-1), lowestIndex, "Should return MaxUint64 when no transactions are active")
}

// TestRaft_LowestActiveIndex_WithTransactions tests the lowestActiveIndex method
// when transactions are active.
func TestRaft_LowestActiveIndex_WithTransactions(t *testing.T) {
	b, dir := GetRaft(t, true, true)
	defer os.RemoveAll(dir)

	ctx := context.Background()

	// Start multiple transactions
	tx1, err := b.BeginTx(ctx)
	require.NoError(t, err)
	raftTx1 := tx1.(*RaftTransaction)

	time.Sleep(50 * time.Millisecond)

	tx2, err := b.BeginTx(ctx)
	require.NoError(t, err)
	raftTx2 := tx2.(*RaftTransaction)

	time.Sleep(50 * time.Millisecond)

	tx3, err := b.BeginTx(ctx)
	require.NoError(t, err)
	raftTx3 := tx3.(*RaftTransaction)

	t.Logf("Transaction 1 index: %d", raftTx1.index)
	t.Logf("Transaction 2 index: %d", raftTx2.index)
	t.Logf("Transaction 3 index: %d", raftTx3.index)

	// Check lowestActiveIndex - should be the lowest of the three
	lowestIndex := b.fsm.fastTxnTracker.lowestActiveIndex()
	t.Logf("Lowest active index: %d", lowestIndex)

	require.Equal(t, raftTx1.index, lowestIndex, "Should return the lowest transaction index")

	// Commit the first transaction
	err = tx1.Commit(ctx)
	require.NoError(t, err)
	time.Sleep(100 * time.Millisecond)

	// Now the lowest should be tx2
	lowestIndex = b.fsm.fastTxnTracker.lowestActiveIndex()
	t.Logf("Lowest active index after first commit: %d", lowestIndex)
	require.Equal(t, raftTx2.index, lowestIndex, "Should return the second transaction index after first commits")

	// Clean up remaining transactions
	err = tx2.Commit(ctx)
	require.NoError(t, err)
	err = tx3.Commit(ctx)
	require.NoError(t, err)
}
