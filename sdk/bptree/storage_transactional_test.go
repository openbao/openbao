// Copyright (c) 2024 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0
package bptree

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/sdk/v2/physical/inmem"
	"github.com/stretchr/testify/require"
)

// createTransactionalStorage creates a transactional storage for testing
func createTransactionalStorage(t *testing.T) logical.TransactionalStorage {
	// Create transactional inmem backend
	inmemBackend, err := inmem.NewInmem(nil, nil)
	require.NoError(t, err, "Failed to create in-memory backend")

	// Wrap it in logical storage
	logicalStorage := logical.NewLogicalStorage(inmemBackend)

	// Verify it's transactional
	txnStorage, ok := logicalStorage.(logical.TransactionalStorage)
	require.True(t, ok, "Logical storage should implement TransactionalStorage")

	return txnStorage
}

// initTransactionalNodeStorageTest initializes a transactional node storage for testing
func initTransactionalNodeStorageTest(t *testing.T) (context.Context, TransactionalStorage) {
	ctx := context.Background()
	// Create transactional storage
	s := createTransactionalStorage(t)

	// Create transactional node storage
	storage, err := NewTransactionalNodeStorage(s, nil, 100)
	require.NoError(t, err, "Failed to create transactional node storage")

	return ctx, storage
}

// TestTransactionalStorageBasics tests the basic transactional functionality
func TestTransactionalStorageBasics(t *testing.T) {
	ctx, storage := initTransactionalNodeStorageTest(t)

	t.Run("EmptyTransactionCommit", func(t *testing.T) {
		// Empty transaction should commit successfully
		txn, err := storage.BeginTx(ctx)
		require.NoError(t, err, "Failed to begin transaction")

		err = txn.Commit(ctx)
		require.NoError(t, err, "Failed to commit empty transaction")

		// Double commit should fail
		err = txn.Commit(ctx)
		require.Error(t, err, "Expected double commit to fail")
	})

	t.Run("EmptyTransactionRollback", func(t *testing.T) {
		// Empty transaction should rollback successfully
		txn, err := storage.BeginTx(ctx)
		require.NoError(t, err, "Failed to begin transaction")

		err = txn.Rollback(ctx)
		require.NoError(t, err, "Failed to rollback empty transaction")

		// Double rollback should fail
		err = txn.Rollback(ctx)
		require.Error(t, err, "Expected double rollback to fail")
	})

	t.Run("EmptyReadOnlyTransactionCommit", func(t *testing.T) {
		// Empty read-only transaction should commit successfully
		txn, err := storage.BeginReadOnlyTx(ctx)
		require.NoError(t, err, "Failed to begin read-only transaction")

		err = txn.Commit(ctx)
		require.NoError(t, err, "Failed to commit empty read-only transaction")

		// Double commit should fail
		err = txn.Commit(ctx)
		require.Error(t, err, "Expected double commit to fail")
	})

	t.Run("CommitThenRollback", func(t *testing.T) {
		// Commit then rollback should fail
		txn, err := storage.BeginTx(ctx)
		require.NoError(t, err, "Failed to begin transaction")

		err = txn.Commit(ctx)
		require.NoError(t, err, "Failed to commit transaction")

		err = txn.Rollback(ctx)
		require.Error(t, err, "Expected rollback after commit to fail")
	})

	t.Run("RollbackThenCommit", func(t *testing.T) {
		// Rollback then commit should fail
		txn, err := storage.BeginTx(ctx)
		require.NoError(t, err, "Failed to begin transaction")

		err = txn.Rollback(ctx)
		require.NoError(t, err, "Failed to rollback transaction")

		err = txn.Commit(ctx)
		require.Error(t, err, "Expected commit after rollback to fail")
	})
}

// TestTransactionalStorageReadOnly tests read-only transaction behavior
func TestTransactionalStorageReadOnly(t *testing.T) {
	ctx, storage := initTransactionalNodeStorageTest(t)

	// First, set up some data outside of transaction
	node := NewLeafNode("test-node")
	err := node.InsertKeyValue("key1", "value1")
	require.NoError(t, err, "Failed to insert key-value pair into node")

	err = storage.SaveNode(ctx, node)
	require.NoError(t, err, "Failed to save initial node")

	t.Run("ReadOnlyTransactionCanRead", func(t *testing.T) {
		txn, err := storage.BeginReadOnlyTx(ctx)
		require.NoError(t, err, "Failed to begin read-only transaction")
		defer txn.Rollback(ctx)

		// Should be able to read existing data
		loadedNode, err := txn.LoadNode(ctx, "test-node")
		require.NoError(t, err, "Failed to load node in read-only transaction")
		require.NotNil(t, loadedNode, "Loaded node should not be nil")
		require.Equal(t, node.Keys, loadedNode.Keys, "Keys should match")
		require.Equal(t, node.Values, loadedNode.Values, "Values should match")

		// Should be able to read root ID
		err = txn.SetRootID(ctx, "test-node")
		require.Error(t, err, "Should not be able to set root ID in read-only transaction")

		// Reading root ID should work
		_, err = txn.GetRootID(ctx)
		require.NoError(t, err, "Should be able to get root ID in read-only transaction")

		err = txn.Commit(ctx)
		require.NoError(t, err, "Failed to commit read-only transaction")
	})

	t.Run("ReadOnlyTransactionCannotWrite", func(t *testing.T) {
		txn, err := storage.BeginReadOnlyTx(ctx)
		require.NoError(t, err, "Failed to begin read-only transaction")
		defer txn.Rollback(ctx)

		newNode := NewLeafNode("new-node")
		newNode.Keys = []string{"key2"}
		newNode.Values = [][]string{{"value2"}}

		// Should not be able to save node in read-only transaction
		err = txn.SaveNode(ctx, newNode)
		require.Error(t, err, "Should not be able to save node in read-only transaction")

		// Should not be able to delete node in read-only transaction
		err = txn.DeleteNode(ctx, "test-node")
		require.Error(t, err, "Should not be able to delete node in read-only transaction")

		// Should not be able to set root ID in read-only transaction
		err = txn.SetRootID(ctx, "new-root")
		require.Error(t, err, "Should not be able to set root ID in read-only transaction")
	})
}

// TestTransactionalStorageIsolation tests transaction isolation
func TestTransactionalStorageIsolation(t *testing.T) {
	ctx, storage := initTransactionalNodeStorageTest(t)

	t.Run("WriteIsolation", func(t *testing.T) {
		// Start a transaction and write some data
		txn1, err := storage.BeginTx(ctx)
		require.NoError(t, err, "Failed to begin first transaction")

		node1 := NewLeafNode("isolation-node")
		err = node1.InsertKeyValue("key1", "value1")
		require.NoError(t, err, "Failed to insert key-value pair into node")

		err = txn1.SaveNode(ctx, node1)
		require.NoError(t, err, "Failed to save node in first transaction")

		// Start a second transaction - should not see the uncommitted data
		txn2, err := storage.BeginTx(ctx)
		require.NoError(t, err, "Failed to begin second transaction")

		loadedNode, err := txn2.LoadNode(ctx, "isolation-node")
		require.NoError(t, err, "Loading non-existent node should not error")
		require.Nil(t, loadedNode, "Should not see uncommitted data from other transaction")

		// Commit first transaction
		err = txn1.Commit(ctx)
		require.NoError(t, err, "Failed to commit first transaction")

		// Second transaction behavior depends on isolation level provided by backend
		// For in-memory backend: may see committed data (read committed isolation)
		// For other backends: may provide snapshot isolation
		_, err = txn2.LoadNode(ctx, "isolation-node")
		require.NoError(t, err, "Loading should not error")
		// We don't assert the result since different backends provide different isolation levels
		// The important thing is that the transaction doesn't error and behaves consistently

		// Clean up
		err = txn2.Rollback(ctx)
		require.NoError(t, err, "Failed to rollback second transaction")

		// New transaction should see the committed data
		txn3, err := storage.BeginTx(ctx)
		require.NoError(t, err, "Failed to begin third transaction")
		defer txn3.Rollback(ctx)

		loadedNode, err = txn3.LoadNode(ctx, "isolation-node")
		require.NoError(t, err, "Failed to load committed node")
		require.NotNil(t, loadedNode, "Should see committed data")
		require.Equal(t, node1.Keys, loadedNode.Keys, "Keys should match")
	})
}

// TestTransactionalStorageRollback tests rollback behavior
func TestTransactionalStorageRollback(t *testing.T) {
	ctx, storage := initTransactionalNodeStorageTest(t)

	t.Run("RollbackPreventsWrites", func(t *testing.T) {
		// Start transaction and write data
		txn, err := storage.BeginTx(ctx)
		require.NoError(t, err, "Failed to begin transaction")

		node := NewLeafNode("rollback-node")
		node.InsertKeyValue("key1", "value1")
		require.NoError(t, err, "Failed to insert key-value pair into node")

		err = txn.SaveNode(ctx, node)
		require.NoError(t, err, "Failed to save node")

		err = txn.SetRootID(ctx, "rollback-node")
		require.NoError(t, err, "Failed to set root ID")

		// Rollback the transaction
		err = txn.Rollback(ctx)
		require.NoError(t, err, "Failed to rollback transaction")

		// Verify data was not persisted
		loadedNode, err := storage.LoadNode(ctx, "rollback-node")
		require.NoError(t, err, "Loading should not error")
		require.Nil(t, loadedNode, "Node should not exist after rollback")

		rootID, err := storage.GetRootID(ctx)
		require.NoError(t, err, "Getting root ID should not error")
		require.Equal(t, "", rootID, "Root ID should not be set after rollback")
	})
}

// TestTransactionalStorageCommit tests commit behavior
func TestTransactionalStorageCommit(t *testing.T) {
	ctx, storage := initTransactionalNodeStorageTest(t)

	t.Run("CommitPersistsWrites", func(t *testing.T) {
		// Start transaction and write data
		txn, err := storage.BeginTx(ctx)
		require.NoError(t, err, "Failed to begin transaction")

		node := NewLeafNode("commit-node")
		node.Keys = []string{"key1", "key2"}
		node.Values = [][]string{{"value1"}, {"value2"}}

		err = txn.SaveNode(ctx, node)
		require.NoError(t, err, "Failed to save node")

		err = txn.SetRootID(ctx, "commit-node")
		require.NoError(t, err, "Failed to set root ID")

		// Commit the transaction
		err = txn.Commit(ctx)
		require.NoError(t, err, "Failed to commit transaction")

		// Verify data was persisted
		loadedNode, err := storage.LoadNode(ctx, "commit-node")
		require.NoError(t, err, "Failed to load committed node")
		require.NotNil(t, loadedNode, "Node should exist after commit")
		require.Equal(t, node.Keys, loadedNode.Keys, "Keys should match")
		require.Equal(t, node.Values, loadedNode.Values, "Values should match")

		rootID, err := storage.GetRootID(ctx)
		require.NoError(t, err, "Failed to get root ID")
		require.Equal(t, "commit-node", rootID, "Root ID should be set after commit")
	})
}

// TestTransactionalStorageCache tests cache behavior in transactions
func TestTransactionalStorageCache(t *testing.T) {
	ctx, storage := initTransactionalNodeStorageTest(t)

	nodeStorage := storage.(*TransactionalNodeStorage)

	t.Run("TransactionCacheIsolation", func(t *testing.T) {
		// Create initial data outside transaction
		node1 := NewLeafNode("cache-node-1")
		err := node1.InsertKeyValue("key1", "value1")
		require.NoError(t, err, "Failed to insert key-value pair into node")

		err = nodeStorage.SaveNode(ctx, node1)
		require.NoError(t, err, "Failed to save initial node")

		// Start transaction
		txn, err := storage.BeginTx(ctx)
		require.NoError(t, err, "Failed to begin transaction")

		// Create new node in transaction
		node2 := NewLeafNode("cache-node-2")
		err = node2.InsertKeyValue("key2", "value2")
		require.NoError(t, err, "Failed to insert key-value pair into node")

		err = txn.SaveNode(ctx, node2)
		require.NoError(t, err, "Failed to save node in transaction")

		// Should be able to read the new node within the transaction
		// TODO (gabrielopesantos): Queues the same op twice...
		loadedNode, err := txn.LoadNode(ctx, "cache-node-2")
		require.NoError(t, err, "Failed to load node within transaction")
		require.NotNil(t, loadedNode, "Node should be accessible within transaction")
		require.Equal(t, node2.Keys, loadedNode.Keys, "Keys should match")

		// Outside the transaction, the node should not be visible yet
		cachedNodeOutside, ok := nodeStorage.cache.Get("cache-node-2")
		require.False(t, ok, "Node should not be in cache outside transaction")
		require.Nil(t, cachedNodeOutside, "Cached node should be nil outside transaction")

		loadedNodeOutside, err := nodeStorage.LoadNode(ctx, "cache-node-2")
		require.NoError(t, err, "Loading should not error")
		require.Nil(t, loadedNodeOutside, "Node should not be visible outside transaction")

		// Commit transaction
		err = txn.Commit(ctx)
		require.NoError(t, err, "Failed to commit transaction")

		// Now the node should be visible outside the transaction
		cachedNodeAfterCommit, ok := nodeStorage.cache.Get(cacheKey(ctx, "cache-node-2"))
		require.True(t, ok, "Node should be in cache after commit")
		require.NotNil(t, cachedNodeAfterCommit, "Cached node should not be nil after commit")
		require.Equal(t, node2.Keys, cachedNodeAfterCommit.Keys, "Cached node keys should match")

		loadedNodeAfterCommit, err := nodeStorage.LoadNode(ctx, "cache-node-2")
		require.NoError(t, err, "Failed to load node after commit")
		require.NotNil(t, loadedNodeAfterCommit, "Node should be visible after commit")
		require.Equal(t, node2.Keys, loadedNodeAfterCommit.Keys, "Keys should match")
	})

	t.Run("CacheOperationsQueuedInTransaction", func(t *testing.T) {
		// Start transaction
		txn, err := storage.BeginTx(ctx)
		require.NoError(t, err, "Failed to begin transaction")

		// Create node in transaction
		node := NewLeafNode("queue-node")
		node.InsertKeyValue("key1", "value1")

		err = txn.SaveNode(ctx, node)
		require.NoError(t, err, "Failed to save node in transaction")

		// The cache operations should be queued, not immediately applied to main cache
		// There's no direct way to check the cache state here, but we can check after commit

		// Rollback transaction
		err = txn.Rollback(ctx)
		require.NoError(t, err, "Failed to rollback transaction")

		// Node should not exist in storage or cache
		loadedNode, err := nodeStorage.LoadNode(ctx, "queue-node")
		require.NoError(t, err, "Loading should not error")
		require.Nil(t, loadedNode, "Node should not exist after rollback")
	})
}

// TestTransactionalStorageConcurrency tests concurrent transaction behavior
func TestTransactionalStorageConcurrency(t *testing.T) {
	ctx, storage := initTransactionalNodeStorageTest(t)

	t.Run("ConcurrentTransactions", func(t *testing.T) {
		var wg sync.WaitGroup
		errChan := make(chan error, 10)

		// Launch multiple concurrent transactions
		for i := range 5 {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()

				txn, err := storage.BeginTx(ctx)
				if err != nil {
					errChan <- fmt.Errorf("failed to begin transaction %d: %w", id, err)
					return
				}

				// Create a unique node for this transaction
				node := NewLeafNode(fmt.Sprintf("concurrent-node-%d", id))
				node.Keys = []string{fmt.Sprintf("key%d", id)}
				node.Values = [][]string{{fmt.Sprintf("value%d", id)}}

				err = txn.SaveNode(ctx, node)
				if err != nil {
					errChan <- fmt.Errorf("failed to save node in transaction %d: %w", id, err)
					txn.Rollback(ctx)
					return
				}

				// Commit the transaction
				err = txn.Commit(ctx)
				if err != nil {
					errChan <- fmt.Errorf("failed to commit transaction %d: %w", id, err)
					return
				}
			}(i)
		}

		// Wait for all goroutines to complete
		done := make(chan struct{})
		go func() {
			wg.Wait()
			close(done)
		}()

		select {
		case <-done:
			// All goroutines completed
		case <-time.After(10 * time.Second):
			t.Fatal("test timed out")
		}

		close(errChan)

		// Check for errors
		for err := range errChan {
			t.Error(err)
		}

		// Verify all nodes were created
		for i := range 5 {
			nodeID := fmt.Sprintf("concurrent-node-%d", i)
			loadedNode, err := storage.LoadNode(ctx, nodeID)
			require.NoError(t, err, "Failed to load node %d", i)
			require.NotNil(t, loadedNode, "Node %d should exist", i)
			require.Equal(t, []string{fmt.Sprintf("key%d", i)}, loadedNode.Keys, "Keys should match for node %d", i)
		}
	})
}

// TestWithTransactionHelper tests the WithTransaction helper function
func TestWithTransactionHelper(t *testing.T) {
	ctx, storage := initTransactionalNodeStorageTest(t)

	t.Run("WithTransactionSuccess", func(t *testing.T) {
		err := WithTransaction(ctx, storage, func(txnStorage Storage) error {
			node := NewLeafNode("helper-node")
			node.Keys = []string{"key1"}
			node.Values = [][]string{{"value1"}}

			err := txnStorage.SaveNode(ctx, node)
			if err != nil {
				return err
			}

			err = txnStorage.SetRootID(ctx, "helper-node")
			if err != nil {
				return err
			}

			return nil
		})

		require.NoError(t, err, "WithTransaction should succeed")

		// Verify data was committed
		loadedNode, err := storage.LoadNode(ctx, "helper-node")
		require.NoError(t, err, "Failed to load node")
		require.NotNil(t, loadedNode, "Node should exist")

		rootID, err := storage.GetRootID(ctx)
		require.NoError(t, err, "Failed to get root ID")
		require.Equal(t, "helper-node", rootID, "Root ID should be set")
	})

	t.Run("WithTransactionFailure", func(t *testing.T) {
		expectedError := fmt.Errorf("intentional error")
		err := WithTransaction(ctx, storage, func(txnStorage Storage) error {
			node := NewLeafNode("failure-node")
			node.Keys = []string{"key1"}
			node.Values = [][]string{{"value1"}}

			err := txnStorage.SaveNode(ctx, node)
			if err != nil {
				return err
			}

			// Return an error to trigger rollback
			return expectedError
		})

		require.Error(t, err, "WithTransaction should fail")
		require.Contains(t, err.Error(), "intentional error", "Should contain the original error")

		// Verify data was not committed (rolled back)
		loadedNode, err := storage.LoadNode(ctx, "failure-node")
		require.NoError(t, err, "Loading should not error")
		require.Nil(t, loadedNode, "Node should not exist after rollback")
	})
}

// TestTransactionalStorageUtilityMethods tests cache utility methods
func TestTransactionalStorageUtilityMethods(t *testing.T) {
	ctx := context.Background()
	s := createTransactionalStorage(t)
	storage, err := NewTransactionalNodeStorage(s, nil, 100)
	require.NoError(t, err, "Failed to create storage")
	nodeStorage := storage.(*TransactionalNodeStorage)
	require.NoError(t, err, "Failed to create storage")

	t.Run("CacheUtilityMethods", func(t *testing.T) {
		// Test cache enabled by default
		require.True(t, nodeStorage.IsCacheEnabled(), "Cache should be enabled by default")

		// Add some data to get cache stats
		node := NewLeafNode("utils-node")
		node.InsertKeyValue("key1", "value1")

		err := nodeStorage.SaveNode(ctx, node)
		require.NoError(t, err, "Failed to save node")

		// Load to populate cache
		_, err = nodeStorage.LoadNode(ctx, "utils-node")
		require.NoError(t, err, "Failed to load node")

		// Test purge cache
		nodeStorage.PurgeCache()

		// Verify cache is empty
		_, ok := nodeStorage.cache.Get("utils-node")
		require.False(t, ok, "Cache should be empty after purge")

		// Test disable cache
		nodeStorage.EnableCache(false)
		require.False(t, nodeStorage.IsCacheEnabled(), "Cache should be disabled")

		// Re-insert data to see if it works without cache
		err = nodeStorage.SaveNode(ctx, node)
		require.NoError(t, err, "Failed to save node with cache disabled")

		// Try to load the node from cache
		_, ok = nodeStorage.cache.Get("utils-node")
		require.False(t, ok, "Cache should not contain node when cache is disabled")

		// Load node to verify it works without cache
		loadedNode, err := nodeStorage.LoadNode(ctx, "utils-node")
		require.NoError(t, err, "Failed to load node with cache disabled")
		require.NotNil(t, loadedNode, "Loaded node should not be nil")
		require.Equal(t, node.Keys, loadedNode.Keys, "Keys should match after loading with cache disabled")
		require.Equal(t, node.Values, loadedNode.Values, "Values should match after loading with cache disabled")

		// Re-enable cache
		nodeStorage.EnableCache(true)
		require.True(t, nodeStorage.IsCacheEnabled(), "Cache should be enabled")
	})
}
