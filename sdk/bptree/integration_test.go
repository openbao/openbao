// Copyright (c) 2024 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package bptree

import (
	"context"
	"fmt"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/sdk/v2/physical/inmem"
	"github.com/stretchr/testify/require"
)

func TestTransactionBufferingIntegration(t *testing.T) {
	// Test integration between transactions and buffering mechanisms
	ctx := context.Background()

	// Create transactional inmem backend
	inmemBackend, err := inmem.NewInmem(nil, nil)
	require.NoError(t, err, "Failed to create in-memory backend")

	// Wrap it in logical storage
	logicalStorage := logical.NewLogicalStorage(inmemBackend)

	// Verify it's transactional
	baseLogicalStorage, ok := logicalStorage.(logical.TransactionalStorage)
	require.True(t, ok, "Logical storage should implement TransactionalStorage")

	// Create transactional node storage
	baseStorage, err := NewNodeStorage(baseLogicalStorage, NewStorageConfig())
	require.NoError(t, err, "Failed to create base node storage")

	transactionalStorage, err := NewTransactionalNodeStorage(baseLogicalStorage, NewTransactionalStorageConfig())
	require.NoError(t, err, "Failed to create transactional node storage")

	t.Run("WithBufferedWrites_InternalTransaction", func(t *testing.T) {
		// Begin a transaction
		tx, err := transactionalStorage.BeginTx(ctx)
		require.NoError(t, err, "failed to begin transaction")

		// Use buffered writes within the transaction
		err = WithBufferedWrites(ctx, tx, func(storage Storage) error {
			node1 := NewLeafNode("node1")
			node2 := NewLeafNode("node2")

			// These should be buffered and then flushed to the transaction
			if err := storage.PutNode(ctx, node1); err != nil {
				return err
			}
			if err := storage.PutNode(ctx, node2); err != nil {
				return err
			}
			return nil
		})
		require.NoError(t, err, "BufferedWrites failed")

		// At this point, nodes should be in the transaction but not base storage
		// Check that base storage doesn't have the nodes yet
		node1, err := baseStorage.GetNode(ctx, "node1")
		require.ErrorIs(t, err, ErrNodeNotFound, "node1 should not be in base storage before commit")
		require.Nil(t, node1, "node1 should be nil in base storage before commit")

		node2, err := baseStorage.GetNode(ctx, "node2")
		require.ErrorIs(t, err, ErrNodeNotFound, "node2 should not be in base storage before commit")
		require.Nil(t, node2, "node2 should be nil in base storage before commit")

		// Commit the transaction
		err = tx.Commit(ctx)
		require.NoError(t, err, "failed to commit transaction")

		// Now nodes should be in base storage
		node1, err = baseStorage.GetNode(ctx, "node1")
		require.NoError(t, err, "node1 should be in base storage after commit")
		require.NotNil(t, node1, "node1 should not be nil in base storage after commit")

		node2, err = baseStorage.GetNode(ctx, "node2")
		require.NoError(t, err, "node2 should be in base storage after commit")
		require.NotNil(t, node2, "node2 should not be nil in base storage after commit")
	})

	t.Run("WithBufferedWrites_TransactionRollback", func(t *testing.T) {
		// Begin a transaction
		tx, err := transactionalStorage.BeginTx(ctx)
		require.NoError(t, err, "Failed to begin transaction")

		// Use buffered writes within the transaction
		err = WithBufferedWrites(ctx, tx, func(storage Storage) error {
			node3 := NewLeafNode("node3")
			return storage.PutNode(ctx, node3)
		})
		require.NoError(t, err, "BufferedWrites failed")

		// Rollback the transaction
		err = tx.Rollback(ctx)
		require.NoError(t, err, "Failed to rollback transaction")

		// Node should not be in base storage
		_, err = baseStorage.GetNode(ctx, "node3")
		require.ErrorIs(t, err, ErrNodeNotFound, "node3 should not be in base storage after rollback")
	})

	t.Run("WithTransaction_NestedBuffering", func(t *testing.T) {
		// This tests the opposite: transaction around buffered writes
		err := WithTransaction(ctx, transactionalStorage, func(txStorage Storage) error {
			return WithBufferedWrites(ctx, txStorage, func(bufferedStorage Storage) error {
				node4 := NewLeafNode("node4")
				node5 := NewLeafNode("node5")

				if err := bufferedStorage.PutNode(ctx, node4); err != nil {
					return err
				}
				if err := bufferedStorage.PutNode(ctx, node5); err != nil {
					return err
				}
				return nil
			})
		})
		require.NoError(t, err, "Nested transaction+buffered failed")

		// Both nodes should be in base storage after commit
		_, err = baseStorage.GetNode(ctx, "node4")
		require.NoError(t, err, "node4 should be in base storage")

		_, err = baseStorage.GetNode(ctx, "node5")
		require.NoError(t, err, "node5 should be in base storage")
	})
}

func TestExternalTransactionIntegration(t *testing.T) {
	// Test external transaction functionality using WithExistingTransaction
	ctx := context.Background()

	// Create transactional inmem backend
	inmemBackend, err := inmem.NewInmem(nil, nil)
	require.NoError(t, err, "Failed to create in-memory backend")

	// Wrap it in logical storage
	logicalStorage := logical.NewLogicalStorage(inmemBackend)
	baseLogicalStorage, ok := logicalStorage.(logical.TransactionalStorage)
	require.True(t, ok, "Logical storage should implement TransactionalStorage")

	// Create base storage
	baseStorage, err := NewNodeStorage(baseLogicalStorage, NewStorageConfig())
	require.NoError(t, err, "Failed to create base node storage")

	t.Run("ExternalTransaction_IsolatedCache", func(t *testing.T) {
		// Test that external transactions get their own isolated cache
		// that doesn't merge back to parent

		// First, put a node in the base storage to establish baseline
		err = WithAutoFlush(ctx, baseStorage, func(storage Storage) error {
			baseNode := NewLeafNode("base-node")
			return storage.PutNode(ctx, baseNode)
		})
		require.NoError(t, err, "failed to put base node")

		// Begin external transaction
		tx, err := baseLogicalStorage.BeginTx(ctx)
		require.NoError(t, err, "failed to begin external transaction")

		// Create NodeStorage from external transaction
		// Transactions should have buffering enabled for proper isolation
		txStorage, err := WithExistingTransaction(ctx, tx, baseStorage, WithBufferingEnabled(true))
		require.NoError(t, err, "failed to create external transaction storage")

		// Read the base node through transaction storage (should cache it locally)
		txNode, err := txStorage.GetNode(ctx, "base-node")
		require.NoError(t, err, "failed to get base node through tx storage")
		require.Equal(t, "base-node", txNode.ID)

		// Put a new node through transaction storage (should buffer and cache locally)
		txOnlyNode := NewLeafNode("tx-only-node")
		err = WithAutoFlush(ctx, txStorage, func(storage Storage) error {
			return storage.PutNode(ctx, txOnlyNode)
		})
		require.NoError(t, err, "failed to put tx-only node")

		// Commit external transaction
		err = tx.Commit(ctx)
		require.NoError(t, err, "failed to commit external transaction")

		// Now the tx-only node should be visible in base storage
		// (because the transaction committed to the underlying storage)
		finalNode, err := baseStorage.GetNode(ctx, "tx-only-node")
		require.NoError(t, err, "tx-only node should be in base storage after commit")
		require.Equal(t, "tx-only-node", finalNode.ID)

		// Verify base storage cache wasn't polluted with transaction cache entries
		// We can't directly access the cache due to encapsulation, but we can verify behavior
		// by checking that the node is still retrievable after cache purge
		baseStorage.PurgeCache() // Clear any cached entries
		finalNodeFromCache, err := baseStorage.GetNode(ctx, "tx-only-node")
		require.NoError(t, err, "tx-only node should still be retrievable from storage")
		require.Equal(t, "tx-only-node", finalNodeFromCache.ID)
	})

	t.Run("ExternalTransaction_Rollback", func(t *testing.T) {
		// Test that external transaction rollback properly discards changes

		// Begin external transaction
		tx, err := baseLogicalStorage.BeginTx(ctx)
		require.NoError(t, err, "failed to begin external transaction")

		// Create NodeStorage from external transaction
		txStorage, err := WithExistingTransaction(ctx, tx, baseStorage)
		require.NoError(t, err, "failed to create external transaction storage")

		// Put a node that we'll rollback
		rollbackNode := NewLeafNode("rollback-node")
		err = txStorage.PutNode(ctx, rollbackNode)
		require.NoError(t, err, "failed to put rollback node")

		// Flush to transaction (but not yet committed)
		if ns, ok := txStorage.(*NodeStorage); ok {
			err = ns.FlushBuffer(ctx)
			require.NoError(t, err, "failed to flush transaction buffer")
		}

		// Rollback external transaction
		err = tx.Rollback(ctx)
		require.NoError(t, err, "failed to rollback external transaction")

		// Verify the node is not in base storage
		_, err = baseStorage.GetNode(ctx, "rollback-node")
		require.ErrorIs(t, err, ErrNodeNotFound, "rollback-node should not be in base storage after rollback")
	})

	t.Run("ExternalTransaction_ConfigurationAndInheritance", func(t *testing.T) {
		// Test that external transactions inherit and can override configuration

		// Create base storage with specific configuration
		baseStorage, err := NewNodeStorage(baseLogicalStorage, NewStorageConfig(
			WithCacheSize(150),
			WithCachingEnabled(true),
			WithBufferingEnabled(true),
		))
		require.NoError(t, err, "Failed to create base storage")

		// Test 1: External transaction with default inheritance
		tx1, err := baseLogicalStorage.BeginTx(ctx)
		require.NoError(t, err, "failed to begin external transaction")

		txStorage1, err := WithExistingTransaction(ctx, tx1, baseStorage)
		require.NoError(t, err, "failed to create external transaction storage")

		node1 := NewLeafNode("config-test-inheritance")
		err = txStorage1.PutNode(ctx, node1)
		require.NoError(t, err, "failed to put node in external transaction")

		if ns, ok := txStorage1.(*NodeStorage); ok {
			err = ns.FlushBuffer(ctx)
			require.NoError(t, err, "failed to flush external transaction buffer")
		}

		err = tx1.Commit(ctx)
		require.NoError(t, err, "failed to commit external transaction")

		// Test 2: External transaction with config overrides
		tx2, err := baseLogicalStorage.BeginTx(ctx)
		require.NoError(t, err, "failed to begin external transaction with overrides")

		txStorage2, err := WithExistingTransaction(ctx, tx2, baseStorage,
			WithCacheSize(10),           // Override cache size
			WithBufferingEnabled(false), // Disable buffering
		)
		require.NoError(t, err, "failed to create override external transaction storage")

		// Put a node (should go directly to transaction since buffering is disabled)
		node2 := NewLeafNode("config-test-override")
		err = txStorage2.PutNode(ctx, node2)
		require.NoError(t, err, "failed to put node with overrides")

		// Verify it's immediately accessible through transaction storage
		retrievedNode, err := txStorage2.GetNode(ctx, "config-test-override")
		require.NoError(t, err, "should be able to get node immediately")
		require.Equal(t, "config-test-override", retrievedNode.ID)

		// No need to flush buffer since buffering is disabled
		err = tx2.Commit(ctx)
		require.NoError(t, err, "failed to commit override external transaction")

		// Verify both nodes are accessible
		for _, nodeID := range []string{"config-test-inheritance", "config-test-override"} {
			node, err := baseStorage.GetNode(ctx, nodeID)
			require.NoError(t, err, "failed to get node %s from base storage", nodeID)
			require.Equal(t, nodeID, node.ID, "node ID mismatch for %s", nodeID)
		}
	})

	t.Run("ExternalTransaction_NestedHelpers", func(t *testing.T) {
		// Test combining WithExistingTransaction with helper functions

		// Begin external transaction
		tx, err := baseLogicalStorage.BeginTx(ctx)
		require.NoError(t, err, "failed to begin external transaction")

		// Create transaction storage with buffering enabled for WithBufferedWrites
		txStorage, err := WithExistingTransaction(ctx, tx, baseStorage, WithBufferingEnabled(true))
		require.NoError(t, err, "failed to create external transaction storage")

		// Use WithBufferedWrites within the existing transaction
		err = WithBufferedWrites(ctx, txStorage, func(bufferedStorage Storage) error {
			// Put multiple nodes that should be buffered
			for i := 1; i <= 3; i++ {
				node := NewLeafNode(fmt.Sprintf("nested-helper-node-%d", i))
				if err := bufferedStorage.PutNode(ctx, node); err != nil {
					return fmt.Errorf("failed to put node %d: %w", i, err)
				}
			}
			return nil
		})
		require.NoError(t, err, "WithBufferedWrites within existing transaction failed")

		// Verify nodes are accessible through transaction storage
		for i := 1; i <= 3; i++ {
			nodeID := fmt.Sprintf("nested-helper-node-%d", i)
			_, err = txStorage.GetNode(ctx, nodeID)
			require.NoError(t, err, "nested helper node %d should be accessible", i)
		}

		// Commit the external transaction
		err = tx.Commit(ctx)
		require.NoError(t, err, "failed to commit external transaction")

		// Verify all nodes are accessible through new transaction
		for i := 1; i <= 3; i++ {
			nodeID := fmt.Sprintf("nested-helper-node-%d", i)
			checkTx, err := baseLogicalStorage.BeginTx(ctx)
			require.NoError(t, err, "failed to begin check transaction")
			checkTxStorage, err := WithExistingTransaction(ctx, checkTx, baseStorage)
			require.NoError(t, err, "failed to create check transaction storage")
			node, err := checkTxStorage.GetNode(ctx, nodeID)
			require.NoError(t, err, "nested helper node %d should be accessible", i)
			require.Equal(t, nodeID, node.ID)
			err = checkTx.Rollback(ctx)
			require.NoError(t, err, "failed to rollback check transaction")
		}
	})

	t.Run("ExternalTransaction_WithAutoFlush", func(t *testing.T) {
		// Test WithAutoFlush with existing transactions

		// Begin external transaction
		tx, err := baseLogicalStorage.BeginTx(ctx)
		require.NoError(t, err, "failed to begin external transaction")

		// Create transaction storage with buffering enabled
		txStorage, err := WithExistingTransaction(ctx, tx, baseStorage, WithBufferingEnabled(true))
		require.NoError(t, err, "failed to create external transaction storage")

		// Use WithAutoFlush
		err = WithAutoFlush(ctx, txStorage, func(storage Storage) error {
			// Put nodes that should be auto-flushed
			for i := 1; i <= 2; i++ {
				node := NewLeafNode(fmt.Sprintf("auto-flush-node-%d", i))
				if err := storage.PutNode(ctx, node); err != nil {
					return fmt.Errorf("failed to put auto-flush node %d: %w", i, err)
				}
			}
			return nil
		})
		require.NoError(t, err, "WithAutoFlush within existing transaction failed")

		// Nodes should be flushed to the transaction but not accessible through other transactions yet
		for i := 1; i <= 2; i++ {
			nodeID := fmt.Sprintf("auto-flush-node-%d", i)

			// Should be accessible through transaction
			_, err = txStorage.GetNode(ctx, nodeID)
			require.NoError(t, err, "auto-flush node %d should be accessible through tx", i)

			// Should not be accessible through other transactions yet
			checkTx, err := baseLogicalStorage.BeginTx(ctx)
			require.NoError(t, err, "failed to begin check transaction")
			checkTxStorage, err := WithExistingTransaction(ctx, checkTx, baseStorage)
			require.NoError(t, err, "failed to create check transaction storage")
			_, err = checkTxStorage.GetNode(ctx, nodeID)
			require.ErrorIs(t, err, ErrNodeNotFound, "auto-flush node %d should not be accessible before commit", i)
			err = checkTx.Rollback(ctx)
			require.NoError(t, err, "failed to rollback check transaction")
		}

		// Commit the external transaction
		err = tx.Commit(ctx)
		require.NoError(t, err, "failed to commit external transaction")

		// Now nodes should be accessible through new transactions
		for i := 1; i <= 2; i++ {
			nodeID := fmt.Sprintf("auto-flush-node-%d", i)
			checkTx, err := baseLogicalStorage.BeginTx(ctx)
			require.NoError(t, err, "failed to begin check transaction")
			checkTxStorage, err := WithExistingTransaction(ctx, checkTx, baseStorage)
			require.NoError(t, err, "failed to create check transaction storage")
			node, err := checkTxStorage.GetNode(ctx, nodeID)
			require.NoError(t, err, "auto-flush node %d should be accessible after commit", i)
			require.Equal(t, nodeID, node.ID)
			err = checkTx.Rollback(ctx)
			require.NoError(t, err, "failed to rollback check transaction")
		}
	})

	t.Run("ExternalTransaction_ErrorHandling", func(t *testing.T) {
		// Test error handling with existing transactions

		// Begin external transaction
		tx, err := baseLogicalStorage.BeginTx(ctx)
		require.NoError(t, err, "failed to begin external transaction")

		// Create transaction storage
		txStorage, err := WithExistingTransaction(ctx, tx, baseStorage)
		require.NoError(t, err, "failed to create external transaction storage")

		// Put a node successfully first
		successNode := NewLeafNode("error-handling-success")
		err = WithAutoFlush(ctx, txStorage, func(storage Storage) error {
			return storage.PutNode(ctx, successNode)
		})
		require.NoError(t, err, "failed to put success node")

		// Simulate an error scenario by trying to get a non-existent node
		_, err = txStorage.GetNode(ctx, "non-existent-node")
		require.ErrorIs(t, err, ErrNodeNotFound, "should get ErrNodeNotFound for non-existent node")

		// The successful node should still be accessible
		retrievedNode, err := txStorage.GetNode(ctx, "error-handling-success")
		require.NoError(t, err, "success node should still be accessible after error")
		require.Equal(t, "error-handling-success", retrievedNode.ID)

		// Commit should still work
		err = tx.Commit(ctx)
		require.NoError(t, err, "commit should work after non-fatal error")

		// Verify the success node is accessible through underlying storage
		checkTx, err := baseLogicalStorage.BeginTx(ctx) // Use read-write transaction to see latest data
		require.NoError(t, err, "failed to begin check transaction")

		txStorage2, err := WithExistingTransaction(ctx, checkTx, baseStorage)
		require.NoError(t, err, "failed to create check transaction storage")

		finalNode, err := txStorage2.GetNode(ctx, "error-handling-success")
		require.NoError(t, err, "success node should be accessible through new transaction")
		require.Equal(t, "error-handling-success", finalNode.ID)

		err = checkTx.Rollback(ctx) // Rollback since we're just reading
		require.NoError(t, err, "failed to rollback check transaction")
	})
}

func TestExternalTransactionAdvancedScenarios(t *testing.T) {
	// Test advanced external transaction scenarios and edge cases
	ctx := context.Background()

	// Create transactional inmem backend
	inmemBackend, err := inmem.NewInmem(nil, nil)
	require.NoError(t, err, "Failed to create in-memory backend")

	// Wrap it in logical storage
	logicalStorage := logical.NewLogicalStorage(inmemBackend)
	baseLogicalStorage, ok := logicalStorage.(logical.TransactionalStorage)
	require.True(t, ok, "Logical storage should implement TransactionalStorage")

	// Create base storage
	baseStorage, err := NewNodeStorage(baseLogicalStorage, NewStorageConfig(
		WithCachingEnabled(true),
		WithBufferingEnabled(true),
		WithCacheSize(50),
	))
	require.NoError(t, err, "Failed to create base storage")

	t.Run("ExternalTransaction_MultipleStorageInstances", func(t *testing.T) {
		// Test multiple NodeStorage instances from the same external transaction

		// Begin external transaction
		tx, err := baseLogicalStorage.BeginTx(ctx)
		require.NoError(t, err, "failed to begin external transaction")

		// Create two different transaction storage instances with different configs
		txStorage1, err := WithExistingTransaction(ctx, tx, baseStorage,
			WithCacheSize(20),
			WithBufferingEnabled(true),
		)
		require.NoError(t, err, "failed to create first external transaction storage")

		txStorage2, err := WithExistingTransaction(ctx, tx, baseStorage,
			WithCacheSize(30),
			WithBufferingEnabled(false),
		)
		require.NoError(t, err, "failed to create second external transaction storage")

		// Put different nodes through each storage instance
		node1 := NewLeafNode("multi-storage-node1")
		err = txStorage1.PutNode(ctx, node1)
		require.NoError(t, err, "failed to put node through first storage")

		node2 := NewLeafNode("multi-storage-node2")
		err = txStorage2.PutNode(ctx, node2)
		require.NoError(t, err, "failed to put node through second storage")

		// Each storage instance should see their own nodes
		_, err = txStorage1.GetNode(ctx, "multi-storage-node1")
		require.NoError(t, err, "first storage should see its own node")

		_, err = txStorage2.GetNode(ctx, "multi-storage-node2")
		require.NoError(t, err, "second storage should see its own node")

		// Both should be able to read from the same underlying transaction
		// (though they might not see each other's cache/buffer)

		// Flush first storage to transaction
		if ns, ok := txStorage1.(*NodeStorage); ok {
			err = ns.FlushBuffer(ctx)
			require.NoError(t, err, "failed to flush first storage buffer")
		}

		// Commit the transaction
		err = tx.Commit(ctx)
		require.NoError(t, err, "failed to commit external transaction")

		// Both nodes should be accessible through new transactions
		checkTx, err := baseLogicalStorage.BeginTx(ctx)
		require.NoError(t, err, "failed to begin check transaction")

		checkTxStorage, err := WithExistingTransaction(ctx, checkTx, baseStorage)
		require.NoError(t, err, "failed to create check transaction storage")

		_, err = checkTxStorage.GetNode(ctx, "multi-storage-node1")
		require.NoError(t, err, "first node should be accessible through new transaction")

		_, err = checkTxStorage.GetNode(ctx, "multi-storage-node2")
		require.NoError(t, err, "second node should be accessible through new transaction")

		err = checkTx.Rollback(ctx)
		require.NoError(t, err, "failed to rollback check transaction")
	})
}

func TestInternalTransactionAPI(t *testing.T) {
	// Test internal transaction API directly (using TransactionalNodeStorage)
	ctx := context.Background()

	// Create transactional inmem backend
	inmemBackend, err := inmem.NewInmem(nil, nil)
	require.NoError(t, err, "Failed to create in-memory backend")

	// Wrap it in logical storage
	logicalStorage := logical.NewLogicalStorage(inmemBackend)
	baseLogicalStorage, ok := logicalStorage.(logical.TransactionalStorage)
	require.True(t, ok, "Logical storage should implement TransactionalStorage")

	// Create transactional node storage
	transactionalStorage, err := NewTransactionalNodeStorage(baseLogicalStorage, NewTransactionalStorageConfig())
	require.NoError(t, err, "Failed to create transactional node storage")

	t.Run("ReadOnlyTransaction_Isolation", func(t *testing.T) {
		// First, put some data in the base storage and commit it to underlying storage
		baseNode := NewLeafNode("base-readonly-node")
		err = WithAutoFlush(ctx, transactionalStorage, func(storage Storage) error {
			return storage.PutNode(ctx, baseNode)
		})
		require.NoError(t, err, "failed to put base node")

		// Begin read-only transaction
		roTx, err := transactionalStorage.BeginReadOnlyTx(ctx)
		require.NoError(t, err, "failed to begin read-only transaction")

		// Read the base node through read-only transaction (should find it in underlying storage)
		roNode, err := roTx.GetNode(ctx, "base-readonly-node")
		require.NoError(t, err, "failed to get base node through read-only tx")
		require.Equal(t, "base-readonly-node", roNode.ID)

		// Try to put a node through read-only transaction (should work in memory)
		// but won't be committed to underlying storage due to read-only nature
		roOnlyNode := NewLeafNode("ro-only-node")
		err = roTx.PutNode(ctx, roOnlyNode)
		require.NoError(t, err, "put through read-only tx should work in memory")

		// Verify it's accessible within the same read-only transaction
		retrievedNode, err := roTx.GetNode(ctx, "ro-only-node")
		require.NoError(t, err, "should be able to get node within same read-only tx")
		require.Equal(t, "ro-only-node", retrievedNode.ID)

		// Rollback the read-only transaction (since commit would fail with writes)
		err = roTx.Rollback(ctx)
		require.NoError(t, err, "failed to rollback read-only transaction")

		// Verify the read-only changes were not persisted
		checkTx, err := transactionalStorage.BeginTx(ctx)
		require.NoError(t, err, "failed to begin verification transaction")
		_, err = checkTx.GetNode(ctx, "ro-only-node")
		require.ErrorIs(t, err, ErrNodeNotFound, "ro-only node should not be persisted after rollback")
		err = checkTx.Rollback(ctx)
		require.NoError(t, err, "failed to rollback verification transaction")
	})

	t.Run("ReadWriteTransaction_CacheIsolation", func(t *testing.T) {
		// Test that read-write transactions have proper cache isolation

		// Put a base node and commit it to underlying storage
		baseNode := NewLeafNode("cache-isolation-base")
		err = WithAutoFlush(ctx, transactionalStorage, func(storage Storage) error {
			return storage.PutNode(ctx, baseNode)
		})
		require.NoError(t, err, "failed to put base node")

		// Begin read-write transaction
		rwTx, err := transactionalStorage.BeginTx(ctx)
		require.NoError(t, err, "failed to begin read-write transaction")

		// Read the base node (should be found in underlying storage)
		txNode, err := rwTx.GetNode(ctx, "cache-isolation-base")
		require.NoError(t, err, "failed to get base node through tx")
		require.Equal(t, "cache-isolation-base", txNode.ID)

		// Put a transaction-only node
		txOnlyNode := NewLeafNode("tx-cache-only")
		err = rwTx.PutNode(ctx, txOnlyNode)
		require.NoError(t, err, "failed to put tx-only node")

		// Verify it's in transaction but not base storage yet
		_, err = rwTx.GetNode(ctx, "tx-cache-only")
		require.NoError(t, err, "tx-only node should be in transaction")

		// Since transactions are isolated, the transactionalStorage won't see uncommitted tx data
		// This is expected behavior for proper transaction isolation

		// Commit transaction
		err = rwTx.Commit(ctx)
		require.NoError(t, err, "failed to commit transaction")

		// Now both nodes should be accessible through a fresh transaction/storage access
		// (they were committed to the underlying storage)
		newTx, err := transactionalStorage.BeginTx(ctx)
		require.NoError(t, err, "failed to begin new transaction for verification")

		_, err = newTx.GetNode(ctx, "cache-isolation-base")
		require.NoError(t, err, "base node should still be accessible")

		_, err = newTx.GetNode(ctx, "tx-cache-only")
		require.NoError(t, err, "tx-only node should now be accessible through new transaction")

		err = newTx.Rollback(ctx) // Clean up
		require.NoError(t, err, "failed to rollback verification transaction")
	})

	t.Run("NestedTransactionBuffering", func(t *testing.T) {
		// Test transaction with buffering enabled and manual buffer management

		// Begin transaction with buffering
		tx, err := transactionalStorage.BeginTx(ctx)
		require.NoError(t, err, "failed to begin transaction")

		// Put multiple nodes (should be buffered)
		for i := 1; i <= 3; i++ {
			node := NewLeafNode(fmt.Sprintf("buffered-node-%d", i))
			err = tx.PutNode(ctx, node)
			require.NoError(t, err, "failed to put buffered node %d", i)
		}

		// Verify nodes are in buffer but not yet committed
		for i := 1; i <= 3; i++ {
			nodeID := fmt.Sprintf("buffered-node-%d", i)

			// Should be accessible through transaction (from buffer/cache)
			_, err = tx.GetNode(ctx, nodeID)
			require.NoError(t, err, "buffered node %d should be accessible through tx", i)

			// Should not be accessible through transactionalStorage (transaction isolation)
			// We need a fresh transaction to check if it was committed to underlying storage
			checkTx, err := transactionalStorage.BeginTx(ctx)
			require.NoError(t, err, "failed to begin check transaction")
			_, err = checkTx.GetNode(ctx, nodeID)
			require.ErrorIs(t, err, ErrNodeNotFound, "buffered node %d should not be accessible before flush", i)
			err = checkTx.Rollback(ctx)
			require.NoError(t, err, "failed to rollback check transaction")
		}

		// Manual flush buffer to transaction
		if ns, ok := tx.(*NodeTransaction); ok {
			err = ns.FlushBuffer(ctx)
			require.NoError(t, err, "failed to flush buffer")
		}

		// Nodes still shouldn't be accessible through other transactions (only flushed to current transaction)
		for i := 1; i <= 3; i++ {
			nodeID := fmt.Sprintf("buffered-node-%d", i)
			checkTx, err := transactionalStorage.BeginTx(ctx)
			require.NoError(t, err, "failed to begin check transaction")
			_, err = checkTx.GetNode(ctx, nodeID)
			require.ErrorIs(t, err, ErrNodeNotFound, "flushed node %d should still not be accessible before commit", i)
			err = checkTx.Rollback(ctx)
			require.NoError(t, err, "failed to rollback check transaction")
		}

		// Commit transaction
		err = tx.Commit(ctx)
		require.NoError(t, err, "failed to commit transaction")

		// Now all nodes should be accessible through new transactions
		for i := 1; i <= 3; i++ {
			nodeID := fmt.Sprintf("buffered-node-%d", i)
			checkTx, err := transactionalStorage.BeginTx(ctx)
			require.NoError(t, err, "failed to begin check transaction")
			node, err := checkTx.GetNode(ctx, nodeID)
			require.NoError(t, err, "committed node %d should be accessible", i)
			require.Equal(t, nodeID, node.ID)
			err = checkTx.Rollback(ctx)
			require.NoError(t, err, "failed to rollback check transaction")
		}
	})

	t.Run("TransactionRollback_BufferDiscard", func(t *testing.T) {
		// Test that rollback properly discards buffered operations

		// Begin transaction
		tx, err := transactionalStorage.BeginTx(ctx)
		require.NoError(t, err, "failed to begin transaction")

		// Put nodes that will be rolled back
		for i := 1; i <= 2; i++ {
			node := NewLeafNode(fmt.Sprintf("rollback-node-%d", i))
			err = tx.PutNode(ctx, node)
			require.NoError(t, err, "failed to put rollback node %d", i)
		}

		// Verify nodes are accessible through transaction
		for i := 1; i <= 2; i++ {
			nodeID := fmt.Sprintf("rollback-node-%d", i)
			_, err = tx.GetNode(ctx, nodeID)
			require.NoError(t, err, "rollback node %d should be accessible through tx", i)
		}

		// Rollback transaction
		err = tx.Rollback(ctx)
		require.NoError(t, err, "failed to rollback transaction")

		// Verify all nodes are gone from underlying storage
		for i := 1; i <= 2; i++ {
			nodeID := fmt.Sprintf("rollback-node-%d", i)
			checkTx, err := transactionalStorage.BeginTx(ctx)
			require.NoError(t, err, "failed to begin check transaction")
			_, err = checkTx.GetNode(ctx, nodeID)
			require.ErrorIs(t, err, ErrNodeNotFound, "rollback node %d should not exist after rollback", i)
			err = checkTx.Rollback(ctx)
			require.NoError(t, err, "failed to rollback check transaction")
		}
	})

	t.Run("ConcurrentTransactions", func(t *testing.T) {
		// Test that concurrent transactions are properly isolated

		// Begin two transactions concurrently
		tx1, err := transactionalStorage.BeginTx(ctx)
		require.NoError(t, err, "failed to begin transaction 1")

		tx2, err := transactionalStorage.BeginTx(ctx)
		require.NoError(t, err, "failed to begin transaction 2")

		// Put different nodes in each transaction
		node1 := NewLeafNode("concurrent-tx1-node")
		err = tx1.PutNode(ctx, node1)
		require.NoError(t, err, "failed to put node in tx1")

		node2 := NewLeafNode("concurrent-tx2-node")
		err = tx2.PutNode(ctx, node2)
		require.NoError(t, err, "failed to put node in tx2")

		// Verify isolation: each transaction can only see its own nodes
		_, err = tx1.GetNode(ctx, "concurrent-tx1-node")
		require.NoError(t, err, "tx1 should see its own node")

		_, err = tx1.GetNode(ctx, "concurrent-tx2-node")
		require.ErrorIs(t, err, ErrNodeNotFound, "tx1 should not see tx2's node")

		_, err = tx2.GetNode(ctx, "concurrent-tx2-node")
		require.NoError(t, err, "tx2 should see its own node")

		_, err = tx2.GetNode(ctx, "concurrent-tx1-node")
		require.ErrorIs(t, err, ErrNodeNotFound, "tx2 should not see tx1's node")

		// Commit tx1 first
		err = tx1.Commit(ctx)
		require.NoError(t, err, "failed to commit tx1")

		// tx2 still shouldn't see tx1's committed node (transaction isolation)
		_, err = tx2.GetNode(ctx, "concurrent-tx1-node")
		require.ErrorIs(t, err, ErrNodeNotFound, "tx2 should still not see tx1's committed node")

		// Rollback tx2 to avoid conflicts (since both might try to commit to same underlying storage)
		err = tx2.Rollback(ctx)
		require.NoError(t, err, "failed to rollback tx2")

		// Verify only tx1's node was committed
		checkTx, err := transactionalStorage.BeginTx(ctx)
		require.NoError(t, err, "failed to begin check transaction")

		_, err = checkTx.GetNode(ctx, "concurrent-tx1-node")
		require.NoError(t, err, "tx1's node should be committed")

		_, err = checkTx.GetNode(ctx, "concurrent-tx2-node")
		require.ErrorIs(t, err, ErrNodeNotFound, "tx2's node should not be committed")

		err = checkTx.Rollback(ctx)
		require.NoError(t, err, "failed to rollback check transaction")
	})
}
