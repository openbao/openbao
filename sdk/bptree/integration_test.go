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
	baseStorage, err := NewNodeStorage(baseLogicalStorage)
	require.NoError(t, err, "Failed to create base node storage")

	t.Run("ExternalTransaction_IsolatedCache", func(t *testing.T) {
		// Test that external transactions get their own isolated cache
		// that doesn't merge back to parent

		// First, put a node in the base storage to establish baseline
		baseNode := NewLeafNode(WithNodeID("base-node"))
		err = baseStorage.PutNode(ctx, baseNode)
		require.NoError(t, err, "failed to put base node")

		// Begin external transaction
		tx, err := baseLogicalStorage.BeginTx(ctx)
		require.NoError(t, err, "failed to begin external transaction")

		// Create NodeStorage from external transaction
		txStorage, err := WithExistingTransaction(ctx, tx, baseStorage)
		require.NoError(t, err, "failed to create external transaction storage")

		// Read the base node through transaction storage (should cache it locally)
		txNode, err := txStorage.GetNode(ctx, "base-node")
		require.NoError(t, err, "failed to get base node through tx storage")
		require.Equal(t, "base-node", txNode.ID)

		// Put a new node through transaction storage (should cache locally)
		txOnlyNode := NewLeafNode(WithNodeID("tx-only-node"))
		err = txStorage.PutNode(ctx, txOnlyNode)
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
		rollbackNode := NewLeafNode(WithNodeID("rollback-node"))
		err = txStorage.PutNode(ctx, rollbackNode)
		require.NoError(t, err, "failed to put rollback node")

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
		baseStorage, err := NewNodeStorage(baseLogicalStorage,
			WithCacheSize(150),
			WithCachingEnabled(true),
		)
		require.NoError(t, err, "Failed to create base storage")

		// Test 1: External transaction with default inheritance
		tx1, err := baseLogicalStorage.BeginTx(ctx)
		require.NoError(t, err, "failed to begin external transaction")

		txStorage1, err := WithExistingTransaction(ctx, tx1, baseStorage)
		require.NoError(t, err, "failed to create external transaction storage")

		node1 := NewLeafNode(WithNodeID("config-test-inheritance"))
		err = txStorage1.PutNode(ctx, node1)
		require.NoError(t, err, "failed to put node in external transaction")

		err = tx1.Commit(ctx)
		require.NoError(t, err, "failed to commit external transaction")

		// Test 2: External transaction with config overrides
		tx2, err := baseLogicalStorage.BeginTx(ctx)
		require.NoError(t, err, "failed to begin external transaction with overrides")

		txStorage2, err := WithExistingTransaction(ctx, tx2, baseStorage,
			WithCacheSize(10), // Override cache size
		)
		require.NoError(t, err, "failed to create override external transaction storage")

		// Put a node through the overridden transaction storage
		node2 := NewLeafNode(WithNodeID("config-test-override"))
		err = txStorage2.PutNode(ctx, node2)
		require.NoError(t, err, "failed to put node with overrides")

		// Verify it's immediately accessible through transaction storage
		retrievedNode, err := txStorage2.GetNode(ctx, "config-test-override")
		require.NoError(t, err, "should be able to get node immediately")
		require.Equal(t, "config-test-override", retrievedNode.ID)

		err = tx2.Commit(ctx)
		require.NoError(t, err, "failed to commit override external transaction")

		// Verify both nodes are accessible
		for _, nodeID := range []string{"config-test-inheritance", "config-test-override"} {
			node, err := baseStorage.GetNode(ctx, nodeID)
			require.NoError(t, err, "failed to get node %s from base storage", nodeID)
			require.Equal(t, nodeID, node.ID, "node ID mismatch for %s", nodeID)
		}
	})

	t.Run("ExternalTransaction_WriteVisibility", func(t *testing.T) {
		// Test write visibility through an existing external transaction

		// Begin external transaction
		tx, err := baseLogicalStorage.BeginTx(ctx)
		require.NoError(t, err, "failed to begin external transaction")

		txStorage, err := WithExistingTransaction(ctx, tx, baseStorage)
		require.NoError(t, err, "failed to create external transaction storage")

		// Put nodes through the transaction storage
		for i := 1; i <= 2; i++ {
			node := NewLeafNode(WithNodeID(fmt.Sprintf("write-visibility-node-%d", i)))
			err := txStorage.PutNode(ctx, node)
			require.NoError(t, err, "failed to put node %d", i)
		}

		// Nodes should be visible through the transaction but not accessible through other transactions yet
		for i := 1; i <= 2; i++ {
			nodeID := fmt.Sprintf("write-visibility-node-%d", i)

			// Should be accessible through transaction
			_, err = txStorage.GetNode(ctx, nodeID)
			require.NoError(t, err, "node %d should be accessible through tx", i)

			// Should not be accessible through other transactions yet
			checkTx, err := baseLogicalStorage.BeginTx(ctx)
			require.NoError(t, err, "failed to begin check transaction")
			checkTxStorage, err := WithExistingTransaction(ctx, checkTx, baseStorage)
			require.NoError(t, err, "failed to create check transaction storage")
			_, err = checkTxStorage.GetNode(ctx, nodeID)
			require.ErrorIs(t, err, ErrNodeNotFound, "node %d should not be accessible before commit", i)
			err = checkTx.Rollback(ctx)
			require.NoError(t, err, "failed to rollback check transaction")
		}

		// Commit the external transaction
		err = tx.Commit(ctx)
		require.NoError(t, err, "failed to commit external transaction")

		// Now nodes should be accessible through new transactions
		for i := 1; i <= 2; i++ {
			nodeID := fmt.Sprintf("write-visibility-node-%d", i)
			checkTx, err := baseLogicalStorage.BeginTx(ctx)
			require.NoError(t, err, "failed to begin check transaction")
			checkTxStorage, err := WithExistingTransaction(ctx, checkTx, baseStorage)
			require.NoError(t, err, "failed to create check transaction storage")
			node, err := checkTxStorage.GetNode(ctx, nodeID)
			require.NoError(t, err, "node %d should be accessible after commit", i)
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
		successNode := NewLeafNode(WithNodeID("error-handling-success"))
		err = txStorage.PutNode(ctx, successNode)
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
	baseStorage, err := NewNodeStorage(baseLogicalStorage,
		WithCachingEnabled(true),
		WithCacheSize(50),
	)
	require.NoError(t, err, "Failed to create base storage")

	t.Run("ExternalTransaction_MultipleStorageInstances", func(t *testing.T) {
		// Test multiple NodeStorage instances from the same external transaction

		// Begin external transaction
		tx, err := baseLogicalStorage.BeginTx(ctx)
		require.NoError(t, err, "failed to begin external transaction")

		// Create two different transaction storage instances with different cache sizes
		txStorage1, err := WithExistingTransaction(ctx, tx, baseStorage, WithCacheSize(20))
		require.NoError(t, err, "failed to create first external transaction storage")

		txStorage2, err := WithExistingTransaction(ctx, tx, baseStorage, WithCacheSize(30))
		require.NoError(t, err, "failed to create second external transaction storage")

		// Put different nodes through each storage instance
		node1 := NewLeafNode(WithNodeID("multi-storage-node1"))
		err = txStorage1.PutNode(ctx, node1)
		require.NoError(t, err, "failed to put node through first storage")

		node2 := NewLeafNode(WithNodeID("multi-storage-node2"))
		err = txStorage2.PutNode(ctx, node2)
		require.NoError(t, err, "failed to put node through second storage")

		// Each storage instance should see their own nodes
		_, err = txStorage1.GetNode(ctx, "multi-storage-node1")
		require.NoError(t, err, "first storage should see its own node")

		_, err = txStorage2.GetNode(ctx, "multi-storage-node2")
		require.NoError(t, err, "second storage should see its own node")

		// Both write directly to the same shared underlying transaction, so
		// each instance's write is already durable to that transaction (though
		// not necessarily visible in the other instance's local cache).

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
	transactionalStorage, err := NewTransactionalNodeStorage(baseLogicalStorage)
	require.NoError(t, err, "Failed to create transactional node storage")

	t.Run("ReadOnlyTransaction_Isolation", func(t *testing.T) {
		// First, put some data in the base storage and commit it to underlying storage
		baseNode := NewLeafNode(WithNodeID("base-readonly-node"))
		err = transactionalStorage.PutNode(ctx, baseNode)
		require.NoError(t, err, "failed to put base node")

		// Begin read-only transaction
		roTx, err := transactionalStorage.BeginReadOnlyTx(ctx)
		require.NoError(t, err, "failed to begin read-only transaction")

		// Read the base node through read-only transaction (should find it in underlying storage)
		roNode, err := roTx.GetNode(ctx, "base-readonly-node")
		require.NoError(t, err, "failed to get base node through read-only tx")
		require.Equal(t, "base-readonly-node", roNode.ID)

		// Try to put a node through the read-only transaction: rejected immediately
		roOnlyNode := NewLeafNode(WithNodeID("ro-only-node"))
		err = roTx.PutNode(ctx, roOnlyNode)
		require.Error(t, err, "put through read-only tx should be rejected")

		err = roTx.Rollback(ctx)
		require.NoError(t, err, "failed to rollback read-only transaction")

		// Verify the rejected write was not persisted
		checkTx, err := transactionalStorage.BeginTx(ctx)
		require.NoError(t, err, "failed to begin verification transaction")
		_, err = checkTx.GetNode(ctx, "ro-only-node")
		require.ErrorIs(t, err, ErrNodeNotFound, "ro-only node should not be persisted")
		err = checkTx.Rollback(ctx)
		require.NoError(t, err, "failed to rollback verification transaction")
	})

	t.Run("ConcurrentTransactions", func(t *testing.T) {
		// Test that concurrent transactions are properly isolated

		// Begin two transactions concurrently
		tx1, err := transactionalStorage.BeginTx(ctx)
		require.NoError(t, err, "failed to begin transaction 1")

		tx2, err := transactionalStorage.BeginTx(ctx)
		require.NoError(t, err, "failed to begin transaction 2")

		// Put different nodes in each transaction
		node1 := NewLeafNode(WithNodeID("concurrent-tx1-node"))
		err = tx1.PutNode(ctx, node1)
		require.NoError(t, err, "failed to put node in tx1")

		node2 := NewLeafNode(WithNodeID("concurrent-tx2-node"))
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
