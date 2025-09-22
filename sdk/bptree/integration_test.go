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

func TestBufferedStorageWithTransactions(t *testing.T) {
	// Create base storage with transaction support using the same approach as existing tests
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

	t.Run("BufferedWrites_WithinTransaction", func(t *testing.T) {
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

		// Commit the transaction
		err = tx.Commit(ctx)
		require.NoError(t, err, "failed to commit transaction")

		// Now nodes should be in base storage
		node1, err = baseStorage.GetNode(ctx, "node1")
		require.NoError(t, err, "node1 should be in base storage after commit")
		require.NotNil(t, node1, "node1 should not be nil in base storage after commit")
	})

	t.Run("BufferedWrites_WithTransactionRollback", func(t *testing.T) {
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

	t.Run("TransactionAroundBufferedWrites", func(t *testing.T) {
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

	t.Run("ExternalTransactionConfigInheritance", func(t *testing.T) {
		// Test that external transactions also inherit and can override configuration

		// Create base storage with specific configuration
		baseStorage, err := NewNodeStorage(baseLogicalStorage, NewStorageConfig(
			WithCacheSize(150),
			WithCachingEnabled(true),
			WithBufferingEnabled(true),
		))
		require.NoError(t, err, "Failed to create base storage")

		// Test external transaction with default inheritance
		tx1, err := baseLogicalStorage.BeginTx(ctx)
		require.NoError(t, err, "failed to begin external transaction")

		txStorage1, err := WithExistingTransaction(ctx, tx1, baseStorage)
		require.NoError(t, err, "failed to create external transaction storage")

		node1 := NewLeafNode("external-inheritance-1")
		err = txStorage1.PutNode(ctx, node1)
		require.NoError(t, err, "failed to put node in external transaction")

		if ns, ok := txStorage1.(*NodeStorage); ok {
			err = ns.FlushBuffer(ctx)
			require.NoError(t, err, "failed to flush external transaction buffer")
		}

		err = tx1.Commit(ctx)
		require.NoError(t, err, "failed to commit external transaction")

		// Test external transaction with overridden configuration
		tx2, err := baseLogicalStorage.BeginTx(ctx)
		require.NoError(t, err, "failed to begin external transaction with overrides")

		txStorage2, err := WithExistingTransaction(ctx, tx2, baseStorage,
			WithCacheSize(25),
			WithBufferingEnabled(false),
		)
		require.NoError(t, err, "failed to create override external transaction storage")

		node2 := NewLeafNode("external-inheritance-2")
		err = txStorage2.PutNode(ctx, node2)
		require.NoError(t, err, "failed to put node in override external transaction")

		// No need to flush buffer since buffering is disabled
		err = tx2.Commit(ctx)
		require.NoError(t, err, "failed to commit override external transaction")

		// Verify both nodes are accessible
		for i := 1; i <= 2; i++ {
			nodeID := fmt.Sprintf("external-inheritance-%d", i)
			node, err := baseStorage.GetNode(ctx, nodeID)
			require.NoError(t, err, "failed to get external node %s from base storage", nodeID)
			require.Equal(t, nodeID, node.ID, "external node ID mismatch for %s", nodeID)
		}
	})
}
