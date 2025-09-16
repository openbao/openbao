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
			node1 := &Node{ID: "node1", IsLeaf: true}
			node2 := &Node{ID: "node2", IsLeaf: true}

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
		require.Equal(t, ErrNodeNotFound, err, "node1 should not be found in base storage before commit")
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
		if err != nil {
			t.Fatalf("Failed to begin transaction: %v", err)
		}

		// Use buffered writes within the transaction
		err = WithBufferedWrites(ctx, tx, func(storage Storage) error {
			node3 := &Node{ID: "node3", IsLeaf: true}
			return tx.PutNode(ctx, node3)
		})
		if err != nil {
			t.Fatalf("BufferedWrites failed: %v", err)
		}

		// Rollback the transaction
		if err := tx.Rollback(ctx); err != nil {
			t.Fatalf("Failed to rollback transaction: %v", err)
		}

		// Node should not be in base storage
		if _, err := baseStorage.GetNode(ctx, "node3"); err == nil {
			t.Error("node3 should not be in base storage after rollback")
		}
	})

	t.Run("TransactionAroundBufferedWrites", func(t *testing.T) {
		// This tests the opposite: transaction around buffered writes
		err := WithTransaction(ctx, transactionalStorage, func(txStorage Storage) error {
			return WithBufferedWrites(ctx, txStorage, func(bufferedStorage Storage) error {
				node4 := &Node{ID: "node4", IsLeaf: true}
				node5 := &Node{ID: "node5", IsLeaf: true}

				if err := bufferedStorage.PutNode(ctx, node4); err != nil {
					return err
				}
				if err := bufferedStorage.PutNode(ctx, node5); err != nil {
					return err
				}
				return nil
			})
		})
		if err != nil {
			t.Fatalf("Nested transaction+buffered failed: %v", err)
		}

		// Both nodes should be in base storage after commit
		if _, err := baseStorage.GetNode(ctx, "node4"); err != nil {
			t.Errorf("node4 should be in base storage: %v", err)
		}
		if _, err := baseStorage.GetNode(ctx, "node5"); err != nil {
			t.Errorf("node5 should be in base storage: %v", err)
		}
	})

	t.Run("ExternalTransaction_IsolatedCache", func(t *testing.T) {
		// Test that external transactions get their own isolated cache
		// that doesn't merge back to parent

		// First, put a node in the base storage to establish baseline
		WithAutoFlush(ctx, baseStorage, func(storage Storage) error {
			baseNode := NewLeafNode("base-node")
			err := baseStorage.PutNode(ctx, baseNode)
			require.NoError(t, err, "failed to put base node")
			return err
		})

		// Begin external transaction
		tx, err := baseLogicalStorage.BeginTx(ctx)
		require.NoError(t, err, "failed to begin external transaction")

		// Create NodeStorage from external transaction
		// Transactions are supposed to have buffering enabled, not sure about externals ...
		// User can't forget to flush buffer...
		txStorage, err := WithExistingTransaction(ctx, tx, baseStorage, WithBufferingEnabled(true))
		require.NoError(t, err, "failed to create external transaction storage")

		// Read the base node through transaction storage (should cache it locally)
		txNode, err := txStorage.GetNode(ctx, "base-node")
		require.NoError(t, err, "failed to get base node through tx storage")
		require.Equal(t, "base-node", txNode.ID)

		// Put a new node through transaction storage (should buffer and cache locally)
		txOnlyNode := NewLeafNode("tx-only-node")
		WithAutoFlush(ctx, txStorage, func(storage Storage) error {
			err = txStorage.PutNode(ctx, txOnlyNode)
			require.NoError(t, err, "failed to put tx-only node")
			return err
		})

		// Commit external transaction
		err = tx.Commit(ctx)
		require.NoError(t, err, "failed to commit external transaction")

		// Now the tx-only node should be visible in base storage
		// (because the transaction committed to the underlying storage)
		finalNode, err := baseStorage.GetNode(ctx, "tx-only-node")
		require.NoError(t, err, "tx-only node should be in base storage after commit")
		require.Equal(t, "tx-only-node", finalNode.ID)

		// Verify base storage cache wasn't polluted with transaction cache entries
		_, exists := baseStorage.cache.Get("tx-only-node")
		require.False(t, exists, "base storage cache should not have tx-only-node")
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
		rollbackNode := &Node{ID: "rollback-node", IsLeaf: true}
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
		require.Equal(t, ErrNodeNotFound, err, "rollback-node should not exist after rollback")
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

		node1 := &Node{ID: "external-inheritance-1", IsLeaf: true}
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

		node2 := &Node{ID: "external-inheritance-2", IsLeaf: true}
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
