// Copyright (c) 2024 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package bptree

import (
	"context"
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

	transactionalStorage := &TransactionalNodeStorage{NodeStorage: baseStorage}

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
}
