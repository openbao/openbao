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

func TestNodeStorageBuiltInBuffering(t *testing.T) {
	// Create a storage with built-in buffering
	inmemBackend, err := inmem.NewInmem(nil, nil)
	require.NoError(t, err)

	logicalStorage := logical.NewLogicalStorage(inmemBackend)
	nodeStorage, err := NewNodeStorage(logicalStorage, WithBufferingEnabled(true))
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("BufferingEnabledByConfig", func(t *testing.T) {
		dirtyCount, bufferingEnabled := nodeStorage.BufferStats()
		require.True(t, bufferingEnabled, "Buffering should be enabled by config")
		require.Equal(t, 0, dirtyCount, "Should start with no dirty nodes")
	})

	t.Run("SaveNodeIsBuffered", func(t *testing.T) {
		node1 := &Node{ID: "test1", IsLeaf: true}

		// Save node - should be buffered, not written to storage
		err := nodeStorage.PutNode(ctx, node1)
		require.NoError(t, err)

		// Check that it's in the buffer
		dirtyCount, _ := nodeStorage.BufferStats()
		require.Equal(t, 1, dirtyCount, "Node should be in dirty buffer")

		// Should be able to load from buffer
		loadedNode, err := nodeStorage.GetNode(ctx, "test1")
		require.NoError(t, err)
		require.NotNil(t, loadedNode)
		require.Equal(t, "test1", loadedNode.ID)

		// Should NOT be in underlying storage yet
		entry, err := logicalStorage.Get(ctx, nodeKey(ctx, "test1"))
		require.NoError(t, err)
		require.Nil(t, entry, "Node should not be in underlying storage before flush")
	})

	t.Run("FlushWritesBufferedNodes", func(t *testing.T) {
		// Add another node to buffer
		node2 := &Node{ID: "test2", IsLeaf: true}
		err := nodeStorage.PutNode(ctx, node2)
		require.NoError(t, err)

		// Should have 2 dirty nodes now
		dirtyCount, _ := nodeStorage.BufferStats()
		require.Equal(t, 2, dirtyCount, "Should have 2 dirty nodes")

		// Flush the buffer
		err = nodeStorage.FlushBuffer(ctx)
		require.NoError(t, err)

		// Buffer should be empty after flush
		dirtyCount, _ = nodeStorage.BufferStats()
		require.Equal(t, 0, dirtyCount, "Buffer should be empty after flush")

		// Both nodes should now be in underlying storage
		entry1, err := logicalStorage.Get(ctx, nodeKey(ctx, "test1"))
		require.NoError(t, err)
		require.NotNil(t, entry1, "Node1 should be in underlying storage after flush")

		entry2, err := logicalStorage.Get(ctx, nodeKey(ctx, "test2"))
		require.NoError(t, err)
		require.NotNil(t, entry2, "Node2 should be in underlying storage after flush")
	})

	t.Run("ClearDiscardsBufferedNodes", func(t *testing.T) {
		// Add a node to buffer
		node3 := &Node{ID: "test3", IsLeaf: true}
		err := nodeStorage.PutNode(ctx, node3)
		require.NoError(t, err)

		dirtyCount, _ := nodeStorage.BufferStats()
		require.Equal(t, 1, dirtyCount, "Should have 1 dirty node")

		// Clear the buffer
		nodeStorage.ClearBuffer()

		// Buffer should be empty
		dirtyCount, _ = nodeStorage.BufferStats()
		require.Equal(t, 0, dirtyCount, "Buffer should be empty after clear")

		// Node should not be in underlying storage
		entry, err := logicalStorage.Get(ctx, nodeKey(ctx, "test3"))
		require.NoError(t, err)
		require.Nil(t, entry, "Node should not be in underlying storage after clear")

		// Cache is also purged when clearing the buffer so getting the node from the
		// node storage should not return it.
		nodeEntry, err := nodeStorage.GetNode(ctx, "test3")
		require.ErrorIs(t, err, ErrNodeNotFound, "Node should not be found after buffer clear")
		require.Nil(t, nodeEntry, "Node should still be retrievable from cache")
	})

	t.Run("WithAutoFlushHelper", func(t *testing.T) {
		// Test the WithAutoFlush helper
		err := WithAutoFlush(ctx, nodeStorage, func(storage Storage) error {
			node4 := NewLeafNode(WithNodeID("test4"))
			node5 := NewLeafNode(WithNodeID("test5"))

			// Multiple saves - should be buffered
			if err := storage.PutNode(ctx, node4); err != nil {
				return err
			}
			return storage.PutNode(ctx, node5)
		})
		require.NoError(t, err)

		// Both nodes should be in underlying storage (auto-flushed)
		entry4, err := logicalStorage.Get(ctx, nodeKey(ctx, "test4"))
		require.NoError(t, err)
		require.NotNil(t, entry4, "Node4 should be in underlying storage")

		entry5, err := logicalStorage.Get(ctx, nodeKey(ctx, "test5"))
		require.NoError(t, err)
		require.NotNil(t, entry5, "Node5 should be in underlying storage")

		// Buffer should be empty after auto-flush
		dirtyCount, _ := nodeStorage.BufferStats()
		require.Equal(t, 0, dirtyCount, "Buffer should be empty after auto-flush")
	})

	t.Run("WithBufferedWritesHelper", func(t *testing.T) {
		// Test the WithBufferedWrites helper which forces buffering ON
		err := WithBufferedWrites(ctx, nodeStorage, func(storage Storage) error {
			node6 := NewLeafNode(WithNodeID("test6"))
			node7 := NewLeafNode(WithNodeID("test7"))

			// Multiple saves - should be buffered regardless of original config
			if err := storage.PutNode(ctx, node6); err != nil {
				return err
			}
			return storage.PutNode(ctx, node7)
		})
		require.NoError(t, err)

		// Both nodes should be in underlying storage (force-flushed)
		entry6, err := logicalStorage.Get(ctx, nodeKey(ctx, "test6"))
		require.NoError(t, err)
		require.NotNil(t, entry6, "Node6 should be in underlying storage")

		entry7, err := logicalStorage.Get(ctx, nodeKey(ctx, "test7"))
		require.NoError(t, err)
		require.NotNil(t, entry7, "Node7 should be in underlying storage")

		// Buffer should be empty after forced flush
		dirtyCount, _ := nodeStorage.BufferStats()
		require.Equal(t, 0, dirtyCount, "Buffer should be empty after forced flush")
	})

	t.Run("DeleteNodeIsBuffered", func(t *testing.T) {
		// First, create and flush a node so it exists in storage
		nodeToDelete := NewLeafNode(WithNodeID("to-delete"))
		err := nodeStorage.PutNode(ctx, nodeToDelete)
		require.NoError(t, err)
		err = nodeStorage.FlushBuffer(ctx)
		require.NoError(t, err)

		// Verify node exists in storage
		entry, err := logicalStorage.Get(ctx, nodeKey(ctx, "to-delete"))
		require.NoError(t, err)
		require.NotNil(t, entry, "Node should exist in storage before delete")

		// Delete node - should be buffered
		err = nodeStorage.DeleteNode(ctx, "to-delete")
		require.NoError(t, err)

		// Check that deletion is in the buffer
		dirtyCount, _ := nodeStorage.BufferStats()
		require.Equal(t, 1, dirtyCount, "Delete should be in dirty buffer")

		// Node should still be in underlying storage (delete not flushed yet)
		entry, err = logicalStorage.Get(ctx, nodeKey(ctx, "to-delete"))
		require.NoError(t, err)
		require.NotNil(t, entry, "Node should still be in underlying storage before flush")

		// Flush should execute the delete
		err = nodeStorage.FlushBuffer(ctx)
		require.NoError(t, err)

		// Node should now be gone from underlying storage
		entry, err = logicalStorage.Get(ctx, nodeKey(ctx, "to-delete"))
		require.NoError(t, err)
		require.Nil(t, entry, "Node should be deleted from underlying storage after flush")
	})

	t.Run("BufferingCanBeDisabled", func(t *testing.T) {
		// Test with buffering disabled
		nonBufferedStorage, err := NewNodeStorage(logicalStorage, WithBufferingEnabled(false))
		require.NoError(t, err)

		dirtyCount, bufferingEnabled := nonBufferedStorage.BufferStats()
		require.False(t, bufferingEnabled, "Buffering should be disabled")
		require.Equal(t, 0, dirtyCount, "Should have no dirty nodes")

		// Save node - should go directly to storage (not buffered)
		node8 := NewLeafNode(WithNodeID("test8"))
		err = nonBufferedStorage.PutNode(ctx, node8)
		require.NoError(t, err)

		// Should still have no dirty nodes (went directly to storage)
		dirtyCount, _ = nonBufferedStorage.BufferStats()
		require.Equal(t, 0, dirtyCount, "Should have no dirty nodes when buffering disabled")

		// Node should be in underlying storage immediately
		entry8, err := logicalStorage.Get(ctx, nodeKey(ctx, "test8"))
		require.NoError(t, err)
		require.NotNil(t, entry8, "Node8 should be in underlying storage immediately")
	})
}
