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
	nodeStorage, err := NewNodeStorage(logicalStorage, NewStorageConfig(WithBufferingEnabled(true)))
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("BufferingEnabledByDefault", func(t *testing.T) {
		dirtyCount, bufferingEnabled := nodeStorage.BufferStats()
		require.True(t, bufferingEnabled, "Buffering should be enabled by default")
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

		// Node might still be in cache, but not in dirty buffer or underlying storage
		// This is correct behavior - cache and buffer are separate systems
	})

	t.Run("WithAutoFlushHelper", func(t *testing.T) {
		// Test the WithAutoFlush helper
		err := WithAutoFlush(ctx, nodeStorage, func(storage Storage) error {
			node4 := &Node{ID: "test4", IsLeaf: true}
			node5 := &Node{ID: "test5", IsLeaf: true}

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
}
