// Copyright (c) 2024 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0
package bptree

import (
	"fmt"
	"reflect"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStorage(t *testing.T) {
	ctx, nodeStorage, _ := initTest(t, nil)

	t.Run("Storage Operations", func(t *testing.T) {
		// Test SetRootID and GetRootID
		rootID := "root-1"
		err := nodeStorage.PutRootID(ctx, rootID)
		require.NoError(t, err, "Failed to set root ID")

		retrievedRootID, err := nodeStorage.GetRootID(ctx)
		require.NoError(t, err, "Failed to get root ID")

		require.Equal(t, rootID, retrievedRootID, "Expected root ID %s, got %s", rootID, retrievedRootID)

		// Test PutNode and GetNode
		nodeID := "node-1"
		node := NewLeafNode(nodeID)
		err = node.InsertKeyValue("key1", "value1")
		require.NoError(t, err, "Failed to insert key-value pair into node")
		err = node.InsertKeyValue("key2", "value2")
		require.NoError(t, err, "Failed to insert key-value pair into node")

		// Save the node
		err = nodeStorage.PutNode(ctx, node)
		require.NoError(t, err, "Failed to save node")

		// Try to load the node from cache using the proper cache key
		cachedNode, ok := nodeStorage.cache.Get(cacheKey(ctx, node.ID))
		require.True(t, ok, "Node should be in cache")
		require.NotNil(t, cachedNode, "Cached node should not be empty")
		require.Equal(t, node, cachedNode, "Cached node should match saved node")

		// Load the node
		loadedNode, err := nodeStorage.GetNode(ctx, nodeID)
		require.NoError(t, err, "Failed to load node")
		require.NotNil(t, loadedNode, "Loaded node is nil")
		require.Equal(t, node, loadedNode, "Loaded node should match saved node")

		// Update the node
		err = node.InsertKeyValue("key3", "value3")
		require.NoError(t, err, "Failed to insert key-value pair into node")

		err = nodeStorage.PutNode(ctx, node)
		require.NoError(t, err, "Failed to update node")

		// Verify if the cache has been updated
		cachedNode, ok = nodeStorage.cache.Get(cacheKey(ctx, node.ID))
		require.True(t, ok, "Updated node should be in cache")
		require.NotNil(t, cachedNode, "Cached node should not be empty after update")
		require.Equal(t, node, cachedNode, "Cached node should match updated node")

		// Load the updated node
		updatedNode, err := nodeStorage.GetNode(ctx, nodeID)
		require.NoError(t, err, "Failed to load updated node")
		require.NotNil(t, updatedNode, "Updated node is nil")
		require.Equal(t, node, updatedNode, "Updated node should match saved node after update")

		// Try to load a non-existent node
		err = nodeStorage.DeleteNode(ctx, nodeID)
		require.NoError(t, err, "Failed to delete node")

		deletedNode, err := nodeStorage.GetNode(ctx, nodeID)
		require.ErrorIs(t, err, ErrNodeNotFound, "Expected ErrNodeNotFound when loading deleted node")
		require.Nil(t, deletedNode, "Node should have been deleted")

		// Verify if the cache has been cleared
		_, ok = nodeStorage.cache.Get(cacheKey(ctx, node.ID))
		require.False(t, ok, "Deleted node should not be in cache")
	})

	t.Run("Concurrent Access", func(t *testing.T) {
		// Create and save a node
		node := NewLeafNode("node-1")
		node.InsertKeyValue("key1", "value1")

		err := nodeStorage.PutNode(ctx, node)
		require.NoError(t, err, "Failed to save node")

		var wg sync.WaitGroup
		errChan := make(chan error, 10)

		for i := range 10 {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()

				// Load the existing node
				loadedNode, err := nodeStorage.GetNode(ctx, node.ID)
				if err != nil {
					errChan <- fmt.Errorf("error loading node: %w", err)
					return
				}
				if !reflect.DeepEqual(node, loadedNode) {
					errChan <- fmt.Errorf("loaded node does not match original: expected %v, got %v", node, loadedNode)
					return
				}

				// Create and save a new node
				newNode := NewLeafNode(fmt.Sprintf("node-%d", i))
				err = newNode.InsertKeyValue(fmt.Sprintf("key%d", i), fmt.Sprintf("value%d", i))
				require.NoError(t, err, "Failed to insert key-value pair into new node")

				err = nodeStorage.PutNode(ctx, newNode)
				if err != nil {
					errChan <- fmt.Errorf("error saving new node: %w", err)
					return
				}

				// Verify new node is in cache using the proper cache key
				cachedNode, ok := nodeStorage.cache.Get(cacheKey(ctx, newNode.ID))
				if !ok {
					errChan <- fmt.Errorf("new node not found in cache")
					return
				}
				if !reflect.DeepEqual(newNode, cachedNode) {
					errChan <- fmt.Errorf("cached node does not match new node: expected %v, got %v", newNode, cachedNode)
					return
				}
			}(i)
		}

		wg.Wait()
		close(errChan)

		for err := range errChan {
			t.Error(err)
		}
	})
}

// TestTreeConfigPersistence tests that tree metadata is properly stored and loaded
func TestTreeConfigPersistence(t *testing.T) {
	ctx, storage, _ := initTest(t, nil)

	t.Run("ConfigStorageAndRetrieval", func(t *testing.T) {
		// Create a tree with specific configuration
		config, err := NewBPlusTreeConfig(WithTreeID("metadata_test"), WithOrder(6))
		require.NoError(t, err, "Should create config")

		tree, err := InitializeBPlusTree(ctx, storage, config)
		require.NoError(t, err, "Should create new tree")

		// Verify config was stored
		treeCtx := tree.contextWithTreeID(ctx)
		storedConfig, err := storage.GetConfig(treeCtx)
		require.NoError(t, err, "Should retrieve stored metadata")
		require.NotNil(t, storedConfig, "Config should exist")
		require.Equal(t, "metadata_test", storedConfig.TreeID)
		require.Equal(t, 6, storedConfig.Order)
		require.Equal(t, 1, storedConfig.Version)
	})

	t.Run("LoadingWithCorrectConfig", func(t *testing.T) {
		// Create a tree
		config, err := NewBPlusTreeConfig(WithTreeID("load_test"))
		require.NoError(t, err)

		tree1, err := InitializeBPlusTree(ctx, storage, config)
		require.NoError(t, err)

		// Add some data
		err = tree1.Insert(ctx, storage, "key1", "value1")
		require.NoError(t, err)

		// Load with same config - should work
		tree2, err := LoadExistingBPlusTree(ctx, storage, config.TreeID)
		require.NoError(t, err, "Should load existing tree with matching config")

		// Verify data is accessible
		values, found, err := tree2.Search(ctx, storage, "key1")
		require.NoError(t, err)
		require.True(t, found)
		require.Equal(t, []string{"value1"}, values)
	})

	t.Run("LoadExistingTreeFunction", func(t *testing.T) {
		// Create a tree with specific order
		treeID := "explicit_load"
		config, err := NewBPlusTreeConfig(WithTreeID(treeID), WithOrder(12))
		require.NoError(t, err)

		tree1, err := NewBPlusTree(ctx, storage, config)
		require.NoError(t, err)

		err = tree1.Insert(ctx, storage, "key1", "value1")
		require.NoError(t, err)

		// Load using LoadExistingTree with just TreeID
		tree2, err := LoadExistingBPlusTree(ctx, storage, treeID)
		require.NoError(t, err, "Should load existing tree using stored config")

		// Verify the loaded tree has the correct order from storage
		require.Equal(t, treeID, tree2.config.TreeID)
		require.Equal(t, 12, tree2.config.Order, "Should use stored order, not placeholder")

		// Verify data is accessible
		values, found, err := tree2.Search(ctx, storage, "key1")
		require.NoError(t, err)
		require.True(t, found)
		require.Equal(t, []string{"value1"}, values)
	})

	t.Run("LoadExistingTreeWrongID", func(t *testing.T) {
		// Try to load non-existent tree
		_, err := LoadExistingBPlusTree(ctx, storage, "nonexistent")
		require.Error(t, err, "Should fail to load non-existent tree")
		require.Contains(t, err.Error(), "does not exist")
	})

	t.Run("LoadExistingTreeIDMismatch", func(t *testing.T) {
		// Create a tree
		config1, err := NewBPlusTreeConfig(WithTreeID("test_tree"))
		require.NoError(t, err)

		_, err = NewBPlusTree(ctx, storage, config1)
		require.NoError(t, err)

		// Try to load with different TreeID in config
		// Override the context to use the correct tree (simulating internal mismatch)
		mismatchCtx := withTreeID(ctx, "mismatch_test")
		_, err = LoadExistingBPlusTree(mismatchCtx, storage, "wrong_id")
		require.Error(t, err, "Should fail to load tree with mismatched TreeID")
	})
}
