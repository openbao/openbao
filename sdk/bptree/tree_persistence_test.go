// Copyright (c) 2024 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package bptree

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestTreePersistenceAndLoading tests various tree initialization scenarios
func TestTreePersistenceAndLoading(t *testing.T) {
	ctx, storage, _ := initTest(t, nil)

	t.Run("AutomaticTreeCreation", func(t *testing.T) {
		// InitializeBPlusTree should automatically create a new tree when none exists
		config, err := NewBPlusTreeConfig("auto_tree", 4)
		require.NoError(t, err)

		tree, err := InitializeBPlusTree(ctx, storage, config)
		require.NoError(t, err, "Should create new tree automatically")
		require.NotNil(t, tree)

		// Verify tree is functional
		err = tree.Insert(ctx, storage, "key1", "value1")
		require.NoError(t, err, "Should be able to insert into new tree")

		values, found, err := tree.Search(ctx, storage, "key1")
		require.NoError(t, err)
		require.True(t, found)
		require.Equal(t, []string{"value1"}, values)
	})

	t.Run("AutomaticTreeLoading", func(t *testing.T) {
		// Create a tree and add some data
		config, err := NewBPlusTreeConfig("persistent_tree", 4)
		require.NoError(t, err)

		tree1, err := InitializeBPlusTree(ctx, storage, config)
		require.NoError(t, err)

		// Add data to the tree
		testData := map[string]string{
			"key1": "value1",
			"key2": "value2",
			"key3": "value3",
		}

		for key, value := range testData {
			err = tree1.Insert(ctx, storage, key, value)
			require.NoError(t, err, "Failed to insert %s", key)
		}

		// Verify data is accessible
		for key, expectedValue := range testData {
			values, found, err := tree1.Search(ctx, storage, key)
			require.NoError(t, err, "Error getting key %s", key)
			require.True(t, found, "Should find key %s", key)
			require.Equal(t, []string{expectedValue}, values, "Value mismatch for key %s", key)
		}

		// Now "restart" by loading the existing tree
		tree2, err := LoadExistingBPlusTree(ctx, storage, "persistent_tree")
		require.NoError(t, err, "Should load existing tree automatically")
		require.NotNil(t, tree2)

		// Verify all data is still accessible
		for key, expectedValue := range testData {
			values, found, err := tree2.Search(ctx, storage, key)
			require.NoError(t, err, "Error getting key %s", key)
			require.True(t, found, "Should find key %s after reload", key)
			require.Equal(t, []string{expectedValue}, values, "Value mismatch for key %s", key)
		}

		// Verify tree is still functional for new operations
		err = tree2.Insert(ctx, storage, "key4", "value4")
		require.NoError(t, err, "Should be able to insert into loaded tree")

		values, found, err := tree2.Search(ctx, storage, "key4")
		require.NoError(t, err)
		require.True(t, found)
		require.Equal(t, []string{"value4"}, values)

		// Check key4 is available on the original tree as well
		values, found, err = tree1.Search(ctx, storage, "key4")
		require.NoError(t, err)
		require.True(t, found)
		require.Equal(t, []string{"value4"}, values, "Key4 should be available on both trees after insert")
	})

	t.Run("ExplicitTreeCreation", func(t *testing.T) {
		// CreateNewTree should create a new tree
		config, err := NewBPlusTreeConfig("explicit_new", 4)
		require.NoError(t, err)

		tree, err := NewBPlusTree(ctx, storage, config)
		require.NoError(t, err, "Should create new tree explicitly")
		require.NotNil(t, tree)

		// Verify tree is functional
		err = tree.Insert(ctx, storage, "test", "data")
		require.NoError(t, err)

		// Trying to create again should fail
		_, err = NewBPlusTree(ctx, storage, config)
		require.Error(t, err, "Should fail to create tree that already exists")
		require.Contains(t, err.Error(), "already exists")
	})

	t.Run("ExplicitTreeLoading", func(t *testing.T) {
		// First create a tree to load
		config, err := NewBPlusTreeConfig("explicit_load", 4)
		require.NoError(t, err)

		tree1, err := NewBPlusTree(ctx, storage, config)
		require.NoError(t, err)

		err = tree1.Insert(ctx, storage, "persistent", "data")
		require.NoError(t, err)

		// Now explicitly load it
		tree2, err := LoadExistingBPlusTree(ctx, storage, config.TreeID)
		require.NoError(t, err, "Should load existing tree explicitly")
		require.NotNil(t, tree2)

		// Verify data is accessible
		values, found, err := tree2.Search(ctx, storage, "persistent")
		require.NoError(t, err)
		require.True(t, found)
		require.Equal(t, []string{"data"}, values)

		// Trying to load non-existent tree should fail
		nonExistentConfig, err := NewBPlusTreeConfig("does_not_exist", 4)
		require.NoError(t, err)

		_, err = LoadExistingBPlusTree(ctx, storage, nonExistentConfig.TreeID)
		require.Error(t, err, "Should fail to load non-existent tree")
		require.Contains(t, err.Error(), "does not exist")
	})

	t.Run("MultipleTreesPersistenceIsolation", func(t *testing.T) {
		// Create multiple trees and verify they maintain isolation after "restart"
		config1, err := NewBPlusTreeConfig("tree_alpha", 4)
		require.NoError(t, err)
		config2, err := NewBPlusTreeConfig("tree_beta", 4)
		require.NoError(t, err)

		// Create and populate first tree
		tree1, err := InitializeBPlusTree(ctx, storage, config1)
		require.NoError(t, err)
		err = tree1.Insert(ctx, storage, "shared_key", "alpha_value")
		require.NoError(t, err)
		err = tree1.Insert(ctx, storage, "alpha_only", "alpha_data")
		require.NoError(t, err)

		// Create and populate second tree
		tree2, err := InitializeBPlusTree(ctx, storage, config2)
		require.NoError(t, err)
		err = tree2.Insert(ctx, storage, "shared_key", "beta_value")
		require.NoError(t, err)
		err = tree2.Insert(ctx, storage, "beta_only", "beta_data")
		require.NoError(t, err)

		// "Restart" both trees by loading them
		reloadedTree1, err := LoadExistingBPlusTree(ctx, storage, "tree_alpha")
		require.NoError(t, err)
		reloadedTree2, err := LoadExistingBPlusTree(ctx, storage, "tree_beta")
		require.NoError(t, err)

		// Verify isolation is maintained
		values, found, err := reloadedTree1.Search(ctx, storage, "shared_key")
		require.NoError(t, err)
		require.True(t, found)
		require.Equal(t, []string{"alpha_value"}, values, "Tree 1 should have its own value")

		values, found, err = reloadedTree2.Search(ctx, storage, "shared_key")
		require.NoError(t, err)
		require.True(t, found)
		require.Equal(t, []string{"beta_value"}, values, "Tree 2 should have its own value")

		// Verify tree-specific keys
		_, found, err = reloadedTree1.Search(ctx, storage, "alpha_only")
		require.NoError(t, err)
		require.True(t, found, "Tree 1 should have its specific key")

		_, found, err = reloadedTree1.Search(ctx, storage, "beta_only")
		require.NoError(t, err)
		require.False(t, found, "Tree 1 should not have tree 2's key")

		_, found, err = reloadedTree2.Search(ctx, storage, "beta_only")
		require.NoError(t, err)
		require.True(t, found, "Tree 2 should have its specific key")

		_, found, err = reloadedTree2.Search(ctx, storage, "alpha_only")
		require.NoError(t, err)
		require.False(t, found, "Tree 2 should not have tree 1's key")
	})

	t.Run("TreeConfigValidation", func(t *testing.T) {
		// Test various config validation scenarios

		// Nil config should use defaults with InitializeBPlusTree
		tree, err := InitializeBPlusTree(ctx, storage, nil)
		require.NoError(t, err, "Should accept nil config and use defaults")
		require.NotNil(t, tree)

		// Invalid order should fail
		invalidConfig := &BPlusTreeConfig{TreeID: "invalid", Order: 1}
		_, err = InitializeBPlusTree(ctx, storage, invalidConfig)
		require.Error(t, err, "Should fail with invalid order")

		// NewBPlusTree with nil config should fail
		_, err = NewBPlusTree(ctx, storage, nil)
		require.Error(t, err, "CreateNewTree should require config")

		// LoadExistingTree (NewBPlusTree) with empty tree ID should fail
		_, err = LoadExistingBPlusTree(ctx, storage, "")
		require.Error(t, err, "NewBPlusTree should require tree ID")
	})

	t.Run("RootNodeCorruption", func(t *testing.T) {
		// Test handling of corrupted/invalid root nodes
		config, err := NewBPlusTreeConfig("corruption_test", 4)
		require.NoError(t, err)

		// Create a tree
		tree, err := InitializeBPlusTree(ctx, storage, config)
		require.NoError(t, err)

		// Get the tree-aware context to access internals
		treeCtx := tree.contextWithTreeID(ctx)

		// Manually corrupt the root ID by setting it to a non-existent node
		err = storage.PutRootID(treeCtx, "non-existent-node-id")
		require.NoError(t, err)

		// Trying to load this corrupted tree should fail gracefully
		_, err = LoadExistingBPlusTree(ctx, storage, "corruption_test")
		require.Error(t, err, "Should fail to load tree with corrupted root")
		// TODO (gabrielopesantos): Review this error, it changed because we no longer return a nil error when a node is not found...
		require.Contains(t, err.Error(), "failed to load root node")
	})
}
