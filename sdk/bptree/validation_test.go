// Copyright (c) 2024 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package bptree

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDebugValidateTreeStructure_BasicValidation(t *testing.T) {
	ctx, storage, tree := initTest(t, &TreeConfig{Order: 3})

	// Insert enough keys to create internal nodes with separators
	keys := []string{"a", "b", "c", "d", "e", "f", "g", "h"}
	for _, key := range keys {
		err := tree.Insert(ctx, storage, key, keyValue(key))
		require.NoError(t, err, "failed to insert key %s", key)
	}

	// Validate the tree structure
	result, err := tree.DebugValidateTreeStructure(ctx, storage)
	require.NoError(t, err, "validation failed")

	// Check that the tree is valid initially
	require.True(t, result.IsValid, "tree should be valid after insertions")
	require.Empty(t, result.Errors, "tree should have no errors")
	require.Equal(t, len(keys), result.Stats.TotalKeys, "tree should have correct number of keys")
	require.Empty(t, result.Stats.OrphanedKeys, "tree should have no orphaned keys")
	require.Equal(t, 4, result.Stats.InternalNodes, "tree should have correct number of internal nodes")
	require.Equal(t, 7, result.Stats.LeafNodes, "tree should have correct number of leaf nodes")
	require.Equal(t, 11, result.Stats.TotalNodes, "tree should have correct total nodes")
	require.Equal(t, 3, result.Stats.TreeHeight, "tree should have correct height")
}

func TestDebugValidateTreeStructure_SeparatorKeyDeletion(t *testing.T) {
	ctx, storage, tree := initTest(t, &TreeConfig{Order: 3})

	// Insert keys to create a specific tree structure
	// This should create internal nodes with separator keys
	keys := []string{"apple", "banana", "cherry", "date", "elderberry", "fig", "grape"}
	for _, key := range keys {
		err := tree.Insert(ctx, storage, key, keyValue(key))
		require.NoError(t, err, "failed to insert key %s", key)
	}

	// Validate before deletion
	result, err := tree.DebugValidateTreeStructure(ctx, storage)
	require.NoError(t, err, "pre-deletion validation failed")
	require.True(t, result.IsValid, "tree should be valid before deletion")

	// Now delete some keys that might be separators in internal nodes
	keysToDelete := []string{"cherry", "elderberry"}
	for _, key := range keysToDelete {
		deleted, err := tree.Delete(ctx, storage, key)
		require.NoError(t, err, "failed to delete key %s", key)
		require.True(t, deleted, "key %s should have been deleted", key)
	}

	// Validate after deletion - this should reveal any separator key issues
	result, err = tree.DebugValidateTreeStructure(ctx, storage)
	require.NoError(t, err, "post-deletion validation failed")

	// Expect no warnings about orphaned keys since cleanup should handle them
	require.Equal(t, 0, len(result.Warnings), "should have zero warnings about orphaned keys")
}
