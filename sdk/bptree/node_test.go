// Copyright (c) 2024 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0
package bptree

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewLeafNode(t *testing.T) {
	node := NewLeafNode(WithNodeID("leaf1"))
	require.NotNil(t, node)
	require.Equal(t, "leaf1", node.ID)
	require.True(t, node.IsLeaf)
	require.Empty(t, node.Keys)
	require.Empty(t, node.Values)
	require.Empty(t, node.ChildrenIDs)
}

func TestNewInternalNode(t *testing.T) {
	node := NewInternalNode(WithNodeID("internal1"))
	require.NotNil(t, node)
	require.Equal(t, "internal1", node.ID)
	require.False(t, node.IsLeaf)
	require.Empty(t, node.Keys)
	require.Empty(t, node.Values)
	require.Empty(t, node.ChildrenIDs)
}

func TestGetKeyValues(t *testing.T) {
	node := NewLeafNode()

	// Test non-existing key
	values, keyFound := node.GetKeyValues("key1")
	require.Empty(t, values)
	require.False(t, keyFound)

	// Add values
	node.InsertKeyValue("key1", "value1")
	node.InsertKeyValue("key1", "value2")
	node.InsertKeyValue("key2", "value3")

	// Test existing key with multiple values
	values, keyFound = node.GetKeyValues("key1")
	require.Equal(t, []string{"value1", "value2"}, values)
	require.True(t, keyFound)

	// Test existing key with single value
	values, keyFound = node.GetKeyValues("key2")
	require.Equal(t, []string{"value3"}, values)
	require.True(t, keyFound)

	// Test non-existing key
	values, keyFound = node.GetKeyValues("key3")
	require.Empty(t, values)
	require.False(t, keyFound)
}

func TestKeyCount(t *testing.T) {
	node := NewLeafNode(WithNodeID("leaf"))

	// Empty node
	require.Equal(t, 0, node.KeyCount())

	// Add keys
	node.InsertKeyValue("key1", "value1")
	require.Equal(t, 1, node.KeyCount())

	node.InsertKeyValue("key2", "value2")
	require.Equal(t, 2, node.KeyCount())

	// Add duplicate key (should not increase count)
	node.InsertKeyValue("key1", "value1b")
	require.Equal(t, 2, node.KeyCount())
}

func TestIsEmpty(t *testing.T) {
	node := NewLeafNode()

	// Empty node
	require.True(t, node.IsEmpty())

	// Add key
	node.InsertKeyValue("key1", "value1")
	require.False(t, node.IsEmpty())

	// Remove key
	result, err := node.RemoveKeyValuesAtIndex(0)
	require.NoError(t, err)
	require.Equal(t, KeyRemoved, result)

	// Check if the node is empty again
	require.True(t, node.IsEmpty())
}

func TestInsertKeyValue(t *testing.T) {
	node := NewLeafNode()

	// Test basic insertion
	err := node.InsertKeyValue("key2", "value2")
	require.NoError(t, err)
	require.Equal(t, []string{"key2"}, node.Keys)
	require.Equal(t, [][]string{{"value2"}}, node.Values)

	// Test insertion at beginning
	err = node.InsertKeyValue("key1", "value1")
	require.NoError(t, err)
	require.Equal(t, []string{"key1", "key2"}, node.Keys)
	require.Equal(t, [][]string{{"value1"}, {"value2"}}, node.Values)

	// Test insertion at end
	err = node.InsertKeyValue("key3", "value3")
	require.NoError(t, err)
	require.Equal(t, []string{"key1", "key2", "key3"}, node.Keys)
	require.Equal(t, [][]string{{"value1"}, {"value2"}, {"value3"}}, node.Values)

	// Test duplicate key (should add to existing values)
	err = node.InsertKeyValue("key2", "value2b")
	require.NoError(t, err)
	require.Equal(t, []string{"key1", "key2", "key3"}, node.Keys)
	require.Equal(t, [][]string{{"value1"}, {"value2", "value2b"}, {"value3"}}, node.Values)
}

func TestInsertKeyValueOnInternalNode(t *testing.T) {
	node := NewInternalNode()

	// Should fail on internal node
	err := node.InsertKeyValue("key1", "value1")
	require.Error(t, err)
	require.Equal(t, err, ErrNotALeafNode)
}

func TestRemoveValueFromKey(t *testing.T) {
	node := NewLeafNode()

	// Setup test data
	node.InsertKeyValue("key1", "value1")
	node.InsertKeyValue("key1", "value2")
	node.InsertKeyValue("key2", "value3")

	// Remove specific value
	result, err := node.RemoveValueFromKey("key1", "value2")
	require.NoError(t, err)
	require.Equal(t, ValueRemoved, result)
	values, _ := node.GetKeyValues("key1")
	require.Equal(t, []string{"value1"}, values)

	// Remove non-existing value
	result, err = node.RemoveValueFromKey("key1", "nonexistent")
	require.NoError(t, err)
	require.Equal(t, ValueNotFound, result)

	// Remove last value (should remove key)
	result, err = node.RemoveValueFromKey("key1", "value1")
	require.NoError(t, err)
	require.Equal(t, KeyRemoved, result)
	_, hasKey := node.GetKeyValues("key1")
	require.False(t, hasKey)

	// Remove from non-existing key
	result, err = node.RemoveValueFromKey("nonexistent", "value")
	require.NoError(t, err)
	require.Equal(t, KeyNotFound, result)
}

func TestInsertKeyChild(t *testing.T) {
	node := NewInternalNode()

	node.ChildrenIDs = []string{"child0"} // Pre-populate with left-most child

	// Test basic insertion
	err := node.InsertKeyChild("key2", "child2")
	require.NoError(t, err)
	require.Equal(t, []string{"key2"}, node.Keys)
	require.Equal(t, []string{"child0", "child2"}, node.ChildrenIDs)

	// Test insertion at beginning
	err = node.InsertKeyChild("key1", "child1")
	require.NoError(t, err)
	require.Equal(t, []string{"key1", "key2"}, node.Keys)
	require.Equal(t, []string{"child0", "child1", "child2"}, node.ChildrenIDs)

	// Test insertion at end
	err = node.InsertKeyChild("key3", "child3")
	require.NoError(t, err)
	require.Equal(t, []string{"key1", "key2", "key3"}, node.Keys)
	require.Equal(t, []string{"child0", "child1", "child2", "child3"}, node.ChildrenIDs)
}

func TestInsertKeyChildOnLeafNode(t *testing.T) {
	node := NewLeafNode()

	// Should fail on leaf node
	err := node.InsertKeyChild("key1", "child1")
	require.Error(t, err)
	require.Contains(t, err.Error(), "leaf node")
}

func TestRemoveKeyChildAt(t *testing.T) {
	node := NewInternalNode()

	// Pre-populate with left-most child
	node.ChildrenIDs = []string{"child0"}

	// Setup test data
	node.InsertKeyChild("key1", "child1")
	node.InsertKeyChild("key2", "child2")
	node.InsertKeyChild("key3", "child3")

	// Remove middle entry
	err := node.RemoveKeyChildAtIndex(1)
	require.NoError(t, err)
	require.Equal(t, []string{"key1", "key3"}, node.Keys)
	require.Equal(t, []string{"child0", "child1", "child3"}, node.ChildrenIDs)

	// Remove first entry
	err = node.RemoveKeyChildAtIndex(0)
	require.NoError(t, err)
	require.Equal(t, []string{"key3"}, node.Keys)
	require.Equal(t, []string{"child0", "child3"}, node.ChildrenIDs)

	// Remove last entry
	err = node.RemoveKeyChildAtIndex(0)
	require.NoError(t, err)
	require.Empty(t, node.Keys)
	require.Equal(t, []string{"child0"}, node.ChildrenIDs)

	// Remove from empty node
	err = node.RemoveKeyChildAtIndex(0)
	require.Error(t, err)
	require.Contains(t, err.Error(), "index out of bounds")
}

func TestGetChildAtIndex(t *testing.T) {
	node := NewInternalNode()

	// Pre-populate with left-most child
	node.ChildrenIDs = []string{"child0"}

	// Setup test data
	node.InsertKeyChild("key1", "child1")
	node.InsertKeyChild("key2", "child2")

	// Test valid indices
	childID, err := node.GetChildAtIndex(0)
	require.NoError(t, err)
	require.Equal(t, "child0", childID)

	childID, err = node.GetChildAtIndex(1)
	require.NoError(t, err)
	require.Equal(t, "child1", childID)

	childID, err = node.GetChildAtIndex(2)
	require.NoError(t, err)
	require.Equal(t, "child2", childID)

	// Test invalid index
	_, err = node.GetChildAtIndex(3)
	require.Error(t, err)
	require.Contains(t, err.Error(), "index out of bounds")
}

func TestGetKeyAt(t *testing.T) {
	node := NewInternalNode()

	// Pre-populate with left-most child
	node.ChildrenIDs = []string{"child0"}

	// Setup test data
	node.InsertKeyChild("key1", "child1")
	node.InsertKeyChild("key2", "child2")

	// Test valid indices
	key, err := node.GetKeyAtIndex(0)
	require.NoError(t, err)
	require.Equal(t, "key1", key)

	key, err = node.GetKeyAtIndex(1)
	require.NoError(t, err)
	require.Equal(t, "key2", key)

	// Test invalid index
	_, err = node.GetKeyAtIndex(2)
	require.Error(t, err)
	require.Contains(t, err.Error(), "index out of bounds")
}

func TestGetChildForKeyTraversal(t *testing.T) {
	node := NewInternalNode()

	// Pre-populate with left-most child
	node.ChildrenIDs = []string{"child0"}

	// Setup test data - keys partition the key space
	// child1 handles keys < "key2"
	// child2 handles keys >= "key2" and < "key4"
	// child3 handles keys >= "key4"
	node.InsertKeyChild("key2", "child1")
	node.InsertKeyChild("key4", "child2")

	// Test key less than first key
	childID, err := node.GetChildForKeyTraversal("key1")
	require.NoError(t, err)
	require.Equal(t, "child0", childID)

	// Test key equal to first key
	childID, err = node.GetChildForKeyTraversal("key2")
	require.NoError(t, err)
	require.Equal(t, "child1", childID)

	// Test key between keys
	childID, err = node.GetChildForKeyTraversal("key3")
	require.NoError(t, err)
	require.Equal(t, "child1", childID)

	// Test key equal to second key
	childID, err = node.GetChildForKeyTraversal("key4")
	require.NoError(t, err)
	require.Equal(t, "child2", childID)

	// Test key greater than all keys
	childID, err = node.GetChildForKeyTraversal("key5")
	require.NoError(t, err)
	require.Equal(t, "child2", childID)
}

func TestFindKeyIndex(t *testing.T) {
	node := NewLeafNode()

	// Setup test data
	node.InsertKeyValue("key1", "value1")
	node.InsertKeyValue("key3", "value3")
	node.InsertKeyValue("key5", "value5")

	// Test existing keys
	idx, found := node.FindKeyIndex("key1")
	require.True(t, found)
	require.Equal(t, 0, idx)

	idx, found = node.FindKeyIndex("key3")
	require.True(t, found)
	require.Equal(t, 1, idx)

	idx, found = node.FindKeyIndex("key5")
	require.True(t, found)
	require.Equal(t, 2, idx)

	// Test non-existing keys (should return insertion position)
	idx, found = node.FindKeyIndex("key0") // Before all keys
	require.False(t, found)
	require.Equal(t, 0, idx)

	idx, found = node.FindKeyIndex("key2") // Between key1 and key3
	require.False(t, found)
	require.Equal(t, 1, idx)

	idx, found = node.FindKeyIndex("key4") // Between key3 and key5
	require.False(t, found)
	require.Equal(t, 2, idx)

	idx, found = node.FindKeyIndex("key6") // After all keys
	require.False(t, found)
	require.Equal(t, 3, idx)
}

func TestNodeOptions(t *testing.T) {
	t.Run("LeafNodeDefaults", func(t *testing.T) {
		node := NewLeafNode()

		require.True(t, node.IsLeaf)
		require.NotEmpty(t, node.ID, "Should have auto-generated ID")
		require.Empty(t, node.Keys)
		require.Empty(t, node.Values)
		require.Empty(t, node.ParentID)
		require.Empty(t, node.NextID)
		require.Empty(t, node.PreviousID)
	})

	t.Run("InternalNodeDefaults", func(t *testing.T) {
		node := NewInternalNode()

		require.False(t, node.IsLeaf)
		require.NotEmpty(t, node.ID, "Should have auto-generated ID")
		require.Empty(t, node.Keys)
		require.Empty(t, node.ChildrenIDs)
		require.Empty(t, node.ParentID)
	})

	t.Run("WithNodeID", func(t *testing.T) {
		customID := "custom-node-id"

		leaf := NewLeafNode(WithNodeID(customID))
		require.Equal(t, customID, leaf.ID)

		internal := NewInternalNode(WithNodeID(customID))
		require.Equal(t, customID, internal.ID)
	})

	t.Run("WithParentID", func(t *testing.T) {
		parentID := "parent-123"

		leaf := NewLeafNode(WithParentID(parentID))
		require.Equal(t, parentID, leaf.ParentID)

		internal := NewInternalNode(WithParentID(parentID))
		require.Equal(t, parentID, internal.ParentID)
	})

	t.Run("LeafNodeLinkingOptions", func(t *testing.T) {
		nextID := "next-node"
		prevID := "prev-node"

		leaf := NewLeafNode(
			WithNextID(nextID),
			WithPreviousID(prevID),
		)

		require.Equal(t, nextID, leaf.NextID)
		require.Equal(t, prevID, leaf.PreviousID)
	})

	t.Run("LeafNodeLinkingOptionsIgnoredForInternal", func(t *testing.T) {
		// Linking options should be ignored for internal nodes
		internal := NewInternalNode(
			WithNextID("should-be-ignored"),
			WithPreviousID("should-be-ignored"),
		)

		require.Empty(t, internal.NextID, "NextID should be ignored for internal nodes")
		require.Empty(t, internal.PreviousID, "PreviousID should be ignored for internal nodes")
	})

	t.Run("WithInitialKeys", func(t *testing.T) {
		keys := []string{"key1", "key2", "key3"}

		leaf := NewLeafNode(WithInitialKeys(keys...))
		require.Equal(t, keys, leaf.Keys)

		internal := NewInternalNode(WithInitialKeys(keys...))
		require.Equal(t, keys, internal.Keys)
	})

	t.Run("WithInitialValues", func(t *testing.T) {
		values := [][]string{
			{"val1a", "val1b"},
			{"val2"},
			{"val3a", "val3b", "val3c"},
		}

		leaf := NewLeafNode(WithInitialValues(values...))
		require.Equal(t, values, leaf.Values)

		// Should be ignored for internal nodes
		internal := NewInternalNode(WithInitialValues(values...))
		require.Empty(t, internal.Values, "Values should be ignored for internal nodes")
	})

	t.Run("WithInitialChildren", func(t *testing.T) {
		children := []string{"child1", "child2", "child3"}

		internal := NewInternalNode(WithInitialChildren(children...))
		require.Equal(t, children, internal.ChildrenIDs)

		// Should be ignored for leaf nodes
		leaf := NewLeafNode(WithInitialChildren(children...))
		require.Empty(t, leaf.ChildrenIDs, "Children should be ignored for leaf nodes")
	})

	t.Run("CombinedLeafOptions", func(t *testing.T) {
		keys := []string{"apple", "banana"}
		values := [][]string{{"red", "green"}, {"yellow"}}

		leaf := NewLeafNode(
			WithNodeID("fruit-leaf"),
			WithParentID("fruit-parent"),
			WithNextID("next-fruit"),
			WithPreviousID("prev-fruit"),
			WithInitialKeys(keys...),
			WithInitialValues(values...),
		)

		require.Equal(t, "fruit-leaf", leaf.ID)
		require.Equal(t, "fruit-parent", leaf.ParentID)
		require.Equal(t, "next-fruit", leaf.NextID)
		require.Equal(t, "prev-fruit", leaf.PreviousID)
		require.Equal(t, keys, leaf.Keys)
		require.Equal(t, values, leaf.Values)
		require.True(t, leaf.IsLeaf)
	})

	t.Run("CombinedInternalOptions", func(t *testing.T) {
		keys := []string{"m", "s"}
		children := []string{"child1", "child2", "child3"}

		internal := NewInternalNode(
			WithNodeID("internal-123"),
			WithParentID("root"),
			WithInitialKeys(keys...),
			WithInitialChildren(children...),
		)

		require.Equal(t, "internal-123", internal.ID)
		require.Equal(t, "root", internal.ParentID)
		require.Equal(t, keys, internal.Keys)
		require.Equal(t, children, internal.ChildrenIDs)
		require.False(t, internal.IsLeaf)
	})

	t.Run("NilOptionsHandling", func(t *testing.T) {
		// Should handle nil options gracefully
		leaf := NewLeafNode(nil, WithNodeID("test"), nil)
		require.Equal(t, "test", leaf.ID)
		require.True(t, leaf.IsLeaf)

		internal := NewInternalNode(nil, WithNodeID("test"), nil)
		require.Equal(t, "test", internal.ID)
		require.False(t, internal.IsLeaf)
	})

	t.Run("DataSafety", func(t *testing.T) {
		// Test that options create independent copies of slices
		originalKeys := []string{"key1", "key2"}
		originalValues := [][]string{{"val1"}, {"val2"}}
		originalChildren := []string{"child1", "child2"}

		leaf := NewLeafNode(
			WithInitialKeys(originalKeys...),
			WithInitialValues(originalValues...),
		)
		internal := NewInternalNode(WithInitialChildren(originalChildren...))

		// Modify original slices
		originalKeys[0] = "modified"
		originalValues[0][0] = "modified"
		originalChildren[0] = "modified"

		// Node data should be unchanged
		require.Equal(t, "key1", leaf.Keys[0])
		require.Equal(t, "val1", leaf.Values[0][0])
		require.Equal(t, "child1", internal.ChildrenIDs[0])
	})

	t.Run("OptionsWorkWithExistingMethods", func(t *testing.T) {
		// Test that nodes created with options work with existing methods
		leaf := NewLeafNode(
			WithInitialKeys("existing"),
			WithInitialValues([]string{"value"}),
		)

		// Should be able to use existing methods
		err := leaf.InsertKeyValue("new", "newvalue")
		require.NoError(t, err)

		values, found := leaf.GetKeyValues("existing")
		require.True(t, found)
		require.Equal(t, []string{"value"}, values)

		values, found = leaf.GetKeyValues("new")
		require.True(t, found)
		require.Equal(t, []string{"newvalue"}, values)
	})

	t.Run("InternalNodeWithOptionsSupportsTraversal", func(t *testing.T) {
		internal := NewInternalNode(
			WithInitialKeys("m"),
			WithInitialChildren("left", "right"),
		)

		// Should work with existing traversal methods
		childID, err := internal.GetChildForKeyTraversal("a") // Should go left
		require.NoError(t, err)
		require.Equal(t, "left", childID)

		childID, err = internal.GetChildForKeyTraversal("z") // Should go right
		require.NoError(t, err)
		require.Equal(t, "right", childID)
	})
}
