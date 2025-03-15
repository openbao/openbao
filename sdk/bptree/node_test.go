// Copyright (c) 2024 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0
package bptree

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewLeafNode(t *testing.T) {
	node := NewLeafNode("leaf1")
	require.NotNil(t, node)
	require.Equal(t, "leaf1", node.ID)
	require.True(t, node.IsLeaf)
	require.Empty(t, node.Keys)
	require.Empty(t, node.Values)
	require.Empty(t, node.ChildrenIDs)
}

func TestNewInternalNode(t *testing.T) {
	node := NewInternalNode("internal1")
	require.NotNil(t, node)
	require.Equal(t, "internal1", node.ID)
	require.False(t, node.IsLeaf)
	require.Empty(t, node.Keys)
	require.Empty(t, node.Values)
	require.Empty(t, node.ChildrenIDs)
}

func TestHasKey(t *testing.T) {
	node := NewLeafNode("leaf")

	// Empty node
	require.False(t, node.HasKey("key1"))

	// Add some keys
	node.InsertKeyValue("key1", "value1")
	node.InsertKeyValue("key3", "value3")

	// Test existing keys
	require.True(t, node.HasKey("key1"))
	require.True(t, node.HasKey("key3"))

	// Test non-existing key
	require.False(t, node.HasKey("key2"))
}

func TestGetKeyValues(t *testing.T) {
	node := NewLeafNode("leaf")

	// Test non-existing key
	values := node.GetKeyValues("key1")
	require.Empty(t, values)

	// Add values
	node.InsertKeyValue("key1", "value1")
	node.InsertKeyValue("key1", "value2")
	node.InsertKeyValue("key2", "value3")

	// Test existing key with multiple values
	values = node.GetKeyValues("key1")
	require.Equal(t, []string{"value1", "value2"}, values)

	// Test existing key with single value
	values = node.GetKeyValues("key2")
	require.Equal(t, []string{"value3"}, values)

	// Test non-existing key
	values = node.GetKeyValues("key3")
	require.Empty(t, values)
}

func TestGetAllKeys(t *testing.T) {
	node := NewLeafNode("leaf")

	// Empty node
	keys := node.GetAllKeys()
	require.Empty(t, keys)

	// Add keys
	node.InsertKeyValue("key3", "value3")
	node.InsertKeyValue("key1", "value1")
	node.InsertKeyValue("key2", "value2")

	// Keys should be sorted
	keys = node.GetAllKeys()
	require.Equal(t, []string{"key1", "key2", "key3"}, keys)
}

func TestKeyCount(t *testing.T) {
	node := NewLeafNode("leaf")

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
	node := NewLeafNode("leaf")

	// Empty node
	require.True(t, node.IsEmpty())

	// Add key
	node.InsertKeyValue("key1", "value1")
	require.False(t, node.IsEmpty())

	// Remove key
	node.RemoveKeyValuesEntry("key1")
	require.True(t, node.IsEmpty())
}

func TestIsFull(t *testing.T) {
	node := NewLeafNode("leaf")
	maxKeys := 3 // Set max for testing

	// Empty node
	require.False(t, node.IsFull(maxKeys))

	// Add keys up to limit
	node.InsertKeyValue("key1", "value1")
	require.False(t, node.IsFull(maxKeys))

	node.InsertKeyValue("key2", "value2")
	require.False(t, node.IsFull(maxKeys))

	node.InsertKeyValue("key3", "value3")
	require.True(t, node.IsFull(maxKeys))
}

func TestInsertKeyValue(t *testing.T) {
	node := NewLeafNode("leaf")

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
	node := NewInternalNode("internal")

	// Should fail on internal node
	err := node.InsertKeyValue("key1", "value1")
	require.Error(t, err)
	require.Equal(t, err, ErrNotALeafNode)
}

func TestRemoveValueFromKey(t *testing.T) {
	node := NewLeafNode("leaf")

	// Setup test data
	node.InsertKeyValue("key1", "value1")
	node.InsertKeyValue("key1", "value2")
	node.InsertKeyValue("key2", "value3")

	// Remove specific value
	result, err := node.RemoveValueFromKey("key1", "value2")
	require.NoError(t, err)
	require.Equal(t, ValueRemoved, result)
	require.Equal(t, []string{"value1"}, node.GetKeyValues("key1"))

	// Remove non-existing value
	result, err = node.RemoveValueFromKey("key1", "nonexistent")
	require.NoError(t, err)
	require.Equal(t, ValueNotFound, result)

	// Remove last value (should remove key)
	result, err = node.RemoveValueFromKey("key1", "value1")
	require.NoError(t, err)
	require.Equal(t, KeyRemoved, result)
	require.False(t, node.HasKey("key1"))

	// Remove from non-existing key
	result, err = node.RemoveValueFromKey("nonexistent", "value")
	require.NoError(t, err)
	require.Equal(t, KeyNotFound, result)
}

func TestRemoveKeyValuesEntry(t *testing.T) {
	node := NewLeafNode("leaf")

	// Setup test data
	node.InsertKeyValue("key1", "value1")
	node.InsertKeyValue("key1", "value2")
	node.InsertKeyValue("key2", "value3")

	// Remove existing key
	result, err := node.RemoveKeyValuesEntry("key1")
	require.NoError(t, err)
	require.Equal(t, KeyRemoved, result)
	require.False(t, node.HasKey("key1"))
	require.Equal(t, []string{"key2"}, node.Keys)

	// Remove non-existing key
	result, err = node.RemoveKeyValuesEntry("nonexistent")
	require.NoError(t, err)
	require.Equal(t, KeyNotFound, result)
}

func TestInsertKeyChild(t *testing.T) {
	node := NewInternalNode("internal")

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
	node := NewLeafNode("leaf")

	// Should fail on leaf node
	err := node.InsertKeyChild("key1", "child1")
	require.Error(t, err)
	require.Contains(t, err.Error(), "leaf node")
}

func TestRemoveKeyChildAt(t *testing.T) {
	node := NewInternalNode("internal")

	// Pre-populate with left-most child
	node.ChildrenIDs = []string{"child0"}

	// Setup test data
	node.InsertKeyChild("key1", "child1")
	node.InsertKeyChild("key2", "child2")
	node.InsertKeyChild("key3", "child3")

	// Remove middle entry
	err := node.RemoveKeyChildAt(1)
	require.NoError(t, err)
	require.Equal(t, []string{"key1", "key3"}, node.Keys)
	require.Equal(t, []string{"child0", "child1", "child3"}, node.ChildrenIDs)

	// Remove first entry
	err = node.RemoveKeyChildAt(0)
	require.NoError(t, err)
	require.Equal(t, []string{"key3"}, node.Keys)
	require.Equal(t, []string{"child0", "child3"}, node.ChildrenIDs)

	// Remove last entry
	err = node.RemoveKeyChildAt(0)
	require.NoError(t, err)
	require.Empty(t, node.Keys)
	require.Equal(t, []string{"child0"}, node.ChildrenIDs)

	// Remove from empty node
	err = node.RemoveKeyChildAt(0)
	require.Error(t, err)
	require.Contains(t, err.Error(), "index out of bounds")
}

func TestGetChildAt(t *testing.T) {
	node := NewInternalNode("internal")

	// Pre-populate with left-most child
	node.ChildrenIDs = []string{"child0"}

	// Setup test data
	node.InsertKeyChild("key1", "child1")
	node.InsertKeyChild("key2", "child2")

	// Test valid indices
	childID, err := node.GetChildAt(0)
	require.NoError(t, err)
	require.Equal(t, "child0", childID)

	childID, err = node.GetChildAt(1)
	require.NoError(t, err)
	require.Equal(t, "child1", childID)

	childID, err = node.GetChildAt(2)
	require.NoError(t, err)
	require.Equal(t, "child2", childID)

	// Test invalid index
	_, err = node.GetChildAt(3)
	require.Error(t, err)
	require.Contains(t, err.Error(), "index out of bounds")
}

func TestGetKeyAt(t *testing.T) {
	node := NewInternalNode("internal")

	// Pre-populate with left-most child
	node.ChildrenIDs = []string{"child0"}

	// Setup test data
	node.InsertKeyChild("key1", "child1")
	node.InsertKeyChild("key2", "child2")

	// Test valid indices
	key, err := node.GetKeyAt(0)
	require.NoError(t, err)
	require.Equal(t, "key1", key)

	key, err = node.GetKeyAt(1)
	require.NoError(t, err)
	require.Equal(t, "key2", key)

	// Test invalid index
	_, err = node.GetKeyAt(2)
	require.Error(t, err)
	require.Contains(t, err.Error(), "index out of bounds")
}

func TestGetChildForKey(t *testing.T) {
	node := NewInternalNode("internal")

	// Pre-populate with left-most child
	node.ChildrenIDs = []string{"child0"}

	// Setup test data - keys partition the key space
	// child1 handles keys < "key2"
	// child2 handles keys >= "key2" and < "key4"
	// child3 handles keys >= "key4"
	node.InsertKeyChild("key2", "child1")
	node.InsertKeyChild("key4", "child2")

	// Test key less than first key
	childID, err := node.GetChildForKey("key1")
	require.NoError(t, err)
	require.Equal(t, "child0", childID)

	// Test key equal to first key
	childID, err = node.GetChildForKey("key2")
	require.NoError(t, err)
	require.Equal(t, "child1", childID)

	// Test key between keys
	childID, err = node.GetChildForKey("key3")
	require.NoError(t, err)
	require.Equal(t, "child1", childID)

	// Test key equal to second key
	childID, err = node.GetChildForKey("key4")
	require.NoError(t, err)
	require.Equal(t, "child2", childID)

	// Test key greater than all keys
	childID, err = node.GetChildForKey("key5")
	require.NoError(t, err)
	require.Equal(t, "child2", childID)
}

func TestFindKeyIndex(t *testing.T) {
	node := NewLeafNode("leaf")

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
