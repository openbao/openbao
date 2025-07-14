// Copyright (c) 2024 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package bptree

import (
	"errors"
	"fmt"
	"slices"
)

// RemovalResult represents the result of a removal operation
type RemovalResult int

const (
	// NilRemovalResult indicates no removal occurred
	Nil RemovalResult = iota
	// KeyRemoved indicates the entire key was removed
	KeyRemoved
	// KeyNotFound indicates the key was not found
	KeyNotFound
	// ValueRemoved indicates a value was removed but the key still exists
	ValueRemoved
	// ValueNotFound indicates the value was not found for the key
	ValueNotFound
)

var (
	// TODO (gabrielopesantos): Consider having a single error for all indexes out of bounds
	// ErrKeyIndexOutOfBounds is returned when an index for a key is out of bounds
	ErrKeyIndexOutOfBounds = errors.New("key index out of bounds")

	// ErrValueIndexOutOfBounds is returned when an index for a value is out of bounds
	ErrValueIndexOutOfBounds = errors.New("value index out of bounds")

	// ErrChildIndexOutOfBounds is returned when an index for a child node is out of bounds
	ErrChildIndexOutOfBounds = errors.New("child index out of bounds")

	// ErrNotALeafNode is returned when an operation is attempted on a non-leaf node
	ErrNotALeafNode = errors.New("operation not allowed on a non-leaf node")

	// ErrNotAnInternalNode is returned when an operation is attempted on a leaf node that requires an internal node
	ErrNotAnInternalNode = errors.New("operation not allowed on a leaf node")
)

// Node represents a node in the B+ tree
type Node struct {
	ID     string `json:"id"`
	IsLeaf bool   `json:"isLeaf"`
	// NOTE (gabrilopesantos): Consider making keys a generic type instead of string
	Keys []string `json:"keys"`
	// NOTE (gabrielopesantos): Have some limit in the number of values per key?
	Values      [][]string `json:"values"`      // Only for leaf nodes
	ChildrenIDs []string   `json:"childrenIDs"` // Only for internal nodes
	ParentID    string     `json:"parentID"`
	NextID      string     `json:"nextID"`     // ID of the next leaf node
	PreviousID  string     `json:"previousID"` // ID of the previous leaf node
}

// NewLeafNode creates a new leaf node
func NewLeafNode(id string) *Node {
	return &Node{
		ID:     id,
		IsLeaf: true,
		Keys:   make([]string, 0),
		Values: make([][]string, 0),
	}
}

// NewInternalNode creates a new internal node
func NewInternalNode(id string) *Node {
	return &Node{
		ID:          id,
		IsLeaf:      false,
		Keys:        make([]string, 0),
		ChildrenIDs: make([]string, 0),
	}
}

// FindKeyIndex finds the index where a key should be inserted or is located
// Returns the index and whether the key was found
func (n *Node) FindKeyIndex(key string) (int, bool) {
	for i, k := range n.Keys {
		if k == key {
			return i, true
		}
		if key < k {
			return i, false
		}
	}
	return len(n.Keys), false
}

// HasKey returns true if the node contains the specified key
func (n *Node) HasKey(key string) bool {
	_, found := n.FindKeyIndex(key)
	return found
}

// GetKeyValues returns all values associated with a key
// if the key exists in a leaf node. (leaf nodes only)
func (n *Node) GetKeyValues(key string) ([]string, bool) {
	if !n.IsLeaf {
		return nil, false
	}

	idx, found := n.FindKeyIndex(key)
	if !found {
		return nil, false
	}

	// Return a copy to prevent external modification
	result := make([]string, len(n.Values[idx]))
	copy(result, n.Values[idx])
	return result, true
}

// GetAllKeys returns all keys in the node
func (n *Node) GetAllKeys() []string {
	result := make([]string, len(n.Keys))
	copy(result, n.Keys)
	return result
}

// KeyCount returns the number of keys in the node
func (n *Node) KeyCount() int {
	return len(n.Keys)
}

// IsEmpty returns true if the node has no keys
func (n *Node) IsEmpty() bool {
	return len(n.Keys) == 0
}

// IsFull returns true if the node has reached the maximum number of keys
func (n *Node) IsFull(maxKeys int) bool {
	return len(n.Keys) >= maxKeys
}

// GetKeyAtIndex returns the key at the specified index
func (n *Node) GetKeyAtIndex(idx int) (string, error) {
	if idx < 0 || idx >= len(n.Keys) {
		return "", ErrKeyIndexOutOfBounds
	}

	return n.Keys[idx], nil
}

// GetChildAtIndex returns the child ID at the specified index (internal nodes only)
func (n *Node) GetChildAtIndex(idx int) (string, error) {
	if n.IsLeaf {
		return "", ErrNotAnInternalNode
	}

	if idx < 0 || idx >= len(n.ChildrenIDs) {
		return "", ErrChildIndexOutOfBounds
	}

	return n.ChildrenIDs[idx], nil
}

// GetChildForKeyTraversal returns the child ID for key traversal in B+ tree (internal nodes only)
// This follows B+ tree navigation rules where we find the rightmost child whose separator is <= key
func (n *Node) GetChildForKeyTraversal(key string) (string, error) {
	if n.IsLeaf {
		return "", ErrNotAnInternalNode
	}

	if len(n.ChildrenIDs) == 0 {
		return "", ErrChildIndexOutOfBounds
	}

	// Find the appropriate child index for the key
	i := 0
	for i < len(n.Keys) && key >= n.Keys[i] {
		i++
	}

	if i >= len(n.ChildrenIDs) {
		return "", ErrChildIndexOutOfBounds
	}

	return n.ChildrenIDs[i], nil
}

// InsertKeyValue inserts a key-value pair (leaf nodes only)
func (n *Node) InsertKeyValue(key, value string) error {
	if !n.IsLeaf {
		return ErrNotALeafNode
	}

	idx, keyExists := n.FindKeyIndex(key)

	if keyExists {
		// Key exists, append value if not already present
		if !slices.Contains(n.Values[idx], value) {
			n.Values[idx] = append(n.Values[idx], value)
		}
	} else {
		// Key doesn't exist, insert both key and value
		n.Keys = slices.Insert(n.Keys, idx, key)
		n.Values = slices.Insert(n.Values, idx, []string{value})
	}

	return nil
}

// InsertKeyChild inserts a key and child at the appropriate position (internal nodes only)
func (n *Node) InsertKeyChild(key, childID string) error {
	if n.IsLeaf {
		return ErrNotAnInternalNode
	}

	idx, _ := n.FindKeyIndex(key)
	n.Keys = slices.Insert(n.Keys, idx, key)
	n.ChildrenIDs = slices.Insert(n.ChildrenIDs, idx+1, childID)
	return nil
}

// RemoveKeyChildAt removes a key and its associated child at the specified index (internal nodes only)
// NOTE (gabrielopesantos): This is also not correct.
func (n *Node) RemoveKeyChildAt(idx int) error {
	if n.IsLeaf {
		return ErrNotAnInternalNode
	}

	if idx < 0 || idx >= len(n.Keys) {
		return ErrKeyIndexOutOfBounds
	}

	n.Keys = slices.Delete(n.Keys, idx, idx+1)
	// Remove the child to the right of the key
	if idx+1 < len(n.ChildrenIDs) {
		n.ChildrenIDs = slices.Delete(n.ChildrenIDs, idx+1, idx+2)
	}
	return nil
}

// RemoveValueFromKey removes the value, if exists, associated with the provided key
func (n *Node) RemoveValueFromKey(key, value string) (RemovalResult, error) {
	if !n.IsLeaf {
		return Nil, ErrNotALeafNode
	}

	idx, found := n.FindKeyIndex(key)
	if !found {
		return KeyNotFound, nil
	}

	values := n.Values[idx]
	valueIdx := slices.Index(values, value)
	if valueIdx == -1 {
		return ValueNotFound, nil
	}

	// Remove the value
	n.Values[idx] = slices.Delete(values, valueIdx, valueIdx+1)

	// If no values left, remove the key entirely
	if len(n.Values[idx]) == 0 {
		n.Keys = slices.Delete(n.Keys, idx, idx+1)
		n.Values = slices.Delete(n.Values, idx, idx+1)
		return KeyRemoved, nil
	}

	return ValueRemoved, nil
}

// RemoveKeyValuesEntry removes a key and all values associated with it
func (n *Node) RemoveKeyValuesEntry(key string) (RemovalResult, error) {
	if !n.IsLeaf {
		return Nil, ErrNotALeafNode
	}

	idx, found := n.FindKeyIndex(key)
	if !found {
		return KeyNotFound, nil
	}

	n.Keys = slices.Delete(n.Keys, idx, idx+1)
	n.Values = slices.Delete(n.Values, idx, idx+1)
	return KeyRemoved, nil
}

// RemoveKeyAtImdex removes a key at the specified index (low-level operation)
func (n *Node) RemoveKeyAtImdex(idx int) error {
	if idx < 0 || idx >= len(n.Keys) {
		return ErrKeyIndexOutOfBounds
	}
	n.Keys = slices.Delete(n.Keys, idx, idx+1)
	return nil
}

// RemoveValueAtIndex removes values at the specified index (low-level operation, leaf nodes only)
func (n *Node) RemoveValueAtIndex(idx int) error {
	if !n.IsLeaf {
		return ErrNotALeafNode
	}
	if idx < 0 || idx >= len(n.Values) {
		return ErrValueIndexOutOfBounds
	}
	n.Values = slices.Delete(n.Values, idx, idx+1)
	return nil
}

// GetFirstKey returns the first key in the node, or empty string if no keys
func (n *Node) GetFirstKey() (string, bool) {
	if len(n.Keys) == 0 {
		return "", false
	}
	return n.Keys[0], true
}

// GetLastKey returns the last key in the node, or empty string if no keys
func (n *Node) GetLastKey() (string, bool) {
	if len(n.Keys) == 0 {
		return "", false
	}
	return n.Keys[len(n.Keys)-1], true
}

// GetLastKeyValue returns the last key-value pair in a leaf node
func (n *Node) GetLastKeyValue() (string, []string, error) {
	if !n.IsLeaf {
		return "", nil, ErrNotALeafNode
	}

	if len(n.Keys) == 0 {
		return "", nil, ErrKeyIndexOutOfBounds
	}

	lastIdx := len(n.Keys) - 1
	return n.Keys[lastIdx], n.Values[lastIdx], nil
}

// GetFirstKeyValue returns the first key-value pair in a leaf node
func (n *Node) GetFirstKeyValue() (string, []string, error) {
	if !n.IsLeaf {
		return "", nil, ErrNotALeafNode
	}

	if len(n.Keys) == 0 {
		return "", nil, ErrKeyIndexOutOfBounds
	}

	return n.Keys[0], n.Values[0], nil
}

// RemoveLastKeyValue removes and returns the last key-value pair from a leaf node
func (n *Node) RemoveLastKeyValue() (string, []string, error) {
	if !n.IsLeaf {
		return "", nil, ErrNotALeafNode
	}

	if len(n.Keys) == 0 {
		return "", nil, ErrKeyIndexOutOfBounds
	}

	lastIdx := len(n.Keys) - 1
	key := n.Keys[lastIdx]
	values := n.Values[lastIdx]

	// Make a copy of the values before removing
	valuesCopy := make([]string, len(values))
	copy(valuesCopy, values)

	// Remove the key and values
	if err := n.RemoveKeyAtImdex(lastIdx); err != nil {
		return "", nil, err
	}
	if err := n.RemoveValueAtIndex(lastIdx); err != nil {
		// This should not happen if RemoveKeyAt succeeded
		return "", nil, err
	}

	return key, valuesCopy, nil
}

// RemoveFirstKeyValue removes and returns the first key-value pair from a leaf node
func (n *Node) RemoveFirstKeyValue() (string, []string, error) {
	if !n.IsLeaf {
		return "", nil, ErrNotALeafNode
	}

	if len(n.Keys) == 0 {
		return "", nil, ErrKeyIndexOutOfBounds
	}

	key := n.Keys[0]
	values := n.Values[0]

	// Make a copy of the values before removing
	valuesCopy := make([]string, len(values))
	copy(valuesCopy, values)

	// Remove the key and values
	if err := n.RemoveKeyAtImdex(0); err != nil {
		return "", nil, err
	}
	if err := n.RemoveValueAtIndex(0); err != nil {
		// This should not happen if RemoveKeyAt succeeded
		return "", nil, err
	}

	return key, valuesCopy, nil
}

// PrependKeyValue inserts a key-value pair at the beginning of a leaf node
func (n *Node) PrependKeyValue(key string, values []string) error {
	if !n.IsLeaf {
		return ErrNotALeafNode
	}

	n.Keys = slices.Insert(n.Keys, 0, key)
	n.Values = slices.Insert(n.Values, 0, values)
	return nil
}

// IterateKeyValues calls the provided function for each key-value pair in the node (leaf nodes only)
// The iteration stops early if the function returns false
func (n *Node) IterateKeyValues(fn func(key string, values []string) bool) error {
	if !n.IsLeaf {
		return ErrNotALeafNode
	}

	for i, key := range n.Keys {
		if !fn(key, n.Values[i]) {
			break
		}
	}
	return nil
}

// SplitLeafAtIndex splits a leaf node at the given index, returning the new right node
// The original node keeps keys/values [0:splitIndex], the new node gets [splitIndex:]
func (n *Node) SplitLeafAtIndex(splitIndex int) (*Node, error) {
	if !n.IsLeaf {
		return nil, ErrNotALeafNode
	}

	if splitIndex < 0 || splitIndex >= len(n.Keys) {
		return nil, ErrKeyIndexOutOfBounds
	}

	// Create a new leaf node
	newLeaf := NewLeafNode(generateUUID())

	// Move second half keys/values to new leaf
	newLeaf.Keys = append(newLeaf.Keys, n.Keys[splitIndex:]...)
	newLeaf.Values = append(newLeaf.Values, n.Values[splitIndex:]...)

	// Update original leaf with first half
	n.Keys = n.Keys[:splitIndex]
	n.Values = n.Values[:splitIndex]

	// Set up NextID linking: newLeaf should point to what the original leaf was pointing to
	newLeaf.NextID = n.NextID
	// The original leaf should now point to the new leaf
	n.NextID = newLeaf.ID

	// Set up PreviousID linking: newLeaf should point to the original leaf
	newLeaf.PreviousID = n.ID

	// Set parent reference for the new leaf
	newLeaf.ParentID = n.ParentID

	return newLeaf, nil
}

// SplitInternalAtIndex splits an internal node at the given index, returning the new right node and promoted key
// The key at splitIndex is promoted to the parent
func (n *Node) SplitInternalAtIndex(splitIndex int) (*Node, string, error) {
	if n.IsLeaf {
		return nil, "", ErrNotAnInternalNode
	}

	if splitIndex < 0 || splitIndex >= len(n.Keys) {
		return nil, "", ErrKeyIndexOutOfBounds
	}

	// Create a new internal node
	newInternal := NewInternalNode(generateUUID())

	// The key at splitIndex is promoted, so do not copy it to any node
	promotedKey := n.Keys[splitIndex]

	// Copy keys and children after splitIndex to newInternal
	newInternal.Keys = append(newInternal.Keys, n.Keys[splitIndex+1:]...)
	newInternal.ChildrenIDs = append(newInternal.ChildrenIDs, n.ChildrenIDs[splitIndex+1:]...)

	// Update original node with first half
	n.Keys = n.Keys[:splitIndex]                 // Keep only keys before the split key
	n.ChildrenIDs = n.ChildrenIDs[:splitIndex+1] // Keep one extra child for the split key

	// Set parent reference for the new internal node
	newInternal.ParentID = n.ParentID

	return newInternal, promotedKey, nil
}

// GetLeftSiblingID returns the left sibling ID for a given child, if exists
func (n *Node) GetLeftSiblingID(childID string) (string, bool) {
	if n.IsLeaf {
		return "", false
	}

	nodeIndex := slices.Index(n.ChildrenIDs, childID)
	if nodeIndex == -1 || nodeIndex == 0 {
		return "", false
	}

	return n.ChildrenIDs[nodeIndex-1], true
}

// GetRightSiblingID returns the right sibling ID for a given child, if exists
func (n *Node) GetRightSiblingID(childID string) (string, bool) {
	if n.IsLeaf {
		return "", false
	}

	nodeIndex := slices.Index(n.ChildrenIDs, childID)
	if nodeIndex == -1 || nodeIndex == len(n.ChildrenIDs)-1 {
		return "", false
	}

	return n.ChildrenIDs[nodeIndex+1], true
}

// GetChildIndex returns the index of a child in this node
func (n *Node) GetChildIndex(childID string) int {
	if n.IsLeaf {
		return -1
	}

	return slices.Index(n.ChildrenIDs, childID)
}

// GetID returns the node's ID
func (n *Node) GetID() string {
	return n.ID
}

// SetParentID sets the node's parent ID
func (n *Node) SetParentID(parentID string) {
	n.ParentID = parentID
}

// GetParentID returns the node's parent ID
func (n *Node) GetParentID() string {
	return n.ParentID
}

// AddChildrenIDs adds child IDs to the node (for internal nodes)
func (n *Node) AddChildrenIDs(childIDs ...string) {
	if n.ChildrenIDs == nil {
		n.ChildrenIDs = make([]string, 0, len(childIDs))
	}
	n.ChildrenIDs = append(n.ChildrenIDs, childIDs...)
}

// SetChildrenIDs sets the children IDs directly (use sparingly)
func (n *Node) SetChildrenIDs(childIDs []string) {
	n.ChildrenIDs = make([]string, len(childIDs))
	copy(n.ChildrenIDs, childIDs)
}

// BorrowLastKeyValueFromLeft borrows the last key-value pair from a left sibling (leaf nodes)
func (n *Node) BorrowLastKeyValueFromLeft(leftSibling *Node) (string, []string, error) {
	if !n.IsLeaf || !leftSibling.IsLeaf {
		return "", nil, fmt.Errorf("both nodes must be leaf nodes")
	}

	// Get the last key-value from left sibling
	key, values, err := leftSibling.RemoveLastKeyValue()
	if err != nil {
		return "", nil, fmt.Errorf("failed to remove last key-value from left sibling: %w", err)
	}

	// Prepend to current node
	if err := n.PrependKeyValue(key, values); err != nil {
		return "", nil, fmt.Errorf("failed to prepend key-value: %w", err)
	}

	return key, values, nil
}

// BorrowFirstKeyValueFromRight borrows the first key-value pair from a right sibling (leaf nodes)
func (n *Node) BorrowFirstKeyValueFromRight(rightSibling *Node) (string, []string, error) {
	if !n.IsLeaf || !rightSibling.IsLeaf {
		return "", nil, fmt.Errorf("both nodes must be leaf nodes")
	}

	// Get the first key-value from right sibling
	key, values, err := rightSibling.RemoveFirstKeyValue()
	if err != nil {
		return "", nil, fmt.Errorf("failed to remove first key-value from right sibling: %w", err)
	}

	// Append to current node
	if err := n.AppendKeyValue(key, values); err != nil {
		return "", nil, fmt.Errorf("failed to append key-value: %w", err)
	}

	return key, values, nil
}

// BorrowLastKeyChildFromLeft borrows the last key and child from a left sibling (internal nodes)
func (n *Node) BorrowLastKeyChildFromLeft(leftSibling *Node, separatorKey string) (string, string, error) {
	if n.IsLeaf || leftSibling.IsLeaf {
		return "", "", fmt.Errorf("both nodes must be internal nodes")
	}

	if len(leftSibling.Keys) == 0 || len(leftSibling.ChildrenIDs) == 0 {
		return "", "", fmt.Errorf("left sibling is empty")
	}

	// Get the last key and child from left sibling
	borrowedKey := leftSibling.Keys[len(leftSibling.Keys)-1]
	borrowedChild := leftSibling.ChildrenIDs[len(leftSibling.ChildrenIDs)-1]

	// Remove from left sibling
	if err := leftSibling.RemoveKeyAtImdex(len(leftSibling.Keys) - 1); err != nil {
		return "", "", fmt.Errorf("failed to remove key from left sibling: %w", err)
	}
	leftSibling.ChildrenIDs = leftSibling.ChildrenIDs[:len(leftSibling.ChildrenIDs)-1]

	// Insert separator key and borrowed child at the beginning of current node
	n.Keys = slices.Insert(n.Keys, 0, separatorKey)
	n.ChildrenIDs = slices.Insert(n.ChildrenIDs, 0, borrowedChild)

	return borrowedKey, borrowedChild, nil
}

// BorrowFirstKeyChildFromRight borrows the first key and child from a right sibling (internal nodes)
func (n *Node) BorrowFirstKeyChildFromRight(rightSibling *Node, separatorKey string) (string, string, error) {
	if n.IsLeaf || rightSibling.IsLeaf {
		return "", "", fmt.Errorf("both nodes must be internal nodes")
	}

	if len(rightSibling.Keys) == 0 || len(rightSibling.ChildrenIDs) == 0 {
		return "", "", fmt.Errorf("right sibling is empty")
	}

	// Get the first key and child from right sibling
	borrowedKey := rightSibling.Keys[0]
	borrowedChild := rightSibling.ChildrenIDs[0]

	// Remove from right sibling
	if err := rightSibling.RemoveKeyAtImdex(0); err != nil {
		return "", "", fmt.Errorf("failed to remove key from right sibling: %w", err)
	}
	rightSibling.ChildrenIDs = rightSibling.ChildrenIDs[1:]

	// Append separator key and borrowed child to current node
	n.Keys = append(n.Keys, separatorKey)
	n.ChildrenIDs = append(n.ChildrenIDs, borrowedChild)

	return borrowedKey, borrowedChild, nil
}

// AppendKeyValue appends a key-value pair to the end of the node (leaf nodes)
func (n *Node) AppendKeyValue(key string, values []string) error {
	if !n.IsLeaf {
		return fmt.Errorf("can only append key-value to leaf nodes")
	}

	n.Keys = append(n.Keys, key)
	n.Values = append(n.Values, values)
	return nil
}

// SetKeyAtIndex sets the key at a specific index
func (n *Node) SetKeyAtIndex(index int, key string) error {
	if index < 0 || index >= len(n.Keys) {
		return fmt.Errorf("index %d out of bounds [0, %d)", index, len(n.Keys))
	}
	n.Keys[index] = key
	return nil
}

// MergeWithLeftSibling merges this node with its left sibling
func (n *Node) MergeWithLeftSibling(leftSibling *Node, separatorKey string) error {
	if n.IsLeaf != leftSibling.IsLeaf {
		return fmt.Errorf("nodes must have the same type (both leaf or both internal)")
	}

	if n.IsLeaf {
		// Merge leaf nodes: append current node's keys/values to left sibling
		leftSibling.Keys = append(leftSibling.Keys, n.Keys...)
		leftSibling.Values = append(leftSibling.Values, n.Values...)

		// Update the next pointer to maintain leaf chain
		leftSibling.NextID = n.NextID
	} else {
		// Merge internal nodes: include separator key between them
		leftSibling.Keys = append(leftSibling.Keys, separatorKey)
		leftSibling.Keys = append(leftSibling.Keys, n.Keys...)
		leftSibling.ChildrenIDs = append(leftSibling.ChildrenIDs, n.ChildrenIDs...)
	}

	return nil
}

// MergeWithRightSibling merges right sibling into this node
func (n *Node) MergeWithRightSibling(rightSibling *Node, separatorKey string) error {
	if n.IsLeaf != rightSibling.IsLeaf {
		return fmt.Errorf("nodes must have the same type (both leaf or both internal)")
	}

	if n.IsLeaf {
		// Merge leaf nodes: append right sibling's keys/values to current node
		n.Keys = append(n.Keys, rightSibling.Keys...)
		n.Values = append(n.Values, rightSibling.Values...)

		// Update the next pointer to maintain leaf chain
		n.NextID = rightSibling.NextID
	} else {
		// Merge internal nodes: include separator key between them
		n.Keys = append(n.Keys, separatorKey)
		n.Keys = append(n.Keys, rightSibling.Keys...)
		n.ChildrenIDs = append(n.ChildrenIDs, rightSibling.ChildrenIDs...)
	}

	return nil
}
