// Copyright (c) 2024 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package bptree

import (
	"errors"
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

// GetKeyValues returns all values associated with a key (leaf nodes only)
func (n *Node) GetKeyValues(key string) []string {
	if !n.IsLeaf {
		return nil
	}

	idx, found := n.FindKeyIndex(key)
	if !found {
		return nil
	}

	// Return a copy to prevent external modification
	result := make([]string, len(n.Values[idx]))
	copy(result, n.Values[idx])
	return result
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

// GetKeyAt returns the key at the specified index
func (n *Node) GetKeyAt(idx int) (string, error) {
	if idx < 0 || idx >= len(n.Keys) {
		return "", ErrKeyIndexOutOfBounds
	}

	return n.Keys[idx], nil
}

// GetChildAt returns the child ID at the specified index (internal nodes only)
func (n *Node) GetChildAt(idx int) (string, error) {
	if n.IsLeaf {
		return "", ErrNotAnInternalNode
	}

	if idx < 0 || idx >= len(n.ChildrenIDs) {
		return "", ErrChildIndexOutOfBounds
	}

	return n.ChildrenIDs[idx], nil
}

// GetChildForKey returns the child ID that should contain the given key (internal nodes only)
// NOTE (gabrielopesantos): This is not really correct.
func (n *Node) GetChildForKey(key string) (string, error) {
	if n.IsLeaf {
		return "", ErrNotAnInternalNode
	}

	idx, found := n.FindKeyIndex(key)
	if found {
		// Key found, return the child to its right
		if idx+1 < len(n.ChildrenIDs) {
			return n.ChildrenIDs[idx+1], nil
		}
	}

	// Key not found or no right child, return the child to the left
	if idx < len(n.ChildrenIDs) {
		return n.ChildrenIDs[idx], nil
	}

	return "", ErrChildIndexOutOfBounds
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

// RemoveKeyAt removes a key at the specified index (low-level operation)
func (n *Node) RemoveKeyAt(idx int) error {
	if idx < 0 || idx >= len(n.Keys) {
		return ErrKeyIndexOutOfBounds
	}
	n.Keys = slices.Delete(n.Keys, idx, idx+1)
	return nil
}

// RemoveValueAt removes values at the specified index (low-level operation, leaf nodes only)
func (n *Node) RemoveValueAt(idx int) error {
	if !n.IsLeaf {
		return ErrNotALeafNode
	}
	if idx < 0 || idx >= len(n.Values) {
		return ErrValueIndexOutOfBounds
	}
	n.Values = slices.Delete(n.Values, idx, idx+1)
	return nil
}
