// Copyright (c) 2024 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package bptree

import (
	"context"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"sync"
)

// BPlusTree represents a B+ tree data structure
type BPlusTree struct {
	config *BPlusTreeConfig // B+Tree configuration
	lock   sync.RWMutex     // Mutex to protect concurrent access
}

// InitializeBPlusTree initializes a tree, creating it if it doesn't exist or loading it if it does.
// For new trees, the provided config is used. For existing trees, stored config is used and only the TreeID is used.
func InitializeBPlusTree(
	ctx context.Context,
	storage Storage,
	config *BPlusTreeConfig,
) (*BPlusTree, error) {
	if config == nil {
		config = NewDefaultBPlusTreeConfig()
	} else if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	// Try to load existing tree first
	existingTree, err := LoadExistingBPlusTree(ctx, storage, config.TreeID)
	if err == nil {
		return existingTree, nil
	}

	// If tree doesn't exist, create it
	return NewBPlusTree(ctx, storage, config)
}

// NewBPlusTree creates a new B+ tree with the given configuration.
// Fails if a tree with the same ID already exists.
func NewBPlusTree(
	ctx context.Context,
	storage Storage,
	config *BPlusTreeConfig,
) (*BPlusTree, error) {
	if config == nil {
		return nil, fmt.Errorf("config is required for tree creation")
	}
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	// Add the treeID to the context
	ctx = config.contextWithTreeID(ctx)

	// Check if tree already exists
	existingConfig, err := storage.GetTreeConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to check for existing tree: %w", err)
	}
	if existingConfig != nil {
		return nil, fmt.Errorf("tree (%s) already exists", config.TreeID)
	}

	tree := &BPlusTree{
		config: config,
	}

	// Create new leaf root
	root := NewLeafNode(generateUUID())
	if err := storage.SaveNode(ctx, root); err != nil {
		return nil, fmt.Errorf("failed to save root node: %w", err)
	}

	// Set root ID
	if err := tree.setRootID(ctx, storage, root.ID); err != nil {
		return nil, fmt.Errorf("failed to set root ID: %w", err)
	}

	// Store configuration
	if err := storage.SetTreeConfig(ctx, config); err != nil {
		return nil, fmt.Errorf("failed to store tree configuration: %w", err)
	}

	return tree, nil
}

// LoadExistingBPlusTree loads an existing B+ tree from storage using the stored configuration
// as the source of truth. If the tree doesn't exist, returns an error.
func LoadExistingBPlusTree(
	ctx context.Context,
	storage Storage,
	treeID string,
) (*BPlusTree, error) {
	if treeID == "" {
		return nil, fmt.Errorf("treeID cannot be empty")
	}
	// Add the TreeID to the context
	ctx = withTreeID(ctx, treeID)

	// Get stored configuration - this is the source of truth
	storedConfig, err := storage.GetTreeConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load tree configuration: %w", err)
	}
	if storedConfig == nil {
		return nil, fmt.Errorf("tree '%s' does not exist", treeID)
	}

	// Create tree with stored configuration
	tree := &BPlusTree{
		config: storedConfig,
	}

	// TODO (gabrielopesantos): Validate tree structure
	// We need to be careful here because a full validation might be too expensive...
	ctx = tree.contextWithTreeID(ctx)
	rootID, err := tree.getRootID(ctx, storage)
	if err != nil {
		return nil, fmt.Errorf("failed to get root ID: %w", err)
	}
	if rootID == "" {
		return nil, fmt.Errorf("tree metadata exists but no root node found - tree may be corrupted")
	}

	// Validate root node exists
	root, err := storage.LoadNode(ctx, rootID)
	if err != nil {
		return nil, fmt.Errorf("failed to load root node: %w", err)
	}
	if root == nil || root.ID != rootID {
		return nil, fmt.Errorf("root node validation failed")
	}

	return tree, nil
}

// getRoot loads the root node from storage
func (t *BPlusTree) getRoot(ctx context.Context, storage Storage) (*Node, error) {
	rootID, err := t.getRootID(ctx, storage)
	if err != nil {
		return nil, fmt.Errorf("failed to get root ID: %w", err)
	}
	if rootID == "" {
		return nil, errors.New("root node not found")
	}

	return storage.LoadNode(ctx, rootID)
}

// TODO: Can be removed...
// getRootID returns the root ID
func (t *BPlusTree) getRootID(ctx context.Context, storage Storage) (string, error) {
	// Load from storage and cache
	rootID, err := storage.GetRootID(ctx)
	if err != nil {
		return "", err
	}

	return rootID, nil
}

// TODO: Can be removed...
// setRootID updates both storage and cache
func (t *BPlusTree) setRootID(ctx context.Context, storage Storage, newRootID string) error {
	// Update storage first
	if err := storage.SetRootID(ctx, newRootID); err != nil {
		return err
	}

	return nil
}

// contextWithTreeID returns a context with the tree's ID added, enabling multi-tree storage
func (t *BPlusTree) contextWithTreeID(ctx context.Context) context.Context {
	return t.config.contextWithTreeID(ctx)
}

// maxChildrenNodes returns the maximum number of children an internal node can have
func (t *BPlusTree) maxChildrenNodes() int {
	return t.config.Order
}

// maxKeys returns the maxium number of keys an internal node can have
func (t *BPlusTree) maxKeys() int {
	return t.maxChildrenNodes() - 1
}

// minChildrenNodes returns the minimum number of children an internal node can have
func (t *BPlusTree) minChildrenNodes() int {
	return int(math.Ceil(float64(t.config.Order) / float64(2)))
}

// minKeys returns the minimum number of keys a node must have
func (t *BPlusTree) minKeys() int {
	return t.minChildrenNodes() - 1
}

// nodeOverflows checks if a node has exceeded its maximum capacity
func (t *BPlusTree) nodeOverflows(node *Node) bool {
	return len(node.Keys) > t.maxKeys()
}

// nodeUnderflows checks if a node has fallen below its minimum capacity
func (t *BPlusTree) nodeUnderflows(node *Node) bool {
	return len(node.Keys) < t.minKeys()
}

// Search retrieves all values for a key
// If the key is not found, it returns an empty slice and false
func (t *BPlusTree) Search(ctx context.Context, storage Storage, key string) ([]string, bool, error) {
	t.lock.RLock()
	defer t.lock.RUnlock()

	ctx = t.contextWithTreeID(ctx)

	return t.search(ctx, storage, key)
}

func (t *BPlusTree) search(ctx context.Context, storage Storage, key string) ([]string, bool, error) {
	leaf, err := t.findLeafNode(ctx, storage, key)
	if err != nil {
		return nil, false, fmt.Errorf("failed to find leaf node: %w", err)
	}

	// If we get here, we are at a leaf node
	idx, found := leaf.FindKeyIndex(key)
	if found {
		// If the key is found, return the values
		return leaf.Values[idx], true, nil
	}

	// Key not found is a valid state, not an error
	return nil, false, nil
}

// SearchPrefix returns all key-value pairs that start with the given prefix
// This function leverages the NextID linking to efficiently traverse leaf nodes sequentially
// No wildcards searches are supported - only exact prefix matches
// TODO (gabrielopesantos): Having some sort of limit on the number of results.
// TODO (gabrielopesantos): If the keys aren't strings, this function will not work as expected.
func (t *BPlusTree) SearchPrefix(ctx context.Context, storage Storage, prefix string) (map[string][]string, error) {
	t.lock.RLock()
	defer t.lock.RUnlock()

	ctx = t.contextWithTreeID(ctx)

	rootID, err := t.getRootID(ctx, storage)
	if err != nil {
		return nil, fmt.Errorf("failed to get root ID: %w", err)
	}

	results := make(map[string][]string)

	// Handle empty prefix - we don't allow this as it would return all keys which is expensive
	if prefix == "" {
		return results, nil // Return empty results for empty prefix
	}

	// Check if prefix is larger than any possible key
	// by comparing with the rightmost (largest) key in the tree
	rightmostLeaf, err := t.findRightmostLeaf(ctx, storage)
	if err != nil {
		return nil, fmt.Errorf("failed to find rightmost leaf: %w", err)
	}

	// If tree is empty (rightmost leaf has no keys), return empty result
	if len(rightmostLeaf.Keys) == 0 {
		return results, nil
	}

	// If prefix is lexicographically greater than the largest key, no matches possible
	largestKey := rightmostLeaf.Keys[len(rightmostLeaf.Keys)-1]
	if prefix > largestKey {
		return results, nil
	}

	// If prefix is lexicographically smaller than any key in the tree,
	// we still need to search, but we can optimize by checking if the prefix could
	// possibly match anything by comparing with the leftmost key
	leftmostLeaf, err := t.findLeftmostLeafInSubtree(ctx, storage, rootID)
	if err != nil {
		return nil, fmt.Errorf("failed to find leftmost leaf: %w", err)
	}

	// Calculate the "limit" string - the smallest string that's larger than any possible match
	// For prefix "app", the limit would be "aq" (increment last character)
	prefixLimit := calculatePrefixLimit(prefix)

	if len(leftmostLeaf.Keys) > 0 {
		smallestKey := leftmostLeaf.Keys[0]
		if prefixLimit <= smallestKey && !strings.HasPrefix(smallestKey, prefix) {
			// The prefix is so small that even after incrementing it,
			// it's still smaller than the smallest key, and the smallest key
			// doesn't match the prefix, so no matches are possible
			return results, nil
		}
	}

	// Find the first leaf that might contain our prefix
	startLeaf, err := t.findLeafNode(ctx, storage, prefix)
	if err != nil {
		return nil, fmt.Errorf("failed to find leaf node for prefix (%s): %w", prefix, err)
	}

	// Traverse leaves using NextID to find all matching keys
	current := startLeaf
	for current != nil {
		// Check all keys in the current leaf
		for i, key := range current.Keys {
			if strings.HasPrefix(key, prefix) {
				// This key matches our prefix
				results[key] = current.Values[i]
			} else if key >= prefixLimit {
				// We've reached keys that are definitely beyond our prefix range
				// Since keys are sorted, we can stop here
				return results, nil
			}
		}

		// Move to the next leaf using NextID
		if current.NextID == "" {
			break
		}
		current, err = storage.LoadNode(ctx, current.NextID)
		if err != nil {
			return nil, fmt.Errorf("failed to load next leaf node: %w", err)
		}
	}

	return results, nil
}

// TODO: Instead of all these methods we can probably have a single method with an opts struct
// SearchRange returns all key-value pairs within the specified range [start, end)
// func (t *BPlusTree) SearchRange(ctx context.Context, storage Storage, start string, end string) (map[string][]string, error) {
// 	return nil, nil
// }

// Insert inserts a key-value pair
func (t *BPlusTree) Insert(ctx context.Context, storage Storage, key string, value string) error {
	t.lock.Lock()
	defer t.lock.Unlock()

	ctx = t.contextWithTreeID(ctx)

	// Find the leaf node where the key should be inserted
	leaf, err := t.findLeafNode(ctx, storage, key)
	if err != nil {
		return err
	}

	_ = leaf.InsertKeyValue(key, value)

	// If the leaf has overflow, we need to split it
	if t.nodeOverflows(leaf) {
		newLeaf, splitKey := t.splitLeafNode(leaf)
		// Save both leaf nodes after splitting
		if err := storage.SaveNode(ctx, leaf); err != nil { // NOTE (gabrielopesantos):  We do not necessarily need to save them, just cache them somewhere
			return fmt.Errorf("failed to save original leaf node: %w", err)
		}
		if err := storage.SaveNode(ctx, newLeaf); err != nil {
			return fmt.Errorf("failed to save new leaf node: %w", err)
		}

		return t.insertIntoParent(ctx, storage, leaf, newLeaf, splitKey)
	} else {
		// Save the leaf node after insertion
		if err := storage.SaveNode(ctx, leaf); err != nil {
			return fmt.Errorf("failed to save leaf node: %w", err)
		}
	}

	return nil
}

// Delete removes all values for a key, if the key exists.
func (t *BPlusTree) Delete(ctx context.Context, storage Storage, key string) (bool, error) {
	t.lock.Lock()
	defer t.lock.Unlock()

	ctx = t.contextWithTreeID(ctx)

	// Find the leaf node where the key belongs
	leaf, err := t.findLeafNode(ctx, storage, key)
	if err != nil {
		return false, err
	}

	// Check if the key exists in the leaf node
	idx, found := leaf.FindKeyIndex(key)
	if !found {
		return false, nil // Key not found, nothing to delete
	}

	// Remove the key-value pair from the leaf
	if err := leaf.RemoveKeyAt(idx); err != nil {
		return false, fmt.Errorf("failed to remove key: %w", err)
	}
	if err := leaf.RemoveValueAt(idx); err != nil {
		return false, fmt.Errorf("failed to remove value: %w", err)
	}

	// Save the modified leaf node
	if err := storage.SaveNode(ctx, leaf); err != nil {
		return false, fmt.Errorf("failed to save leaf node: %w", err)
	}

	// Handle potential underflow using the canonical algorithm
	if err := t.rebalanceTreeIfNeeded(ctx, storage, leaf); err != nil {
		return false, fmt.Errorf("failed to fix underflow: %w", err)
	}

	// Clean up orphaned separator keys AFTER rebalancing when tree structure is stable
	// Start from the leaf where deletion occurred and work upward through ancestors
	// THIS IS AN EXPENSIVE OPERATION AND MIGHT BE OPTIMIZED LATER OR BATCHED AND
	// EXECUTED AS A BACKGROUND JOB
	if err := t.cleanupOrphanedSplitKey(ctx, storage, leaf, key); err != nil {
		return false, fmt.Errorf("failed to cleanup orphaned separators: %w", err)
	}

	return true, nil
}

// DeleteValue removes a specific value for a key
func (t *BPlusTree) DeleteValue(ctx context.Context, storage Storage, key string, value string) (bool, error) {
	t.lock.Lock()
	defer t.lock.Unlock()

	ctx = t.contextWithTreeID(ctx)

	// Find the leaf node where the key belongs
	leaf, err := t.findLeafNode(ctx, storage, key)
	if err != nil {
		return false, err
	}

	// Check if the key exists in the leaf node
	if !leaf.HasKey(key) {
		return false, nil
	}

	// Remove the specific value from the key
	result, _ := leaf.RemoveValueFromKey(key, value)
	if result == KeyNotFound {
		return false, nil
	}

	// Save the modified leaf node
	if err := storage.SaveNode(ctx, leaf); err != nil {
		return false, fmt.Errorf("failed to save leaf node: %w", err)
	}

	// If the key was completely removed (no values left), handle underflow
	if result == KeyRemoved {
		if err := t.rebalanceTreeIfNeeded(ctx, storage, leaf); err != nil {
			return false, fmt.Errorf("failed to fix underflow: %w", err)
		}

		// Clean up orphaned separator keys after rebalancing
		if err := t.cleanupOrphanedSplitKey(ctx, storage, leaf, key); err != nil {
			return false, fmt.Errorf("failed to cleanup orphaned separators: %w", err)
		}
	}

	return true, nil
}

// Purge removes all keys and values from the tree
// func (t *BPlusTree[K, V]) Purge(ctx context.Context) error {
// 	return nil
// }

// findLeafNode finds the leaf node where the key should be located.
func (t *BPlusTree) findLeafNode(ctx context.Context, storage Storage, key string) (*Node, error) {
	// Load the root node
	node, err := t.getRoot(ctx, storage)
	if err != nil {
		return nil, err
	}

	for !node.IsLeaf {
		i := 0
		for i < node.KeyCount() && key >= node.Keys[i] {
			i++
		}
		var err error
		node, err = storage.LoadNode(ctx, node.ChildrenIDs[i])
		if err != nil {
			return nil, err
		}
	}

	return node, nil
}

func (t *BPlusTree) splitLeafNode(leaf *Node) (*Node, string) {
	// Split at the median index
	splitIndex := int(math.Floor(float64(len(leaf.Keys)) / float64(2)))

	// Create a new leaf node
	newLeaf := NewLeafNode(generateUUID())

	// Move second half keys/values to new leaf (includes the split key)
	newLeaf.Keys = append(newLeaf.Keys, leaf.Keys[splitIndex:]...)
	newLeaf.Values = append(newLeaf.Values, leaf.Values[splitIndex:]...)

	// Update original leaf with first half
	leaf.Keys = leaf.Keys[:splitIndex]
	leaf.Values = leaf.Values[:splitIndex]

	// Set up NextID linking: newLeaf should point to what the original leaf was pointing to
	newLeaf.NextID = leaf.NextID
	// The original leaf should now point to the new leaf
	leaf.NextID = newLeaf.ID

	// Set up PreviousID linking: newLeaf should point to what the original leaf
	newLeaf.PreviousID = leaf.ID

	// Set parent reference for the new leaf
	newLeaf.ParentID = leaf.ParentID

	// Return new leaf and split key to be copied into the parent
	return newLeaf, newLeaf.Keys[0]
}

// insertIntoParent inserts a key and right node into the parent of left node
func (t *BPlusTree) insertIntoParent(ctx context.Context, storage Storage, leftNode *Node, rightNode *Node, splitKey string) error {
	// If leftNode was the root, we need to create a new root
	// and make the leftNode and rightNode its children
	rootID, err := t.getRootID(ctx, storage)
	if err != nil {
		return fmt.Errorf("failed to get root ID: %w", err)
	}
	if leftNode.ID == rootID {
		newRoot := NewInternalNode(generateUUID())
		newRoot.Keys = []string{splitKey}
		newRoot.ChildrenIDs = []string{leftNode.ID, rightNode.ID}

		// Update parent references
		leftNode.ParentID = newRoot.ID
		rightNode.ParentID = newRoot.ID

		// Save all nodes with updated parent references
		if err := storage.SaveNode(ctx, leftNode); err != nil {
			return fmt.Errorf("failed to save left node: %w", err)
		}
		if err := storage.SaveNode(ctx, rightNode); err != nil {
			return fmt.Errorf("failed to save right node: %w", err)
		}
		if err := storage.SaveNode(ctx, newRoot); err != nil {
			return fmt.Errorf("failed to save new root node: %w", err)
		}

		// Update root ID in storage
		return t.setRootID(ctx, storage, newRoot.ID)
	}

	// Otherwise, we need to insert into the existing parent node
	// Load parent node
	parent, err := storage.LoadNode(ctx, leftNode.ParentID)
	if err != nil {
		return err
	}

	// Insert the split key and right node into the parent
	err = parent.InsertKeyChild(splitKey, rightNode.ID)
	if err != nil {
		return fmt.Errorf("failed to insert key-child into parent: %w", err)
	}

	rightNode.ParentID = parent.ID

	// Save the updated nodes
	if err := storage.SaveNode(ctx, leftNode); err != nil {
		return fmt.Errorf("failed to save left node: %w", err)
	}
	if err := storage.SaveNode(ctx, rightNode); err != nil {
		return fmt.Errorf("failed to save right node: %w", err)
	}
	if err := storage.SaveNode(ctx, parent); err != nil {
		return fmt.Errorf("failed to save parent: %w", err)
	}

	// If the internal node is overflows, we need to split it
	if t.nodeOverflows(parent) {
		newInternal, splitKey := t.splitInternalNode(ctx, storage, parent)
		// Save both internal nodes after splitting
		if err := storage.SaveNode(ctx, parent); err != nil {
			return fmt.Errorf("failed to save original internal node: %w", err)
		}
		if err := storage.SaveNode(ctx, newInternal); err != nil {
			return fmt.Errorf("failed to save new internal node: %w", err)
		}
		return t.insertIntoParent(ctx, storage, parent, newInternal, splitKey)
	}

	return nil
}

func (t *BPlusTree) splitInternalNode(ctx context.Context, storage Storage, node *Node) (*Node, string) {
	// Split at the median index
	splitIndex := int(math.Floor(float64(len(node.Keys)) / float64(2)))

	// Create a new internal node
	newInternal := NewInternalNode(generateUUID())

	// The key at splitIndex is promoted, so do not copy it to any node
	splitKey := node.Keys[splitIndex]

	// Copy keys and children after splitIndex to newInternal
	newInternal.Keys = append(newInternal.Keys, node.Keys[splitIndex+1:]...)
	newInternal.ChildrenIDs = append(newInternal.ChildrenIDs, node.ChildrenIDs[splitIndex+1:]...)

	// Update original node with first half
	node.Keys = node.Keys[:splitIndex]                 // Keep only keys before the split key
	node.ChildrenIDs = node.ChildrenIDs[:splitIndex+1] // Keep one extra child for the split key

	// Update parent references of newInternal's children
	for _, childID := range newInternal.ChildrenIDs {
		child, err := storage.LoadNode(ctx, childID)
		if err != nil {
			// TODO: Review...
			// Log error but continue since we can't fail here
			continue
		}
		child.ParentID = newInternal.ID
		if err := storage.SaveNode(ctx, child); err != nil {
			// Log error but continue since we can't fail here
			continue
		}
	}

	return newInternal, splitKey
}

// rebalanceTreeIfNeeded handles rebalancing after a deletion
func (t *BPlusTree) rebalanceTreeIfNeeded(ctx context.Context, storage Storage, node *Node) error {
	// Get the root ID to check if this node is the root
	rootID, err := t.getRootID(ctx, storage)
	if err != nil {
		return fmt.Errorf("failed to get root ID: %w", err)
	}

	// If this is the root node, handle special root cases
	if node.ID == rootID {
		return t.handleRootAfterDeletion(ctx, storage, node)
	} else if t.nodeUnderflows(node) {
		// Node underflows, need to rebalance
		return t.rebalanceAfterDeletion(ctx, storage, node)
	}

	// If this is not the root node and not underflowing, no action needed
	return nil
}

// handleRootAfterDeletion handles the root node after deletion
func (t *BPlusTree) handleRootAfterDeletion(ctx context.Context, storage Storage, root *Node) error {
	// If root is a leaf and becomes empty, tree becomes empty (allowed)
	if root.IsLeaf {
		return nil
	}

	// If root is internal and has no keys but has exactly one child,
	// promote the child to be the new root
	if len(root.Keys) == 0 && len(root.ChildrenIDs) == 1 {
		newRootID := root.ChildrenIDs[0]

		// Load the new root and clear its parent reference
		newRoot, err := storage.LoadNode(ctx, newRootID)
		if err != nil {
			return fmt.Errorf("failed to load new root: %w", err)
		}
		newRoot.ParentID = ""

		// Save the new root and update the tree's root ID
		if err := storage.SaveNode(ctx, newRoot); err != nil {
			return fmt.Errorf("failed to save new root: %w", err)
		}
		if err := t.setRootID(ctx, storage, newRootID); err != nil {
			return fmt.Errorf("failed to set new root ID: %w", err)
		}

		// Delete the old root
		if err := storage.DeleteNode(ctx, root.ID); err != nil {
			return fmt.Errorf("failed to delete old root: %w", err)
		}
	}

	return nil
}

// rebalanceAfterDeletion rebalances a node that underflows after deletion
func (t *BPlusTree) rebalanceAfterDeletion(ctx context.Context, storage Storage, node *Node) error {
	// Load the parent
	parent, err := storage.LoadNode(ctx, node.ParentID)
	if err != nil {
		return fmt.Errorf("failed to load parent: %w", err)
	}

	// Find the node's position in the parent
	nodeIndex := -1
	for i, childID := range parent.ChildrenIDs {
		if childID == node.ID {
			nodeIndex = i
			break
		}
	}
	if nodeIndex == -1 {
		return errors.New("node not found in parent's children")
	}

	// Try to borrow from left sibling
	if nodeIndex > 0 {
		leftSiblingID := parent.ChildrenIDs[nodeIndex-1]
		leftSibling, err := storage.LoadNode(ctx, leftSiblingID)
		if err != nil {
			return fmt.Errorf("failed to load left sibling: %w", err)
		}

		// Check if left sibling has enough keys to lend
		if len(leftSibling.Keys) > t.minKeys() {
			if err := t.borrowFromLeftSibling(ctx, storage, node, leftSibling, parent, nodeIndex); err != nil {
				return fmt.Errorf("failed to borrow from left sibling: %w", err)
			}
			return nil // Only return if borrowing succeeded
		}
	}

	// Try to borrow from right sibling
	if nodeIndex < len(parent.ChildrenIDs)-1 {
		rightSiblingID := parent.ChildrenIDs[nodeIndex+1]
		rightSibling, err := storage.LoadNode(ctx, rightSiblingID)
		if err != nil {
			return fmt.Errorf("failed to load right sibling: %w", err)
		}

		// Check if right sibling has enough keys to lend
		if len(rightSibling.Keys) > t.minKeys() {
			if err := t.borrowFromRightSibling(ctx, storage, node, rightSibling, parent, nodeIndex); err != nil {
				return fmt.Errorf("failed to borrow from right sibling: %w", err)
			}
			return nil // Only return if borrowing succeeded
		}
	}

	// Can't borrow, must merge
	// Prefer merging with left sibling if available
	if nodeIndex > 0 {
		leftSiblingID := parent.ChildrenIDs[nodeIndex-1]
		leftSibling, err := storage.LoadNode(ctx, leftSiblingID)
		if err != nil {
			return fmt.Errorf("failed to load left sibling for merge: %w", err)
		}
		if err := t.mergeWithLeftSibling(ctx, storage, node, leftSibling, parent, nodeIndex); err != nil {
			return fmt.Errorf("failed to merge with left sibling: %w", err)
		}
		return nil
	} else {
		// Merge with right sibling
		rightSiblingID := parent.ChildrenIDs[nodeIndex+1]
		rightSibling, err := storage.LoadNode(ctx, rightSiblingID)
		if err != nil {
			return fmt.Errorf("failed to load right sibling for merge: %w", err)
		}
		if err := t.mergeWithRightSibling(ctx, storage, node, rightSibling, parent, nodeIndex); err != nil {
			return fmt.Errorf("failed to merge with right sibling: %w", err)
		}
		return nil
	}
}

// borrowFromLeftSibling borrows a key from the left sibling
func (t *BPlusTree) borrowFromLeftSibling(ctx context.Context, storage Storage, node *Node, leftSibling *Node, parent *Node, nodeIndex int) error {
	if node.IsLeaf {
		// Borrow the rightmost key-value from left sibling
		borrowedKey := leftSibling.Keys[len(leftSibling.Keys)-1]
		borrowedValue := leftSibling.Values[len(leftSibling.Values)-1]

		// Remove from left sibling
		if err := leftSibling.RemoveKeyAt(len(leftSibling.Keys) - 1); err != nil {
			return fmt.Errorf("failed to remove key from left sibling: %w", err)
		}
		if err := leftSibling.RemoveValueAt(len(leftSibling.Values) - 1); err != nil {
			return fmt.Errorf("failed to remove value from left sibling: %w", err)
		}

		// Insert at the beginning of the node
		node.Keys = slices.Insert(node.Keys, 0, borrowedKey)
		node.Values = slices.Insert(node.Values, 0, borrowedValue)

		// Update the separator key in parent (key between left sibling and node)
		parent.Keys[nodeIndex-1] = node.Keys[0]
	} else {
		// Internal node: borrow key and child from left sibling
		separatorKey := parent.Keys[nodeIndex-1]
		borrowedKey := leftSibling.Keys[len(leftSibling.Keys)-1]
		borrowedChild := leftSibling.ChildrenIDs[len(leftSibling.ChildrenIDs)-1]

		// Remove from left sibling
		if err := leftSibling.RemoveKeyAt(len(leftSibling.Keys) - 1); err != nil {
			return fmt.Errorf("failed to remove key from left sibling: %w", err)
		}
		leftSibling.ChildrenIDs = leftSibling.ChildrenIDs[:len(leftSibling.ChildrenIDs)-1]

		// Insert separator key at the beginning of the node
		node.Keys = slices.Insert(node.Keys, 0, separatorKey)
		node.ChildrenIDs = slices.Insert(node.ChildrenIDs, 0, borrowedChild)

		// Update parent reference of the borrowed child
		child, err := storage.LoadNode(ctx, borrowedChild)
		if err != nil {
			return fmt.Errorf("failed to load borrowed child: %w", err)
		}
		child.ParentID = node.ID
		if err := storage.SaveNode(ctx, child); err != nil {
			return fmt.Errorf("failed to save borrowed child: %w", err)
		}

		// Update the separator key in parent
		parent.Keys[nodeIndex-1] = borrowedKey
	}

	// Save all modified nodes
	if err := storage.SaveNode(ctx, node); err != nil {
		return fmt.Errorf("failed to save node: %w", err)
	}
	if err := storage.SaveNode(ctx, leftSibling); err != nil {
		return fmt.Errorf("failed to save left sibling: %w", err)
	}
	if err := storage.SaveNode(ctx, parent); err != nil {
		return fmt.Errorf("failed to save parent: %w", err)
	}

	return nil
}

// borrowFromRightSibling borrows a key from the right sibling
func (t *BPlusTree) borrowFromRightSibling(ctx context.Context, storage Storage, node *Node, rightSibling *Node, parent *Node, nodeIndex int) error {
	if node.IsLeaf {
		// Borrow the leftmost key-value from right sibling
		borrowedKey := rightSibling.Keys[0]
		borrowedValue := rightSibling.Values[0]

		// Remove from right sibling
		if err := rightSibling.RemoveKeyAt(0); err != nil {
			return fmt.Errorf("failed to remove key from right sibling: %w", err)
		}
		if err := rightSibling.RemoveValueAt(0); err != nil {
			return fmt.Errorf("failed to remove value from right sibling: %w", err)
		}

		// Insert at the end of the node
		node.Keys = append(node.Keys, borrowedKey)
		node.Values = append(node.Values, borrowedValue)

		// Update the separator key in parent (key between node and right sibling)
		parent.Keys[nodeIndex] = rightSibling.Keys[0]
	} else {
		// Internal node: borrow key and child from right sibling
		separatorKey := parent.Keys[nodeIndex]
		borrowedKey := rightSibling.Keys[0]
		borrowedChild := rightSibling.ChildrenIDs[0]

		// Remove from right sibling
		if err := rightSibling.RemoveKeyAt(0); err != nil {
			return fmt.Errorf("failed to remove key from right sibling: %w", err)
		}
		rightSibling.ChildrenIDs = rightSibling.ChildrenIDs[1:]

		// Insert separator key at the end of the node
		node.Keys = append(node.Keys, separatorKey)
		node.ChildrenIDs = append(node.ChildrenIDs, borrowedChild)

		// Update parent reference of the borrowed child
		child, err := storage.LoadNode(ctx, borrowedChild)
		if err != nil {
			return fmt.Errorf("failed to load borrowed child: %w", err)
		}
		child.ParentID = node.ID
		if err := storage.SaveNode(ctx, child); err != nil {
			return fmt.Errorf("failed to save borrowed child: %w", err)
		}

		// Update the separator key in parent
		parent.Keys[nodeIndex] = borrowedKey
	}

	// Save all modified nodes
	if err := storage.SaveNode(ctx, node); err != nil {
		return fmt.Errorf("failed to save node: %w", err)
	}
	if err := storage.SaveNode(ctx, rightSibling); err != nil {
		return fmt.Errorf("failed to save right sibling: %w", err)
	}
	if err := storage.SaveNode(ctx, parent); err != nil {
		return fmt.Errorf("failed to save parent: %w", err)
	}

	return nil
}

// mergeWithLeftSibling merges the node with its left sibling
func (t *BPlusTree) mergeWithLeftSibling(ctx context.Context, storage Storage, node *Node, leftSibling *Node, parent *Node, nodeIndex int) error {
	if node.IsLeaf {
		// Merge leaf nodes: move all keys/values from node to left sibling
		leftSibling.Keys = append(leftSibling.Keys, node.Keys...)
		leftSibling.Values = append(leftSibling.Values, node.Values...)

		// Update the next pointer to maintain leaf chain
		leftSibling.NextID = node.NextID
	} else {
		// Merge internal nodes: include separator key from parent
		separatorKey := parent.Keys[nodeIndex-1]

		// Add separator key and merge keys/children
		leftSibling.Keys = append(leftSibling.Keys, separatorKey)
		leftSibling.Keys = append(leftSibling.Keys, node.Keys...)
		leftSibling.ChildrenIDs = append(leftSibling.ChildrenIDs, node.ChildrenIDs...)

		// Update parent references for all children from the merged node
		for _, childID := range node.ChildrenIDs {
			child, err := storage.LoadNode(ctx, childID)
			if err != nil {
				continue // Log error but continue
			}
			child.ParentID = leftSibling.ID
			if err := storage.SaveNode(ctx, child); err != nil {
				continue // Log error but continue
			}
		}
	}

	// Remove the separator key from parent
	separatorIndex := nodeIndex - 1
	parent.Keys = slices.Delete(parent.Keys, separatorIndex, separatorIndex+1)
	parent.ChildrenIDs = slices.Delete(parent.ChildrenIDs, nodeIndex, nodeIndex+1)

	// Save the merged node and parent
	if err := storage.SaveNode(ctx, leftSibling); err != nil {
		return fmt.Errorf("failed to save merged node: %w", err)
	}
	if err := storage.SaveNode(ctx, parent); err != nil {
		return fmt.Errorf("failed to save parent: %w", err)
	}

	// Delete the merged node
	if err := storage.DeleteNode(ctx, node.ID); err != nil {
		return fmt.Errorf("failed to delete merged node: %w", err)
	}

	// Recursively handle parent underflow
	return t.rebalanceTreeIfNeeded(ctx, storage, parent)
}

// mergeWithRightSibling merges the node with its right sibling
func (t *BPlusTree) mergeWithRightSibling(ctx context.Context, storage Storage, node *Node, rightSibling *Node, parent *Node, nodeIndex int) error {
	if node.IsLeaf {
		// Merge leaf nodes: move all keys/values from right sibling to node
		node.Keys = append(node.Keys, rightSibling.Keys...)
		node.Values = append(node.Values, rightSibling.Values...)

		// Update the next pointer to maintain leaf chain
		node.NextID = rightSibling.NextID
	} else {
		// Merge internal nodes: include separator key from parent
		separatorKey := parent.Keys[nodeIndex]

		// Add separator key and merge keys/children
		node.Keys = append(node.Keys, separatorKey)
		node.Keys = append(node.Keys, rightSibling.Keys...)
		node.ChildrenIDs = append(node.ChildrenIDs, rightSibling.ChildrenIDs...)

		// Update parent references for all children from the right sibling
		for _, childID := range rightSibling.ChildrenIDs {
			child, err := storage.LoadNode(ctx, childID)
			if err != nil {
				continue // Log error but continue
			}
			child.ParentID = node.ID
			if err := storage.SaveNode(ctx, child); err != nil {
				continue // Log error but continue
			}
		}
	}

	// Remove the separator key from parent
	separatorIndex := nodeIndex
	parent.Keys = slices.Delete(parent.Keys, separatorIndex, separatorIndex+1)
	parent.ChildrenIDs = slices.Delete(parent.ChildrenIDs, nodeIndex+1, nodeIndex+2)

	// Save the merged node and parent
	if err := storage.SaveNode(ctx, node); err != nil {
		return fmt.Errorf("failed to save merged node: %w", err)
	}
	if err := storage.SaveNode(ctx, parent); err != nil {
		return fmt.Errorf("failed to save parent: %w", err)
	}

	// Delete the merged node
	if err := storage.DeleteNode(ctx, rightSibling.ID); err != nil {
		return fmt.Errorf("failed to delete merged node: %w", err)
	}

	// Recursively handle parent underflow
	return t.rebalanceTreeIfNeeded(ctx, storage, parent)
}

// cleanupOrphanedSplitKey efficiently cleans up orphaned separator keys by starting from the deletion point
func (t *BPlusTree) cleanupOrphanedSplitKey(ctx context.Context, storage Storage, startNode *Node, deletedKey string) error {
	// Start from the leaf node where deletion occurred and walk up through ancestors
	// Orphaned separators can only exist in the ancestor path of the deleted key
	currentNode := startNode

	for currentNode != nil && currentNode.ParentID != "" {
		// Load the parent node
		parent, err := storage.LoadNode(ctx, currentNode.ParentID)
		if err != nil {
			return fmt.Errorf("failed to load parent node: %w", err)
		}

		// Check if this parent contains the orphaned separator
		removed, err := t.removeOrphanedSplitKeyInNode(ctx, storage, parent, deletedKey)
		if err != nil {
			return fmt.Errorf("failed to fix orphaned separator: %w", err)
		}

		if removed {
			// The orphaned separator was removed and the tree structure possibly restructured
			break
		}

		currentNode = parent // Move up to the parent node
	}

	return nil
}

// removeOrphanedSplitKeyInNode checks and fixes orphaned separator in a single node
func (t *BPlusTree) removeOrphanedSplitKeyInNode(ctx context.Context, storage Storage, node *Node, deletedKey string) (bool, error) {
	if node == nil || node.IsLeaf {
		return false, nil // No separators in leaf nodes
	}

	// Look for the orphaned separator key
	separatorIndex := -1
	for i, separatorKey := range node.Keys {
		if separatorKey == deletedKey {
			separatorIndex = i
			break
		}
	}

	if separatorIndex == -1 {
		return false, nil // No orphaned separator found in this node
	}

	// Found orphaned separator, try to replace it with successor
	successor, err := t.findSuccessorKey(ctx, storage, node, separatorIndex)
	if err != nil { // TODO: Not on all errors...
		// No right subtree available, remove the separator key entirely
		node.Keys = slices.Delete(node.Keys, separatorIndex, separatorIndex+1)
		// Also remove the corresponding child pointer
		if separatorIndex+1 < len(node.ChildrenIDs) {
			node.ChildrenIDs = slices.Delete(node.ChildrenIDs, separatorIndex+1, separatorIndex+2)
		}

		// Save the node after removing the separator
		if err := storage.SaveNode(ctx, node); err != nil {
			return false, fmt.Errorf("failed to save node after removing separator: %w", err)
		}

		// Get the root ID to check if this node is the root
		rootID, err := t.getRootID(ctx, storage)
		if err != nil {
			return false, fmt.Errorf("failed to get root ID: %w", err)
		}

		// Check if rebalancing is needed
		needsRebalancing := false
		if node.ID == rootID {
			// Root node: rebalance if it's internal and has no keys but has children
			needsRebalancing = !node.IsLeaf && len(node.Keys) == 0 && len(node.ChildrenIDs) > 0
		} else {
			// Non-root node: rebalance if it underflows
			needsRebalancing = t.nodeUnderflows(node)
		}

		if needsRebalancing {
			if err := t.rebalanceTreeIfNeeded(ctx, storage, node); err != nil {
				return false, fmt.Errorf("failed to rebalance after separator removal: %w", err)
			}
		}

		return true, nil
	}

	// Update the separator key with successor
	node.Keys[separatorIndex] = successor

	// Save the updated node
	if err := storage.SaveNode(ctx, node); err != nil {
		return false, fmt.Errorf("failed to save updated node: %w", err)
	}

	return true, nil
}

// findSuccessorKey finds the smallest key in the right subtree of a separator at the given index
func (t *BPlusTree) findSuccessorKey(ctx context.Context, storage Storage, parentNode *Node, separatorIndex int) (string, error) {
	// The right subtree starts at separatorIndex + 1
	if separatorIndex+1 >= len(parentNode.ChildrenIDs) {
		return "", fmt.Errorf("invalid separator index: no right subtree")
	}

	rightChildID := parentNode.ChildrenIDs[separatorIndex+1]

	// Find the leftmost leaf in the right subtree
	leftmostLeaf, err := t.findLeftmostLeafInSubtree(ctx, storage, rightChildID)
	if err != nil {
		return "", fmt.Errorf("failed to find leftmost leaf: %w", err)
	}

	// If the leftmost leaf has no keys, we need to handle this case
	if len(leftmostLeaf.Keys) == 0 {
		// This can happen during deletion when nodes become empty
		// In this case, we should remove the separator entirely rather than replace it
		return "", fmt.Errorf("no valid successor found: right subtree is empty")
	}

	return leftmostLeaf.Keys[0], nil
}

// findRightmostLeaf finds the rightmost leaf node in the tree
func (t *BPlusTree) findRightmostLeaf(ctx context.Context, storage Storage) (*Node, error) {
	// Load the root node
	rootID, err := t.getRootID(ctx, storage)
	if err != nil {
		return nil, err
	}

	return t.findRightmostLeafInSubtree(ctx, storage, rootID)
}

// findRightmostLeaf finds the rightmost leaf node in the tree
func (t *BPlusTree) findRightmostLeafInSubtree(ctx context.Context, storage Storage, nodeID string) (*Node, error) {
	node, err := storage.LoadNode(ctx, nodeID)
	if err != nil {
		return nil, fmt.Errorf("failed to load node: %w", err)
	}

	for !node.IsLeaf {
		// Always go to the rightmost child
		if len(node.ChildrenIDs) == 0 {
			return nil, errors.New("internal node has no children")
		}
		rightmostIndex := len(node.ChildrenIDs) - 1
		node, err = storage.LoadNode(ctx, node.ChildrenIDs[rightmostIndex])
		if err != nil {
			return nil, fmt.Errorf("failed to load child node: %w", err)
		}
	}

	return node, nil
}

// findLeftmostLeaf finds the leftmost leaf node in the tree
func (t *BPlusTree) findLeftmostLeaf(ctx context.Context, storage Storage) (*Node, error) {
	// Load the root node
	rootID, err := t.getRootID(ctx, storage)
	if err != nil {
		return nil, err
	}

	return t.findLeftmostLeafInSubtree(ctx, storage, rootID)
}

// findLeftmostLeafInSubtree finds the leftmost leaf node in a subtree rooted at the given node ID
func (t *BPlusTree) findLeftmostLeafInSubtree(ctx context.Context, storage Storage, nodeID string) (*Node, error) {
	node, err := storage.LoadNode(ctx, nodeID)
	if err != nil {
		return nil, fmt.Errorf("failed to load node: %w", err)
	}

	// Keep going left until we reach a leaf
	for !node.IsLeaf {
		if len(node.ChildrenIDs) == 0 {
			return nil, fmt.Errorf("internal node has no children")
		}
		// Go to the leftmost child
		node, err = storage.LoadNode(ctx, node.ChildrenIDs[0])
		if err != nil {
			return nil, fmt.Errorf("failed to load child node: %w", err)
		}
	}

	return node, nil
}
