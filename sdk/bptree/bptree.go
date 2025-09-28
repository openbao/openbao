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

// Tree represents a B+ tree data structure
type Tree struct {
	config *TreeConfig  // Configuration for the tree
	lock   sync.RWMutex // Mutex to protect concurrent access
}

// InitializeTree initializes a tree, creating it if it doesn't exist or loading it if it does.
// For new trees, the provided config is used. For existing trees, stored config is used and only the TreeID is used.
func InitializeTree(ctx context.Context, storage Storage, treeOpts ...TreeOption) (*Tree, error) {
	config, err := NewTreeConfig(treeOpts...)
	if err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return InitializeTreeWithConfig(ctx, storage, config)
}

// InitializeTreeWithConfig initializes a B+ tree with the given configuration.
func InitializeTreeWithConfig(ctx context.Context, storage Storage, config *TreeConfig) (*Tree, error) {
	if config == nil {
		config = NewDefaultTreeConfig()
	}

	// Try to load existing tree first
	existingTree, err := loadExistingTree(ctx, storage, config.TreeID)
	if err != nil {
		return nil, fmt.Errorf("failed while verifying whether a tree with the provided id (%s) exists", config.TreeID)
	}
	if existingTree != nil {
		return existingTree, nil
	}

	// If tree doesn't exist, create it
	return newTree(ctx, storage, config)
}

// loadExistingTree loads an existing B+ tree from storage using the stored
// configuration as the source of truth. If the tree doesn't exist, returns an error.
func loadExistingTree(ctx context.Context, storage Storage, treeID string) (*Tree, error) {
	// Add the TreeID to the context
	ctx = withTreeID(ctx, treeID)

	// Get stored configuration - this is the source of truth
	storedConfig, err := storage.GetConfig(ctx)
	if err != nil {
		if !errors.Is(err, ErrConfigNotFound) {
			return nil, fmt.Errorf("failed to load tree configuration: %w", err)
		}

		return nil, nil
	}

	// TODO: Init?
	// Create tree with stored configuration
	tree := &Tree{
		config: storedConfig,
	}

	// TODO (gabrielopesantos): Validate tree structure
	// We need to be careful here because a full validation might be too expensive...
	rootID, err := tree.getRootID(ctx, storage)
	if err != nil {
		return nil, fmt.Errorf("failed to get root ID: %w", err)
	}
	if rootID == "" {
		return nil, fmt.Errorf("tree metadata exists but no root node found - tree may be corrupted")
	}

	// Validate root node exists
	root, err := storage.GetNode(ctx, rootID)
	if err != nil {
		return nil, fmt.Errorf("failed to load root node: %w", err)
	}
	if root == nil || root.GetID() != rootID {
		return nil, fmt.Errorf("root node validation failed")
	}

	return tree, nil
}

// newTree creates a new B+ tree with the given configuration.
// Fails if a tree with the same ID already exists.
func newTree(
	ctx context.Context,
	storage Storage,
	config *TreeConfig,
) (*Tree, error) {
	// Add the treeID to the context
	ctx = config.contextWithTreeID(ctx)

	tree := &Tree{config: config}

	// Create new leaf root
	root := NewLeafNode(generateUUID())
	if err := storage.PutNode(ctx, root); err != nil {
		return nil, fmt.Errorf("failed to save root node: %w", err)
	}

	// Set root ID
	if err := tree.setRootID(ctx, storage, root.GetID()); err != nil {
		return nil, fmt.Errorf("failed to set root ID: %w", err)
	}

	// Store configuration
	if err := storage.PutConfig(ctx, config); err != nil {
		return nil, fmt.Errorf("failed to store tree configuration: %w", err)
	}

	return tree, nil
}

// getRoot loads the root node from storage
func (t *Tree) getRoot(ctx context.Context, storage Storage) (*Node, error) {
	rootID, err := t.getRootID(ctx, storage)
	if err != nil {
		return nil, fmt.Errorf("failed to get root ID: %w", err)
	}
	if rootID == "" {
		return nil, errors.New("root node not found")
	}

	return storage.GetNode(ctx, rootID)
}

// TODO: Can be removed...
// getRootID returns the root ID
func (t *Tree) getRootID(ctx context.Context, storage Storage) (string, error) {
	// Load from storage and cache
	rootID, err := storage.GetRootID(ctx)
	if err != nil {
		return "", err
	}

	return rootID, nil
}

// TODO: Can be removed...
// setRootID updates both storage and cache
func (t *Tree) setRootID(ctx context.Context, storage Storage, newRootID string) error {
	// Update storage first
	if err := storage.PutRootID(ctx, newRootID); err != nil {
		return err
	}

	return nil
}

// contextWithTreeID returns a context with the tree's ID added, enabling multi-tree storage
func (t *Tree) contextWithTreeID(ctx context.Context) context.Context {
	return t.config.contextWithTreeID(ctx)
}

// maxChildrenNodes returns the maximum number of children an internal node can have
func (t *Tree) maxChildrenNodes() int {
	return t.config.Order
}

// maxKeys returns the maxium number of keys an internal node can have
func (t *Tree) maxKeys() int {
	return t.maxChildrenNodes() - 1
}

// minChildrenNodes returns the minimum number of children an internal node can have
func (t *Tree) minChildrenNodes() int {
	return int(math.Ceil(float64(t.config.Order) / float64(2)))
}

// minKeys returns the minimum number of keys a node must have
func (t *Tree) minKeys() int {
	return t.minChildrenNodes() - 1
}

// nodeOverflows checks if a node has exceeded its maximum capacity
func (t *Tree) nodeOverflows(node *Node) bool {
	return node.KeyCount() > t.maxKeys()
}

// nodeUnderflows checks if a node has fallen below its minimum capacity
func (t *Tree) nodeUnderflows(node *Node) bool {
	return node.KeyCount() < t.minKeys()
}

// Search retrieves all values for a key
// If the key is not found, it returns an empty slice and false
func (t *Tree) Search(ctx context.Context, storage Storage, key string) ([]string, bool, error) {
	t.lock.RLock()
	defer t.lock.RUnlock()

	ctx = t.contextWithTreeID(ctx)

	return t.search(ctx, storage, key)
}

func (t *Tree) search(ctx context.Context, storage Storage, key string) ([]string, bool, error) {
	leaf, err := t.findLeafNode(ctx, storage, key)
	if err != nil {
		return nil, false, fmt.Errorf("failed to find leaf node: %w", err)
	}

	// Get key values from the leaf node
	values, keyFound := leaf.GetKeyValues(key)

	return values, keyFound, nil
}

// SearchPrefix returns all key-value pairs that start with the given prefix
// This function leverages the NextID linking to efficiently traverse leaf nodes sequentially
// No wildcards searches are supported - only exact prefix matches
// TODO (gabrielopesantos): Having some sort of limit on the number of results.
// TODO (gabrielopesantos): If the keys aren't strings, this function will not work as expected.
func (t *Tree) SearchPrefix(ctx context.Context, storage Storage, prefix string) (map[string][]string, error) {
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
	if rightmostLeaf.IsEmpty() {
		return results, nil
	}

	// If prefix is lexicographically greater than the largest key, no matches possible
	largestKey, hasLargest := rightmostLeaf.GetLastKey()
	if hasLargest && prefix > largestKey {
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

	if smallestKey, hasSmallest := leftmostLeaf.GetFirstKey(); hasSmallest {
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
		shouldContinue := true
		err := current.IterateKeyValues(func(key string, values []string) bool {
			if strings.HasPrefix(key, prefix) {
				// This key matches our prefix
				results[key] = values
				return true
			} else if key >= prefixLimit {
				// We've reached keys that are definitely beyond our prefix range
				// Since keys are sorted, we can stop here
				shouldContinue = false
				return false
			}
			return true
		})
		if err != nil {
			return nil, fmt.Errorf("failed to iterate keys: %w", err)
		}

		if !shouldContinue {
			break
		}

		// Move to the next leaf using NextID
		if current.NextID == "" {
			break
		}
		current, err = storage.GetNode(ctx, current.NextID)
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
func (t *Tree) Insert(ctx context.Context, storage Storage, key string, value string) error {
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
		if err := storage.PutNode(ctx, leaf); err != nil {
			return fmt.Errorf("failed to save original leaf node: %w", err)
		}
		if err := storage.PutNode(ctx, newLeaf); err != nil {
			return fmt.Errorf("failed to save new leaf node: %w", err)
		}

		return t.insertIntoParent(ctx, storage, leaf, newLeaf, splitKey)
	} else {
		// Save the leaf node after insertion
		if err := storage.PutNode(ctx, leaf); err != nil {
			return fmt.Errorf("failed to save leaf node: %w", err)
		}
	}

	return nil
}

// Delete removes all values for a key, if the key exists.
func (t *Tree) Delete(ctx context.Context, storage Storage, key string) (bool, error) {
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
	if err := leaf.RemoveKeyAtIndex(idx); err != nil {
		return false, fmt.Errorf("failed to remove key: %w", err)
	}
	if err := leaf.RemoveValueAtIndex(idx); err != nil {
		return false, fmt.Errorf("failed to remove value: %w", err)
	}

	// Save the modified leaf node
	if err := storage.PutNode(ctx, leaf); err != nil {
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
func (t *Tree) DeleteValue(ctx context.Context, storage Storage, key string, value string) (bool, error) {
	t.lock.Lock()
	defer t.lock.Unlock()

	ctx = t.contextWithTreeID(ctx)

	// Find the leaf node where the key belongs
	leaf, err := t.findLeafNode(ctx, storage, key)
	if err != nil {
		return false, err
	}

	// Check if the key exists in the leaf node
	_, hasKey := leaf.FindKeyIndex(key)
	if !hasKey {
		return false, nil
	}

	// Remove the specific value from the key
	result, _ := leaf.RemoveValueFromKey(key, value)
	if result == KeyNotFound {
		return false, nil
	}

	// Save the modified leaf node
	if err := storage.PutNode(ctx, leaf); err != nil {
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
func (t *Tree) findLeafNode(ctx context.Context, storage Storage, key string) (*Node, error) {
	// Load the root node
	node, err := t.getRoot(ctx, storage)
	if err != nil {
		return nil, err
	}

	for !node.IsLeaf {
		childID, err := node.GetChildForKeyTraversal(key)
		if err != nil {
			return nil, fmt.Errorf("failed to get child for key traversal: %w", err)
		}

		node, err = storage.GetNode(ctx, childID)
		if err != nil {
			return nil, err
		}
	}

	return node, nil
}

func (t *Tree) splitLeafNode(leaf *Node) (*Node, string) {
	// Split at the median index
	splitIndex := int(math.Floor(float64(leaf.KeyCount()) / float64(2)))

	// Split the leaf node
	newLeaf, err := leaf.SplitLeafAtIndex(splitIndex)
	if err != nil {
		// This should never happen in normal operation
		panic(fmt.Sprintf("failed to split leaf node: %v", err))
	}

	// Return new leaf and split key to be copied into the parent
	firstKey, hasKey := newLeaf.GetFirstKey()
	if !hasKey {
		// This should never happen - we just split and the new leaf should have keys
		panic("split leaf node has no keys")
	}

	return newLeaf, firstKey
}

// insertIntoParent inserts a key and right node into the parent of left node
func (t *Tree) insertIntoParent(ctx context.Context, storage Storage, leftNode *Node, rightNode *Node, splitKey string) error {
	// If leftNode was the root, we need to create a new root
	// and make the leftNode and rightNode its children
	rootID, err := t.getRootID(ctx, storage)
	if err != nil {
		return fmt.Errorf("failed to get root ID: %w", err)
	}
	if leftNode.GetID() == rootID {
		newRoot := NewInternalNode(generateUUID())
		newRoot.Keys = []string{splitKey}
		newRoot.SetChildrenIDs([]string{leftNode.GetID(), rightNode.GetID()})

		// Update parent references
		leftNode.SetParentID(newRoot.GetID())
		rightNode.SetParentID(newRoot.GetID())

		// Save all nodes with updated parent references
		if err := storage.PutNode(ctx, leftNode); err != nil {
			return fmt.Errorf("failed to save left node: %w", err)
		}
		if err := storage.PutNode(ctx, rightNode); err != nil {
			return fmt.Errorf("failed to save right node: %w", err)
		}
		if err := storage.PutNode(ctx, newRoot); err != nil {
			return fmt.Errorf("failed to save new root node: %w", err)
		}

		// Update root ID in storage
		return t.setRootID(ctx, storage, newRoot.GetID())
	}

	// Otherwise, we need to insert into the existing parent node
	// Load parent node
	parent, err := storage.GetNode(ctx, leftNode.GetParentID())
	if err != nil {
		return err
	}

	// Insert the split key and right node into the parent
	err = parent.InsertKeyChild(splitKey, rightNode.GetID())
	if err != nil {
		return fmt.Errorf("failed to insert key-child into parent: %w", err)
	}

	rightNode.SetParentID(parent.GetID())

	// Save the updated nodes
	if err := storage.PutNode(ctx, leftNode); err != nil {
		return fmt.Errorf("failed to save left node: %w", err)
	}
	if err := storage.PutNode(ctx, rightNode); err != nil {
		return fmt.Errorf("failed to save right node: %w", err)
	}
	if err := storage.PutNode(ctx, parent); err != nil {
		return fmt.Errorf("failed to save parent: %w", err)
	}

	// If the internal node is overflows, we need to split it
	if t.nodeOverflows(parent) {
		newInternal, splitKey := t.splitInternalNode(ctx, storage, parent)
		// Save both internal nodes after splitting
		if err := storage.PutNode(ctx, parent); err != nil {
			return fmt.Errorf("failed to save original internal node: %w", err)
		}
		if err := storage.PutNode(ctx, newInternal); err != nil {
			return fmt.Errorf("failed to save new internal node: %w", err)
		}
		return t.insertIntoParent(ctx, storage, parent, newInternal, splitKey)
	}

	return nil
}

func (t *Tree) splitInternalNode(ctx context.Context, storage Storage, node *Node) (*Node, string) {
	// Split at the median index
	splitIndex := int(math.Floor(float64(node.KeyCount()) / float64(2)))

	// Split the internal node
	newInternal, promotedKey, err := node.SplitInternalAtIndex(splitIndex)
	if err != nil {
		// This should never happen in normal operation
		panic(fmt.Sprintf("failed to split internal node: %v", err))
	}

	// Update parent references of newInternal's children
	for _, childID := range newInternal.ChildrenIDs {
		child, err := storage.GetNode(ctx, childID)
		if err != nil {
			// TODO: Review...
			// Log error but continue since we can't fail here
			continue
		}
		child.SetParentID(newInternal.GetID())
		if err := storage.PutNode(ctx, child); err != nil {
			// Log error but continue since we can't fail here
			continue
		}
	}

	return newInternal, promotedKey
}

// rebalanceTreeIfNeeded handles rebalancing after a deletion
func (t *Tree) rebalanceTreeIfNeeded(ctx context.Context, storage Storage, node *Node) error {
	// Get the root ID to check if this node is the root
	rootID, err := t.getRootID(ctx, storage)
	if err != nil {
		return fmt.Errorf("failed to get root ID: %w", err)
	}

	// If this is the root node, handle special root cases
	if node.GetID() == rootID {
		return t.handleRootAfterDeletion(ctx, storage, node)
	} else if t.nodeUnderflows(node) {
		// Node underflows, need to rebalance
		return t.rebalanceAfterDeletion(ctx, storage, node)
	}

	// If this is not the root node and not underflowing, no action needed
	return nil
}

// handleRootAfterDeletion handles the root node after deletion
func (t *Tree) handleRootAfterDeletion(ctx context.Context, storage Storage, root *Node) error {
	// If root is a leaf and becomes empty, tree becomes empty (allowed)
	if root.IsLeaf {
		return nil
	}

	// If root is internal and has no keys but has exactly one child,
	// promote the child to be the new root
	if root.IsEmpty() && len(root.ChildrenIDs) == 1 {
		newRootID, err := root.GetChildAtIndex(0)
		if err != nil {
			return fmt.Errorf("failed to get child for new root: %w", err)
		}

		// Load the new root and clear its parent reference
		newRoot, err := storage.GetNode(ctx, newRootID)
		if err != nil {
			return fmt.Errorf("failed to load new root: %w", err)
		}
		newRoot.SetParentID("")

		// Save the new root and update the tree's root ID
		if err := storage.PutNode(ctx, newRoot); err != nil {
			return fmt.Errorf("failed to save new root: %w", err)
		}
		if err := t.setRootID(ctx, storage, newRootID); err != nil {
			return fmt.Errorf("failed to set new root ID: %w", err)
		}

		// Delete the old root
		if err := storage.DeleteNode(ctx, root.GetID()); err != nil {
			return fmt.Errorf("failed to delete old root: %w", err)
		}
	}

	return nil
}

// rebalanceAfterDeletion rebalances a node that underflows after deletion
func (t *Tree) rebalanceAfterDeletion(ctx context.Context, storage Storage, node *Node) error {
	// Load the parent
	parent, err := storage.GetNode(ctx, node.GetParentID())
	if err != nil {
		return fmt.Errorf("failed to load parent: %w", err)
	}

	// Find the node's position in the parent
	nodeIndex := parent.GetChildIndex(node.GetID())
	if nodeIndex == -1 {
		return errors.New("node not found in parent's children")
	}

	// Try to borrow from left sibling
	if leftSiblingID, hasLeft := parent.GetLeftSiblingID(node.GetID()); hasLeft {
		leftSibling, err := storage.GetNode(ctx, leftSiblingID)
		if err != nil {
			return fmt.Errorf("failed to load left sibling: %w", err)
		}

		// Check if left sibling has enough keys to lend
		if leftSibling.KeyCount() > t.minKeys() {
			if err := t.borrowFromLeftSibling(ctx, storage, node, leftSibling, parent, nodeIndex); err != nil {
				return fmt.Errorf("failed to borrow from left sibling: %w", err)
			}
			return nil // Only return if borrowing succeeded
		}
	}

	// Try to borrow from right sibling
	if rightSiblingID, hasRight := parent.GetRightSiblingID(node.GetID()); hasRight {
		rightSibling, err := storage.GetNode(ctx, rightSiblingID)
		if err != nil {
			return fmt.Errorf("failed to load right sibling: %w", err)
		}

		// Check if right sibling has enough keys to lend
		if rightSibling.KeyCount() > t.minKeys() {
			if err := t.borrowFromRightSibling(ctx, storage, node, rightSibling, parent, nodeIndex); err != nil {
				return fmt.Errorf("failed to borrow from right sibling: %w", err)
			}
			return nil // Only return if borrowing succeeded
		}
	}

	// Can't borrow, must merge
	// Prefer merging with left sibling if available
	if leftSiblingID, hasLeft := parent.GetLeftSiblingID(node.GetID()); hasLeft {
		leftSibling, err := storage.GetNode(ctx, leftSiblingID)
		if err != nil {
			return fmt.Errorf("failed to load left sibling for merge: %w", err)
		}
		if err := t.mergeWithLeftSibling(ctx, storage, node, leftSibling, parent, nodeIndex); err != nil {
			return fmt.Errorf("failed to merge with left sibling: %w", err)
		}
		return nil
	} else {
		// Merge with right sibling
		rightSiblingID, hasRight := parent.GetRightSiblingID(node.GetID())
		if !hasRight {
			return errors.New("node has no siblings to merge with")
		}
		rightSibling, err := storage.GetNode(ctx, rightSiblingID)
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
func (t *Tree) borrowFromLeftSibling(ctx context.Context, storage Storage, node *Node, leftSibling *Node, parent *Node, nodeIndex int) error {
	if node.IsLeaf {
		// Borrow the rightmost key-value from left sibling
		_, _, err := node.BorrowLastKeyValueFromLeft(leftSibling)
		if err != nil {
			return fmt.Errorf("failed to borrow from left sibling: %w", err)
		}

		// Update the separator key in parent (key between left sibling and node)
		firstKey, exists := node.GetFirstKey()
		if !exists {
			return fmt.Errorf("node has no keys after borrowing")
		}
		if err := parent.SetKeyAtIndex(nodeIndex-1, firstKey); err != nil {
			return fmt.Errorf("failed to update separator key in parent: %w", err)
		}
	} else {
		// Internal node: borrow key and child from left sibling
		separatorKey, err := parent.GetKeyAtIndex(nodeIndex - 1)
		if err != nil {
			return fmt.Errorf("failed to get separator key from parent: %w", err)
		}

		borrowedKey, borrowedChild, err := node.BorrowLastKeyChildFromLeft(leftSibling, separatorKey)
		if err != nil {
			return fmt.Errorf("failed to borrow key and child from left sibling: %w", err)
		}

		// Update parent reference of the borrowed child
		child, err := storage.GetNode(ctx, borrowedChild)
		if err != nil {
			return fmt.Errorf("failed to load borrowed child: %w", err)
		}
		child.SetParentID(node.GetID())
		if err := storage.PutNode(ctx, child); err != nil {
			return fmt.Errorf("failed to save borrowed child: %w", err)
		}

		// Update the separator key in parent
		if err := parent.SetKeyAtIndex(nodeIndex-1, borrowedKey); err != nil {
			return fmt.Errorf("failed to update separator key in parent: %w", err)
		}
	}

	// Save all modified nodes
	if err := storage.PutNode(ctx, node); err != nil {
		return fmt.Errorf("failed to save node: %w", err)
	}
	if err := storage.PutNode(ctx, leftSibling); err != nil {
		return fmt.Errorf("failed to save left sibling: %w", err)
	}
	if err := storage.PutNode(ctx, parent); err != nil {
		return fmt.Errorf("failed to save parent: %w", err)
	}

	return nil
}

// borrowFromRightSibling borrows a key from the right sibling
func (t *Tree) borrowFromRightSibling(ctx context.Context, storage Storage, node *Node, rightSibling *Node, parent *Node, nodeIndex int) error {
	if node.IsLeaf {
		// Borrow the leftmost key-value from right sibling
		_, _, err := node.BorrowFirstKeyValueFromRight(rightSibling)
		if err != nil {
			return fmt.Errorf("failed to borrow from right sibling: %w", err)
		}

		// Update the separator key in parent (key between node and right sibling)
		firstKey, exists := rightSibling.GetFirstKey()
		if !exists {
			return fmt.Errorf("right sibling has no keys after borrowing")
		}
		if err := parent.SetKeyAtIndex(nodeIndex, firstKey); err != nil {
			return fmt.Errorf("failed to update separator key in parent: %w", err)
		}
	} else {
		// Internal node: borrow key and child from right sibling
		separatorKey, err := parent.GetKeyAtIndex(nodeIndex)
		if err != nil {
			return fmt.Errorf("failed to get separator key from parent: %w", err)
		}

		borrowedKey, borrowedChild, err := node.BorrowFirstKeyChildFromRight(rightSibling, separatorKey)
		if err != nil {
			return fmt.Errorf("failed to borrow key and child from right sibling: %w", err)
		}

		// Update parent reference of the borrowed child
		child, err := storage.GetNode(ctx, borrowedChild)
		if err != nil {
			return fmt.Errorf("failed to load borrowed child: %w", err)
		}
		child.SetParentID(node.GetID())
		if err := storage.PutNode(ctx, child); err != nil {
			return fmt.Errorf("failed to save borrowed child: %w", err)
		}

		// Update the separator key in parent
		if err := parent.SetKeyAtIndex(nodeIndex, borrowedKey); err != nil {
			return fmt.Errorf("failed to update separator key in parent: %w", err)
		}
	}

	// Save all modified nodes
	if err := storage.PutNode(ctx, node); err != nil {
		return fmt.Errorf("failed to save node: %w", err)
	}
	if err := storage.PutNode(ctx, rightSibling); err != nil {
		return fmt.Errorf("failed to save right sibling: %w", err)
	}
	if err := storage.PutNode(ctx, parent); err != nil {
		return fmt.Errorf("failed to save parent: %w", err)
	}

	return nil
}

// mergeWithLeftSibling merges the node with its left sibling
func (t *Tree) mergeWithLeftSibling(ctx context.Context, storage Storage, node *Node, leftSibling *Node, parent *Node, nodeIndex int) error {
	var separatorKey string

	if !node.IsLeaf {
		// Get separator key from parent for internal nodes
		var err error
		separatorKey, err = parent.GetKeyAtIndex(nodeIndex - 1)
		if err != nil {
			return fmt.Errorf("failed to get separator key from parent: %w", err)
		}
	}

	// Merge node into left sibling
	if err := node.MergeWithLeftSibling(leftSibling, separatorKey); err != nil {
		return fmt.Errorf("failed to merge with left sibling: %w", err)
	}

	// Update parent references for all children from the merged node (internal nodes only)
	if !node.IsLeaf {
		for _, childID := range node.ChildrenIDs {
			child, err := storage.GetNode(ctx, childID)
			if err != nil {
				continue // Log error but continue
			}
			child.SetParentID(leftSibling.GetID())
			if err := storage.PutNode(ctx, child); err != nil {
				continue // Log error but continue
			}
		}
	}

	// Remove the separator key from parent
	separatorIndex := nodeIndex - 1
	parent.Keys = slices.Delete(parent.Keys, separatorIndex, separatorIndex+1)
	parent.ChildrenIDs = slices.Delete(parent.ChildrenIDs, nodeIndex, nodeIndex+1)

	// Save the merged node and parent
	if err := storage.PutNode(ctx, leftSibling); err != nil {
		return fmt.Errorf("failed to save merged node: %w", err)
	}
	if err := storage.PutNode(ctx, parent); err != nil {
		return fmt.Errorf("failed to save parent: %w", err)
	}

	// Delete the merged node
	if err := storage.DeleteNode(ctx, node.GetID()); err != nil {
		return fmt.Errorf("failed to delete merged node: %w", err)
	}

	// Recursively handle parent underflow
	return t.rebalanceTreeIfNeeded(ctx, storage, parent)
}

// mergeWithRightSibling merges the node with its right sibling
func (t *Tree) mergeWithRightSibling(ctx context.Context, storage Storage, node *Node, rightSibling *Node, parent *Node, nodeIndex int) error {
	var separatorKey string

	if !node.IsLeaf {
		// Get separator key from parent for internal nodes
		var err error
		separatorKey, err = parent.GetKeyAtIndex(nodeIndex)
		if err != nil {
			return fmt.Errorf("failed to get separator key from parent: %w", err)
		}
	}

	// Merge right sibling into current node
	if err := node.MergeWithRightSibling(rightSibling, separatorKey); err != nil {
		return fmt.Errorf("failed to merge with right sibling: %w", err)
	}

	// Update parent references for all children from the right sibling (internal nodes only)
	if !node.IsLeaf {
		for _, childID := range rightSibling.ChildrenIDs {
			child, err := storage.GetNode(ctx, childID)
			if err != nil {
				continue // Log error but continue
			}
			child.SetParentID(node.GetID())
			if err := storage.PutNode(ctx, child); err != nil {
				continue // Log error but continue
			}
		}
	}

	// Remove the separator key from parent
	separatorIndex := nodeIndex
	err := parent.RemoveKeyChildAtIndex(separatorIndex)
	if err != nil {
		return err
	}

	// Save the merged node and parent
	if err := storage.PutNode(ctx, node); err != nil {
		return fmt.Errorf("failed to save merged node: %w", err)
	}
	if err := storage.PutNode(ctx, parent); err != nil {
		return fmt.Errorf("failed to save parent: %w", err)
	}

	// Delete the merged node
	if err := storage.DeleteNode(ctx, rightSibling.GetID()); err != nil {
		return fmt.Errorf("failed to delete merged node: %w", err)
	}

	// Recursively handle parent underflow
	return t.rebalanceTreeIfNeeded(ctx, storage, parent)
}

// cleanupOrphanedSplitKey efficiently cleans up orphaned separator keys by starting from the deletion point
func (t *Tree) cleanupOrphanedSplitKey(ctx context.Context, storage Storage, startNode *Node, deletedKey string) error {
	// Start from the leaf node where deletion occurred and walk up through ancestors
	// Orphaned separators can only exist in the ancestor path of the deleted key
	currentNode := startNode

	for currentNode != nil && currentNode.GetParentID() != "" {
		// Load the parent node
		parent, err := storage.GetNode(ctx, currentNode.GetParentID())
		if err != nil && err != ErrNodeNotFound { // TODO (gabrielopesantos): Review this
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
func (t *Tree) removeOrphanedSplitKeyInNode(ctx context.Context, storage Storage, node *Node, deletedKey string) (bool, error) {
	if node == nil || node.IsLeaf {
		return false, nil // No separators in leaf nodes
	}

	// Look for the orphaned separator key
	separatorIndex, exists := node.FindKeyIndex(deletedKey)
	if !exists {
		return false, nil // No orphaned separator found in this node
	}

	// Found orphaned separator, try to replace it with successor
	successor, err := t.findSuccessorKey(ctx, storage, node, separatorIndex)
	if err != nil { // TODO: Not on all errors...
		// No right subtree available, remove the separator key entirely
		err := node.RemoveKeyChildAtIndex(separatorIndex)
		if err != nil {
			return false, err
		}

		// Save the node after removing the separator
		if err := storage.PutNode(ctx, node); err != nil {
			return false, fmt.Errorf("failed to save node after removing separator: %w", err)
		}

		// Get the root ID to check if this node is the root
		rootID, err := t.getRootID(ctx, storage)
		if err != nil {
			return false, fmt.Errorf("failed to get root ID: %w", err)
		}

		// Check if rebalancing is needed
		needsRebalancing := false
		if node.GetID() == rootID {
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
	if err := storage.PutNode(ctx, node); err != nil {
		return false, fmt.Errorf("failed to save updated node: %w", err)
	}

	return true, nil
}

// findSuccessorKey finds the smallest key in the right subtree of a separator at the given index
func (t *Tree) findSuccessorKey(ctx context.Context, storage Storage, parentNode *Node, separatorIndex int) (string, error) {
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
func (t *Tree) findRightmostLeaf(ctx context.Context, storage Storage) (*Node, error) {
	// Load the root node
	rootID, err := t.getRootID(ctx, storage)
	if err != nil {
		return nil, err
	}

	return t.findRightmostLeafInSubtree(ctx, storage, rootID)
}

// findRightmostLeaf finds the rightmost leaf node in the tree
func (t *Tree) findRightmostLeafInSubtree(ctx context.Context, storage Storage, nodeID string) (*Node, error) {
	node, err := storage.GetNode(ctx, nodeID)
	if err != nil {
		return nil, fmt.Errorf("failed to load node: %w", err)
	}

	for !node.IsLeaf {
		// Always go to the rightmost child
		if len(node.ChildrenIDs) == 0 {
			return nil, errors.New("internal node has no children")
		}
		rightmostIndex := len(node.ChildrenIDs) - 1
		node, err = storage.GetNode(ctx, node.ChildrenIDs[rightmostIndex])
		if err != nil {
			return nil, fmt.Errorf("failed to load child node: %w", err)
		}
	}

	return node, nil
}

// findLeftmostLeaf finds the leftmost leaf node in the tree
func (t *Tree) findLeftmostLeaf(ctx context.Context, storage Storage) (*Node, error) {
	// Load the root node
	rootID, err := t.getRootID(ctx, storage)
	if err != nil {
		return nil, err
	}

	return t.findLeftmostLeafInSubtree(ctx, storage, rootID)
}

// findLeftmostLeafInSubtree finds the leftmost leaf node in a subtree rooted at the given node ID
func (t *Tree) findLeftmostLeafInSubtree(ctx context.Context, storage Storage, nodeID string) (*Node, error) {
	node, err := storage.GetNode(ctx, nodeID)
	if err != nil {
		return nil, fmt.Errorf("failed to load node: %w", err)
	}

	// Keep going left until we reach a leaf
	for !node.IsLeaf {
		if len(node.ChildrenIDs) == 0 {
			return nil, fmt.Errorf("internal node has no children")
		}
		// Go to the leftmost child
		node, err = storage.GetNode(ctx, node.ChildrenIDs[0])
		if err != nil {
			return nil, fmt.Errorf("failed to load child node: %w", err)
		}
	}

	return node, nil
}
