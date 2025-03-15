// Copyright (c) 2024 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package bptree

import (
	"context"
	"errors"
	"fmt"
)

// ValidationResult contains the results of tree structure validation
type ValidationResult struct {
	IsValid  bool      `json:"is_valid"`
	Errors   []string  `json:"errors"`
	Warnings []string  `json:"warnings"`
	Stats    TreeStats `json:"stats"`
}

// TreeStats provides statistics about the tree structure
type TreeStats struct {
	TotalNodes             int      `json:"total_nodes"`
	InternalNodes          int      `json:"internal_nodes"`
	LeafNodes              int      `json:"leaf_nodes"`
	TreeHeight             int      `json:"tree_height"`
	TotalKeys              int      `json:"total_keys"`
	OrphanedKeys           []string `json:"orphaned_keys"`           // Keys in internal nodes not found in leaves
	InconsistentSeparators []string `json:"inconsistent_separators"` // Separator keys that don't correctly separate subtrees
}

// DebugValidateTreeStructure performs comprehensive validation of the B+ tree structure
// This method checks all B+ tree invariants and detects issues like orphaned separator keys
// It is intended for debugging and testing purposes, not for production use as it loads all nodes into memory.
func (t *BPlusTree) DebugValidateTreeStructure(ctx context.Context, storage Storage) (*ValidationResult, error) {
	t.lock.RLock()
	defer t.lock.RUnlock()

	ctx = t.contextWithTreeID(ctx)
	result := &ValidationResult{
		IsValid:  true,
		Errors:   []string{},
		Warnings: []string{},
		Stats:    TreeStats{OrphanedKeys: []string{}, InconsistentSeparators: []string{}},
	}

	// Get root node
	root, err := t.getRoot(ctx, storage)
	if err != nil {
		return nil, fmt.Errorf("failed to get root node: %w", err)
	}

	// Collect all nodes and build structure maps
	allNodes := make(map[string]*Node)
	leafKeys := make(map[string]bool)         // All keys that exist in leaf nodes
	internalKeys := make(map[string][]string) // Maps internal keys to node IDs that contain them

	// Traverse and collect all nodes
	if err := t.collectAllNodes(ctx, storage, root, allNodes, leafKeys, internalKeys, &result.Stats); err != nil {
		return nil, fmt.Errorf("failed to collect nodes: %w", err)
	}

	// Calculate tree height
	height, err := t.getTreeHeight(ctx, storage, root)
	if err != nil {
		return nil, err
	}
	result.Stats.TreeHeight = height

	// Validate tree structure
	t.validateStructuralIntegrity(allNodes, root.ID, result)
	t.validateBTreeInvariants(allNodes, result)
	t.validateSeparatorKeys(allNodes, leafKeys, internalKeys, result)
	t.validateLeafChain(ctx, storage, allNodes, result)
	t.validateSearchPaths(ctx, storage, leafKeys, result)

	// Set overall validity
	result.IsValid = len(result.Errors) == 0

	return result, nil
}

// collectAllNodes recursively collects all nodes and builds key maps
func (t *BPlusTree) collectAllNodes(ctx context.Context, storage Storage, node *Node, allNodes map[string]*Node, leafKeys map[string]bool, internalKeys map[string][]string, stats *TreeStats) error {
	if node == nil {
		return errors.New("encountered nil node")
	}

	// Add to all nodes map
	allNodes[node.ID] = node
	stats.TotalNodes++

	if node.IsLeaf {
		stats.LeafNodes++
		// Collect all keys from this leaf
		for _, key := range node.Keys {
			leafKeys[key] = true
			stats.TotalKeys++
		}
	} else {
		stats.InternalNodes++
		// Collect all keys from this internal node
		for _, key := range node.Keys {
			if internalKeys[key] == nil {
				internalKeys[key] = []string{}
			}
			internalKeys[key] = append(internalKeys[key], node.ID)
		}

		// Recursively process children
		for _, childID := range node.ChildrenIDs {
			child, err := storage.LoadNode(ctx, childID)
			if err != nil {
				return fmt.Errorf("failed to load child node %s: %w", childID, err)
			}
			if err := t.collectAllNodes(ctx, storage, child, allNodes, leafKeys, internalKeys, stats); err != nil {
				return err
			}
		}
	}

	return nil
}

// getTreeHeight calculates the height of the tree
func (t *BPlusTree) getTreeHeight(ctx context.Context, storage Storage, node *Node) (int, error) {
	if node == nil {
		return 0, errors.New("nil node provided for height calculation")
	}

	height := 1
	for !node.IsLeaf {
		child, err := storage.LoadNode(ctx, node.ChildrenIDs[0])
		if err != nil {
			return 0, fmt.Errorf("failed to load child node %s: %w", node.ChildrenIDs[0], err)
		}

		height += 1
		node = child
	}

	return height, nil
}

// validateStructuralIntegrity checks parent-child relationships and basic structure
func (t *BPlusTree) validateStructuralIntegrity(allNodes map[string]*Node, rootID string, result *ValidationResult) {
	for nodeID, node := range allNodes {
		// Check root node
		if nodeID == rootID {
			if node.ParentID != "" {
				result.Errors = append(result.Errors, fmt.Sprintf("Root node %s has non-empty parent ID: %s", nodeID, node.ParentID))
			}
		} else {
			// Non-root nodes must have a parent
			if node.ParentID == "" {
				result.Errors = append(result.Errors, fmt.Sprintf("Non-root node %s has empty parent ID", nodeID))
				continue
			}

			// Check parent exists
			parent, exists := allNodes[node.ParentID]
			if !exists {
				result.Errors = append(result.Errors, fmt.Sprintf("Node %s references non-existent parent %s", nodeID, node.ParentID))
				continue
			}

			// Check parent-child relationship is bidirectional
			found := false
			for _, childID := range parent.ChildrenIDs {
				if childID == nodeID {
					found = true
					break
				}
			}
			if !found {
				result.Errors = append(result.Errors, fmt.Sprintf("Node %s claims parent %s, but parent doesn't list it as child", nodeID, node.ParentID))
			}
		}

		// Check node type consistency
		if node.IsLeaf {
			if len(node.ChildrenIDs) > 0 {
				result.Errors = append(result.Errors, fmt.Sprintf("Leaf node %s has children", nodeID))
			}
		} else {
			if len(node.ChildrenIDs) == 0 {
				result.Errors = append(result.Errors, fmt.Sprintf("Internal node %s has no children", nodeID))
			}
		}
	}
}

// validateBTreeInvariants checks B+ tree specific rules
func (t *BPlusTree) validateBTreeInvariants(allNodes map[string]*Node, result *ValidationResult) {
	for nodeID, node := range allNodes {
		// Check key count limits (root can have fewer)
		isRoot := node.ParentID == ""
		if !isRoot {
			if len(node.Keys) < t.minKeys() {
				result.Errors = append(result.Errors, fmt.Sprintf("Node %s has too few keys: %d (min: %d)", nodeID, len(node.Keys), t.minKeys()))
			}
		}
		if len(node.Keys) > t.maxKeys() {
			result.Errors = append(result.Errors, fmt.Sprintf("Node %s has too many keys: %d (max: %d)", nodeID, len(node.Keys), t.maxKeys()))
		}

		// Check key ordering within node
		for i := 1; i < len(node.Keys); i++ {
			if node.Keys[i] <= node.Keys[i-1] {
				result.Errors = append(result.Errors, fmt.Sprintf("Node %s has keys out of order: %s >= %s", nodeID, node.Keys[i-1], node.Keys[i]))
			}
		}

		// Check internal node children count
		if !node.IsLeaf {
			expectedChildren := len(node.Keys) + 1
			if len(node.ChildrenIDs) != expectedChildren {
				result.Errors = append(result.Errors, fmt.Sprintf("Internal node %s has %d children but %d keys (expected %d children)", nodeID, len(node.ChildrenIDs), len(node.Keys), expectedChildren))
			}
		}

		// Check leaf node values match keys
		if node.IsLeaf {
			if len(node.Keys) != len(node.Values) {
				result.Errors = append(result.Errors, fmt.Sprintf("Leaf node %s has %d keys but %d value arrays", nodeID, len(node.Keys), len(node.Values)))
			}
		}
	}
}

// validateSeparatorKeys checks that separator keys correctly separate subtrees and exist in leaves
func (t *BPlusTree) validateSeparatorKeys(allNodes map[string]*Node, leafKeys map[string]bool, internalKeys map[string][]string, result *ValidationResult) {
	// Find orphaned keys (in internal nodes but not in any leaf)
	for key := range internalKeys {
		if !leafKeys[key] {
			result.Stats.OrphanedKeys = append(result.Stats.OrphanedKeys, key)
			result.Warnings = append(result.Warnings, fmt.Sprintf("Key '%s' exists in internal nodes but not in any leaf node", key))
		}
	}

	// Validate separator key placement for each internal node
	for nodeID, node := range allNodes {
		if node.IsLeaf {
			continue
		}

		for i, separatorKey := range node.Keys {
			// Get left and right subtrees
			leftChildID := node.ChildrenIDs[i]
			rightChildID := node.ChildrenIDs[i+1]

			leftChild := allNodes[leftChildID]
			rightChild := allNodes[rightChildID]

			if leftChild == nil || rightChild == nil {
				continue // This error will be caught in structural validation
			}

			// Check that separator correctly divides subtrees
			leftMax := t.getMaxKeyInSubtree(leftChild, allNodes)
			rightMin := t.getMinKeyInSubtree(rightChild, allNodes)

			if leftMax != "" && leftMax >= separatorKey {
				result.Stats.InconsistentSeparators = append(result.Stats.InconsistentSeparators, separatorKey)
				result.Errors = append(result.Errors, fmt.Sprintf("Separator key '%s' in node %s doesn't separate subtrees correctly: left max key '%s' >= separator", separatorKey, nodeID, leftMax))
			}

			if rightMin != "" && rightMin < separatorKey {
				result.Stats.InconsistentSeparators = append(result.Stats.InconsistentSeparators, separatorKey)
				result.Errors = append(result.Errors, fmt.Sprintf("Separator key '%s' in node %s doesn't separate subtrees correctly: right min key '%s' < separator", separatorKey, nodeID, rightMin))
			}
		}
	}
}

// getMaxKeyInSubtree finds the maximum key in a subtree
func (t *BPlusTree) getMaxKeyInSubtree(node *Node, allNodes map[string]*Node) string {
	if node.IsLeaf {
		if len(node.Keys) == 0 {
			return ""
		}
		return node.Keys[len(node.Keys)-1]
	}

	// For internal nodes, go to rightmost child
	if len(node.ChildrenIDs) == 0 {
		return ""
	}
	rightmostChild := allNodes[node.ChildrenIDs[len(node.ChildrenIDs)-1]]
	if rightmostChild == nil {
		return ""
	}
	return t.getMaxKeyInSubtree(rightmostChild, allNodes)
}

// getMinKeyInSubtree finds the minimum key in a subtree
func (t *BPlusTree) getMinKeyInSubtree(node *Node, allNodes map[string]*Node) string {
	if node.IsLeaf {
		if len(node.Keys) == 0 {
			return ""
		}
		return node.Keys[0]
	}

	// For internal nodes, go to leftmost child
	if len(node.ChildrenIDs) == 0 {
		return ""
	}
	leftmostChild := allNodes[node.ChildrenIDs[0]]
	if leftmostChild == nil {
		return ""
	}
	return t.getMinKeyInSubtree(leftmostChild, allNodes)
}

// validateLeafChain checks NextID linking in leaf nodes
func (t *BPlusTree) validateLeafChain(ctx context.Context, storage Storage, allNodes map[string]*Node, result *ValidationResult) {
	// Find leftmost leaf
	leftmost, err := t.findLeftmostLeaf(ctx, storage)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Failed to find leftmost leaf: %v", err))
		return
	}

	visitedLeaves := make(map[string]bool)
	current := leftmost
	leafCount := 0

	// Traverse the chain
	for current != nil {
		if visitedLeaves[current.ID] {
			result.Errors = append(result.Errors, fmt.Sprintf("Cycle detected in leaf chain at node %s", current.ID))
			break
		}
		visitedLeaves[current.ID] = true
		leafCount++

		// Check that this is actually a leaf
		if !current.IsLeaf {
			result.Errors = append(result.Errors, fmt.Sprintf("Non-leaf node %s in leaf chain", current.ID))
		}

		// Move to next
		if current.NextID == "" {
			break
		}

		next, exists := allNodes[current.NextID]
		if !exists {
			result.Errors = append(result.Errors, fmt.Sprintf("Leaf node %s points to non-existent next node %s", current.ID, current.NextID))
			break
		}
		current = next
	}

	// Check that all leaf nodes are in the chain
	expectedLeafCount := 0
	for _, node := range allNodes {
		if node.IsLeaf {
			expectedLeafCount++
		}
	}

	if leafCount != expectedLeafCount {
		result.Errors = append(result.Errors, fmt.Sprintf("Leaf chain contains %d nodes but tree has %d leaf nodes", leafCount, expectedLeafCount))
	}
}

// validateSearchPaths checks that all keys can be found via tree traversal
func (t *BPlusTree) validateSearchPaths(ctx context.Context, storage Storage, leafKeys map[string]bool, result *ValidationResult) {
	for key := range leafKeys {
		leaf, err := t.findLeafNode(ctx, storage, key)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("Failed to find leaf for key '%s': %v", key, err))
			continue
		}

		// Check that the key actually exists in the found leaf
		_, found := leaf.FindKeyIndex(key)
		if !found {
			result.Errors = append(result.Errors, fmt.Sprintf("Key '%s' not found in leaf node %s where search led", key, leaf.ID))
		}
	}
}
