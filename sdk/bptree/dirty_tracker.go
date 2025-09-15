// Copyright (c) 2024 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package bptree

import (
	"context"
	"sync"
)

// TODO (gabrielopesantos): Instead of having a dirty tracer we could probably use the
// cache itself to track dirty nodes by having a special marker for dirty vs clean nodes.

// DirtyTracker tracks nodes that have been modified but not yet persisted
type DirtyTracker struct {
	dirtyNodes   map[string]*Node // Key -> Modified Node (nil means deleted)
	deletedNodes map[string]bool  // Key -> true if node should be deleted
	mutex        sync.RWMutex
}

// NewDirtyTracker creates a new dirty node tracker
func NewDirtyTracker() *DirtyTracker {
	return &DirtyTracker{
		dirtyNodes:   make(map[string]*Node),
		deletedNodes: make(map[string]bool),
	}
}

// MarkDirty marks a node as dirty (modified but not persisted)
func (dt *DirtyTracker) MarkDirty(key string, node *Node) {
	dt.mutex.Lock()
	defer dt.mutex.Unlock()
	dt.dirtyNodes[key] = node
	// Remove from deleted nodes if it was there (update supersedes delete)
	delete(dt.deletedNodes, key)
}

// IsDirty checks if a node is marked as dirty
func (dt *DirtyTracker) IsDirty(key string) bool {
	dt.mutex.RLock()
	defer dt.mutex.RUnlock()
	_, exists := dt.dirtyNodes[key]
	return exists
}

// GetDirty returns the dirty version of a node if it exists
func (dt *DirtyTracker) GetDirty(key string) (*Node, bool) {
	dt.mutex.RLock()
	defer dt.mutex.RUnlock()

	// If marked for deletion, return nil to indicate it doesn't exist
	if dt.deletedNodes[key] {
		return nil, false
	}

	node, exists := dt.dirtyNodes[key]
	return node, exists
}

// FlushAll persists all dirty nodes and clears the tracker
func (dt *DirtyTracker) FlushAll(ctx context.Context, storage Storage) error {
	dt.mutex.Lock()
	defer dt.mutex.Unlock()

	// First, process all deletions
	for key := range dt.deletedNodes {
		if err := storage.DeleteNode(ctx, key); err != nil {
			return err
		}
	}

	// Then, process all saves/updates
	for _, node := range dt.dirtyNodes {
		if err := storage.PutNode(ctx, node); err != nil {
			return err
		}
	}

	// Clear all tracking after successful flush
	dt.dirtyNodes = make(map[string]*Node)
	dt.deletedNodes = make(map[string]bool)
	return nil
}

// Clear removes all dirty tracking without persisting
func (dt *DirtyTracker) Clear() {
	dt.mutex.Lock()
	defer dt.mutex.Unlock()
	dt.dirtyNodes = make(map[string]*Node)
	dt.deletedNodes = make(map[string]bool)
}

// Count returns the number of dirty operations (saves + deletes)
func (dt *DirtyTracker) Count() int {
	dt.mutex.RLock()
	defer dt.mutex.RUnlock()
	return len(dt.dirtyNodes) + len(dt.deletedNodes)
}

// Keys returns all keys with pending operations (both dirty and deleted)
func (dt *DirtyTracker) Keys() []string {
	dt.mutex.RLock()
	defer dt.mutex.RUnlock()

	// Collect all unique keys from both dirty and deleted maps
	keySet := make(map[string]bool)

	for key := range dt.dirtyNodes {
		keySet[key] = true
	}

	for key := range dt.deletedNodes {
		keySet[key] = true
	}

	keys := make([]string, 0, len(keySet))
	for key := range keySet {
		keys = append(keys, key)
	}
	return keys
}

// MarkDeleted marks a node for deletion (buffered delete)
func (dt *DirtyTracker) MarkDeleted(key string) {
	dt.mutex.Lock()
	defer dt.mutex.Unlock()
	dt.deletedNodes[key] = true
	// Remove from dirty nodes if it was there (delete supersedes update)
	delete(dt.dirtyNodes, key)
}

// IsDeleted checks if a node is marked for deletion
func (dt *DirtyTracker) IsDeleted(key string) bool {
	dt.mutex.RLock()
	defer dt.mutex.RUnlock()
	return dt.deletedNodes[key]
}

// DirtyKeys returns all keys that have dirty (modified) nodes
func (dt *DirtyTracker) DirtyKeys() []string {
	dt.mutex.RLock()
	defer dt.mutex.RUnlock()

	keys := make([]string, 0, len(dt.dirtyNodes))
	for key := range dt.dirtyNodes {
		keys = append(keys, key)
	}
	return keys
}

// DeletedKeys returns all keys that are marked for deletion
func (dt *DirtyTracker) DeletedKeys() []string {
	dt.mutex.RLock()
	defer dt.mutex.RUnlock()

	keys := make([]string, 0, len(dt.deletedNodes))
	for key := range dt.deletedNodes {
		keys = append(keys, key)
	}
	return keys
}
