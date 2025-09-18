// Copyright (c) 2024 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package bptree

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/sdk/v2/lru"
)

const (
	nodesPath  = "nodes"
	rootPath   = "root"
	configPath = "config"
)

var (
	ErrNodeNotFound   = errors.New("node not found")
	ErrRootIDNotSet   = errors.New("root ID not set")
	ErrConfigNotFound = errors.New("tree config not found")
)

type Storage interface {
	// GetRootID gets the ID of the root node
	GetRootID(ctx context.Context) (string, error)
	// PutRootID sets the ID of the root node
	PutRootID(ctx context.Context, id string) error

	// GetNode retrieves a node by its ID
	GetNode(ctx context.Context, id string) (*Node, error)
	// PutNode persists a node to storage
	PutNode(ctx context.Context, node *Node) error
	// DeleteNode deletes a node from storage
	DeleteNode(ctx context.Context, id string) error
	// PurgeNodes clears all nodes from storage starting with the prefix
	// PurgeNodes(ctx context.Context) error

	// GetConfig gets the config/metadata for a tree
	GetConfig(ctx context.Context) (*BPlusTreeConfig, error)
	// PutConfig sets the config/metadata for a tree
	PutConfig(ctx context.Context, config *BPlusTreeConfig) error
}

var _ Storage = &NodeStorage{}

// NodeStorage adapts the logical.Storage interface to the bptree.Storage interface
// with built-in write buffering for optimal performance
type NodeStorage struct {
	storage       logical.Storage
	isTransaction bool // Explicit flag to track transaction state
	lock          sync.RWMutex

	// Serializer for nodes
	serializer NodeSerializer

	// Built-in caching layer
	cachingEnabled bool // Whether to skip cache operations
	cache          *lru.LRU[string, *Node]

	// Built-in write buffering
	bufferingEnabled bool          // Whether write buffering is enabled
	dirtyTracker     *DirtyTracker // Tracks dirty nodes for batching writes
}

// NewNodeStorage creates a new adapter for the logical.Storage interface
// with built-in write buffering enabled by default
func NewNodeStorage(
	storage logical.Storage,
	config *StorageConfig,
) (*NodeStorage, error) {
	if config == nil {
		config = NewStorageConfig() // Use defaults if nil
	} else {
		if err := ValidateStorageConfig(config); err != nil {
			return nil, err
		}
	}

	var cache *lru.LRU[string, *Node]
	if config.CachingEnabled {
		var err error
		cache, err = lru.NewLRU[string, *Node](config.CacheSize)
		if err != nil {
			return nil, err
		}
	}

	var dirtyTracker *DirtyTracker
	if config.BufferingEnabled {
		dirtyTracker = NewDirtyTracker()
	}

	return &NodeStorage{
		storage:          storage,
		isTransaction:    false,
		serializer:       config.NodeSerializer,
		cachingEnabled:   config.CachingEnabled,
		cache:            cache,
		bufferingEnabled: config.BufferingEnabled,
		dirtyTracker:     dirtyTracker,
	}, nil
}

// NewTransactionalNodeStorage creates a new adapter for transactional logical.Storage
func NewTransactionalNodeStorage(
	storage logical.TransactionalStorage,
	config *StorageConfig,
) (TransactionalStorage, error) {
	nodeStorage, err := NewNodeStorage(storage, config)
	if err != nil {
		return nil, err
	}

	// Return a new TransactionalNodeStorage instance
	return &TransactionalNodeStorage{
		NodeStorage: nodeStorage,
	}, nil
}

// configKey constructs the storage key for tree metadata, using tree ID from context if available
func configKey(ctx context.Context) string {
	treeID := getTreeIDOrDefault(ctx, DefaultTreeID)
	return treeID + "/" + configPath
}

// rootKey constructs the storage key for the root ID, using tree ID from context if available
func rootKey(ctx context.Context) string {
	treeID := getTreeIDOrDefault(ctx, DefaultTreeID)
	return treeID + "/" + rootPath
}

// nodeKey constructs the storage key for a node, using tree ID from context if available
func nodeKey(ctx context.Context, nodeID string) string {
	treeID := getTreeIDOrDefault(ctx, DefaultTreeID)
	return treeID + "/" + nodesPath + "/" + nodeID
}

// cacheKey constructs the cache key for a node, using tree ID from context if available
func cacheKey(ctx context.Context, nodeID string) string {
	treeID := getTreeIDOrDefault(ctx, DefaultTreeID)
	return treeID + ":" + nodeID
}

// GetRootID gets the root node identifier
func (s *NodeStorage) GetRootID(ctx context.Context) (string, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	entry, err := s.storage.Get(ctx, rootKey(ctx))
	if err != nil {
		return "", fmt.Errorf("failed to get root ID: %w", err)
	}

	if entry == nil {
		return "", ErrRootIDNotSet
	}

	return string(entry.Value), nil
}

// PutRootID persists the root node identifier
func (s *NodeStorage) PutRootID(ctx context.Context, id string) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	entry := &logical.StorageEntry{
		Key:   rootKey(ctx),
		Value: []byte(id),
	}

	if err := s.storage.Put(ctx, entry); err != nil {
		return fmt.Errorf("failed to set root ID: %w", err)
	}

	return nil
}

// GetNode loads a node from storage, checking dirty tracker first
func (s *NodeStorage) GetNode(ctx context.Context, id string) (*Node, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	// First check if we have a dirty (buffered) version
	if s.bufferingEnabled && s.dirtyTracker != nil {
		if node, isDirty := s.dirtyTracker.GetDirty(id); isDirty {
			return node, nil
		}
	}

	// Try to get from cache second (unless cache is disabled)
	if s.cachingEnabled {
		if node, ok := s.cache.Get(cacheKey(ctx, id)); ok {
			return node, nil
		}
	}

	// Load from storage as last resort
	entry, err := s.storage.Get(ctx, nodeKey(ctx, id))
	if err != nil {
		return nil, fmt.Errorf("failed to get node %s: %w", id, err)
	}

	if entry == nil {
		return nil, ErrNodeNotFound
	}

	node, err := s.serializer.Deserialize(entry.Value)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize node %s: %w", id, err)
	}

	// Cache the loaded node
	if s.cachingEnabled {
		s.cache.Add(cacheKey(ctx, id), node)
	}

	return node, nil
}

// PutNode saves a node to storage with built-in buffering
func (s *NodeStorage) PutNode(ctx context.Context, node *Node) error {
	// Check if the node is nil
	if node == nil {
		return fmt.Errorf("cannot save nil node")
	}

	// Lock storage for writing
	s.lock.Lock()
	defer s.lock.Unlock()

	// If buffering is enabled, buffer the write instead of immediate save
	if s.bufferingEnabled {
		s.dirtyTracker.MarkDirty(node.ID, node)
		// Also update cache immediately for read consistency within the operation
		if s.cachingEnabled {
			s.cache.Add(cacheKey(ctx, node.ID), node)
		}
		return nil
	}

	// Fallback to immediate save (if buffering disabled)
	return s.putNodeImmediate(ctx, node)
}

// putNodeImmediate performs the actual storage write without buffering
func (s *NodeStorage) putNodeImmediate(ctx context.Context, node *Node) error {
	data, err := s.serializer.Serialize(node)
	if err != nil {
		return fmt.Errorf("failed to serialize node %s: %w", node.ID, err)
	}

	entry := &logical.StorageEntry{
		Key:   nodeKey(ctx, node.ID),
		Value: data,
	}

	if err := s.storage.Put(ctx, entry); err != nil {
		return fmt.Errorf("failed to save node %s: %w", node.ID, err)
	}

	// Cache the saved node
	if s.cachingEnabled {
		s.cache.Add(cacheKey(ctx, node.ID), node)
	}

	return nil
}

// DeleteNode deletes a node from storage with built-in buffering
func (s *NodeStorage) DeleteNode(ctx context.Context, id string) error {
	// Lock the nodes for writing
	s.lock.Lock()
	defer s.lock.Unlock()

	// If buffering is enabled, buffer the delete instead of immediate delete
	if s.bufferingEnabled {
		s.dirtyTracker.MarkDeleted(id)
		// Also remove from cache immediately for consistency within the operation
		if s.cachingEnabled {
			s.cache.Delete(cacheKey(ctx, id))
		}
		return nil
	}

	// Fallback to immediate delete (if buffering disabled)
	return s.deleteNodeImmediate(ctx, id)
}

// deleteNodeImmediate performs the actual storage delete without buffering
func (s *NodeStorage) deleteNodeImmediate(ctx context.Context, id string) error {
	if err := s.storage.Delete(ctx, nodeKey(ctx, id)); err != nil {
		return fmt.Errorf("failed to delete node %s: %w", id, err)
	}

	// Remove from cache
	if s.cachingEnabled {
		s.cache.Delete(cacheKey(ctx, id))
	}

	return nil
}

// GetConfig gets the metadata for a tree
func (s *NodeStorage) GetConfig(ctx context.Context) (*BPlusTreeConfig, error) {
	// Lock for reading the tree configuration
	s.lock.RLock()
	defer s.lock.RUnlock()

	entry, err := s.storage.Get(ctx, configKey(ctx))
	if err != nil {
		return nil, fmt.Errorf("failed to get tree metadata: %w", err)
	}

	if entry == nil {
		return nil, ErrConfigNotFound
	}

	var config BPlusTreeConfig
	if err := json.Unmarshal(entry.Value, &config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal tree metadata: %w", err)
	}

	return &config, nil
}

// PutConfig sets the metadata for a tree
func (s *NodeStorage) PutConfig(ctx context.Context, config *BPlusTreeConfig) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	data, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal tree config: %w", err)
	}

	entry := &logical.StorageEntry{
		Key:   configKey(ctx),
		Value: data,
	}

	if err := s.storage.Put(ctx, entry); err != nil {
		return fmt.Errorf("failed to set tree config: %w", err)
	}

	return nil
}

// EnableCache enables or disables cache operations
func (s *NodeStorage) EnableCache(enabled bool) {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.cachingEnabled = enabled
}

// IsCacheEnabled returns whether cache operations are enabled
func (s *NodeStorage) IsCacheEnabled() bool {
	return s.cachingEnabled
}

// PurgeCache clears all entries from the cache
func (s *NodeStorage) PurgeCache() {
	if s.cache != nil {
		s.cache.Purge()
	}
}

// FlushBuffer persists all dirty (buffered) operations to storage
func (s *NodeStorage) FlushBuffer(ctx context.Context) error {
	if !s.bufferingEnabled || s.dirtyTracker == nil {
		return nil // Nothing to flush
	}

	s.lock.Lock()
	defer s.lock.Unlock()

	// Process deletions first
	for _, key := range s.dirtyTracker.Keys() {
		if s.dirtyTracker.IsDeleted(key) {
			if err := s.deleteNodeImmediate(ctx, key); err != nil {
				return fmt.Errorf("failed to flush delete for node %s: %w", key, err)
			}
		}
	}

	// Then process saves/updates
	for _, key := range s.dirtyTracker.Keys() {
		if node, isDirty := s.dirtyTracker.GetDirty(key); isDirty {
			if err := s.putNodeImmediate(ctx, node); err != nil {
				return fmt.Errorf("failed to flush save for node %s: %w", key, err)
			}
		}
	}

	// Clear the dirty tracker after successful flush
	s.dirtyTracker.Clear()
	return nil
}

// ClearBuffer discards all buffered changes without persisting
func (s *NodeStorage) ClearBuffer() {
	if s.bufferingEnabled && s.dirtyTracker != nil {
		s.lock.Lock()
		defer s.lock.Unlock()
		s.dirtyTracker.Clear()
	}
}

// BufferStats returns information about the current buffer state
func (s *NodeStorage) BufferStats() (dirtyCount int, bufferingEnabled bool) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	if s.dirtyTracker != nil {
		dirtyCount = s.dirtyTracker.Count()
	}
	return dirtyCount, s.bufferingEnabled
}

// SetBufferingEnabled controls whether write buffering is enabled
// When disabled, writes go directly to storage
func (s *NodeStorage) SetBufferingEnabled(enabled bool) {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.bufferingEnabled = enabled
}

// Helper Functions for Write Buffering
//
// These helper functions are designed for use with regular NodeStorage instances only.
// Do NOT use these with transactional storage (Transaction interface) as transactions handle
// their own buffering and flushing lifecycle automatically:
//
// - Transactions buffer writes in their own DirtyTracker during execution
// - Transactions automatically flush buffers during Commit()
// - Transactions automatically clear buffers during Rollback()
//
// For transactional operations, use WithTransaction() which provides proper
// transaction lifecycle management including automatic buffer handling.
//
// These functions provide convenient ways to use the built-in buffering functionality

// WithBufferedWrites executes a function with write buffering ENABLED, then flushes all writes.
// This function forces buffering ON during execution, regardless of the storage's default setting.
// Operations are guaranteed to be buffered and flushed together as a batch.
func WithBufferedWrites(ctx context.Context, storage Storage, fn func(Storage) error) error {
	// Force buffering ON for NodeStorage types
	var originalBuffering bool
	var needsRestore bool

	if ns, ok := storage.(*NodeStorage); ok {
		originalBuffering = ns.bufferingEnabled
		if !originalBuffering {
			ns.SetBufferingEnabled(true) // Force buffering ON
			needsRestore = true
		}
	}

	// Ensure buffering is restored on exit
	if needsRestore {
		defer func() {
			if ns, ok := storage.(*NodeStorage); ok {
				ns.SetBufferingEnabled(originalBuffering)
			}
		}()
	}

	// Execute the function with forced buffering
	if err := fn(storage); err != nil {
		// Clear buffer on error
		clearBufferIfSupported(storage)
		return err
	}

	// Flush buffer on success
	return flushBufferIfSupported(ctx, storage)
}

// WithAutoFlush executes a function with the storage's CURRENT buffering behavior and automatically
// flushes any buffered writes at the end. This respects the storage's existing configuration.
//
// Unlike WithBufferedWrites, this doesn't change the storage behavior - it just
// ensures any existing buffered operations are flushed.
func WithAutoFlush(ctx context.Context, storage Storage, fn func(Storage) error) error {
	// Execute the function with the storage as-is (no behavior changes)
	if err := fn(storage); err != nil {
		// Clear buffer on error
		clearBufferIfSupported(storage)
		return err
	}

	// Flush buffer on success
	return flushBufferIfSupported(ctx, storage)
}

// Helper functions for buffer operations
// Note: These work with transactional storage types but should generally not be used
// with them as transactions handle their own buffering and flushing lifecycle.
func clearBufferIfSupported(storage Storage) {
	switch ns := storage.(type) {
	case *NodeStorage:
		ns.ClearBuffer()
	case *TransactionalNodeStorage:
		ns.ClearBuffer()
	}
}

func flushBufferIfSupported(ctx context.Context, storage Storage) error {
	switch ns := storage.(type) {
	case *NodeStorage:
		return ns.FlushBuffer(ctx)
	case *TransactionalNodeStorage:
		return ns.FlushBuffer(ctx)
	default:
		// Storage does not support buffering, no flush needed
		return nil
	}
}
