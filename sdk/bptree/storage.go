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

// TODO: Review ...
// NewNodeStorage creates a new adapter for the logical.Storage interface
// with built-in write buffering enabled by default
func NewNodeStorage(
	storage logical.Storage,
	configOpts ...StorageOption,
) (*NodeStorage, error) {
	return NewNodeStorageFromConfig(storage, NewStorageConfig(configOpts...))
}

// NewNodeStorageFromConfig ...
func NewNodeStorageFromConfig(
	storage logical.Storage,
	config *StorageConfig,
) (*NodeStorage, error) {
	err := ValidateStorageConfig(config)
	if err != nil {
		return nil, fmt.Errorf("invalid storage config: %w", err)
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
	configOpts ...StorageOption,
) (TransactionalStorage, error) {
	nodeStorage, err := NewNodeStorageFromConfig(storage, NewTransactionalStorageConfig(configOpts...))
	if err != nil {
		return nil, err
	}

	// Return a new TransactionalNodeStorage instance
	return &TransactionalNodeStorage{
		NodeStorage: nodeStorage,
	}, nil
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
	if node := s.getFromCache(ctx, id); node != nil {
		return node, nil
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
	s.addToCache(ctx, node)

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
		s.addToCache(ctx, node)
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
	s.addToCache(ctx, node)

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
		s.removeFromCache(ctx, id)
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
	s.removeFromCache(ctx, id)

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
