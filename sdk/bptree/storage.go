// Copyright (c) 2024 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package bptree

import (
	"context"
	"encoding/json"
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

type Storage interface {
	// GetRootID gets the ID of the root node
	GetRootID(ctx context.Context) (string, error)
	// SetRootID sets the ID of the root node
	SetRootID(ctx context.Context, id string) error

	// LoadNode loads a node from storage
	LoadNode(ctx context.Context, id string) (*Node, error)
	// SaveNode saves a node to storage
	SaveNode(ctx context.Context, node *Node) error
	// DeleteNode deletes a node from storage
	DeleteNode(ctx context.Context, id string) error
	// PurgeNodes clears all nodes from storage starting with the prefix
	// PurgeNodes(ctx context.Context) error

	// GetTreeConfig gets the config/metadata for a tree
	GetTreeConfig(ctx context.Context) (*BPlusTreeConfig, error)
	// SetTreeConfig sets the config/metadata for a tree
	SetTreeConfig(ctx context.Context, config *BPlusTreeConfig) error
}

var _ Storage = &NodeStorage{}

// NodeStorage adapts the logical.Storage interface to the bptree.Storage interface
type NodeStorage struct {
	storage            logical.Storage
	serializer         NodeSerializer
	skipCache          bool
	lock               sync.RWMutex
	cache              *lru.LRU[string, *Node]
	pendingCacheOps    []cacheOperation // Operations to be applied on commit
	cachesOpsQueueLock sync.Mutex
}

// NodeSerializer defines how to serialize and deserialize nodes
type NodeSerializer interface {
	Serialize(node *Node) ([]byte, error)
	Deserialize(data []byte) (*Node, error)
}

// JSONSerializer is a simple JSON-based serializer for nodes
type JSONSerializer struct{}

// Serialize converts a node to JSON
func (s *JSONSerializer) Serialize(node *Node) ([]byte, error) {
	return json.Marshal(node)
}

// Deserialize converts JSON to a node
func (s *JSONSerializer) Deserialize(data []byte) (*Node, error) {
	var node Node
	if err := json.Unmarshal(data, &node); err != nil {
		return nil, err
	}
	return &node, nil
}

// NewNodeStorage creates a new adapter for the logical.Storage interface
func NewNodeStorage(
	storage logical.Storage,
	serializer NodeSerializer,
	cacheSize int,
) (*NodeStorage, error) {
	if serializer == nil {
		serializer = &JSONSerializer{}
	}

	cache, err := lru.NewLRU[string, *Node](cacheSize)
	if err != nil {
		return nil, err
	}

	return &NodeStorage{
		storage:    storage,
		serializer: serializer,
		cache:      cache,
	}, nil
}

// NewTransactionalNodeStorage ...
func NewTransactionalNodeStorage(
	storage logical.TransactionalStorage,
	serializer NodeSerializer,
	cacheSize int,
) (TransactionalStorage, error) {
	nodeStorage, err := NewNodeStorage(storage, serializer, cacheSize)
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
		return "", nil
	}

	return string(entry.Value), nil
}

// SetRootID persists the root node identifier
func (s *NodeStorage) SetRootID(ctx context.Context, id string) error {
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

// LoadNode loads a node from storage
func (s *NodeStorage) LoadNode(ctx context.Context, id string) (*Node, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	// Try to get from cache first (unless cache is disabled)
	if !s.skipCache {
		if node, ok := s.cache.Get(cacheKey(ctx, id)); ok {
			return node, nil
		}
	}

	// Load from storage
	entry, err := s.storage.Get(ctx, nodeKey(ctx, id))
	if err != nil {
		return nil, fmt.Errorf("failed to load node %s: %w", id, err)
	}

	if entry == nil {
		return nil, nil
	}

	node, err := s.serializer.Deserialize(entry.Value)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize node %s: %w", id, err)
	}

	// Cache the loaded node (immediate for non-transactional, queued for transactional)
	if !s.skipCache {
		s.applyCacheOp(CacheOpAdd, cacheKey(ctx, id), node)
	}

	return node, nil
}

// SaveNode saves a node to storage
func (s *NodeStorage) SaveNode(ctx context.Context, node *Node) error {
	// Check if the node is nil
	if node == nil {
		return fmt.Errorf("cannot save nil node")
	}

	// Lock storage for writing
	s.lock.Lock()
	defer s.lock.Unlock()

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

	// Cache the saved node (immediate for non-transactional, queued for transactional)
	if !s.skipCache {
		s.applyCacheOp(CacheOpAdd, cacheKey(ctx, node.ID), node)
	}

	return nil
}

// DeleteNode deletes a node from storage
func (s *NodeStorage) DeleteNode(ctx context.Context, id string) error {
	// Lock the nodes for writing
	s.lock.Lock()
	defer s.lock.Unlock()

	if err := s.storage.Delete(ctx, nodeKey(ctx, id)); err != nil {
		return fmt.Errorf("failed to delete node %s: %w", id, err)
	}

	// Remove from cache (immediate for non-transactional, queued for transactional)
	if !s.skipCache {
		s.applyCacheOp(CacheOpDelete, cacheKey(ctx, id), nil)
	}

	return nil
}

// GetTreeConfig gets the metadata for a tree
func (s *NodeStorage) GetTreeConfig(ctx context.Context) (*BPlusTreeConfig, error) {
	// Lock for reading the tree configuration
	s.lock.RLock()
	defer s.lock.RUnlock()

	entry, err := s.storage.Get(ctx, configKey(ctx))
	if err != nil {
		return nil, fmt.Errorf("failed to get tree metadata: %w", err)
	}

	if entry == nil {
		return nil, nil // No metadata stored
	}

	var config BPlusTreeConfig
	if err := json.Unmarshal(entry.Value, &config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal tree metadata: %w", err)
	}

	return &config, nil
}

// SetTreeConfig sets the metadata for a tree
func (s *NodeStorage) SetTreeConfig(ctx context.Context, config *BPlusTreeConfig) error {
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

type cacheOp string

const (
	CacheOpAdd    cacheOp = "add"
	CacheOpDelete cacheOp = "delete"
)

// cacheOperation is a struct to hold the operation type, key, and value
type cacheOperation struct {
	opType cacheOp
	key    string
	value  *Node
}

// queueCacheOp adds an operation to the pending cache operations queue.
// This allows batching cache operations and applying them only on successful commits.
func (s *NodeStorage) queueCacheOp(opType cacheOp, key string, value *Node) {
	s.cachesOpsQueueLock.Lock()
	defer s.cachesOpsQueueLock.Unlock()

	s.pendingCacheOps = append(s.pendingCacheOps, cacheOperation{
		opType: opType,
		key:    key,
		value:  value,
	})
}

// applyCacheOp applies cache operations immediately if not in a transaction,
// or queues them if in a transaction context.
func (s *NodeStorage) applyCacheOp(opType cacheOp, key string, value *Node) {
	// Check if this is a transaction by seeing if we have a transaction storage type
	if _, isTransaction := s.storage.(logical.Transaction); isTransaction {
		// We're in a transaction - queue the operation for later commit/rollback
		s.queueCacheOp(opType, key, value)
	} else {
		// Not in a transaction - apply immediately
		switch opType {
		case CacheOpAdd:
			if value != nil {
				s.cache.Add(key, value)
			}
		case CacheOpDelete:
			s.cache.Delete(key)
		}
	}
}

// flushCacheOps applies or discards pending cache operations.
// If apply is true, operations are applied to the cache.
// If apply is false, operations are discarded (rollback behavior).
func (s *NodeStorage) flushCacheOps(apply bool) error {
	s.cachesOpsQueueLock.Lock()
	defer func() {
		// Clear the queue after processing
		s.pendingCacheOps = s.pendingCacheOps[:0]
		s.cachesOpsQueueLock.Unlock()
	}()

	if !apply || len(s.pendingCacheOps) == 0 {
		// Rollback: just clear the queue without applying operations
		// Or nothing to apply
		return nil
	}

	// Apply operations to cache
	for _, op := range s.pendingCacheOps {
		switch op.opType {
		case CacheOpAdd:
			if op.value != nil {
				s.cache.Add(op.key, op.value)
			}
		case CacheOpDelete:
			s.cache.Delete(op.key)
		}
	}

	return nil
}

// EnableCache enables or disables cache operations
func (s *NodeStorage) EnableCache(enabled bool) {
	s.skipCache = !enabled
	if !enabled {
		// If cache is disabled, clear any pending operations
		s.flushCacheOps(false)
		// Clear the cache immediately
		s.cache.Purge()
	}
}

// IsCacheEnabled returns whether cache operations are enabled
func (s *NodeStorage) IsCacheEnabled() bool {
	return !s.skipCache
}

// PurgeCache clears all entries from the cache
func (s *NodeStorage) PurgeCache() {
	s.cache.Purge()
}
