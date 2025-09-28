// Copyright (c) 2024 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package bptree

import (
	"context"
	"fmt"
	"sync"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/sdk/v2/lru"
)

type Transactional interface {
	BeginReadOnlyTx(context.Context) (Transaction, error)
	BeginTx(context.Context) (Transaction, error)
}

type Transaction interface {
	Storage
	// Commit a transaction, persisting any changes made during the transaction.
	Commit(context.Context) error
	// Rollback a transaction, preventing any changes from being persisted.
	// Either Commit or Rollback must be called to release resources.
	Rollback(context.Context) error
}

// TransactionalStorage is implemented if a storage backend implements
// Transactional as well.
type TransactionalStorage interface {
	Storage
	Transactional
}

type TransactionalNodeStorage struct {
	*NodeStorage
}

var _ TransactionalStorage = &TransactionalNodeStorage{}

type NodeTransaction struct {
	*NodeStorage
	// Reference to parent for cache merging
	parentStorage *TransactionalNodeStorage
}

var _ Transaction = &NodeTransaction{}

// NOTE (gabrielopesantos): Should it be possible for cache size, buffering, etc to be overridden per transaction?
// BeginReadOnlyTx starts a read-only transaction and inherits all configuration from the parent storage.
// It creates a transaction-local cache, that is then merged with the parent's, and buffer that are completely
// isolated
func (s *TransactionalNodeStorage) BeginReadOnlyTx(ctx context.Context) (Transaction, error) {
	tx, err := s.storage.(logical.TransactionalStorage).BeginReadOnlyTx(ctx)
	if err != nil {
		return nil, err
	}

	var txCache *lru.LRU[string, *Node]
	if s.cachingEnabled {
		// Create transaction-local cache for isolation (inherit parent's cache size)
		cacheSize := defaultCacheSize
		if s.cache != nil {
			cacheSize = s.cache.Size()
		}
		txCache, err = lru.NewLRU[string, *Node](cacheSize)
		if err != nil {
			return nil, fmt.Errorf("failed to create transaction cache: %w", err)
		}
	}

	var dirtyTracker *DirtyTracker
	if s.bufferingEnabled {
		// Create transaction-local dirty tracker
		dirtyTracker = NewDirtyTracker()
	}

	return &NodeTransaction{
		NodeStorage: &NodeStorage{
			storage:        tx,
			isTransaction:  true, // Explicit transaction flag
			serializer:     s.serializer,
			cachingEnabled: s.cachingEnabled, // Inherit caching setting from parent
			cache:          txCache,          // Transaction-local cache
			// New mutex instance for the transaction
			lock:             sync.RWMutex{},
			bufferingEnabled: s.bufferingEnabled, // Inherit buffering setting from parent
			dirtyTracker:     dirtyTracker,       // Each transaction gets its own buffer
		},
		parentStorage: s, // Keep reference to parent for cache merging
	}, nil
}

func (s *TransactionalNodeStorage) BeginTx(ctx context.Context) (Transaction, error) {
	tx, err := s.storage.(logical.TransactionalStorage).BeginTx(ctx)
	if err != nil {
		return nil, err
	}

	var txCache *lru.LRU[string, *Node]
	if s.cachingEnabled {
		// Create transaction-local cache for isolation (inherit parent's cache size)
		cacheSize := defaultCacheSize
		if s.cache != nil {
			cacheSize = s.cache.Size()
		}
		txCache, err = lru.NewLRU[string, *Node](cacheSize)
		if err != nil {
			return nil, fmt.Errorf("failed to create transaction cache: %w", err)
		}
	}

	var dirtyTracker *DirtyTracker
	if s.bufferingEnabled {
		// Create transaction-local dirty tracker
		dirtyTracker = NewDirtyTracker()
	}

	return &NodeTransaction{
		NodeStorage: &NodeStorage{
			storage:        tx,
			isTransaction:  true, // Explicit transaction flag
			serializer:     s.serializer,
			cachingEnabled: s.cachingEnabled, // Inherit caching setting from parent
			cache:          txCache,          // Transaction-local cache
			// New mutex instance for the transaction
			lock:             sync.RWMutex{},
			bufferingEnabled: s.bufferingEnabled, // Inherit buffering setting from parent
			dirtyTracker:     dirtyTracker,       // Each transaction gets its own buffer
		},
		parentStorage: s, // Keep reference to parent for cache merging
	}, nil
}

func (s *NodeTransaction) Commit(ctx context.Context) error {
	// First flush any buffered operations to the transaction
	if err := s.FlushBuffer(ctx); err != nil {
		return fmt.Errorf("failed to flush buffer before commit: %w", err)
	}

	// Then commit the underlying transaction
	if err := s.storage.(logical.Transaction).Commit(ctx); err != nil {
		return err
	}

	// After successful commit, merge transaction cache into parent cache
	s.mergeCacheIntoParent()

	return nil
}

func (s *NodeTransaction) Rollback(ctx context.Context) error {
	// Clear buffered operations (don't flush them)
	s.ClearBuffer()

	// Rollback the underlying transaction
	// Transaction-local cache is automatically discarded (no merging)
	return s.storage.(logical.Transaction).Rollback(ctx)
}

// mergeCacheIntoParent merges the transaction's cache into the parent storage's cache
func (s *NodeTransaction) mergeCacheIntoParent() {
	if s.parentStorage == nil || s.parentStorage.cache == nil || s.cache == nil {
		return
	}

	// always lock parent before transaction to prevent deadlocks with other
	// operations that might lock in the same order
	s.parentStorage.lock.Lock()
	defer s.parentStorage.lock.Unlock()

	s.lock.Lock()
	defer s.lock.Unlock()

	keys := s.cache.Keys()
	allEntries := make(map[string]*Node, len(keys))

	for _, key := range keys {
		if value, ok := s.cache.Get(key); ok {
			allEntries[key] = value
		}
	}

	// Copy entries to parent cache
	for key, value := range allEntries {
		// Add to parent cache
		s.parentStorage.cache.Add(key, value)
	}
}

// WithTransaction will begin and end a transaction around the execution of the `callback` function.
// If the storage supports transactions, it creates a transaction and passes it to the callback.
// On success, the transaction is committed; on failure, it's rolled back.
func WithTransaction(ctx context.Context, originalStorage Storage, callback func(Storage) error) error {
	if txnStorage, ok := originalStorage.(TransactionalStorage); ok {
		txn, err := txnStorage.BeginTx(ctx)
		if err != nil {
			return fmt.Errorf("failed to begin transaction: %w", err)
		}

		// Track commit status to avoid double rollback
		var committed bool
		defer func() {
			if !committed {
				if rollbackErr := txn.Rollback(ctx); rollbackErr != nil {
					// Rollback errors in defer are typically unrecoverable
					// The original error takes precedence over rollback failures
					// Logging would be inappropriate in a library - let caller handle errors
					_ = rollbackErr // Explicitly ignore rollback error
				}
			}
		}()

		// Execute the callback with the transaction storage
		if err := callback(txn); err != nil {
			return err
		}

		// Commit the transaction
		if err := txn.Commit(ctx); err != nil {
			return fmt.Errorf("failed to commit transaction: %w", err)
		}

		committed = true
		return nil
	} else {
		// If storage doesn't support transactions, execute directly
		return callback(originalStorage)
	}
}

// NewNodeStorageFromTransaction creates a NodeStorage that works within an existing external transaction.
// This creates a completely isolated transaction-local cache that will NOT be merged back to the parent.
// Buffering is enabled with its own DirtyTracker.
//
// Use this when you have an external transaction that you manage yourself and want to use
// NodeStorage functionality within it, but don't want cache pollution in the parent storage.
func NewNodeStorageFromTransaction(
	tx logical.Transaction,
	config *StorageConfig,
) (*NodeStorage, error) {
	if config == nil {
		config = NewTransactionalStorageConfig() // Use defaults if nil
	} else {
		if err := ValidateStorageConfig(config); err != nil {
			return nil, err
		}
	}

	// Create transaction-local cache (isolated, won't be merged)
	var cache *lru.LRU[string, *Node]
	if config.CachingEnabled {
		var err error
		cache, err = lru.NewLRU[string, *Node](config.CacheSize)
		if err != nil {
			return nil, fmt.Errorf("failed to create transaction-local cache: %w", err)
		}
	}

	// Create transaction-local dirty tracker
	var dirtyTracker *DirtyTracker
	if config.BufferingEnabled {
		dirtyTracker = NewDirtyTracker()
	}

	return &NodeStorage{
		storage:          tx,
		isTransaction:    true, // Mark as transaction
		serializer:       config.NodeSerializer,
		cachingEnabled:   config.CachingEnabled,
		cache:            cache, // Transaction-local cache (isolated)
		bufferingEnabled: config.BufferingEnabled,
		dirtyTracker:     dirtyTracker, // Transaction-local buffer
		lock:             sync.RWMutex{},
	}, nil
}

// WithExistingTransaction creates a NodeStorage wrapper that participates in an existing external transaction.
// This creates a transaction-local cache and buffer that are completely isolated and will NOT be merged
// back to the parent storage. This is the recommended approach for external transaction management.
//
// The returned NodeStorage should NOT have Commit/Rollback called on it - the original transaction
// should handle that. When the external transaction commits/rolls back, the transaction-local cache
// and buffer are automatically discarded.
func WithExistingTransaction(
	ctx context.Context,
	tx logical.Transaction,
	parentStorage *NodeStorage, // Parent storage for config inheritance only
	opts ...StorageOption, // Optional overrides for transaction-specific config
) (Storage, error) {
	// Create transaction config by inheriting from parent and applying overrides
	parentConfig := &StorageConfig{
		NodeSerializer:   parentStorage.serializer,
		CachingEnabled:   parentStorage.cachingEnabled,
		CacheSize:        parentStorage.cache.Size(),
		BufferingEnabled: parentStorage.bufferingEnabled,
	}

	// Apply overrides
	ApplyStorageOptions(parentConfig, opts...)

	// Create NodeStorage with transaction-local resources
	nodeStorage, err := NewNodeStorageFromTransaction(tx, parentConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create NodeStorage for existing transaction: %w", err)
	}

	return nodeStorage, nil
}
