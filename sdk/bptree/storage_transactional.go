// Copyright (c) 2024 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package bptree

import (
	"context"
	"fmt"
	"log"
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

func (s *TransactionalNodeStorage) BeginReadOnlyTx(ctx context.Context) (Transaction, error) {
	tx, err := s.storage.(logical.TransactionalStorage).BeginReadOnlyTx(ctx)
	if err != nil {
		return nil, err
	}

	// Create transaction-local cache for isolation (use reasonable default size)
	txCache, err := lru.NewLRU[string, *Node](100) // Transaction cache size - can be configurable later
	if err != nil {
		return nil, fmt.Errorf("failed to create transaction cache: %w", err)
	}

	return &NodeTransaction{
		NodeStorage: &NodeStorage{
			storage:        tx,
			serializer:     s.serializer,
			cache:          txCache, // Transaction-local cache
			cachingEnabled: true,    // Enable caching within transaction
			isTransaction:  true,    // Explicit transaction flag
			// New mutex instance for the transaction
			lock: sync.RWMutex{},
			// Enable built-in buffering for transaction
			dirtyTracker:     NewDirtyTracker(), // Each transaction gets its own buffer
			bufferingEnabled: true,              // Buffering enabled for transaction
		},
		parentStorage: s, // Keep reference to parent for cache merging
	}, nil
}

func (s *TransactionalNodeStorage) BeginTx(ctx context.Context) (Transaction, error) {
	tx, err := s.storage.(logical.TransactionalStorage).BeginTx(ctx)
	if err != nil {
		return nil, err
	}

	// Create transaction-local cache for isolation (use reasonable default size)
	txCache, err := lru.NewLRU[string, *Node](100) // Transaction cache size - can be configurable later
	if err != nil {
		return nil, fmt.Errorf("failed to create transaction cache: %w", err)
	}

	return &NodeTransaction{
		NodeStorage: &NodeStorage{
			storage:        tx,
			serializer:     s.serializer,
			cache:          txCache, // Transaction-local cache
			cachingEnabled: true,    // Enable caching within transaction
			isTransaction:  true,    // Explicit transaction flag
			// New mutex instance for the transaction
			lock: sync.RWMutex{},
			// Enable built-in buffering for transaction
			dirtyTracker:     NewDirtyTracker(), // Each transaction gets its own buffer
			bufferingEnabled: true,              // Buffering enabled for transaction
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

	// Lock both caches to ensure thread safety
	s.lock.Lock()
	defer s.lock.Unlock()

	s.parentStorage.lock.Lock()
	defer s.parentStorage.lock.Unlock()

	// Get all keys from transaction cache
	keys := s.cache.Keys()

	// Copy each entry from transaction cache to parent cache
	for _, key := range keys {
		if value, ok := s.cache.Get(key); ok {
			// Add to parent cache (this will handle LRU eviction automatically)
			s.parentStorage.cache.Add(key, value)
		}
	}
}

// NewNodeStorageFromTransaction creates a NodeStorage that works within an existing transaction.
// Caching is disabled to avoid cache coherency issues with external transaction control.
func NewNodeStorageFromTransaction(
	tx logical.Transaction,
	serializer NodeSerializer,
	cache *lru.LRU[string, *Node], // Shared cache from parent storage (not used due to skipCache)
) (*NodeStorage, error) {
	if serializer == nil {
		serializer = &JSONSerializer{}
	}

	return &NodeStorage{
		storage:        tx,
		serializer:     serializer,
		cache:          cache, // Not used due to skipCache=true
		cachingEnabled: true,  // Enable caching within transaction (would be merged to parent)
		isTransaction:  true,  // Explicit transaction flag
		lock:           sync.RWMutex{},
	}, nil
}

// WithExistingTransaction creates a NodeStorage wrapper that participates in an existing transaction.
// This allows using the wrapper's utility methods within a transaction managed externally.
// Caching is disabled to avoid cache coherency issues with external transaction control.
// The returned NodeStorage should NOT have Commit/Rollback called on it - the original transaction
// should handle that.
func WithExistingTransaction(
	ctx context.Context,
	tx logical.Transaction,
	parentStorage *NodeStorage, // Parent storage for shared cache and config
) Storage {
	return &NodeStorage{
		storage:        tx,
		serializer:     parentStorage.serializer,
		cache:          parentStorage.cache, // Not used due to skipCache=true
		cachingEnabled: true,                // Enable caching within transaction (wont be merged to parent)
		isTransaction:  true,                // Explicit transaction flag
		lock:           sync.RWMutex{},      // New mutex for transaction isolation
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
					// Log rollback errors but don't override the main error
					log.Printf("failed to rollback transaction: %v", err)
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
