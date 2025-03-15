// Copyright (c) 2024 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package bptree

import (
	"context"
	"fmt"
	"sync"

	"github.com/openbao/openbao/sdk/v2/logical"
)

type Transactional interface {
	BeginReadOnlyTx(context.Context) (Transaction, error)
	BeginTx(context.Context) (Transaction, error)
}

type Transaction interface {
	Storage
	// Commit ...
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
}

var _ Transaction = &NodeTransaction{}

func (s *TransactionalNodeStorage) BeginReadOnlyTx(ctx context.Context) (Transaction, error) {
	tx, err := s.storage.(logical.TransactionalStorage).BeginReadOnlyTx(ctx)
	if err != nil {
		return nil, err
	}

	return &NodeTransaction{
		NodeStorage: &NodeStorage{
			storage:    tx,
			serializer: s.serializer,
			cache:      s.cache, // Share cache for read-only transactions
			skipCache:  false,   // Enable cache for read-only transactions
			// New mutex instance for the transaction (read-only still needs its own locks)
			lock:               sync.RWMutex{},
			cachesOpsQueueLock: sync.Mutex{},
			pendingCacheOps:    nil, // No cache operations for read-only
		},
	}, nil
}

func (s *TransactionalNodeStorage) BeginTx(ctx context.Context) (Transaction, error) {
	tx, err := s.storage.(logical.TransactionalStorage).BeginTx(ctx)
	if err != nil {
		return nil, err
	}

	return &NodeTransaction{
		NodeStorage: &NodeStorage{
			storage:    tx,
			serializer: s.serializer,
			cache:      s.cache, // Share cache within transactions
			skipCache:  false,   // Enable cache within transactions
			// New mutex instances for the transaction
			lock:               sync.RWMutex{},
			cachesOpsQueueLock: sync.Mutex{},
			pendingCacheOps:    make([]cacheOperation, 0),
		},
	}, nil
}

func (s *NodeTransaction) Commit(ctx context.Context) error {
	var err error
	defer s.flushCacheOps(err == nil) // Ensure cache operations are flushed on commit

	// Commit the underlying transaction
	if err = s.storage.(logical.Transaction).Commit(ctx); err != nil {
		return err
	}

	return nil
}

func (s *NodeTransaction) Rollback(ctx context.Context) error {
	// Clear any pending cache operations (don't apply them)
	s.flushCacheOps(false)

	// Rollback the underlying transaction
	return s.storage.(logical.Transaction).Rollback(ctx)
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

		// Ensure rollback is called if commit is not reached
		defer func() {
			if rollbackErr := txn.Rollback(ctx); rollbackErr != nil {
				// Log rollback errors but don't override the main error
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

		return nil
	} else {
		// If storage doesn't support transactions, execute directly
		return callback(originalStorage)
	}
}
