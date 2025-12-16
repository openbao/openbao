// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package logical

import (
	"context"

	"github.com/openbao/openbao/sdk/v2/physical"
)

type LogicalStorage struct {
	underlying physical.Backend
}

var _ Storage = &LogicalStorage{}

func (s *LogicalStorage) Get(ctx context.Context, key string) (*StorageEntry, error) {
	entry, err := s.underlying.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	return &StorageEntry{
		Key:      entry.Key,
		Value:    entry.Value,
		SealWrap: entry.SealWrap,
	}, nil
}

func (s *LogicalStorage) Put(ctx context.Context, entry *StorageEntry) error {
	return s.underlying.Put(ctx, &physical.Entry{
		Key:      entry.Key,
		Value:    entry.Value,
		SealWrap: entry.SealWrap,
	})
}

func (s *LogicalStorage) Delete(ctx context.Context, key string) error {
	return s.underlying.Delete(ctx, key)
}

func (s *LogicalStorage) List(ctx context.Context, prefix string) ([]string, error) {
	return s.underlying.List(ctx, prefix)
}

func (s *LogicalStorage) ListPage(ctx context.Context, prefix string, after string, limit int) ([]string, error) {
	return s.underlying.ListPage(ctx, prefix, after, limit)
}

func (s *LogicalStorage) Underlying() physical.Backend {
	return s.underlying
}

type TransactionalLogicalStorage struct {
	LogicalStorage
}

var _ TransactionalStorage = &TransactionalLogicalStorage{}

type LogicalTransaction struct {
	LogicalStorage
}

var _ Transaction = &LogicalTransaction{}

func (s *TransactionalLogicalStorage) BeginReadOnlyTx(ctx context.Context) (Transaction, error) {
	tx, err := s.Underlying().(physical.TransactionalBackend).BeginReadOnlyTx(ctx)
	if err != nil {
		return nil, err
	}

	return &LogicalTransaction{
		LogicalStorage{
			underlying: tx,
		},
	}, nil
}

func (s *TransactionalLogicalStorage) BeginTx(ctx context.Context) (Transaction, error) {
	tx, err := s.Underlying().(physical.TransactionalBackend).BeginTx(ctx)
	if err != nil {
		return nil, err
	}

	return &LogicalTransaction{
		LogicalStorage{
			underlying: tx,
		},
	}, nil
}

func (s *LogicalTransaction) Commit(ctx context.Context) error {
	return s.Underlying().(physical.Transaction).Commit(ctx)
}

func (s *LogicalTransaction) Rollback(ctx context.Context) error {
	return s.Underlying().(physical.Transaction).Rollback(ctx)
}

// WithTransaction will begin and end a transaction around the execution of the `callback` function.
func WithTransaction(ctx context.Context, originalStorage Storage, callback func(Storage) error) error {
	if txnStorage, ok := originalStorage.(TransactionalStorage); ok {
		txn, err := txnStorage.BeginTx(ctx)
		if err != nil {
			return err
		}
		defer txn.Rollback(ctx) //nolint:errcheck
		if err := callback(txn); err != nil {
			return err
		}
		if err := txn.Commit(ctx); err != nil {
			return err
		}
	} else {
		return callback(originalStorage)
	}
	return nil
}

// StartTxStorage can begin a longer-running transaction by modifying the `Storage` field of the `req` param.
// It returns a rollback function to defer in the calling context.
func StartTxStorage(ctx context.Context, req *Request) (func(), error) {
	if txnStorage, ok := req.Storage.(TransactionalStorage); ok {
		txn, err := txnStorage.BeginTx(ctx)
		if err != nil {
			return nil, err
		}
		req.OriginalStorage = req.Storage
		req.Storage = txn
		return func() { txn.Rollback(ctx) }, nil //nolint:errcheck
	}
	return func() {}, nil
}

// EndTxStorage will commit a longer-running transaction and restore the `Storage` field of the `req` param.
func EndTxStorage(ctx context.Context, req *Request) error {
	if txn, ok := req.Storage.(Transaction); ok {
		if err := txn.Commit(ctx); err != nil {
			return err
		}
		if req.OriginalStorage != nil {
			req.Storage = req.OriginalStorage
			req.OriginalStorage = nil
		}
	}
	return nil
}

func NewLogicalStorage(underlying physical.Backend) Storage {
	ls := &LogicalStorage{
		underlying: underlying,
	}

	if _, ok := underlying.(physical.TransactionalBackend); ok {
		return &TransactionalLogicalStorage{
			*ls,
		}
	}

	return ls
}
