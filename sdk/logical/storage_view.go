// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package logical

import (
	"context"
	"errors"
	"strings"
)

type StorageViewCore interface {
	Prefix() string
	SubView(prefix string) StorageView
	SanityCheck(key string) error
	ExpandKey(suffix string) string
	TruncateKey(full string) string
}

type StorageView interface {
	Storage
	StorageViewCore
}

type TransactionalStorageView interface {
	TransactionalStorage
	StorageViewCore
}

// Note that, within a transaction, creating and committing from a
// SubView commits the entire transaction.
type StorageViewTransaction interface {
	Transaction
	StorageViewCore
}

var ErrRelativePath = errors.New("relative paths not supported")

func NewStorageView(storage Storage, prefix string) StorageView {
	sv := &storageView{
		storage: storage,
		prefix:  prefix,
	}

	if _, ok := storage.(TransactionalStorage); ok {
		return &transactionalStorageView{
			*sv,
		}
	}

	if _, ok := storage.(Transaction); ok {
		return &storageViewTransaction{
			*sv,
		}
	}

	return sv
}

type storageView struct {
	storage Storage
	prefix  string
}

var (
	_ Storage     = &storageView{}
	_ StorageView = &storageView{}
)

// logical.Storage impl.
func (s *storageView) List(ctx context.Context, prefix string) ([]string, error) {
	if err := s.SanityCheck(prefix); err != nil {
		return nil, err
	}
	return s.storage.List(ctx, s.ExpandKey(prefix))
}

func (s *storageView) ListPage(ctx context.Context, prefix string, after string, limit int) ([]string, error) {
	if err := s.SanityCheck(prefix); err != nil {
		return nil, err
	}
	return s.storage.ListPage(ctx, s.ExpandKey(prefix), after, limit)
}

func (s *storageView) Get(ctx context.Context, key string) (*StorageEntry, error) {
	if err := s.SanityCheck(key); err != nil {
		return nil, err
	}
	entry, err := s.storage.Get(ctx, s.ExpandKey(key))
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	entry.Key = s.TruncateKey(entry.Key)

	return &StorageEntry{
		Key:      entry.Key,
		Value:    entry.Value,
		SealWrap: entry.SealWrap,
	}, nil
}

func (s *storageView) Put(ctx context.Context, entry *StorageEntry) error {
	if entry == nil {
		return errors.New("cannot write nil entry")
	}

	if err := s.SanityCheck(entry.Key); err != nil {
		return err
	}

	expandedKey := s.ExpandKey(entry.Key)

	nested := &StorageEntry{
		Key:      expandedKey,
		Value:    entry.Value,
		SealWrap: entry.SealWrap,
	}

	return s.storage.Put(ctx, nested)
}

func (s *storageView) Delete(ctx context.Context, key string) error {
	if err := s.SanityCheck(key); err != nil {
		return err
	}

	expandedKey := s.ExpandKey(key)

	return s.storage.Delete(ctx, expandedKey)
}

// Prefix returns the prefix of storage this storage view is limited to.
func (s *storageView) Prefix() string {
	return s.prefix
}

// SubView constructs a nested sub-view using the given prefix
func (s *storageView) SubView(prefix string) StorageView {
	sub := s.ExpandKey(prefix)
	return NewStorageView(s.storage, sub)
}

// SanityCheck is used to perform a sanity check on a key
func (s *storageView) SanityCheck(key string) error {
	if strings.Contains(key, "..") {
		return ErrRelativePath
	}
	return nil
}

// ExpandKey is used to expand to the full key path with the prefix
func (s *storageView) ExpandKey(suffix string) string {
	return s.prefix + suffix
}

// TruncateKey is used to remove the prefix of the key
func (s *storageView) TruncateKey(full string) string {
	return strings.TrimPrefix(full, s.prefix)
}

type transactionalStorageView struct {
	storageView
}

var (
	_ Storage                  = &transactionalStorageView{}
	_ StorageView              = &transactionalStorageView{}
	_ TransactionalStorage     = &transactionalStorageView{}
	_ TransactionalStorageView = &transactionalStorageView{}
)

type storageViewTransaction struct {
	storageView
}

var (
	_ Storage                = &storageViewTransaction{}
	_ StorageView            = &storageViewTransaction{}
	_ Transaction            = &storageViewTransaction{}
	_ StorageViewTransaction = &storageViewTransaction{}
)

// logical.TransactionalStorage impl.
func (s *transactionalStorageView) BeginReadOnlyTx(ctx context.Context) (Transaction, error) {
	txn, err := s.storageView.storage.(TransactionalStorage).BeginReadOnlyTx(ctx)
	if err != nil {
		return nil, err
	}

	return &storageViewTransaction{
		storageView{
			storage: txn,
			prefix:  s.prefix,
		},
	}, nil
}

func (s *transactionalStorageView) BeginTx(ctx context.Context) (Transaction, error) {
	txn, err := s.storageView.storage.(TransactionalStorage).BeginTx(ctx)
	if err != nil {
		return nil, err
	}

	return &storageViewTransaction{
		storageView{
			storage: txn,
			prefix:  s.prefix,
		},
	}, nil
}

// storage.Transaction impl.
func (s *storageViewTransaction) Commit(ctx context.Context) error {
	return s.storageView.storage.(Transaction).Commit(ctx)
}

func (s *storageViewTransaction) Rollback(ctx context.Context) error {
	return s.storageView.storage.(Transaction).Rollback(ctx)
}
