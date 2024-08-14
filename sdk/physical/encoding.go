// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package physical

import (
	"context"
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"
)

var (
	ErrNonUTF8      = errors.New("key contains invalid UTF-8 characters")
	ErrNonPrintable = errors.New("key contains non-printable characters")
)

// StorageEncoding is used to add errors into underlying physical requests
type StorageEncoding interface {
	Backend
}

type storageEncoding struct {
	Backend
}

// TransactionalStorageEncoding is used to add errors to underlying physical
// requests, when the backend supports Transactions.
type TransactionalStorageEncoding interface {
	TransactionalBackend
}

type transactionalStorageEncoding struct {
	storageEncoding
}

type StorageEncodingTransaction interface {
	Transaction
}

type storageEncodingTransaction struct {
	storageEncoding
}

// Verify StorageEncoding satisfies the correct interfaces
var (
	_ Backend              = &storageEncoding{}
	_ TransactionalBackend = &transactionalStorageEncoding{}
	_ Transaction          = &storageEncodingTransaction{}
)

// NewStorageEncoding returns a wrapped physical backend and verifies the key
// encoding
func NewStorageEncoding(b Backend) Backend {
	se := &storageEncoding{
		Backend: b,
	}

	if _, ok := b.(TransactionalBackend); ok {
		return &transactionalStorageEncoding{
			*se,
		}
	}

	return se
}

func (e *storageEncoding) containsNonPrintableChars(key string) bool {
	idx := strings.IndexFunc(key, func(c rune) bool {
		return !unicode.IsPrint(c)
	})

	return idx != -1
}

func (e *storageEncoding) Put(ctx context.Context, entry *Entry) error {
	if !utf8.ValidString(entry.Key) {
		return ErrNonUTF8
	}

	if e.containsNonPrintableChars(entry.Key) {
		return ErrNonPrintable
	}

	return e.Backend.Put(ctx, entry)
}

func (e *storageEncoding) Delete(ctx context.Context, key string) error {
	if !utf8.ValidString(key) {
		return ErrNonUTF8
	}

	if e.containsNonPrintableChars(key) {
		return ErrNonPrintable
	}

	return e.Backend.Delete(ctx, key)
}

func (e *storageEncoding) Purge(ctx context.Context) {
	if purgeable, ok := e.Backend.(ToggleablePurgemonster); ok {
		purgeable.Purge(ctx)
	}
}

func (e *storageEncoding) SetEnabled(enabled bool) {
	if purgeable, ok := e.Backend.(ToggleablePurgemonster); ok {
		purgeable.SetEnabled(enabled)
	}
}

func (e *transactionalStorageEncoding) BeginReadOnlyTx(ctx context.Context) (Transaction, error) {
	txn, err := e.storageEncoding.Backend.(TransactionalBackend).BeginReadOnlyTx(ctx)
	if err != nil {
		return nil, err
	}

	return &storageEncodingTransaction{
		storageEncoding{
			Backend: txn,
		},
	}, nil
}

func (e *transactionalStorageEncoding) BeginTx(ctx context.Context) (Transaction, error) {
	txn, err := e.storageEncoding.Backend.(TransactionalBackend).BeginTx(ctx)
	if err != nil {
		return nil, err
	}

	return &storageEncodingTransaction{
		storageEncoding{
			Backend: txn,
		},
	}, nil
}

func (e *storageEncodingTransaction) Commit(ctx context.Context) error {
	return e.storageEncoding.Backend.(Transaction).Commit(ctx)
}

func (e *storageEncodingTransaction) Rollback(ctx context.Context) error {
	return e.storageEncoding.Backend.(Transaction).Rollback(ctx)
}
