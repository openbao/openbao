// Copyright (c) 2024 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package logical

import (
	"context"
	"errors"
)

type contextKey string

const TransactionContextKey contextKey = "transaction"

// Transactional is an optional interface for backends that support
// interactive (mixed code & statement) transactions in a similar
// style as Go's Database paradigm. This is equivalent to
// physical.Transactional, not the earlier, one-shot version of the
// interface.
type Transactional interface {
	// This function allows the creation of a new interactive transaction
	// handle, only supporting read operations. Attempts to perform write
	// operations (Put(...) or Delete(...)) will err.
	BeginReadOnlyTx(context.Context) (Transaction, error)

	// This function allows the creation of a new interactive transaction
	// handle, supporting read/write transactions. In some cases, the
	// underlying physical storage backend cannot handle parallel read/write
	// transactions.
	BeginTx(context.Context) (Transaction, error)
}

// Transaction is an interactive transactional interface: backend storage
// operations can be performed, and when finished, Commit or Rollback can
// be called. When a read-only transaction is created, write calls (Put(...)
// and Delete(...)) will err out.
type Transaction interface {
	Storage

	// Commit a transaction; this is equivalent to Rollback on a read-only
	// transaction. Either Commit or Rollback must be called to release
	// resources.
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

// FromContext will return Transaction from context where available
func FromContext(ctx context.Context) (Transaction, error) {
	if ctx == nil {
		return nil, errors.New("context was nil")
	}

	txRaw := ctx.Value(TransactionContextKey)
	if txRaw == nil {
		return nil, errors.New("context does not have transaction")
	}

	tx, ok := txRaw.(Transaction)
	if !ok || tx == nil {
		return nil, errors.New("context does not have transaction")
	}

	return tx, nil
}
