// Copyright (c) 2024 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0
// This file was completely removed in a prior commit and entirely
// new contents added to it.

package physical

import (
	"context"
	"errors"
)

var (
	ErrTransactionReadOnly         error = errors.New("transaction is read-only")
	ErrTransactionCommitFailure    error = errors.New("transaction commit failed")
	ErrTransactionAlreadyCommitted error = errors.New("transaction has been committed or rolled back")
)

// Transactional is an optional interface for backends that support
// interactive (mixed code & statement) transactions in a similar style
// as Go's Database paradigm. This differs from the earlier Transactional:
// that one is a one-shot (list of transactions to execute) transaction
// interface.
type Transactional interface {
	// This function allows the creation of a new interactive transaction
	// handle, only supporting read operations. Attempts to perform write
	// operations (PUT or DELETE) will result in immediate errors.
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
	Backend

	// Commit a transaction; this is equivalent to Rollback on a read-only
	// transaction. Either Commit or Rollback must be called to release
	// resources.
	Commit(context.Context) error

	// Rollback a transaction, preventing any changes from being persisted.
	// Either Commit or Rollback must be called to release resources.
	Rollback(context.Context) error
}

// TransactionalBackend is implemented if a storage backend implements
// interactive transactions as well as normal backend operations.
type TransactionalBackend interface {
	Backend
	Transactional
}
