// Copyright (c) 2024 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package postgresql

import (
	"context"
	"database/sql"
	"fmt"
	"sync"

	"github.com/openbao/openbao/sdk/v2/physical"
)

type PostgreSQLBackendTransaction struct {
	l  sync.Mutex
	b  *PostgreSQLBackend
	tx *sql.Tx

	readOnly       bool
	haveWritten    bool
	haveFinishedTx bool
}

func (b *PostgreSQLBackend) newTransaction(ctx context.Context, readOnly bool) (physical.Transaction, error) {
	// Grab a transaction permit pool entry so that we can limit the number of
	// concurrent transactions.
	b.txnPermitPool.Acquire()

	tx, err := b.client.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelRepeatableRead,
		ReadOnly:  readOnly,
	})
	if err != nil {
		b.txnPermitPool.Release()
		return nil, fmt.Errorf("failed to start underlying postgresql transaction: %w", err)
	}

	return &PostgreSQLBackendTransaction{
		b:        b,
		tx:       tx,
		readOnly: readOnly,
	}, nil
}

func (b *PostgreSQLBackend) BeginTx(ctx context.Context) (physical.Transaction, error) {
	return b.newTransaction(ctx, false)
}

func (b *PostgreSQLBackend) BeginReadOnlyTx(ctx context.Context) (physical.Transaction, error) {
	return b.newTransaction(ctx, true)
}

func (t *PostgreSQLBackendTransaction) Put(ctx context.Context, entry *physical.Entry) error {
	t.l.Lock()
	defer t.l.Unlock()

	if t.readOnly {
		return physical.ErrTransactionReadOnly
	}
	if t.haveFinishedTx {
		return physical.ErrTransactionAlreadyCommitted
	}

	parentPath, path, key := t.b.splitKey(entry.Key)

	_, err := t.tx.ExecContext(ctx, t.b.putQuery, parentPath, path, key, entry.Value)
	if err != nil {
		return err
	}

	t.haveWritten = true

	return nil
}

func (t *PostgreSQLBackendTransaction) Delete(ctx context.Context, fullPath string) error {
	t.l.Lock()
	defer t.l.Unlock()

	if t.readOnly {
		return physical.ErrTransactionReadOnly
	}
	if t.haveFinishedTx {
		return physical.ErrTransactionAlreadyCommitted
	}

	_, path, key := t.b.splitKey(fullPath)

	_, err := t.tx.ExecContext(ctx, t.b.deleteQuery, path, key)
	if err != nil {
		return err
	}

	t.haveWritten = true

	return nil
}

func (t *PostgreSQLBackendTransaction) Get(ctx context.Context, fullPath string) (*physical.Entry, error) {
	t.l.Lock()
	defer t.l.Unlock()

	if t.haveFinishedTx {
		return nil, physical.ErrTransactionAlreadyCommitted
	}

	_, path, key := t.b.splitKey(fullPath)

	var result []byte
	err := t.tx.QueryRowContext(ctx, t.b.getQuery, path, key).Scan(&result)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	ent := &physical.Entry{
		Key:   fullPath,
		Value: result,
	}
	return ent, nil
}

func (t *PostgreSQLBackendTransaction) List(ctx context.Context, prefix string) ([]string, error) {
	t.l.Lock()
	defer t.l.Unlock()

	if t.haveFinishedTx {
		return nil, physical.ErrTransactionAlreadyCommitted
	}

	rows, err := t.tx.QueryContext(ctx, t.b.listQuery, "/"+prefix)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []string
	for rows.Next() {
		var key string
		err = rows.Scan(&key)
		if err != nil {
			return nil, fmt.Errorf("failed to scan rows: %w", err)
		}

		keys = append(keys, key)
	}

	return keys, nil
}

func (t *PostgreSQLBackendTransaction) ListPage(ctx context.Context, prefix string, after string, limit int) ([]string, error) {
	t.l.Lock()
	defer t.l.Unlock()

	if t.haveFinishedTx {
		return nil, physical.ErrTransactionAlreadyCommitted
	}

	var rows *sql.Rows
	var err error
	if limit <= 0 {
		rows, err = t.tx.QueryContext(ctx, t.b.listPageQuery, "/"+prefix, after)
	} else {
		rows, err = t.tx.QueryContext(ctx, t.b.listPageLimitedQuery, "/"+prefix, after, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []string
	for rows.Next() {
		var key string
		err = rows.Scan(&key)
		if err != nil {
			return nil, fmt.Errorf("failed to scan rows: %w", err)
		}

		keys = append(keys, key)
	}

	return keys, nil
}

func (t *PostgreSQLBackendTransaction) Commit(ctx context.Context) error {
	if t.readOnly || !t.haveWritten {
		return t.Rollback(ctx)
	}

	t.l.Lock()
	defer t.l.Unlock()

	if t.haveFinishedTx {
		return physical.ErrTransactionAlreadyCommitted
	}

	defer func() {
		t.b.txnPermitPool.Release()
		t.haveFinishedTx = true
	}()

	if err := t.b.validateFence(ctx); err != nil {
		return err
	}

	if err := t.tx.Commit(); err != nil {
		return fmt.Errorf("%v: %w", err, physical.ErrTransactionCommitFailure)
	}

	return nil
}

func (t *PostgreSQLBackendTransaction) Rollback(ctx context.Context) error {
	t.l.Lock()
	defer t.l.Unlock()

	if t.haveFinishedTx {
		return physical.ErrTransactionAlreadyCommitted
	}

	defer func() {
		t.b.txnPermitPool.Release()
		t.haveFinishedTx = true
	}()

	if err := t.tx.Rollback(); err != nil {
		return err
	}

	return nil
}
