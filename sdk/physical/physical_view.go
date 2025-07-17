// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package physical

import (
	"context"
	"errors"
	"strings"
)

var ErrRelativePath = errors.New("relative paths not supported")

type ViewCore interface {
	Prefix() string
	sanityCheck(key string) error
	expandKey(suffix string) string
	truncateKey(full string) string
}

type View interface {
	Backend
	ViewCore
}

type TransactionalView interface {
	TransactionalBackend
	ViewCore
}

type ViewTransaction interface {
	Transaction
	ViewCore
}

var _ Backend = &view{}

// View represents a prefixed view of a physical backend
type view struct {
	backend Backend
	prefix  string
}

// NewView takes an underlying physical backend and returns
// a view of it that can only operate with the given prefix.
func NewView(backend Backend, prefix string) View {
	v := view{
		backend: backend,
		prefix:  prefix,
	}

	if _, ok := backend.(TransactionalBackend); ok {
		return &transactionalView{v}
	}

	if _, ok := backend.(Transaction); ok {
		return &viewTransaction{v}
	}

	return &v
}

// List the contents of the prefixed view
func (v *view) List(ctx context.Context, prefix string) ([]string, error) {
	if err := v.sanityCheck(prefix); err != nil {
		return nil, err
	}
	return v.backend.List(ctx, v.expandKey(prefix))
}

// List a page of the contents of the prefixed view
func (v *view) ListPage(ctx context.Context, prefix string, after string, limit int) ([]string, error) {
	if err := v.sanityCheck(prefix); err != nil {
		return nil, err
	}
	return v.backend.ListPage(ctx, v.expandKey(prefix), after, limit)
}

// Get the key of the prefixed view
func (v *view) Get(ctx context.Context, key string) (*Entry, error) {
	if err := v.sanityCheck(key); err != nil {
		return nil, err
	}
	entry, err := v.backend.Get(ctx, v.expandKey(key))
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	return &Entry{
		Key:   v.truncateKey(entry.Key),
		Value: entry.Value,
	}, nil
}

// Put the entry into the prefix view
func (v *view) Put(ctx context.Context, entry *Entry) error {
	if err := v.sanityCheck(entry.Key); err != nil {
		return err
	}

	nested := &Entry{
		Key:   v.expandKey(entry.Key),
		Value: entry.Value,
	}
	return v.backend.Put(ctx, nested)
}

// Delete the entry from the prefix view
func (v *view) Delete(ctx context.Context, key string) error {
	if err := v.sanityCheck(key); err != nil {
		return err
	}
	return v.backend.Delete(ctx, v.expandKey(key))
}

// Prefix returns back prefix of the view
func (v *view) Prefix() string {
	return v.prefix
}

// sanityCheck is used to perform a sanity check on a key
func (v *view) sanityCheck(key string) error {
	if strings.Contains(key, "..") {
		return ErrRelativePath
	}
	return nil
}

// expandKey is used to expand to the full key path with the prefix
func (v *view) expandKey(suffix string) string {
	return v.prefix + suffix
}

// truncateKey is used to remove the prefix of the key
func (v *view) truncateKey(full string) string {
	return strings.TrimPrefix(full, v.prefix)
}

type transactionalView struct {
	view
}

var (
	_ Backend              = &transactionalView{}
	_ TransactionalBackend = &transactionalView{}
	_ TransactionalView    = &transactionalView{}
)

type viewTransaction struct {
	view
}

var (
	_ Backend         = &viewTransaction{}
	_ Transaction     = &viewTransaction{}
	_ ViewTransaction = &viewTransaction{}
)

func (tv *transactionalView) BeginReadOnlyTx(ctx context.Context) (Transaction, error) {
	txn, err := tv.view.backend.(TransactionalBackend).BeginReadOnlyTx(ctx)
	if err != nil {
		return nil, err
	}

	return &viewTransaction{
		view{
			backend: txn,
			prefix:  tv.prefix,
		},
	}, nil
}

func (tv *transactionalView) BeginTx(ctx context.Context) (Transaction, error) {
	txn, err := tv.view.backend.(TransactionalBackend).BeginTx(ctx)
	if err != nil {
		return nil, err
	}

	return &viewTransaction{
		view{
			backend: txn,
			prefix:  tv.prefix,
		},
	}, nil
}

func (vt *viewTransaction) Commit(ctx context.Context) error {
	return vt.view.backend.(Transaction).Commit(ctx)
}

func (vt *viewTransaction) Rollback(ctx context.Context) error {
	return vt.view.backend.(Transaction).Rollback(ctx)
}
