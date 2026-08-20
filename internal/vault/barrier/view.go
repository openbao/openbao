// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package barrier

import (
	"context"
	"errors"
	"sync"

	"github.com/openbao/openbao/sdk/v2/logical"
)

// viewCore defines the core operations unique to BarrierView.
type viewCore interface {
	Prefix() string
	SubView(string) View
	SetReadOnlyErr(error)
	GetReadOnlyErr() error
}

// View wraps a SecurityBarrier and ensures all access is automatically
// prefixed. This is used to prevent anyone with access to the view to access
// any data in the durable storage outside of their prefix. Conceptually this
// is like a "chroot" into the barrier.
//
// View implements logical.Storage so it can be passed in as the
// durable storage mechanism for logical views.
type View interface {
	logical.Storage
	viewCore
}

type view struct {
	storage         logical.StorageView
	readOnlyErr     error
	readOnlyErrLock sync.RWMutex
}

var (
	_ View                  = &view{}
	_ logical.ClearableView = &view{}
)

// TransactionalView is like BarrierView but transactional.
type TransactionalView interface {
	logical.TransactionalStorage
	viewCore
}

type transactionalView struct {
	view
}

var (
	_ View              = &transactionalView{}
	_ TransactionalView = &transactionalView{}
)

// ViewTransaction is the result of beginning a transaction on a
// BarrierView.
type ViewTransaction interface {
	logical.Transaction
	viewCore
}

type viewTransaction struct {
	view
	wasReadOnly bool
}

var (
	_ View                  = &viewTransaction{}
	_ logical.Transaction   = &viewTransaction{}
	_ ViewTransaction       = &viewTransaction{}
	_ logical.ClearableView = &viewTransaction{}
)

// NewView takes an underlying security barrier and returns
// a view of it that can only operate with the given prefix.
func NewView(barrier logical.Storage, prefix string) View {
	return newView(logical.NewStorageView(barrier, prefix))
}

func newView(s logical.StorageView) View {
	if _, ok := s.(logical.TransactionalStorageView); ok {
		return &transactionalView{
			view: view{
				storage: s,
			},
		}
	}

	return &view{
		storage: s,
	}
}

func (v *view) SetReadOnlyErr(readOnlyErr error) {
	v.readOnlyErrLock.Lock()
	defer v.readOnlyErrLock.Unlock()
	v.readOnlyErr = readOnlyErr
}

func (v *view) GetReadOnlyErr() error {
	v.readOnlyErrLock.RLock()
	defer v.readOnlyErrLock.RUnlock()
	return v.readOnlyErr
}

func (v *view) Prefix() string {
	return v.storage.Prefix()
}

func (v *view) List(ctx context.Context, prefix string) ([]string, error) {
	return v.storage.List(ctx, prefix)
}

func (v *view) ListPage(ctx context.Context, prefix string, after string, limit int) ([]string, error) {
	return v.storage.ListPage(ctx, prefix, after, limit)
}

func (v *view) Get(ctx context.Context, key string) (*logical.StorageEntry, error) {
	return v.storage.Get(ctx, key)
}

// Put differs from List/Get because it checks read-only errors
func (v *view) Put(ctx context.Context, entry *logical.StorageEntry) error {
	if entry == nil {
		return errors.New("cannot write nil entry")
	}

	roErr := v.GetReadOnlyErr()
	if roErr != nil {
		return roErr
	}

	return v.storage.Put(ctx, entry)
}

func (v *view) Delete(ctx context.Context, key string) error {
	roErr := v.GetReadOnlyErr()
	if roErr != nil {
		return roErr
	}

	return v.storage.Delete(ctx, key)
}

// SubView constructs a nested sub-view using the given prefix
func (v *view) SubView(prefix string) View {
	bv := newView(v.storage.SubView(prefix))
	bv.SetReadOnlyErr(v.GetReadOnlyErr())
	return bv
}

func (v *transactionalView) BeginReadOnlyTx(ctx context.Context) (logical.Transaction, error) {
	txn, err := v.view.storage.(logical.TransactionalStorage).BeginReadOnlyTx(ctx)
	if err != nil {
		return nil, err
	}

	return &viewTransaction{
		view{
			storage:     txn.(logical.StorageView),
			readOnlyErr: v.GetReadOnlyErr(),
		},
		true,
	}, nil
}

func (v *transactionalView) BeginTx(ctx context.Context) (logical.Transaction, error) {
	txn, err := v.view.storage.(logical.TransactionalStorage).BeginTx(ctx)
	if err != nil {
		return nil, err
	}

	return &viewTransaction{
		view{
			storage:     txn.(logical.StorageView),
			readOnlyErr: v.GetReadOnlyErr(),
		},
		false,
	}, nil
}

func (v *viewTransaction) Commit(ctx context.Context) error {
	roErr := v.GetReadOnlyErr()
	if roErr != nil && !v.wasReadOnly {
		return roErr
	}

	return v.view.storage.(logical.Transaction).Commit(ctx)
}

func (v *viewTransaction) Rollback(ctx context.Context) error {
	return v.view.storage.(logical.Transaction).Rollback(ctx)
}
