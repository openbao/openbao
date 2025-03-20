// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"errors"
	"sync"

	"github.com/openbao/openbao/sdk/v2/logical"
)

// BarrierCore defines the core operations unique to BarrierView.
type BarrierCore interface {
	Prefix() string
	SubView(string) BarrierView
	SetReadOnlyErr(error)
	GetReadOnlyErr() error
}

// BarrierView wraps a SecurityBarrier and ensures all access is automatically
// prefixed. This is used to prevent anyone with access to the view to access
// any data in the durable storage outside of their prefix. Conceptually this
// is like a "chroot" into the barrier.
//
// BarrierView implements logical.Storage so it can be passed in as the
// durable storage mechanism for logical views.
type BarrierView interface {
	logical.Storage
	BarrierCore
}

type barrierView struct {
	storage         logical.StorageView
	readOnlyErr     error
	readOnlyErrLock sync.RWMutex
}

var (
	_ BarrierView           = &barrierView{}
	_ logical.ClearableView = &barrierView{}
)

// TransactionalBarrierView is like BarrierView but transactional.
type TransactionalBarrierView interface {
	logical.TransactionalStorage
	BarrierCore
}

type transactionalBarrierView struct {
	barrierView
}

var (
	_ BarrierView              = &transactionalBarrierView{}
	_ TransactionalBarrierView = &transactionalBarrierView{}
)

// BarrierViewTransaction is the result of beginning a transaction on a
// BarrierView.
type BarrierViewTransaction interface {
	logical.Transaction
	BarrierCore
}

type barrierViewTransaction struct {
	barrierView
	wasReadOnly bool
}

var (
	_ BarrierView            = &barrierViewTransaction{}
	_ logical.Transaction    = &barrierViewTransaction{}
	_ BarrierViewTransaction = &barrierViewTransaction{}
	_ logical.ClearableView  = &barrierViewTransaction{}
)

// NewBarrierView takes an underlying security barrier and returns
// a view of it that can only operate with the given prefix.
func NewBarrierView(barrier logical.Storage, prefix string) BarrierView {
	return newBarrierView(logical.NewStorageView(barrier, prefix))
}

func newBarrierView(s logical.StorageView) BarrierView {
	bv := &barrierView{
		storage: s,
	}

	if _, ok := s.(logical.TransactionalStorageView); ok {
		return &transactionalBarrierView{
			*bv,
		}
	}

	return bv
}

func (v *barrierView) SetReadOnlyErr(readOnlyErr error) {
	v.readOnlyErrLock.Lock()
	defer v.readOnlyErrLock.Unlock()
	v.readOnlyErr = readOnlyErr
}

func (v *barrierView) GetReadOnlyErr() error {
	v.readOnlyErrLock.RLock()
	defer v.readOnlyErrLock.RUnlock()
	return v.readOnlyErr
}

func (v *barrierView) Prefix() string {
	return v.storage.Prefix()
}

func (v *barrierView) List(ctx context.Context, prefix string) ([]string, error) {
	return v.storage.List(ctx, prefix)
}

func (v *barrierView) ListPage(ctx context.Context, prefix string, after string, limit int) ([]string, error) {
	return v.storage.ListPage(ctx, prefix, after, limit)
}

func (v *barrierView) Get(ctx context.Context, key string) (*logical.StorageEntry, error) {
	return v.storage.Get(ctx, key)
}

// Put differs from List/Get because it checks read-only errors
func (v *barrierView) Put(ctx context.Context, entry *logical.StorageEntry) error {
	if entry == nil {
		return errors.New("cannot write nil entry")
	}

	roErr := v.GetReadOnlyErr()
	if roErr != nil {
		return roErr
	}

	return v.storage.Put(ctx, entry)
}

func (v *barrierView) Delete(ctx context.Context, key string) error {
	roErr := v.GetReadOnlyErr()
	if roErr != nil {
		return roErr
	}

	return v.storage.Delete(ctx, key)
}

// SubView constructs a nested sub-view using the given prefix
func (v *barrierView) SubView(prefix string) BarrierView {
	bv := newBarrierView(v.storage.SubView(prefix))
	bv.SetReadOnlyErr(v.GetReadOnlyErr())
	return bv
}

func (v *transactionalBarrierView) BeginReadOnlyTx(ctx context.Context) (logical.Transaction, error) {
	txn, err := v.barrierView.storage.(logical.TransactionalStorage).BeginReadOnlyTx(ctx)
	if err != nil {
		return nil, err
	}

	return &barrierViewTransaction{
		barrierView{
			storage:     txn.(logical.StorageView),
			readOnlyErr: v.GetReadOnlyErr(),
		},
		true,
	}, nil
}

func (v *transactionalBarrierView) BeginTx(ctx context.Context) (logical.Transaction, error) {
	txn, err := v.barrierView.storage.(logical.TransactionalStorage).BeginTx(ctx)
	if err != nil {
		return nil, err
	}

	return &barrierViewTransaction{
		barrierView{
			storage:     txn.(logical.StorageView),
			readOnlyErr: v.GetReadOnlyErr(),
		},
		false,
	}, nil
}

func (v *barrierViewTransaction) Commit(ctx context.Context) error {
	roErr := v.GetReadOnlyErr()
	if roErr != nil && !v.wasReadOnly {
		return roErr
	}

	return v.barrierView.storage.(logical.Transaction).Commit(ctx)
}

func (v *barrierViewTransaction) Rollback(ctx context.Context) error {
	return v.barrierView.storage.(logical.Transaction).Rollback(ctx)
}
