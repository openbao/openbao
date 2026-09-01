// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package inmem

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"

	log "github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/sdk/v2/physical"
	"github.com/openbao/openbao/v2/internal/physical/pebbledb"
)

// Verify interfaces are satisfied
var (
	_ physical.Backend   = (*InmemBackend)(nil)
	_ physical.HABackend = (*InmemHABackend)(nil)
	_ physical.Lock      = (*InmemLock)(nil)
)

var (
	ErrPutDisabled    = errors.New("put operations disabled in inmem backend")
	ErrGetDisabled    = errors.New("get operations disabled in inmem backend")
	ErrDeleteDisabled = errors.New("delete operations disabled in inmem backend")
	ErrListDisabled   = errors.New("list operations disabled in inmem backend")
)

// InmemBackend is an in-memory only physical backend. It is useful
// for testing and development situations where the data is not
// expected to be durable.
type InmemBackend struct {
	parent     physical.Backend
	logger     log.Logger
	failGet    atomic.Bool
	failPut    atomic.Bool
	failDelete atomic.Bool
	failList   atomic.Bool
	logOps     bool
}

var _ physical.Backend = &InmemBackend{}

// TransactionalInmemBackend is only separate right now as logical.Storage is
// separate and backends may want to test non-transactional storage devices.
type TransactionalInmemBackend struct {
	InmemBackend
}

var _ physical.TransactionalBackend = &TransactionalInmemBackend{}

// listInMemOp isn't required as it is handled by listPageInMemOp
const (
	PutInMemOp int = 1 << iota
	DeleteInMemOp
	ListInMemOp
	ListPageInMemOp
	GetInMemOp
	BeginTxInMemOp
	BeginReadOnlyTxInMemOp
	CommitTxInMemOp
	RollbackTxInMemOp
)

func OpName(op int) string {
	switch op {
	case PutInMemOp:
		return "put"
	case DeleteInMemOp:
		return "delete"
	case ListInMemOp:
		return "list"
	case ListPageInMemOp:
		return "list-page"
	case GetInMemOp:
		return "get"
	case BeginTxInMemOp:
		return "begin-tx"
	case BeginReadOnlyTxInMemOp:
		return "begin-ro-tx"
	case CommitTxInMemOp:
		return "commit-tx"
	case RollbackTxInMemOp:
		return "rollback-tx"
	}

	return "unknown"
}

type InmemOp struct {
	OpType int
	OpTx   int

	ArgKey   string
	ArgEntry *physical.Entry
	ArgAfter string
	ArgLimit int

	CurrEntry *physical.Entry

	RetList  []string
	RetEntry *physical.Entry
}

type InmemBackendTransaction struct {
	InmemBackend
	parent *TransactionalInmemBackend
}

var _ physical.Transaction = &InmemBackendTransaction{}

func NewDirectInmem(conf map[string]string, logger log.Logger) (physical.Backend, error) {
	if len(conf) == 0 {
		conf = map[string]string{}
	}

	conf["path"] = ":memory:"
	backend, err := pebbledb.NewBackend(conf, logger)
	if err != nil {
		return nil, fmt.Errorf("error creating underlying implementation: %w", err)
	}

	doLog := api.ReadBaoVariable("BAO_INMEM_LOG_ALL_OPS") != ""
	if logger == nil {
		if !doLog {
			logger = log.NewNullLogger()
		} else {
			logger = log.New(log.DefaultOptions)
			logger.SetLevel(log.Trace)
		}
	}

	logger = logger.Named("inmem")

	return &InmemBackend{
		parent: backend,
		logger: logger,
		logOps: doLog,
	}, nil
}

// NewInmem constructs a new in-memory backend
func NewInmem(conf map[string]string, logger log.Logger) (physical.Backend, error) {
	b, err := NewDirectInmem(conf, logger)
	if err != nil {
		return nil, err
	}

	if value, ok := conf["disable_transactions"]; ok && value == "true" {
		return b, nil
	}

	return &TransactionalInmemBackend{
		*b.(*InmemBackend),
	}, nil
}

// Put is used to insert or update an entry
func (i *InmemBackend) Put(ctx context.Context, entry *physical.Entry) error {
	if i.logOps {
		i.logger.Trace("put", "key", entry.Key)
	}

	if i.failPut.Load() {
		return ErrPutDisabled
	}

	return i.parent.Put(ctx, entry)
}

func (i *InmemBackend) FailPut(fail bool) {
	i.failPut.Store(fail)
}

// Get is used to fetch an entry
func (i *InmemBackend) Get(ctx context.Context, key string) (*physical.Entry, error) {
	if i.logOps {
		i.logger.Trace("get", "key", key)
	}

	if i.failGet.Load() {
		return nil, ErrGetDisabled
	}

	return i.parent.Get(ctx, key)
}

func (i *InmemBackend) FailGet(fail bool) {
	i.failGet.Store(fail)
}

// Delete is used to permanently delete an entry
func (i *InmemBackend) Delete(ctx context.Context, key string) error {
	if i.logOps {
		i.logger.Trace("delete", "key", key)
	}

	if i.failDelete.Load() {
		return ErrDeleteDisabled
	}

	return i.parent.Delete(ctx, key)
}

func (i *InmemBackend) FailDelete(fail bool) {
	i.failDelete.Store(fail)
}

// List is used to list all the keys under a given
// prefix, up to the next prefix.
func (i *InmemBackend) List(ctx context.Context, prefix string) ([]string, error) {
	return i.ListPage(ctx, prefix, "", -1)
}

// ListPage is used to list all the keys under a given
// prefix, up to the next prefix, but limiting to a
// specified number of keys after a given entry.
func (i *InmemBackend) ListPage(ctx context.Context, prefix string, after string, limit int) ([]string, error) {
	if i.logOps {
		i.logger.Trace("list", "prefix", prefix, "after", after, "limit", limit)
	}

	if i.failList.Load() {
		return nil, ErrListDisabled
	}

	return i.parent.ListPage(ctx, prefix, after, limit)
}

func (i *InmemBackend) FailList(fail bool) {
	i.failList.Store(fail)
}

func (i *TransactionalInmemBackend) BeginReadOnlyTx(ctx context.Context) (physical.Transaction, error) {
	txn, err := i.parent.(physical.TransactionalBackend).BeginReadOnlyTx(ctx)
	if err != nil {
		return nil, fmt.Errorf("error beginning underlying transaction: %w", err)
	}

	return i.beginTxn(ctx, txn)
}

func (i *TransactionalInmemBackend) BeginTx(ctx context.Context) (physical.Transaction, error) {
	txn, err := i.parent.(physical.TransactionalBackend).BeginTx(ctx)
	if err != nil {
		return nil, fmt.Errorf("error beginning underlying transaction: %w", err)
	}

	return i.beginTxn(ctx, txn)
}

func (i *TransactionalInmemBackend) beginTxn(ctx context.Context, parent physical.Transaction) (physical.Transaction, error) {
	// Grab a transaction pool instance.
	tx := &InmemBackendTransaction{
		InmemBackend: InmemBackend{
			parent: parent,
			logger: i.logger,
			logOps: i.logOps,
		},
		parent: i,
	}

	tx.failGet.Store(i.failGet.Load())
	tx.failPut.Store(i.failPut.Load())
	tx.failDelete.Store(i.failDelete.Load())
	tx.failList.Store(i.failList.Load())

	return tx, nil
}

func (i *InmemBackendTransaction) Commit(ctx context.Context) error {
	return i.InmemBackend.parent.(physical.Transaction).Commit(ctx)
}

func (i *InmemBackendTransaction) Rollback(ctx context.Context) error {
	return i.InmemBackend.parent.(physical.Transaction).Rollback(ctx)
}
