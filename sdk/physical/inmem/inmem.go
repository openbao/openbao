// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package inmem

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/armon/go-radix"
	log "github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/sdk/v2/physical"
)

// Verify interfaces are satisfied
var (
	_ physical.Backend   = (*InmemBackend)(nil)
	_ physical.HABackend = (*InmemHABackend)(nil)
	_ physical.Lock      = (*InmemLock)(nil)
)

var (
	PutDisabledError    = errors.New("put operations disabled in inmem backend")
	GetDisabledError    = errors.New("get operations disabled in inmem backend")
	DeleteDisabledError = errors.New("delete operations disabled in inmem backend")
	ListDisabledError   = errors.New("list operations disabled in inmem backend")
)

// InmemBackend is an in-memory only physical backend. It is useful
// for testing and development situations where the data is not
// expected to be durable.
type InmemBackend struct {
	sync.RWMutex
	root         *radix.Tree
	permitPool   *physical.PermitPool
	logger       log.Logger
	failGet      *uint32
	failPut      *uint32
	failDelete   *uint32
	failList     *uint32
	logOps       bool
	maxValueSize int
}

var _ physical.Backend = &InmemBackend{}

type TransactionalInmemBackend struct {
	InmemBackend

	txnPermitPool *physical.PermitPool
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

	txLock     sync.Mutex
	writable   bool
	written    bool
	finishedTx bool
	operations []*InmemOp
	parent     *TransactionalInmemBackend
}

var _ physical.Transaction = &InmemBackendTransaction{}

func NewDirectInmem(conf map[string]string, logger log.Logger) (physical.Backend, error) {
	maxValueSize := 0
	maxValueSizeStr, ok := conf["max_value_size"]
	if ok {
		var err error
		maxValueSize, err = strconv.Atoi(maxValueSizeStr)
		if err != nil {
			return nil, err
		}
	}

	return &InmemBackend{
		root:         radix.New(),
		permitPool:   physical.NewPermitPool(physical.DefaultParallelOperations),
		logger:       logger,
		failGet:      new(uint32),
		failPut:      new(uint32),
		failDelete:   new(uint32),
		failList:     new(uint32),
		logOps:       api.ReadBaoVariable("BAO_INMEM_LOG_ALL_OPS") != "",
		maxValueSize: maxValueSize,
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
		physical.NewPermitPool(physical.DefaultParallelOperations),
	}, nil
}

// Put is used to insert or update an entry
func (i *InmemBackend) Put(ctx context.Context, entry *physical.Entry) error {
	i.permitPool.Acquire()
	defer i.permitPool.Release()

	i.Lock()
	defer i.Unlock()

	return i.PutInternal(ctx, entry)
}

func (i *InmemBackend) PutInternal(ctx context.Context, entry *physical.Entry) error {
	if i.logOps {
		i.logger.Trace("put", "key", entry.Key)
	}
	if atomic.LoadUint32(i.failPut) != 0 {
		return PutDisabledError
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	if i.maxValueSize > 0 && len(entry.Value) > i.maxValueSize {
		return fmt.Errorf("%s", physical.ErrValueTooLarge)
	}

	i.root.Insert(entry.Key, entry.Value)
	return nil
}

func (i *InmemBackend) FailPut(fail bool) {
	var val uint32
	if fail {
		val = 1
	}
	atomic.StoreUint32(i.failPut, val)
}

// Get is used to fetch an entry
func (i *InmemBackend) Get(ctx context.Context, key string) (*physical.Entry, error) {
	i.permitPool.Acquire()
	defer i.permitPool.Release()

	i.RLock()
	defer i.RUnlock()

	return i.GetInternal(ctx, key)
}

func (i *InmemBackend) GetInternal(ctx context.Context, key string) (*physical.Entry, error) {
	if i.logOps {
		i.logger.Trace("get", "key", key)
	}
	if atomic.LoadUint32(i.failGet) != 0 {
		return nil, GetDisabledError
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	return i.getInternal(ctx, key)
}

func (i *InmemBackend) getInternal(ctx context.Context, key string) (*physical.Entry, error) {
	if raw, ok := i.root.Get(key); ok {
		return &physical.Entry{
			Key:   key,
			Value: raw.([]byte),
		}, nil
	}
	return nil, nil
}

func (i *InmemBackend) FailGet(fail bool) {
	var val uint32
	if fail {
		val = 1
	}
	atomic.StoreUint32(i.failGet, val)
}

// Delete is used to permanently delete an entry
func (i *InmemBackend) Delete(ctx context.Context, key string) error {
	i.permitPool.Acquire()
	defer i.permitPool.Release()

	i.Lock()
	defer i.Unlock()

	return i.DeleteInternal(ctx, key)
}

func (i *InmemBackend) DeleteInternal(ctx context.Context, key string) error {
	if i.logOps {
		i.logger.Trace("delete", "key", key)
	}
	if atomic.LoadUint32(i.failDelete) != 0 {
		return DeleteDisabledError
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	i.root.Delete(key)
	return nil
}

func (i *InmemBackend) FailDelete(fail bool) {
	var val uint32
	if fail {
		val = 1
	}
	atomic.StoreUint32(i.failDelete, val)
}

// List is used to list all the keys under a given
// prefix, up to the next prefix.
func (i *InmemBackend) List(ctx context.Context, prefix string) ([]string, error) {
	i.permitPool.Acquire()
	defer i.permitPool.Release()

	i.RLock()
	defer i.RUnlock()

	return i.ListInternal(ctx, prefix)
}

// ListPage is used to list all the keys under a given
// prefix, up to the next prefix, but limiting to a
// specified number of keys after a given entry.
func (i *InmemBackend) ListPage(ctx context.Context, prefix string, after string, limit int) ([]string, error) {
	i.permitPool.Acquire()
	defer i.permitPool.Release()

	i.RLock()
	defer i.RUnlock()

	return i.ListPaginatedInternal(ctx, prefix, after, limit)
}

func (i *InmemBackend) ListInternal(ctx context.Context, prefix string) ([]string, error) {
	return i.ListPaginatedInternal(ctx, prefix, "", -1)
}

func (i *InmemBackend) ListPaginatedInternal(ctx context.Context, prefix string, after string, limit int) ([]string, error) {
	if i.logOps {
		i.logger.Trace("list", "prefix", prefix)
	}
	if atomic.LoadUint32(i.failList) != 0 {
		return nil, ListDisabledError
	}

	return i.listPaginatedInternal(ctx, prefix, after, limit)
}

func (i *InmemBackend) listPaginatedInternal(ctx context.Context, prefix string, after string, limit int) ([]string, error) {
	var out []string
	seen := make(map[string]interface{})
	walkFn := func(s string, v interface{}) bool {
		if limit > 0 && len(out) >= limit {
			// We've seen enough entries; exit early.
			return true
		}

		// Note that we push the comparison with trimmed down until
		// after we add in the directory suffix, if necessary.
		trimmed := strings.TrimPrefix(s, prefix)
		sep := strings.Index(trimmed, "/")
		if sep == -1 {
			if after != "" && trimmed <= after {
				// Still prior to our cut-off point, so retry.
				return false
			}

			out = append(out, trimmed)
		} else {
			// Include the directory suffix to distinguish keys from
			// subtrees.
			trimmed = trimmed[:sep+1]
			if after != "" && trimmed <= after {
				// Still prior to our cut-off point, so retry.
				return false
			}

			if _, ok := seen[trimmed]; !ok {
				out = append(out, trimmed)
				seen[trimmed] = struct{}{}
			}
		}

		return false
	}
	i.root.WalkPrefix(prefix, walkFn)

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	return out, nil
}

func (i *InmemBackend) FailList(fail bool) {
	var val uint32
	if fail {
		val = 1
	}
	atomic.StoreUint32(i.failList, val)
}

func (i *TransactionalInmemBackend) BeginReadOnlyTx(ctx context.Context) (physical.Transaction, error) {
	tx, err := i.BeginTx(ctx)
	if err != nil {
		return nil, err
	}

	itx := tx.(*InmemBackendTransaction)
	itx.writable = false

	return tx, nil
}

func (i *TransactionalInmemBackend) BeginTx(ctx context.Context) (physical.Transaction, error) {
	i.Lock()
	defer i.Unlock()

	// Grab a transaction pool instance.
	i.txnPermitPool.Acquire()

	tx := &InmemBackendTransaction{
		InmemBackend: InmemBackend{
			root:         radix.NewFromMap(i.root.ToMap()),
			permitPool:   physical.NewPermitPool(physical.DefaultParallelOperations),
			logger:       i.logger,
			failGet:      new(uint32),
			failPut:      new(uint32),
			failDelete:   new(uint32),
			failList:     new(uint32),
			logOps:       i.logOps,
			maxValueSize: i.maxValueSize,
		},
		writable: true,
		written:  false,
		parent:   i,
	}

	*tx.failGet = *i.failGet
	*tx.failPut = *i.failPut
	*tx.failDelete = *i.failDelete
	*tx.failList = *i.failList

	return tx, nil
}

func (i *InmemBackendTransaction) Put(ctx context.Context, entry *physical.Entry) error {
	i.txLock.Lock()
	defer i.txLock.Unlock()

	if !i.writable {
		return physical.ErrTransactionReadOnly
	}

	if i.finishedTx {
		return physical.ErrTransactionAlreadyCommitted
	}

	currEntry, err := i.getInternal(ctx, entry.Key)
	if err != nil {
		return err
	}
	err = i.InmemBackend.Put(ctx, entry)
	if err == nil {
		op := &InmemOp{
			OpType: PutInMemOp,
			ArgKey: entry.Key,
			ArgEntry: &physical.Entry{
				Key:   entry.Key,
				Value: make([]byte, len(entry.Value)),
			},
		}
		copy(op.ArgEntry.Value, entry.Value)
		if currEntry != nil {
			op.CurrEntry = &physical.Entry{
				Key:   currEntry.Key,
				Value: make([]byte, len(currEntry.Value)),
			}
			copy(op.CurrEntry.Value, currEntry.Value)
		}
		i.operations = append(i.operations, op)
		i.written = true
	}
	return err
}

func (i *InmemBackendTransaction) Delete(ctx context.Context, key string) error {
	i.txLock.Lock()
	defer i.txLock.Unlock()

	if !i.writable {
		return physical.ErrTransactionReadOnly
	}

	if i.finishedTx {
		return physical.ErrTransactionAlreadyCommitted
	}

	entry, err := i.getInternal(ctx, key)
	if err != nil {
		return err
	}
	err = i.InmemBackend.Delete(ctx, key)
	if err == nil {
		op := &InmemOp{
			OpType: DeleteInMemOp,
			ArgKey: key,
		}
		if entry != nil {
			op.CurrEntry = &physical.Entry{
				Key:   entry.Key,
				Value: make([]byte, len(entry.Value)),
			}
			copy(op.CurrEntry.Value, entry.Value)
		}
		i.operations = append(i.operations, op)
		i.written = true
	}
	return err
}

func (i *InmemBackendTransaction) Get(ctx context.Context, key string) (*physical.Entry, error) {
	i.txLock.Lock()
	defer i.txLock.Unlock()

	if i.finishedTx {
		return nil, physical.ErrTransactionAlreadyCommitted
	}

	entry, err := i.InmemBackend.Get(ctx, key)
	if err == nil {
		op := &InmemOp{
			OpType: GetInMemOp,
			ArgKey: key,
		}
		if entry != nil {
			op.RetEntry = &physical.Entry{
				Key:   entry.Key,
				Value: make([]byte, len(entry.Value)),
			}
			copy(op.RetEntry.Value, entry.Value)
		}
		i.operations = append(i.operations, op)
	}

	return entry, err
}

func (i *InmemBackendTransaction) List(ctx context.Context, prefix string) ([]string, error) {
	i.txLock.Lock()
	defer i.txLock.Unlock()

	if i.finishedTx {
		return nil, physical.ErrTransactionAlreadyCommitted
	}

	entries, err := i.InmemBackend.List(ctx, prefix)
	if err == nil {
		op := &InmemOp{
			OpType: ListInMemOp,
			ArgKey: prefix,
		}
		if entries != nil {
			op.RetList = make([]string, len(entries))
			copy(op.RetList, entries)
		}
		i.operations = append(i.operations, op)
	}
	return entries, err
}

func (i *InmemBackendTransaction) ListPage(ctx context.Context, prefix string, after string, limit int) ([]string, error) {
	i.txLock.Lock()
	defer i.txLock.Unlock()

	if i.finishedTx {
		return nil, physical.ErrTransactionAlreadyCommitted
	}

	entries, err := i.InmemBackend.ListPage(ctx, prefix, after, limit)
	if err == nil {
		op := &InmemOp{
			OpType:   ListPageInMemOp,
			ArgKey:   prefix,
			ArgAfter: after,
			ArgLimit: limit,
		}
		if entries != nil {
			op.RetList = make([]string, len(entries))
			copy(op.RetList, entries)
		}
		i.operations = append(i.operations, op)
	}
	return entries, err
}

func (i *InmemBackendTransaction) Commit(ctx context.Context) error {
	i.txLock.Lock()
	defer i.txLock.Unlock()

	if i.finishedTx {
		return physical.ErrTransactionAlreadyCommitted
	}

	// At this point, we mark the transaction as finished either way.
	i.finishedTx = true
	i.parent.txnPermitPool.Release()

	if !i.writable || !i.written {
		// Nothing to do.
		return nil
	}

	// The following operations update parent's tree, so we'll want
	// to recreate it.
	i.parent.Lock()
	defer i.parent.Unlock()

	// We don't have a way of creating a transaction on the radix tree
	// natively, so we take a copy and restore it on any failure.
	parentCopy := i.parent.root.ToMap()

	retErr := func() error {
		// Replay all operations back on the parent backend.
		for index, op := range i.operations {
			switch op.OpType {
			case GetInMemOp:
				entry, err := i.parent.getInternal(ctx, op.ArgKey)
				if err != nil {
					return fmt.Errorf("get failed: %v: %w", err, physical.ErrTransactionCommitFailure)
				}

				if !reflect.DeepEqual(entry, op.RetEntry) {
					return fmt.Errorf("[%d] gets had different structure: %v vs %v: %w\n%#v", index, entry, op.RetEntry, physical.ErrTransactionCommitFailure, i.operations)
				}
			case ListInMemOp, ListPageInMemOp:
				entries, err := i.parent.listPaginatedInternal(ctx, op.ArgKey, op.ArgAfter, op.ArgLimit)
				if err != nil {
					return fmt.Errorf("list failed: %v: %w", err, physical.ErrTransactionCommitFailure)
				}

				if !reflect.DeepEqual(entries, op.RetList) {
					return fmt.Errorf("[%d] lists had different structure: %v vs %v: %w\n%#v", index, entries, op.RetList, physical.ErrTransactionCommitFailure, i.operations)
				}
			case PutInMemOp:
				entry, err := i.parent.getInternal(ctx, op.ArgKey)
				if err != nil {
					return fmt.Errorf("verify failed: %v: %w", err, physical.ErrTransactionCommitFailure)
				}

				if !reflect.DeepEqual(entry, op.CurrEntry) {
					return fmt.Errorf("[%d] contents changed before put: %v vs %v: %w: %#v", index, entry, op.CurrEntry, physical.ErrTransactionCommitFailure, i.operations)
				}

				i.parent.root.Insert(op.ArgEntry.Key, op.ArgEntry.Value)
			case DeleteInMemOp:
				entry, err := i.parent.getInternal(ctx, op.ArgKey)
				if err != nil {
					return fmt.Errorf("verify failed: %v: %w", err, physical.ErrTransactionCommitFailure)
				}

				if !reflect.DeepEqual(entry, op.CurrEntry) {
					return fmt.Errorf("[%d] contents changed before delete: %v vs %v: %w: %#v", index, entry, op.CurrEntry, physical.ErrTransactionCommitFailure, i.operations)
				}

				i.parent.root.Delete(op.ArgKey)
			default:
				return fmt.Errorf("unknown operation: %v", op.OpType)
			}
		}

		return nil
	}()
	if retErr != nil {
		i.parent.root = radix.NewFromMap(parentCopy)
		return retErr
	}

	// All good. Parent is now up-to-date with the latest state.
	return nil
}

func (i *InmemBackendTransaction) Rollback(ctx context.Context) error {
	i.txLock.Lock()
	defer i.txLock.Unlock()

	if i.finishedTx {
		return physical.ErrTransactionAlreadyCommitted
	}

	i.finishedTx = true
	i.parent.txnPermitPool.Release()

	return nil
}
