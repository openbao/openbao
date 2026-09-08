package physical

import (
	"context"
	"maps"
	"slices"
	"sync"

	log "github.com/hashicorp/go-hclog"
)

type writeNotifier struct {
	backend     Backend
	logger      log.Logger
	notifyWrite InvalidateFunc
}

type transactionalWriteNotifier struct {
	*writeNotifier
}

type writeNotifierTransaction struct {
	*writeNotifier
	txn       Transaction
	writeLock sync.Mutex
	writes    map[string]struct{}
}

func NewWriteNotifier(b Backend, logger log.Logger, notifyWrite InvalidateFunc) Backend {
	w := &writeNotifier{
		backend:     b,
		logger:      logger,
		notifyWrite: notifyWrite,
	}

	if _, ok := b.(TransactionalBackend); ok {
		return &transactionalWriteNotifier{
			w,
		}
	}

	return w
}

// We do nothing here. We don't directly call this hook as its handled by the
// GRPC-based invalidation that is inserted into Core directly. Phrased
// differently, it is impossible to implement this as this particular layer
// is not replicated in any way and thus nothing would be able to call this
// hook on a standby when new data appears.
func (w *writeNotifier) HookInvalidate(hook InvalidateFunc) {}

func (w *writeNotifier) Put(ctx context.Context, entry *Entry) error {
	err := w.backend.Put(ctx, entry)
	if err == nil {
		w.notifyWrite(entry.Key)
	}

	return err
}

func (w *writeNotifier) Get(ctx context.Context, key string) (*Entry, error) {
	return w.backend.Get(ctx, key)
}

func (w *writeNotifier) Delete(ctx context.Context, key string) error {
	err := w.backend.Delete(ctx, key)
	if err == nil {
		w.notifyWrite(key)
	}

	return err
}

func (w *writeNotifier) List(ctx context.Context, prefix string) ([]string, error) {
	return w.backend.List(ctx, prefix)
}

func (w *writeNotifier) ListPage(ctx context.Context, prefix string, after string, limit int) ([]string, error) {
	return w.backend.ListPage(ctx, prefix, after, limit)
}

func (w *transactionalWriteNotifier) BeginReadOnlyTx(ctx context.Context) (Transaction, error) {
	// Read-only transactions don't need write tracking.
	return w.writeNotifier.backend.(TransactionalBackend).BeginReadOnlyTx(ctx)
}

func (w *transactionalWriteNotifier) BeginTx(ctx context.Context) (Transaction, error) {
	txn, err := w.writeNotifier.backend.(TransactionalBackend).BeginTx(ctx)
	if err != nil {
		return nil, err
	}

	return &writeNotifierTransaction{
		writeNotifier: w.writeNotifier,
		txn:           txn,
		writes:        map[string]struct{}{},
	}, nil
}

func (w *writeNotifierTransaction) Put(ctx context.Context, entry *Entry) error {
	w.writeLock.Lock()
	defer w.writeLock.Unlock()

	err := w.txn.Put(ctx, entry)
	if err == nil {
		w.writes[entry.Key] = struct{}{}
	}

	return err
}

func (w *writeNotifierTransaction) Get(ctx context.Context, key string) (*Entry, error) {
	return w.txn.Get(ctx, key)
}

func (w *writeNotifierTransaction) Delete(ctx context.Context, key string) error {
	w.writeLock.Lock()
	defer w.writeLock.Unlock()

	err := w.txn.Delete(ctx, key)
	if err == nil {
		w.writes[key] = struct{}{}
	}

	return err
}

func (w *writeNotifierTransaction) List(ctx context.Context, prefix string) ([]string, error) {
	return w.txn.List(ctx, prefix)
}

func (w *writeNotifierTransaction) ListPage(ctx context.Context, prefix string, after string, limit int) ([]string, error) {
	return w.txn.ListPage(ctx, prefix, after, limit)
}

func (w *writeNotifierTransaction) Commit(ctx context.Context) error {
	w.writeLock.Lock()
	defer w.writeLock.Unlock()

	err := w.txn.Commit(ctx)
	if err == nil {
		w.notifyWrite(slices.Collect(maps.Keys(w.writes))...)
	}
	return err
}

func (w *writeNotifierTransaction) Rollback(ctx context.Context) error {
	return w.txn.Rollback(ctx)
}
