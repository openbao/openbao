// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package physical

import (
	"context"
	"sync"
	"sync/atomic"

	metrics "github.com/armon/go-metrics"
	log "github.com/hashicorp/go-hclog"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/openbao/openbao/sdk/v2/helper/locksutil"
	"github.com/openbao/openbao/sdk/v2/helper/pathmanager"
)

const (
	// DefaultCacheSize is used if no cache size is specified for NewCache
	DefaultCacheSize = 128 * 1024

	// TransactionCacheFactor is a multiple of cache size to reduce
	// transactions by, to avoid high memory usage.
	TransactionCacheFactor = DefaultParallelTransactions

	// refreshCacheCtxKey is a ctx value that denotes the cache should be
	// refreshed during a Get call.
	refreshCacheCtxKey = "refresh_cache"
)

// These paths don't need to be cached by the LRU cache. This should
// particularly help memory pressure when unsealing.
var cacheExceptionsPaths = []string{
	"wal/logs/",
	"index/pages/",
	"index-dr/pages/",
	"sys/expire/",
	"core/poison-pill",
	"core/raft/tls",

	// Add barrierSealConfigPath and recoverySealConfigPlaintextPath to the cache
	// exceptions to avoid unseal errors. See VAULT-17227
	"core/seal-config",
	"core/recovery-config",
}

// CacheRefreshContext returns a context with an added value denoting if the
// cache should attempt a refresh.
func CacheRefreshContext(ctx context.Context, r bool) context.Context {
	return context.WithValue(ctx, refreshCacheCtxKey, r)
}

// cacheRefreshFromContext is a helper to look up if the provided context is
// requesting a cache refresh.
func cacheRefreshFromContext(ctx context.Context) bool {
	r, ok := ctx.Value(refreshCacheCtxKey).(bool)
	if !ok {
		return false
	}
	return r
}

// Cache is used to wrap an underlying physical backend
// and provide an LRU cache layer on top. Most of the reads done by
// Vault are for policy objects so there is a large read reduction
// by using a simple write-through cache.
type Cache interface {
	ToggleablePurgemonster
	Backend
}

type TransactionalCache interface {
	ToggleablePurgemonster
	TransactionalBackend
}

type cache struct {
	backend         Backend
	size            int
	lru             *lru.TwoQueueCache[string, *Entry]
	locks           []*locksutil.LockEntry
	logger          log.Logger
	enabled         *uint32
	cacheExceptions *pathmanager.PathManager
	metricSink      metrics.MetricSink
}

type transactionalCache struct {
	cache
}

type cacheTransaction struct {
	cache
	parent TransactionalCache

	// lock is necessary because, while cache.locks protects access to the
	// same key from parallel threads, we could still adding new modified
	// entries with different keys from parallel threads.
	modifiedLock sync.Mutex
	modified     map[string]struct{}
}

// Verify Cache satisfies the correct interfaces
var (
	_ ToggleablePurgemonster = &cache{}
	_ Backend                = &cache{}

	_ ToggleablePurgemonster = &transactionalCache{}
	_ TransactionalBackend   = &transactionalCache{}

	_ Transaction = &cacheTransaction{}
)

// NewCache returns a physical cache of the given size.
// If no size is provided, the default size is used.
func NewCache(b Backend, size int, logger log.Logger, metricSink metrics.MetricSink) Cache {
	if logger.IsDebug() {
		logger.Debug("creating LRU cache", "size", size)
	}

	return newCache(b, size, logger, metricSink)
}

func newCache(b Backend, size int, logger log.Logger, metricSink metrics.MetricSink) Cache {
	if size <= 0 {
		size = DefaultCacheSize
	}

	pm := pathmanager.New()
	pm.AddPaths(cacheExceptionsPaths)

	lruCache, _ := lru.New2Q[string, *Entry](size)
	c := &cache{
		backend: b,
		size:    size,
		lru:     lruCache,
		locks:   locksutil.CreateLocks(),
		logger:  logger,
		// This fails safe.
		enabled:         new(uint32),
		cacheExceptions: pm,
		metricSink:      metricSink,
	}

	if _, ok := b.(TransactionalBackend); ok {
		return &transactionalCache{
			*c,
		}
	}

	return c
}

func (c *cache) ShouldCache(key string) bool {
	if atomic.LoadUint32(c.enabled) == 0 {
		return false
	}

	return !c.cacheExceptions.HasPath(key)
}

// SetEnabled is used to toggle whether the cache is on or off. It must be
// called with true to actually activate the cache after creation.
func (c *cache) SetEnabled(enabled bool) {
	if enabled {
		atomic.StoreUint32(c.enabled, 1)
		return
	}
	atomic.StoreUint32(c.enabled, 0)
}

func (c *cache) GetEnabled() bool {
	return atomic.LoadUint32(c.enabled) == 1
}

// Purge is used to clear the cache
func (c *cache) Purge(ctx context.Context) {
	// Lock the world
	for _, lock := range c.locks {
		lock.Lock()
		defer lock.Unlock()
	}

	c.lru.Purge()
}

// modifications to this function should also be applied to cacheTransaction.
func (c *cache) Put(ctx context.Context, entry *Entry) error {
	if entry != nil && !c.ShouldCache(entry.Key) {
		return c.backend.Put(ctx, entry)
	}

	lock := locksutil.LockForKey(c.locks, entry.Key)
	lock.Lock()
	defer lock.Unlock()

	err := c.backend.Put(ctx, entry)
	if err == nil {
		// While lower layers could modify entry, we want to ensure we don't
		// open ourselves up to cache modification so clone the entry.
		cacheEntry := &Entry{
			Key:      entry.Key,
			SealWrap: entry.SealWrap,
		}
		if entry.Value != nil {
			cacheEntry.Value = make([]byte, len(entry.Value))
			copy(cacheEntry.Value, entry.Value)
		}
		if entry.ValueHash != nil {
			cacheEntry.ValueHash = make([]byte, len(entry.ValueHash))
			copy(cacheEntry.ValueHash, entry.ValueHash)
		}
		c.lru.Add(entry.Key, cacheEntry)
		c.metricSink.IncrCounter([]string{"cache", "write"}, 1)
	}
	return err
}

func (c *cache) Get(ctx context.Context, key string) (*Entry, error) {
	if !c.ShouldCache(key) {
		return c.backend.Get(ctx, key)
	}

	lock := locksutil.LockForKey(c.locks, key)
	lock.RLock()
	defer lock.RUnlock()

	// Check the LRU first
	if !cacheRefreshFromContext(ctx) {
		if raw, ok := c.lru.Get(key); ok {
			if raw == nil {
				return nil, nil
			}
			c.metricSink.IncrCounter([]string{"cache", "hit"}, 1)
			return raw, nil
		}
	}

	c.metricSink.IncrCounter([]string{"cache", "miss"}, 1)
	// Read from the underlying backend
	ent, err := c.backend.Get(ctx, key)
	if err != nil {
		return nil, err
	}

	// Cache the result, even if nil
	c.lru.Add(key, ent)

	return ent, nil
}

// modifications to this function should also be applied to cacheTransaction
func (c *cache) Delete(ctx context.Context, key string) error {
	if !c.ShouldCache(key) {
		return c.backend.Delete(ctx, key)
	}

	lock := locksutil.LockForKey(c.locks, key)
	lock.Lock()
	defer lock.Unlock()

	err := c.backend.Delete(ctx, key)
	if err == nil {
		c.lru.Remove(key)
	}
	return err
}

func (c *cache) List(ctx context.Context, prefix string) ([]string, error) {
	// Always pass-through as this would be difficult to cache. For the same
	// reason we don't lock as we can't reasonably know which locks to readlock
	// ahead of time.
	return c.backend.List(ctx, prefix)
}

func (c *cache) ListPage(ctx context.Context, prefix string, after string, limit int) ([]string, error) {
	// See note above about List(...).
	return c.backend.ListPage(ctx, prefix, after, limit)
}

func (c *cache) cloneWithStorage(b Backend) *cache {
	// We construct a new cache here: this starts the transaction with a
	// fresh, localized cache. This is globally sub-optimal (as it starts
	// with an empty cache), but easiest to implement (as the transaction can
	// modify its cache as it pleases).
	cacheCopy := newCache(b, c.size/TransactionCacheFactor, c.logger, c.metricSink).(*cache)
	cacheCopy.SetEnabled(c.GetEnabled())
	return cacheCopy
}

func (c *transactionalCache) BeginReadOnlyTx(ctx context.Context) (Transaction, error) {
	txn, err := c.cache.backend.(TransactionalBackend).BeginReadOnlyTx(ctx)
	if err != nil {
		return nil, err
	}

	// txn does not implement TransactionalBackend because we don't support
	// nested transactions so this will always cast to *cache.
	ctxn := c.cloneWithStorage(txn)
	return &cacheTransaction{
		*ctxn,
		c,
		sync.Mutex{},
		make(map[string]struct{}),
	}, nil
}

func (c *transactionalCache) BeginTx(ctx context.Context) (Transaction, error) {
	txn, err := c.backend.(TransactionalBackend).BeginTx(ctx)
	if err != nil {
		return nil, err
	}

	// See note above in BeginReadOnlyTx(...).
	ctxn := c.cloneWithStorage(txn)
	return &cacheTransaction{
		*ctxn,
		c,
		sync.Mutex{},
		make(map[string]struct{}),
	}, nil
}

func (c *cacheTransaction) Put(ctx context.Context, entry *Entry) error {
	if entry != nil && !c.ShouldCache(entry.Key) {
		return c.backend.Put(ctx, entry)
	}

	lock := locksutil.LockForKey(c.locks, entry.Key)
	lock.Lock()
	defer lock.Unlock()

	err := c.backend.Put(ctx, entry)
	if err == nil {
		// While lower layers could modify entry, we want to ensure we don't
		// open ourselves up to cache modification so clone the entry.
		cacheEntry := &Entry{
			Key:      entry.Key,
			SealWrap: entry.SealWrap,
		}
		if entry.Value != nil {
			cacheEntry.Value = make([]byte, len(entry.Value))
			copy(cacheEntry.Value, entry.Value)
		}
		if entry.ValueHash != nil {
			cacheEntry.ValueHash = make([]byte, len(entry.ValueHash))
			copy(cacheEntry.ValueHash, entry.ValueHash)
		}
		c.lru.Add(entry.Key, cacheEntry)
		c.modifiedLock.Lock()
		c.modified[entry.Key] = struct{}{}
		c.modifiedLock.Unlock()
		c.metricSink.IncrCounter([]string{"cache", "write"}, 1)
	}
	return err
}

func (c *cacheTransaction) Delete(ctx context.Context, key string) error {
	if !c.ShouldCache(key) {
		return c.backend.Delete(ctx, key)
	}

	lock := locksutil.LockForKey(c.locks, key)
	lock.Lock()
	defer lock.Unlock()

	err := c.backend.Delete(ctx, key)
	if err == nil {
		c.modifiedLock.Lock()
		c.modified[key] = struct{}{}
		c.modifiedLock.Unlock()

		c.lru.Remove(key)
	}
	return err
}

func (c *cacheTransaction) Commit(ctx context.Context) error {
	if err := c.cache.backend.(Transaction).Commit(ctx); err != nil {
		return err
	}

	// Make sure we invalidate any modified entries in the parent cache. Note
	// that because we don't hold a global lock on the parent, we cannot tell
	// if another modification to our key has occurred between when we
	// committed the underlying storage transaction (above) and when we go to
	// update this cache. Thus, removing the value from the cache is the most
	// optimal strategy (incurring one additional read) without causing
	// incorrect behavior.
	c.modifiedLock.Lock()
	for key := range c.modified {
		func() {
			lock := locksutil.LockForKey(c.parent.(*transactionalCache).locks, key)
			lock.Lock()
			defer lock.Unlock()

			c.parent.(*transactionalCache).lru.Remove(key)
		}()
	}
	c.modifiedLock.Unlock()

	return nil
}

func (c *cacheTransaction) Rollback(ctx context.Context) error {
	if err := c.cache.backend.(Transaction).Rollback(ctx); err != nil {
		return err
	}

	// Rollback does not affect the parent cache as we did not modify it or
	// the underlying storage at all.

	return nil
}

// Invalidate removes the value for key from the cache.
// This will not affect transactions that have already been started.
func (c *cache) Invalidate(ctx context.Context, key string) {
	lock := locksutil.LockForKey(c.locks, key)
	lock.Lock()
	defer lock.Unlock()

	c.lru.Remove(key)
}
