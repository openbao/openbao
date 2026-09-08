// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package locksutil

import (
	"context"
	"sync"
)

// KeyedCancelLock is a dynamic set of [CancelLock]s over a generic key type.
// It supports truly individual locking per-key (opposed to a fixed set of
// lock shards) and context cancellation. These properties make it particularly
// useful when managing a set of I/O-ful resources that must not block each
// other but require exclusive access individually.
type KeyedCancelLock[K comparable] struct {
	mu    sync.Mutex
	locks map[K]*keyedCancelLockEntry
}

// keyedCancelLockEntry is the internal representation of entries for
// KeyedCancelLock.
type keyedCancelLockEntry struct {
	CancelLock
	refs int
}

// keyedCancelLockPool is used to pool allocations of [CancelLock]s for
// [KeyedCancelLock].
var keyedCancelLockPool sync.Pool

// resetKeyedCancelLockPool initializes the above. This is made reusable as a
// function only such that the pool can be reset between synctest bubbles, which
// otherwise breaks tests due to channels escaping from bubbles.
func resetKeyedCancelLockPool() {
	keyedCancelLockPool = sync.Pool{
		New: func() any {
			return &keyedCancelLockEntry{
				NewCancelLock(), 0,
			}
		},
	}
}

func init() {
	resetKeyedCancelLockPool()
}

// NewKeyedCancelLock returns a new [KeyedCancelLock].
func NewKeyedCancelLock[K comparable]() *KeyedCancelLock[K] {
	return &KeyedCancelLock[K]{
		locks: make(map[K]*keyedCancelLockEntry),
	}
}

// Lock acquires a lock over the given key unless ctx is canceled therewhile, in
// which case an error is returned.
func (l *KeyedCancelLock[K]) Lock(ctx context.Context, key K) error {
	l.mu.Lock()

	entry, ok := l.locks[key]
	if !ok {
		entry = keyedCancelLockPool.Get().(*keyedCancelLockEntry)
		l.locks[key] = entry
	}

	entry.refs++

	l.mu.Unlock()

	if err := entry.Lock(ctx); err != nil {
		l.unref(key, entry)
		return err
	}

	return nil
}

// Unlock releases the lock over the given key.
func (l *KeyedCancelLock[K]) Unlock(key K) {
	l.mu.Lock()
	entry, ok := l.locks[key]
	l.mu.Unlock()

	if !ok {
		panic("locksutil: unlock of unlocked key in KeyedCancelLock")
	}

	entry.Unlock()
	l.unref(key, entry)
}

func (l *KeyedCancelLock[K]) unref(key K, entry *keyedCancelLockEntry) {
	l.mu.Lock()

	entry.refs--
	if entry.refs == 0 {
		delete(l.locks, key)
		defer keyedCancelLockPool.Put(entry)
	}

	// Don't use a defer for this unlock so the deferred pool put above runs
	// outside of the critical section.
	l.mu.Unlock()
}
