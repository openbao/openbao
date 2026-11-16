// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package locksutil

import (
	"sync"

	"github.com/openbao/openbao/sdk/v2/helper/cryptoutil"
)

const (
	LockCount = 256
)

// LockEntry is the default lock type used by [CreateLocks].
type LockEntry struct {
	sync.RWMutex
}

// CreateLocks returns an array so that the locks can be iterated over in
// order.
//
// This is only threadsafe if a process is using a single lock, or iterating
// over the entire lock slice in order. Using a consistent order avoids
// deadlocks because you can never have the following:
//
// Lock A, Lock B
// Lock B, Lock A
//
// Where process 1 is now deadlocked trying to lock B, and process 2 deadlocked trying to lock A
func CreateLocks() []*LockEntry {
	ret := make([]*LockEntry, LockCount)
	for i := range ret {
		ret[i] = new(LockEntry)
	}
	return ret
}

// CreateGenericLocks is a generic version of [CreateLocks] that allows choosing
// a different lock implementation (e.g., [sync.Mutex] when shared locks are not
// needed).
func CreateGenericLocks[L any]() []*L {
	ret := make([]*L, LockCount)
	for i := range ret {
		ret[i] = new(L)
	}
	return ret
}

// LockIndexForKey returns the index of the lock for the given key.
func LockIndexForKey(key string) uint8 {
	return uint8(cryptoutil.Blake2b256Hash(key)[0])
}

// LockForKey returns the lock for the given key.
func LockForKey[L any](locks []*L, key string) *L {
	return locks[LockIndexForKey(key)]
}

// LocksForKeys returns all locks that apply for the given keys in a consistent
// order.
func LocksForKeys[L any](locks []*L, keys []string) []*L {
	lockIndexes := make(map[uint8]struct{}, len(keys))
	for _, k := range keys {
		lockIndexes[LockIndexForKey(k)] = struct{}{}
	}

	locksToReturn := make([]*L, 0, len(keys))
	for i, l := range locks {
		if _, ok := lockIndexes[uint8(i)]; ok {
			locksToReturn = append(locksToReturn, l)
		}
	}

	return locksToReturn
}

// LockWithUnlock acquires the lock for the given key and returns the respective
// unlock function.
func LockWithUnlock[L any, P interface {
	*L
	sync.Locker
}](locks []*L, key string) func() {
	l := P(LockForKey(locks, key))
	l.Lock()
	return l.Unlock
}

// RLockWithUnlock acquires a shared lock for the given key and returns the
// respective unlock function.
func RLockWithUnlock[L any, P interface {
	*L
	RLock()
	RUnlock()
}](locks []*L, key string) func() {
	l := P(LockForKey(locks, key))
	l.RLock()
	return l.RUnlock
}
