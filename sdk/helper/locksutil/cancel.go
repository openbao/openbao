// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package locksutil

import (
	"context"
)

// CancelLock is a lock that supports context cancellation on the acquisition
// path. This is particularly useful when the critical section contains I/O.
type CancelLock struct {
	ch chan struct{}
}

// NewCancelLock returns a new [CancelLock].
func NewCancelLock() CancelLock {
	return CancelLock{
		ch: make(chan struct{}, 1),
	}
}

// Lock acquires the lock unless ctx is canceled therewhile, in which case an
// error is returned.
func (l *CancelLock) Lock(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case l.ch <- struct{}{}:
		return nil
	}
}

// Unlock releases the lock.
func (l *CancelLock) Unlock() {
	select {
	case <-l.ch:
	default:
		panic("locksutil: unlock of unlocked CancelLock")
	}
}
