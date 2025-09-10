// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"math/rand"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGrabLockOrStopped is a non-deterministic test to detect deadlocks in the
// grabLockOrStopped function. This test starts a bunch of workers which
// continually lock/unlock and rlock/runlock the same RWMutex. Each worker also
// starts a goroutine which closes the stop channel 1/2 the time, which races
// with acquisition of the lock.
func TestGrabLockOrStop(t *testing.T) {
	// Stop the test early if we deadlock.
	const (
		workers      = 100
		testDuration = time.Second
		testTimeout  = 10 * testDuration
	)
	done := make(chan struct{})
	defer close(done)
	var lockCount int64
	go func() {
		select {
		case <-done:
		case <-time.After(testTimeout):
			panic(fmt.Sprintf("deadlock after %d lock count",
				atomic.LoadInt64(&lockCount)))
		}
	}()

	// lock is locked/unlocked and rlocked/runlocked concurrently.
	var lock sync.RWMutex
	start := time.Now()

	// workerWg is used to wait until all workers exit.
	var workerWg sync.WaitGroup
	workerWg.Add(workers)

	// Start a bunch of worker goroutines.
	for g := range workers {
		g := g
		go func() {
			defer workerWg.Done()
			for time.Since(start) < testDuration {
				stop := make(chan struct{})

				// closerWg waits until the closer goroutine exits before we do
				// another iteration. This makes sure goroutines don't pile up.
				var closerWg sync.WaitGroup
				closerWg.Add(1)
				go func() {
					defer closerWg.Done()
					// Close the stop channel half the time.
					if rand.Int()%2 == 0 {
						close(stop)
					}
				}()

				// Half the goroutines lock/unlock and the other half rlock/runlock.
				if g%2 == 0 {
					if !grabLockOrStop(lock.Lock, lock.Unlock, stop) {
						lock.Unlock()
					}
				} else {
					if !grabLockOrStop(lock.RLock, lock.RUnlock, stop) {
						lock.RUnlock()
					}
				}

				closerWg.Wait()

				// This lets us know how many lock/unlock and rlock/runlock have
				// happened if there's a deadlock.
				atomic.AddInt64(&lockCount, 1)
			}
		}()
	}
	workerWg.Wait()
}

func TestCoreRestart(t *testing.T) {
	t.Parallel()

	t.Run("active", func(t *testing.T) {
		t.Skip("there is a data-race in waitForLeadership: https://github.com/openbao/openbao/blob/5a93ec0549a88516a8a15e96ef74dadac8ed506f/vault/ha.go#L676-L687")
		testCoreRestart(t, 0)
	})
	t.Run("standby", func(t *testing.T) {
		testCoreRestart(t, 1)
	})
}

func testCoreRestart(t *testing.T, core int) {
	t.Parallel()

	c := NewTestCluster(t, &CoreConfig{}, &TestClusterOptions{
		NumCores: 2,
	})

	c.Start()
	defer c.Cleanup()

	TestWaitActive(t, c.Cores[0].Core)

	c.Cores[core].stateLock.RLock()
	activeContextDone := c.Cores[core].activeContext.Done()
	c.Cores[core].stateLock.RUnlock()

	// trigger the restart
	c.Cores[core].restart()

	// wait until the active context is cancelled
	select {
	case <-activeContextDone:
	case <-time.NewTimer(10 * time.Second).C:
		t.Fatal("timeout while waiting for context to be cancelled")
	}

	// a new context should be started
	require.EventuallyWithT(t, func(t *assert.CollectT) {
		c.Cores[core].stateLock.RLock()
		defer c.Cores[core].stateLock.RUnlock()
		require.NotNil(t, c.Cores[core].activeContext)
		require.Nil(t, c.Cores[core].activeContext.Err())
	}, 10*time.Second, 10*time.Millisecond)
}
