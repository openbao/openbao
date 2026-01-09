//go:build !race

package vault

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/sasha-s/go-deadlock"
)

func TestDetectedDeadlock(t *testing.T) {
	testCore, _, _ := TestCoreUnsealedWithConfig(t, &CoreConfig{DetectDeadlocks: "statelock"})
	InduceDeadlock(t, testCore, 1)
}

func TestDefaultDeadlock(t *testing.T) {
	testCore, _, _ := TestCoreUnsealed(t)
	InduceDeadlock(t, testCore, 0)
}

func RestoreDeadlockOpts() func() {
	opts := deadlock.Opts
	return func() {
		deadlock.Opts = opts
	}
}

func InduceDeadlock(t *testing.T, vaultcore *Core, expected uint32) {
	defer RestoreDeadlockOpts()()
	deadlocks := atomic.Uint32{}
	deadlock.Opts.OnPotentialDeadlock = func() {
		deadlocks.Add(1)
	}
	var mtx deadlock.Mutex
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		vaultcore.expiration.coreStateLock.Lock()
		mtx.Lock()
		mtx.Unlock() //nolint:staticcheck
		vaultcore.expiration.coreStateLock.Unlock()
	}()
	wg.Wait()
	wg.Add(1)
	go func() {
		defer wg.Done()
		mtx.Lock()
		vaultcore.expiration.coreStateLock.RLock()
		vaultcore.expiration.coreStateLock.RUnlock() //nolint:staticcheck
		mtx.Unlock()
	}()
	wg.Wait()
	if deadlocks.Load() != expected {
		t.Fatalf("expected 1 deadlock, detected %d", deadlocks.Load())
	}
}
