// Copyright (c) AppsCode Inc.
// SPDX-License-Identifier: MPL-2.0

package runner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	dbplugin "github.com/openbao/openbao/sdk/v2/database/dbplugin/v5"
)

// stubDB is a minimal dbplugin.Database used to exercise the runner's
// cache/refcount discipline without spinning up a real database backend.
//
// Counters are atomic so test assertions can read them while concurrent
// goroutines invoke methods. A 0-value duration in slowClose / slowNewUser
// means "respond immediately"; a positive value sleeps for that long inside
// the method so tests can race acquire/release against close/evict.
type stubDB struct {
	initialized atomic.Int32
	newUser     atomic.Int32
	closed      atomic.Int32

	slowClose   time.Duration
	slowNewUser time.Duration
	initErr     error
}

func (s *stubDB) Initialize(_ context.Context, _ dbplugin.InitializeRequest) (dbplugin.InitializeResponse, error) {
	s.initialized.Add(1)
	if s.initErr != nil {
		return dbplugin.InitializeResponse{}, s.initErr
	}
	return dbplugin.InitializeResponse{Config: map[string]interface{}{"ok": true}}, nil
}

func (s *stubDB) NewUser(_ context.Context, _ dbplugin.NewUserRequest) (dbplugin.NewUserResponse, error) {
	s.newUser.Add(1)
	if s.slowNewUser > 0 {
		time.Sleep(s.slowNewUser)
	}
	return dbplugin.NewUserResponse{Username: "u"}, nil
}

func (s *stubDB) UpdateUser(_ context.Context, _ dbplugin.UpdateUserRequest) (dbplugin.UpdateUserResponse, error) {
	return dbplugin.UpdateUserResponse{}, nil
}

func (s *stubDB) DeleteUser(_ context.Context, _ dbplugin.DeleteUserRequest) (dbplugin.DeleteUserResponse, error) {
	return dbplugin.DeleteUserResponse{}, nil
}

func (s *stubDB) Type() (string, error) { return "stub", nil }

func (s *stubDB) Close() error {
	if s.slowClose > 0 {
		time.Sleep(s.slowClose)
	}
	s.closed.Add(1)
	return nil
}

// withStubLoader swaps loadPluginFunc with one that returns a fresh stubDB
// each time it's called, and restores the original on test cleanup. The
// per-test slice records every stub the runner asked for, so a test can
// assert the cardinality of Initialize / Close calls across handlers.
func withStubLoader(t *testing.T, configure func(*stubDB)) *[]*stubDB {
	t.Helper()
	prev := loadPluginFunc
	var (
		mu    sync.Mutex
		stubs []*stubDB
	)
	loadPluginFunc = func(_ string) (dbplugin.Database, error) {
		s := &stubDB{}
		if configure != nil {
			configure(s)
		}
		mu.Lock()
		stubs = append(stubs, s)
		mu.Unlock()
		return s, nil
	}
	t.Cleanup(func() { loadPluginFunc = prev })
	return &stubs
}

func initializeJSON(t *testing.T, instanceID string) string {
	t.Helper()
	req := map[string]interface{}{
		"method":      "Initialize",
		"plugin_name": "stub-plugin",
		"instance_id": instanceID,
		"config":      map[string]interface{}{"host": "127.0.0.1"},
	}
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func newUserJSON(t *testing.T, instanceID string) string {
	t.Helper()
	req := map[string]interface{}{
		"method":      "NewUser",
		"plugin_name": "stub-plugin",
		"instance_id": instanceID,
		"config":      map[string]interface{}{"host": "127.0.0.1"},
		"username_config": map[string]interface{}{
			"display_name": "test",
			"role_name":    "test",
		},
		"expiration": time.Now().Add(time.Hour).Unix(),
	}
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func closeJSON(t *testing.T, instanceID string) string {
	t.Helper()
	req := map[string]interface{}{
		"method":      "Close",
		"instance_id": instanceID,
	}
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestRunner_InitializeNewUserClose(t *testing.T) {
	stubs := withStubLoader(t, nil)
	r := NewPluginRunnerWithTTL(0)

	if _, err := r.ExecuteRequest(initializeJSON(t, "inst-1")); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	if _, err := r.ExecuteRequest(newUserJSON(t, "inst-1")); err != nil {
		t.Fatalf("NewUser: %v", err)
	}
	if _, err := r.ExecuteRequest(closeJSON(t, "inst-1")); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if got := len(*stubs); got != 1 {
		t.Fatalf("expected 1 plugin instance, got %d", got)
	}
	s := (*stubs)[0]
	if s.initialized.Load() != 1 {
		t.Errorf("Initialize count: got %d, want 1", s.initialized.Load())
	}
	if s.newUser.Load() != 1 {
		t.Errorf("NewUser count: got %d, want 1", s.newUser.Load())
	}
	if s.closed.Load() != 1 {
		t.Errorf("Close count: got %d, want 1", s.closed.Load())
	}
}

func TestRunner_NewUserReusesCachedPlugin(t *testing.T) {
	stubs := withStubLoader(t, nil)
	r := NewPluginRunnerWithTTL(0)

	if _, err := r.ExecuteRequest(initializeJSON(t, "inst-1")); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		if _, err := r.ExecuteRequest(newUserJSON(t, "inst-1")); err != nil {
			t.Fatal(err)
		}
	}

	if got := len(*stubs); got != 1 {
		t.Fatalf("expected exactly one plugin instance across 10 NewUser calls, got %d", got)
	}
	if s := (*stubs)[0]; s.newUser.Load() != 10 {
		t.Errorf("NewUser count: got %d, want 10", s.newUser.Load())
	}
}

func TestRunner_CloseIsIdempotent(t *testing.T) {
	stubs := withStubLoader(t, nil)
	r := NewPluginRunnerWithTTL(0)

	if _, err := r.ExecuteRequest(initializeJSON(t, "inst-1")); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := r.ExecuteRequest(closeJSON(t, "inst-1")); err != nil {
			t.Fatalf("Close #%d: %v", i, err)
		}
	}
	if s := (*stubs)[0]; s.closed.Load() != 1 {
		t.Errorf("Close should only fire once; got %d", s.closed.Load())
	}
}

func TestRunner_CacheMissReinitializesFromRequestConfig(t *testing.T) {
	stubs := withStubLoader(t, nil)
	r := NewPluginRunnerWithTTL(0)

	// NewUser against a fresh instance_id (no prior Initialize) triggers
	// the cache-miss self-heal path that re-Initializes from the config in
	// the request body.
	if _, err := r.ExecuteRequest(newUserJSON(t, "inst-1")); err != nil {
		t.Fatalf("NewUser cold-miss: %v", err)
	}
	if got := len(*stubs); got != 1 {
		t.Fatalf("expected one plugin instance, got %d", got)
	}
	if s := (*stubs)[0]; s.initialized.Load() != 1 || s.newUser.Load() != 1 {
		t.Errorf("init=%d new=%d, want init=1 new=1",
			s.initialized.Load(), s.newUser.Load())
	}
}

func TestRunner_ReInitializeDisplacesOldEntry(t *testing.T) {
	stubs := withStubLoader(t, nil)
	r := NewPluginRunnerWithTTL(0)

	if _, err := r.ExecuteRequest(initializeJSON(t, "inst-1")); err != nil {
		t.Fatal(err)
	}
	if _, err := r.ExecuteRequest(initializeJSON(t, "inst-1")); err != nil {
		t.Fatal(err)
	}

	if got := len(*stubs); got != 2 {
		t.Fatalf("expected 2 plugin instances after two Initialize, got %d", got)
	}
	// First plugin's slot ref was dropped by installOrReplace; with no
	// handler holding it, Close fires synchronously.
	if (*stubs)[0].closed.Load() != 1 {
		t.Errorf("displaced plugin should have been closed; got %d", (*stubs)[0].closed.Load())
	}
	if (*stubs)[1].closed.Load() != 0 {
		t.Errorf("new plugin should still be open; got close count %d", (*stubs)[1].closed.Load())
	}
}

func TestRunner_CloseWhileHandlerInflight(t *testing.T) {
	stubs := withStubLoader(t, func(s *stubDB) { s.slowNewUser = 200 * time.Millisecond })
	r := NewPluginRunnerWithTTL(0)

	if _, err := r.ExecuteRequest(initializeJSON(t, "inst-1")); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := r.ExecuteRequest(newUserJSON(t, "inst-1"))
		done <- err
	}()

	// Let the handler acquire the entry before we Close.
	time.Sleep(20 * time.Millisecond)
	if _, err := r.ExecuteRequest(closeJSON(t, "inst-1")); err != nil {
		t.Fatal(err)
	}

	// Close dropped the slot ref but the handler still holds one; the
	// underlying db.Close must not run until the handler releases.
	if c := (*stubs)[0].closed.Load(); c != 0 {
		t.Fatalf("plugin closed while handler in flight: closed=%d", c)
	}

	if err := <-done; err != nil {
		t.Fatalf("NewUser: %v", err)
	}
	// After the handler returns, the final release runs db.Close exactly
	// once. Allow a brief grace period for the release goroutine.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if (*stubs)[0].closed.Load() == 1 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("plugin not closed after handler released: closed=%d", (*stubs)[0].closed.Load())
}

func TestRunner_IdleEviction(t *testing.T) {
	stubs := withStubLoader(t, nil)
	// The background evictor ticks at min(idleTTL/4, 1m) — too slow for a
	// unit test. Drive evictIdle directly with a future timestamp instead;
	// it's the exact code the background ticker runs.
	r := NewPluginRunnerWithTTL(time.Millisecond)

	if _, err := r.ExecuteRequest(initializeJSON(t, "inst-1")); err != nil {
		t.Fatal(err)
	}
	if (*stubs)[0].closed.Load() != 0 {
		t.Fatalf("plugin closed before eviction: closed=%d", (*stubs)[0].closed.Load())
	}

	r.evictIdle(time.Now().Add(time.Hour))

	if (*stubs)[0].closed.Load() != 1 {
		t.Fatalf("expected eviction to close the cached plugin; closed=%d",
			(*stubs)[0].closed.Load())
	}
}

func TestRunner_IdleEvictionSkipsInflightHandler(t *testing.T) {
	stubs := withStubLoader(t, func(s *stubDB) { s.slowNewUser = 100 * time.Millisecond })
	r := NewPluginRunnerWithTTL(time.Millisecond)

	if _, err := r.ExecuteRequest(initializeJSON(t, "inst-1")); err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() {
		_, _ = r.ExecuteRequest(newUserJSON(t, "inst-1"))
		close(done)
	}()

	// Give the handler time to acquire the entry, then try to evict.
	time.Sleep(20 * time.Millisecond)
	r.evictIdle(time.Now().Add(time.Hour))
	if (*stubs)[0].closed.Load() != 0 {
		t.Fatalf("evictor should skip entry while handler is in flight; closed=%d",
			(*stubs)[0].closed.Load())
	}
	<-done
}

func TestRunner_ConcurrentColdMissSingleFlight(t *testing.T) {
	stubs := withStubLoader(t, func(s *stubDB) { s.slowNewUser = 0 })
	r := NewPluginRunnerWithTTL(0)

	const N = 32
	var wg sync.WaitGroup
	errs := make(chan error, N)
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := r.ExecuteRequest(newUserJSON(t, "inst-cold"))
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("NewUser: %v", err)
		}
	}
	// loadOrInit single-flights cold-miss loads, so we expect exactly one
	// plugin instance backing all N callers. (A second instance is allowed
	// in principle when retry-after-failure races; this test only uses the
	// happy path, where the single-flight guarantee holds.)
	if got := len(*stubs); got != 1 {
		t.Fatalf("expected 1 plugin from single-flighted cold-miss, got %d", got)
	}
	if s := (*stubs)[0]; s.newUser.Load() != N {
		t.Errorf("NewUser count: got %d, want %d", s.newUser.Load(), N)
	}
}

func TestRunner_InitializeFailureDoesNotPoisonCache(t *testing.T) {
	bad := errors.New("boom")
	stubs := withStubLoader(t, func(s *stubDB) { s.initErr = bad })
	r := NewPluginRunnerWithTTL(0)

	if _, err := r.ExecuteRequest(initializeJSON(t, "inst-1")); err == nil {
		t.Fatal("Initialize should have failed")
	}
	if (*stubs)[0].closed.Load() != 1 {
		t.Errorf("plugin should be closed after failed Initialize; got %d",
			(*stubs)[0].closed.Load())
	}

	// Cache must NOT have a stale entry for inst-1 — a subsequent NewUser
	// hits the cold-miss path and Initializes a fresh plugin.
	loadPluginFunc = func(_ string) (dbplugin.Database, error) {
		s := &stubDB{} // healthy
		*stubs = append(*stubs, s)
		return s, nil
	}
	if _, err := r.ExecuteRequest(newUserJSON(t, "inst-1")); err != nil {
		t.Fatalf("NewUser after failed Initialize: %v", err)
	}
	if got := len(*stubs); got != 2 {
		t.Fatalf("expected a fresh plugin on the retry, got %d total", got)
	}
}

func TestRunner_Shutdown_ClosesAllCachedPlugins(t *testing.T) {
	stubs := withStubLoader(t, nil)
	r := NewPluginRunnerWithTTL(0)

	for i := 0; i < 3; i++ {
		if _, err := r.ExecuteRequest(initializeJSON(t, fmt.Sprintf("inst-%d", i))); err != nil {
			t.Fatal(err)
		}
	}
	r.Shutdown()

	for i, s := range *stubs {
		if s.closed.Load() != 1 {
			t.Errorf("plugin %d: close count = %d, want 1", i, s.closed.Load())
		}
	}
}
