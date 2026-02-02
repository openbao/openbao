package vault

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/openbao/openbao/sdk/v2/physical"
)

// --- MOCK BACKEND (Isolated Test Implementation) ---
// We remove the dependency on 'physical/inmem' to avoid circular imports
// and ensure strict isolation for this core logic test.
type MockPhysicalBackend struct {
	data map[string][]byte
	mu   sync.RWMutex
}

func NewMockBackend() *MockPhysicalBackend {
	return &MockPhysicalBackend{
		data: make(map[string][]byte),
	}
}

func (m *MockPhysicalBackend) Put(ctx context.Context, entry *physical.Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[entry.Key] = entry.Value
	return nil
}

func (m *MockPhysicalBackend) Get(ctx context.Context, key string) (*physical.Entry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	val, ok := m.data[key]
	if !ok {
		return nil, nil
	}
	return &physical.Entry{Key: key, Value: val}, nil
}

func (m *MockPhysicalBackend) Delete(ctx context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, key)
	return nil
}

func (m *MockPhysicalBackend) List(ctx context.Context, prefix string) ([]string, error) {
	return nil, nil // Not required for this specific test
}

// Stub implementation for other physical.Backend interface methods
// to satisfy the Go compiler requirements.

// --- ACTUAL TEST SUITE ---

func TestCore_SelfInit_StateTransition(t *testing.T) {
	// 1. Setup
	backend := NewMockBackend()
	core := &Core{
		physical: backend,
	}

	// PHASE 1: Clean Slate Verification
	// Ensure the system correctly identifies an uninitialized state.
	complete, err := core.IsSelfInitComplete()
	if err != nil {
		t.Fatalf("Unexpected error on empty storage: %v", err)
	}
	if complete {
		t.Fatal("SAFETY VIOLATION: Returned true (initialized) on empty storage")
	}

	// PHASE 2: State Transition
	// Attempt to mark initialization as complete.
	if err := core.MarkSelfInitComplete(); err != nil {
		t.Fatalf("Write operation failed: %v", err)
	}

	// PHASE 3: Consistency Verification
	// Ensure the state is persistently reflected immediately after write.
	complete, err = core.IsSelfInitComplete()
	if err != nil {
		t.Fatalf("Read operation failed: %v", err)
	}
	if !complete {
		t.Fatal("CONSISTENCY VIOLATION: Returned false (uninitialized) after successful write")
	}

	// PHASE 4: Raw Integrity Check
	// Verify the actual bytes written to the backend match expectations.
	entry, _ := backend.Get(context.Background(), coreStatusSelfInit)
	if string(entry.Value) != "true" {
		t.Fatalf("INTEGRITY VIOLATION: Invalid payload written to storage")
	}
}

func TestCore_SelfInit_FaultInjection(t *testing.T) {
	// Setup a faulty backend to simulate storage failure
	faulty := &FaultyPhysicalBackend{
		Backend: NewMockBackend(),
		FailPut: true,
	}
	core := &Core{physical: faulty}

	// Ensure errors are propagated up the stack and not swallowed
	if err := core.MarkSelfInitComplete(); err == nil {
		t.Fatal("SAFETY VIOLATION: Swallowed critical storage error")
	}
}

// Faulty Wrapper for Error Injection
type FaultyPhysicalBackend struct {
	physical.Backend
	FailPut bool
}

func (f *FaultyPhysicalBackend) Put(ctx context.Context, entry *physical.Entry) error {
	if f.FailPut {
		return errors.New("simulated io error")
	}
	return f.Backend.Put(ctx, entry)
}

// Correct signature for OpenBao/Vault SDK v2 compliance
func (m *MockPhysicalBackend) ListPage(ctx context.Context, prefix string, page string, limit int) ([]string, error) {
	return nil, nil
}
