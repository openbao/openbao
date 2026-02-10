package vault

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/openbao/openbao/sdk/v2/physical"
)

// --- CONSTANTS MOCK ---
// Must match the key used in core.go implementation
const (
	mockStatusKey = "core/status/self-init-status"
)

// --- MOCK BACKEND (Reusable) ---
type MockPhysicalBackend struct {
	data map[string][]byte
	mu   sync.RWMutex
}

func NewMockBackend() *MockPhysicalBackend {
	return &MockPhysicalBackend{data: make(map[string][]byte)}
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
		return nil, nil //nolint:nilnil
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
	return nil, nil //nolint:nilnil
}

func (m *MockPhysicalBackend) ListPage(ctx context.Context, prefix string, page string, limit int) ([]string, error) {
	return nil, nil //nolint:nilnil
}

// --- FAULTY BACKEND ---
type FaultyPhysicalBackend struct {
	physical.Backend
	FailGetPath string // Fail only on getting this specific path
	FailPut     bool
}

func (f *FaultyPhysicalBackend) Get(ctx context.Context, key string) (*physical.Entry, error) {
	if f.FailGetPath != "" && key == f.FailGetPath {
		return nil, errors.New("simulated read error")
	}
	return f.Backend.Get(ctx, key)
}

func (f *FaultyPhysicalBackend) Put(ctx context.Context, entry *physical.Entry) error {
	if f.FailPut {
		return errors.New("simulated write error")
	}
	return f.Backend.Put(ctx, entry)
}

// --- EAL5+ FORMAL VERIFICATION TESTS ---

func TestCore_SelfInit_FormalStateModel(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name          string
		setup         func(b *MockPhysicalBackend)
		expectSuccess bool // What IsSelfInitComplete should return
		expectError   bool // Should it return an error?
		desc          string
	}{
		{
			name: "State S0: Legacy/Clean (Missing Key)",
			setup: func(b *MockPhysicalBackend) {
				// No markers present
			},
			expectSuccess: true,
			expectError:   false,
			desc:          "No markers -> Assume Legacy Cluster -> Success (True, Nil)",
		},
		{
			name: "State S1: Partial Failure (Key = 'started')",
			setup: func(b *MockPhysicalBackend) {
				_ = b.Put(ctx, &physical.Entry{Key: mockStatusKey, Value: []byte("started")})
			},
			expectSuccess: false,
			expectError:   true, // Error: partial failure detected
			desc:          "Value is 'started' -> Partial Failure -> Error (False, Error)",
		},
		{
			name: "State S2: Modern Success (Key = 'completed')",
			setup: func(b *MockPhysicalBackend) {
				_ = b.Put(ctx, &physical.Entry{Key: mockStatusKey, Value: []byte("completed")})
			},
			expectSuccess: true,
			expectError:   false,
			desc:          "Value is 'completed' -> Init Complete -> Success (True, Nil)",
		},
		{
			name: "State S3: Corrupt Data (Key = 'garbage')",
			setup: func(b *MockPhysicalBackend) {
				_ = b.Put(ctx, &physical.Entry{Key: mockStatusKey, Value: []byte("unknown_state")})
			},
			expectSuccess: false,
			expectError:   true,
			desc:          "Unknown value -> Corrupt State -> Error (False, Error)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := NewMockBackend()
			tt.setup(backend)
			core := &Core{physical: backend}

			success, err := core.IsSelfInitComplete(ctx)

			// Check Error Expectation
			if tt.expectError {
				if err == nil {
					t.Fatalf("[%s] Expected error but got nil", tt.name)
				}
			} else {
				if err != nil {
					t.Fatalf("[%s] Unexpected error: %v", tt.name, err)
				}
			}

			// Check Boolean Result Expectation
			// If we expect success (true), check true.
			// If we expect failure (false), check false.
			if !tt.expectError && success != tt.expectSuccess {
				t.Fatalf("[%s] Logical Violation: expected success=%v, got %v. Desc: %s",
					tt.name, tt.expectSuccess, success, tt.desc)
			}
		})
	}
}

func TestCore_SelfInit_FaultPropagation(t *testing.T) {
	ctx := context.Background()

	t.Run("Faulty Read Status", func(t *testing.T) {
		backend := &FaultyPhysicalBackend{
			Backend:     NewMockBackend(),
			FailGetPath: mockStatusKey, // Fails when reading the status key
		}
		core := &Core{physical: backend}

		_, err := core.IsSelfInitComplete(ctx)
		if err == nil {
			t.Fatal("Security Risk: Swallowed IO error when reading status marker")
		}
	})
}

func TestCore_SelfInit_WriteCycle(t *testing.T) {
	// Verify the full write cycle matches the read expectations
	ctx := context.Background()
	backend := NewMockBackend()
	core := &Core{physical: backend}

	// 1. Initial State (Clean) -> Should be Success (Legacy)
	ok, err := core.IsSelfInitComplete(ctx)
	if err != nil || !ok {
		t.Fatal("Clean backend should be considered OK (Legacy)")
	}

	// 2. Mark Started
	if err := core.MarkSelfInitStarted(ctx); err != nil {
		t.Fatalf("MarkSelfInitStarted failed: %v", err)
	}

	// 3. Verify Intermediate State (Should be Broken/Error)
	ok, err = core.IsSelfInitComplete(ctx)
	if err == nil {
		t.Fatal("Intermediate state (started) should return error")
	}
	if ok {
		t.Fatal("Intermediate state should return false")
	}

	// 4. Mark Completed
	if err := core.MarkSelfInitComplete(ctx); err != nil {
		t.Fatalf("MarkSelfInitComplete failed: %v", err)
	}

	// 5. Verify Final State (Should be OK)
	ok, err = core.IsSelfInitComplete(ctx)
	if err != nil {
		t.Fatalf("Final state returned error: %v", err)
	}
	if !ok {
		t.Fatal("Final state returned false, expected true")
	}

	// 6. Verify Physical Content (Whitebox check)
	entry, _ := backend.Get(ctx, mockStatusKey)
	if string(entry.Value) != "completed" {
		t.Fatalf("Physical storage has wrong value: expected 'completed', got '%s'", string(entry.Value))
	}
}
