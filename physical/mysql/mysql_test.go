// Copyright (c) HashiCorp, Inc.
// Copyright (c) 2024 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package mysql

import (
	"os"
	"testing"
	"time"

	log "github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/sdk/v2/physical"
)

func TestMySQLBackend_Basic(t *testing.T) {
	// Skip if MYSQL_ADDR is not set
	if os.Getenv("MYSQL_ADDR") == "" {
		t.Skip("MYSQL_ADDR not set, skipping MySQL backend tests")
	}

	logger := log.New(&log.LoggerOptions{
		Name:  "mysql-test",
		Level: log.Debug,
	})

	backend, cleanup, err := MakeMySQLTestBackend(t, logger)
	if err != nil {
		t.Fatalf("failed to create test backend: %v", err)
	}
	defer cleanup()

	physical.ExerciseBackend(t, backend)
}

func TestMySQLBackend_ListPrefix(t *testing.T) {
	// Skip if MYSQL_ADDR is not set
	if os.Getenv("MYSQL_ADDR") == "" {
		t.Skip("MYSQL_ADDR not set, skipping MySQL backend tests")
	}

	logger := log.New(&log.LoggerOptions{
		Name:  "mysql-test",
		Level: log.Debug,
	})

	backend, cleanup, err := MakeMySQLTestBackend(t, logger)
	if err != nil {
		t.Fatalf("failed to create test backend: %v", err)
	}
	defer cleanup()

	physical.ExerciseBackend_ListPrefix(t, backend)
}

func TestMySQLBackend_HA(t *testing.T) {
	// Skip if MYSQL_ADDR is not set
	if os.Getenv("MYSQL_ADDR") == "" {
		t.Skip("MYSQL_ADDR not set, skipping MySQL backend tests")
	}

	logger := log.New(&log.LoggerOptions{
		Name:  "mysql-test",
		Level: log.Debug,
	})

	backend, cleanup, err := MakeMySQLTestBackend(t, logger)
	if err != nil {
		t.Fatalf("failed to create test backend: %v", err)
	}
	defer cleanup()

	if !backend.HAEnabled() {
		t.Skip("HA not enabled, skipping HA tests")
	}

	physical.ExerciseHABackend(t, backend, backend)
}

func TestMySQLBackend_LockBasics(t *testing.T) {
	// Skip if MYSQL_ADDR is not set
	if os.Getenv("MYSQL_ADDR") == "" {
		t.Skip("MYSQL_ADDR not set, skipping MySQL backend tests")
	}

	logger := log.New(&log.LoggerOptions{
		Name:  "mysql-test",
		Level: log.Debug,
	})

	backend, cleanup, err := MakeMySQLTestBackend(t, logger)
	if err != nil {
		t.Fatalf("failed to create test backend: %v", err)
	}
	defer cleanup()

	if !backend.HAEnabled() {
		t.Skip("HA not enabled, skipping lock tests")
	}

	// Test basic lock acquisition
	lock, err := backend.LockWith("test-lock-key", "test-lock-value")
	if err != nil {
		t.Fatalf("failed to create lock: %v", err)
	}

	// Create a stop channel
	stopCh := make(chan struct{})

	// Acquire the lock
	leaderCh, err := lock.Lock(stopCh)
	if err != nil {
		t.Fatalf("failed to acquire lock: %v", err)
	}
	if leaderCh == nil {
		t.Fatal("expected leader channel, got nil")
	}

	// Unlock
	if err := lock.Unlock(); err != nil {
		t.Fatalf("failed to unlock: %v", err)
	}
}

func TestMySQLBackend_LockContention(t *testing.T) {
	// Skip if MYSQL_ADDR is not set
	if os.Getenv("MYSQL_ADDR") == "" {
		t.Skip("MYSQL_ADDR not set, skipping MySQL backend tests")
	}

	logger := log.New(&log.LoggerOptions{
		Name:  "mysql-test",
		Level: log.Debug,
	})

	backend, cleanup, err := MakeMySQLTestBackend(t, logger)
	if err != nil {
		t.Fatalf("failed to create test backend: %v", err)
	}
	defer cleanup()

	if !backend.HAEnabled() {
		t.Skip("HA not enabled, skipping lock contention tests")
	}

	// Create two locks for the same key
	lock1, err := backend.LockWith("contention-key", "value-1")
	if err != nil {
		t.Fatalf("failed to create lock1: %v", err)
	}

	lock2, err := backend.LockWith("contention-key", "value-2")
	if err != nil {
		t.Fatalf("failed to create lock2: %v", err)
	}

	stopCh := make(chan struct{})
	defer close(stopCh)

	// First lock should succeed
	leaderCh1, err := lock1.Lock(stopCh)
	if err != nil {
		t.Fatalf("failed to acquire lock1: %v", err)
	}
	if leaderCh1 == nil {
		t.Fatal("expected leader channel for lock1")
	}

	// Second lock should not be able to acquire immediately
	// Use a short timeout to test contention
	lock2StopCh := make(chan struct{})
	go func() {
		time.Sleep(2 * time.Second)
		close(lock2StopCh)
	}()

	leaderCh2, err := lock2.Lock(lock2StopCh)
	if err != nil {
		t.Fatalf("lock2.Lock returned error: %v", err)
	}
	if leaderCh2 != nil {
		t.Fatal("lock2 should not have acquired the lock while lock1 holds it")
	}

	// Release lock1
	if err := lock1.Unlock(); err != nil {
		t.Fatalf("failed to unlock lock1: %v", err)
	}
}

func TestValidateDBTable(t *testing.T) {
	tests := []struct {
		name      string
		db        string
		table     string
		expectErr bool
	}{
		{"valid", "vault", "vault", false},
		{"valid with underscore", "vault_db", "vault_table", false},
		{"empty db", "", "vault", true},
		{"empty table", "vault", "", true},
		{"db with backtick", "vault`db", "vault", true},
		{"table with backtick", "vault", "vault`table", true},
		{"db with quote", "vault'db", "vault", true},
		{"table with quote", "vault", "vault'table", true},
		{"db with space", "vault db", "vault", true},
		{"table with space", "vault", "vault table", true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateDBTable(test.db, test.table)
			if test.expectErr && err == nil {
				t.Errorf("expected error, got nil")
			}
			if !test.expectErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}
