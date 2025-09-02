// Copyright (c) OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault_test

import (
	"testing"

	log "github.com/hashicorp/go-hclog"
	testingintf "github.com/mitchellh/go-testing-interface"
	"github.com/openbao/openbao/api/v2"
	vaulthttp "github.com/openbao/openbao/http"
	"github.com/openbao/openbao/sdk/v2/physical/file"
	"github.com/openbao/openbao/sdk/v2/physical/inmem"
	"github.com/openbao/openbao/vault"
)

// TestStorageBackend_TransactionalInmem verifies that the inmem storage backend
// supports transactions when properly configured
func TestStorageBackend_TransactionalInmem(t *testing.T) {
	// Create transactional inmem backend
	physicalFactory := func(t testingintf.T, coreIdx int, logger log.Logger, conf map[string]interface{}) *vault.PhysicalBackendBundle {
		// Create inmem backend with transactions enabled (default)
		backend, err := inmem.NewInmem(nil, logger)
		if err != nil {
			t.Fatal(err)
		}
		return &vault.PhysicalBackendBundle{
			Backend: backend,
		}
	}

	cluster := vault.NewTestCluster(t, nil, &vault.TestClusterOptions{
		HandlerFunc:     vaulthttp.Handler,
		NumCores:        1,
		PhysicalFactory: physicalFactory,
	})
	cluster.Start()
	defer cluster.Cleanup()

	core := cluster.Cores[0].Core
	vault.TestWaitActive(t, core)

	// Test that we can perform basic operations with the cluster
	// This indirectly tests that the transactional storage is working
	client := cluster.Cores[0].Client

	// Enable a secret engine to test storage operations
	err := client.Sys().Mount("test/", &api.MountInput{
		Type: "kv",
	})
	if err != nil {
		t.Fatalf("Failed to mount KV engine: %v", err)
	}

	// Write and read data to verify storage works
	_, err = client.Logical().Write("test/data", map[string]interface{}{
		"key": "value",
	})
	if err != nil {
		t.Fatalf("Failed to write data: %v", err)
	}

	resp, err := client.Logical().Read("test/data")
	if err != nil {
		t.Fatalf("Failed to read data: %v", err)
	}
	if resp == nil {
		t.Fatal("Got nil response")
	}

	t.Logf("Successfully performed storage operations with transactional inmem backend")
}

// TestStorageBackend_NonTransactionalFile verifies that the file storage backend
// works correctly (file backend is non-transactional)
func TestStorageBackend_NonTransactionalFile(t *testing.T) {
	tempDir := t.TempDir()

	// Create non-transactional file backend
	physicalFactory := func(t testingintf.T, coreIdx int, logger log.Logger, conf map[string]interface{}) *vault.PhysicalBackendBundle {
		fileConf := map[string]string{
			"path": tempDir,
		}
		backend, err := file.NewFileBackend(fileConf, logger)
		if err != nil {
			t.Fatal(err)
		}
		return &vault.PhysicalBackendBundle{
			Backend: backend,
		}
	}

	cluster := vault.NewTestCluster(t, nil, &vault.TestClusterOptions{
		HandlerFunc:     vaulthttp.Handler,
		NumCores:        1,
		PhysicalFactory: physicalFactory,
	})
	cluster.Start()
	defer cluster.Cleanup()

	core := cluster.Cores[0].Core
	vault.TestWaitActive(t, core)

	// Test that we can perform basic operations with the cluster
	// This tests that non-transactional storage works correctly
	client := cluster.Cores[0].Client

	// Enable a secret engine to test storage operations
	err := client.Sys().Mount("test/", &api.MountInput{
		Type: "kv",
	})
	if err != nil {
		t.Fatalf("Failed to mount KV engine: %v", err)
	}

	// Write and read data to verify storage works
	_, err = client.Logical().Write("test/data", map[string]interface{}{
		"key": "value",
	})
	if err != nil {
		t.Fatalf("Failed to write data: %v", err)
	}

	resp, err := client.Logical().Read("test/data")
	if err != nil {
		t.Fatalf("Failed to read data: %v", err)
	}
	if resp == nil {
		t.Fatal("Got nil response")
	}

	t.Logf("Successfully performed storage operations with file backend")
}

// TestStorageBackend_DisabledTransactions verifies that inmem backend works when
// transactions are explicitly disabled
func TestStorageBackend_DisabledTransactions(t *testing.T) {
	// Create inmem backend with transactions explicitly disabled
	physicalFactory := func(t testingintf.T, coreIdx int, logger log.Logger, conf map[string]interface{}) *vault.PhysicalBackendBundle {
		inmemConf := map[string]string{
			"disable_transactions": "true",
		}
		backend, err := inmem.NewInmem(inmemConf, logger)
		if err != nil {
			t.Fatal(err)
		}
		return &vault.PhysicalBackendBundle{
			Backend: backend,
		}
	}

	cluster := vault.NewTestCluster(t, nil, &vault.TestClusterOptions{
		HandlerFunc:     vaulthttp.Handler,
		NumCores:        1,
		PhysicalFactory: physicalFactory,
	})
	cluster.Start()
	defer cluster.Cleanup()

	core := cluster.Cores[0].Core
	vault.TestWaitActive(t, core)

	// Test that we can perform basic operations with the cluster
	// This tests that storage works correctly even when transactions are disabled
	client := cluster.Cores[0].Client

	// Enable a secret engine to test storage operations
	err := client.Sys().Mount("test/", &api.MountInput{
		Type: "kv",
	})
	if err != nil {
		t.Fatalf("Failed to mount KV engine: %v", err)
	}

	// Write and read data to verify storage works
	_, err = client.Logical().Write("test/data", map[string]interface{}{
		"key": "value",
	})
	if err != nil {
		t.Fatalf("Failed to write data: %v", err)
	}

	resp, err := client.Logical().Read("test/data")
	if err != nil {
		t.Fatalf("Failed to read data: %v", err)
	}
	if resp == nil {
		t.Fatal("Got nil response")
	}

	t.Logf("Successfully performed storage operations with transactions disabled")
}

// TestStorageBackend_CompareTransactionalVsNonTransactional verifies both backends work
func TestStorageBackend_CompareTransactionalVsNonTransactional(t *testing.T) {
	// Test both transactional and non-transactional backends in one test
	testCases := []struct {
		name    string
		factory func(t testingintf.T, coreIdx int, logger log.Logger, conf map[string]interface{}) *vault.PhysicalBackendBundle
	}{
		{
			name: "transactional_inmem",
			factory: func(t testingintf.T, coreIdx int, logger log.Logger, conf map[string]interface{}) *vault.PhysicalBackendBundle {
				backend, err := inmem.NewInmem(nil, logger)
				if err != nil {
					t.Fatal(err)
				}
				return &vault.PhysicalBackendBundle{Backend: backend}
			},
		},
		{
			name: "disabled_transactions_inmem",
			factory: func(t testingintf.T, coreIdx int, logger log.Logger, conf map[string]interface{}) *vault.PhysicalBackendBundle {
				inmemConf := map[string]string{"disable_transactions": "true"}
				backend, err := inmem.NewInmem(inmemConf, logger)
				if err != nil {
					t.Fatal(err)
				}
				return &vault.PhysicalBackendBundle{Backend: backend}
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cluster := vault.NewTestCluster(t, nil, &vault.TestClusterOptions{
				HandlerFunc:     vaulthttp.Handler,
				NumCores:        1,
				PhysicalFactory: tc.factory,
			})
			cluster.Start()
			defer cluster.Cleanup()

			core := cluster.Cores[0].Core
			vault.TestWaitActive(t, core)
			client := cluster.Cores[0].Client

			// Test basic storage operations
			err := client.Sys().Mount("test/", &api.MountInput{Type: "kv"})
			if err != nil {
				t.Fatalf("Failed to mount KV engine: %v", err)
			}

			_, err = client.Logical().Write("test/data", map[string]interface{}{"key": "value"})
			if err != nil {
				t.Fatalf("Failed to write data: %v", err)
			}

			resp, err := client.Logical().Read("test/data")
			if err != nil {
				t.Fatalf("Failed to read data: %v", err)
			}
			if resp == nil {
				t.Fatal("Got nil response")
			}

			t.Logf("Successfully tested %s storage backend", tc.name)
		})
	}
}
