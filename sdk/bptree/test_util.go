// Copyright (c) 2024 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package bptree

import (
	"context"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/sdk/v2/physical/inmem"
	"github.com/stretchr/testify/require"
)

func keyValue(key string) string {
	return "value_" + key
}

// TODO: Accept a storage config
func initTest(t *testing.T, treeConfig *TreeConfig) (context.Context, *NodeStorage, *Tree) {
	// Initialize context
	ctx := context.Background()
	// Initialize in-memory storage for testing
	s := &logical.InmemStorage{}

	if treeConfig == nil {
		treeConfig = NewDefaultTreeConfig()
	}

	// Create node storage
	storage, err := NewNodeStorage(s)
	require.NoError(t, err, "failed to create storage")

	// Initialize B+ tree with a small order to force splits and create internal nodes
	tree, err := InitializeTreeWithConfig(ctx, storage, treeConfig)
	require.NoError(t, err, "failed to initialize B+ tree")
	require.NotNil(t, tree, "tree should not be nil")

	return ctx, storage, tree
}

// createTransactionalStorage creates a transactional storage for testing
func createTransactionalStorage(t *testing.T) logical.TransactionalStorage {
	// Create transactional inmem backend
	inmemBackend, err := inmem.NewInmem(nil, nil)
	require.NoError(t, err, "failed to create in-memory backend")

	// Wrap it in logical storage
	logicalStorage := logical.NewLogicalStorage(inmemBackend)

	// Verify it's transactional
	txnStorage, ok := logicalStorage.(logical.TransactionalStorage)
	require.True(t, ok, "logical storage should implement TransactionalStorage")

	return txnStorage
}

// initTransactionalNodeStorageTest initializes a transactional node storage for testing
func initTransactionalNodeStorageTest(t *testing.T) (context.Context, TransactionalStorage) {
	ctx := context.Background()
	// Create transactional storage
	s := createTransactionalStorage(t)

	// Create transactional node storage
	storage, err := NewTransactionalNodeStorage(s)
	require.NoError(t, err, "failed to create transactional node storage")

	return ctx, storage
}
