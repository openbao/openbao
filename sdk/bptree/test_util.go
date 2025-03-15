// Copyright (c) 2024 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package bptree

import (
	"context"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
)

func keyValue(key string) string {
	return "value_" + key
}

func initTest(t *testing.T, treeConfig *BPlusTreeConfig) (context.Context, *NodeStorage, *BPlusTree) {
	// Initialize context
	ctx := context.Background()
	// Initialize in-memory storage for testing
	s := &logical.InmemStorage{}
	storage, err := NewNodeStorage(s, nil, 1_000)
	require.NoError(t, err, "failed to create storage")

	if treeConfig == nil {
		treeConfig = NewDefaultBPlusTreeConfig()
	}

	// Initialize B+ tree with a small order to force splits and create internal nodes
	tree, err := InitializeBPlusTree(context.Background(), storage, treeConfig)
	require.NoError(t, err, "failed to create B+ tree")

	return ctx, storage, tree
}
