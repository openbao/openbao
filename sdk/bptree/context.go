// Copyright (c) 2024 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package bptree

import "context"

// NOTE (gabrielopesantos): What if the storage was also passed in the context?

// Context keys for tree identification
type contextKey string

const TreeIDContextKey contextKey = "bptree-tree-id"

// withTreeID adds a tree ID to the context
func withTreeID(ctx context.Context, treeID string) context.Context {
	return context.WithValue(ctx, TreeIDContextKey, treeID)
}

// getTreeID extracts the tree ID from context, returns default if not found
func getTreeID(ctx context.Context) (string, bool) {
	treeID, ok := ctx.Value(TreeIDContextKey).(string)
	return treeID, ok
}

// getTreeIDOrDefault extracts tree ID from context or returns a default
func getTreeIDOrDefault(ctx context.Context, defaultTreeID string) string {
	if treeID, ok := getTreeID(ctx); ok && treeID != "" {
		return treeID
	}
	return defaultTreeID
}
