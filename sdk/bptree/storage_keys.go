package bptree

import "context"

// Storage path constants
const (
	nodesPath  = "nodes"
	rootPath   = "root"
	configPath = "config"
)

// configKey constructs the storage key for tree metadata, using tree ID from context if available
func configKey(ctx context.Context) string {
	treeID := getTreeIDOrDefault(ctx, DefaultTreeID)
	return treeID + "/" + configPath
}

// rootKey constructs the storage key for the root ID, using tree ID from context if available
func rootKey(ctx context.Context) string {
	treeID := getTreeIDOrDefault(ctx, DefaultTreeID)
	return treeID + "/" + rootPath
}

// nodeKey constructs the storage key for a node, using tree ID from context if available
func nodeKey(ctx context.Context, nodeID string) string {
	treeID := getTreeIDOrDefault(ctx, DefaultTreeID)
	return treeID + "/" + nodesPath + "/" + nodeID
}

// cacheKey constructs the cache key for a node, using tree ID from context if available
func cacheKey(ctx context.Context, nodeID string) string {
	treeID := getTreeIDOrDefault(ctx, DefaultTreeID)
	return treeID + ":" + nodeID
}
