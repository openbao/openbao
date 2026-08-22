// Copyright (c) 2024 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package bptree

import "context"

// EnableCache enables or disables cache operations
func (s *NodeStorage) EnableCache(enabled bool) {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.cachingEnabled = enabled
}

// IsCacheEnabled returns whether cache operations are enabled
func (s *NodeStorage) IsCacheEnabled() bool {
	return s.cachingEnabled
}

// PurgeCache clears all entries from the cache
func (s *NodeStorage) PurgeCache() {
	if s.cache != nil {
		s.cache.Purge()
	}
}

// Internal cache helper methods

// getFromCache retrieves a node from cache if available
func (s *NodeStorage) getFromCache(ctx context.Context, id string) *Node {
	if !s.cachingEnabled || s.cache == nil {
		return nil
	}

	if node, ok := s.cache.Get(cacheKey(ctx, id)); ok {
		return node
	}
	return nil
}

// addToCache stores a node in cache
func (s *NodeStorage) addToCache(ctx context.Context, node *Node) {
	if s.cachingEnabled && s.cache != nil {
		s.cache.Add(cacheKey(ctx, node.ID), node)
	}
}

// removeFromCache removes a node from cache
func (s *NodeStorage) removeFromCache(ctx context.Context, nodeID string) {
	if s.cachingEnabled && s.cache != nil {
		s.cache.Delete(cacheKey(ctx, nodeID))
	}
}
