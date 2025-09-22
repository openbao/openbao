// Copyright (c) 2024 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package bptree

import (
	"context"
	"fmt"
)

// FlushBuffer persists all dirty (buffered) operations to storage
func (s *NodeStorage) FlushBuffer(ctx context.Context) error {
	if !s.bufferingEnabled || s.dirtyTracker == nil {
		return nil // Nothing to flush
	}

	s.lock.Lock()
	defer s.lock.Unlock()

	// Process deletions first
	for _, key := range s.dirtyTracker.Keys() {
		if s.dirtyTracker.IsDeleted(key) {
			if err := s.deleteNodeImmediate(ctx, key); err != nil {
				return fmt.Errorf("failed to flush delete for node %s: %w", key, err)
			}
		}
	}

	// Then process saves/updates
	for _, key := range s.dirtyTracker.Keys() {
		if node, isDirty := s.dirtyTracker.GetDirty(key); isDirty {
			if err := s.putNodeImmediate(ctx, node); err != nil {
				return fmt.Errorf("failed to flush save for node %s: %w", key, err)
			}
		}
	}

	// Clear the dirty tracker after successful flush
	s.dirtyTracker.Clear()
	return nil
}

// ClearBuffer discards all buffered changes without persisting
func (s *NodeStorage) ClearBuffer() {
	s.PurgeCache()
	if s.bufferingEnabled && s.dirtyTracker != nil {
		s.lock.Lock()
		defer s.lock.Unlock()
		s.dirtyTracker.Clear()
	}

	// NOTE (gabrielopesantos): Does this make sense?
	// Also clear the cache to avoid stale reads
	s.PurgeCache()
}

// BufferStats returns information about the current buffer state
func (s *NodeStorage) BufferStats() (dirtyCount int, bufferingEnabled bool) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	if s.dirtyTracker != nil {
		dirtyCount = s.dirtyTracker.Count()
	}
	return dirtyCount, s.bufferingEnabled
}

// SetBufferingEnabled controls whether write buffering is enabled
// When disabled, writes go directly to storage
func (s *NodeStorage) SetBufferingEnabled(enabled bool) {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.bufferingEnabled = enabled
}
