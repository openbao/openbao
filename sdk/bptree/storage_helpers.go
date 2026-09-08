// Copyright (c) 2024 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package bptree

import (
	"context"
)

// TODO (gabrielopesantos): Evaluate if these functions are really needed...

// Helper Functions for Write Buffering (non-transactional storage only)
//
// These helper functions are designed for use with regular NodeStorage instances only.
// Do NOT use these with transactional storage (Transaction interface) as transactions handle
// their own buffering and flushing lifecycle automatically:
//
// - Transactions buffer writes in their own DirtyTracker during execution
// - Transactions automatically flush buffers during Commit()
// - Transactions automatically clear buffers during Rollback()
//
// For transactional operations, use WithTransaction() which provides proper
// transaction lifecycle management including automatic buffer handling.

// WithBufferedWrites executes a function with write buffering enabled, then flushes all writes.
// This function forces buffering on during execution, regardless of the storage's default setting.
// Operations are guaranteed to be buffered and flushed together as a batch.
func WithBufferedWrites(ctx context.Context, storage Storage, fn func(Storage) error) error {
	// Force buffering ON for NodeStorage types
	var originalBuffering bool
	var needsRestore bool

	if ns, ok := storage.(*NodeStorage); ok {
		_, originalBuffering = ns.BufferStats()
		if !originalBuffering {
			ns.SetBufferingEnabled(true) // Force buffering ON
			needsRestore = true
		}
	}

	// Ensure buffering is restored on exit
	if needsRestore {
		defer func() {
			if ns, ok := storage.(*NodeStorage); ok {
				ns.SetBufferingEnabled(originalBuffering)
			}
		}()
	}

	// Execute the function with forced buffering
	if err := fn(storage); err != nil {
		// Clear buffer on error
		clearBufferIfSupported(storage)
		return err
	}

	// Flush buffer on success
	return flushBufferIfSupported(ctx, storage)
}

// WithAutoFlush executes a function with the storage's current buffering behavior and automatically
// flushes any buffered writes at the end. This respects the storage's existing configuration.
//
// This is designed for non-transactional storage operations only.
// For transactional storage (Transaction interface), the transaction lifecycle already
// handles flushing automatically during Commit(). Using this with transactions is
// unnecessary and may cause confusion about when data is actually persisted.
//
// Unlike WithBufferedWrites, this doesn't change the storage behavior - it just
// ensures any existing buffered operations are flushed.
func WithAutoFlush(ctx context.Context, storage Storage, fn func(Storage) error) error {
	// Execute the function with the storage as-is (no behavior changes)
	if err := fn(storage); err != nil {
		// Clear buffer on error
		clearBufferIfSupported(storage)
		return err
	}

	// Flush buffer on success
	return flushBufferIfSupported(ctx, storage)
}

// Helper functions for buffer operations
// Note: These work with transactional storage types but should generally not be used
// with them as transactions handle their own buffering and flushing lifecycle.
func clearBufferIfSupported(storage Storage) {
	switch ns := storage.(type) {
	case *NodeStorage:
		ns.ClearBuffer()
	case *TransactionalNodeStorage:
		ns.ClearBuffer()
	}
}

func flushBufferIfSupported(ctx context.Context, storage Storage) error {
	switch ns := storage.(type) {
	case *NodeStorage:
		return ns.FlushBuffer(ctx)
	case *TransactionalNodeStorage:
		return ns.FlushBuffer(ctx)
	default:
		// Storage does not support buffering, no flush needed
		return nil
	}
}
