// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

// Auto-init state machine persisted to the physical backend.
// Tracks whether auto-initialization was attempted and completed successfully.
//
// Pattern matches: vault/core.go (Core struct, c.physical usage)

import (
	"context"
	"fmt"

	"github.com/openbao/openbao/sdk/v2/physical"
)

const (
	// coreStatusSelfInitKey is the physical backend key for the auto-init state machine.
	//
	// State machine values:
	//   (missing) : legacy cluster or manual init — success assumed (backward compat)
	//   "started" : auto-init was attempted but did not complete — corrupt state
	//   "completed" : auto-init finished successfully
	coreStatusSelfInitKey = "core/status/self-init"

	// coreStatusSelfInitStarted is written before auto-init begins.
	// Finding this value at startup means the previous run crashed mid-init.
	coreStatusSelfInitStarted = "started"

	// coreStatusSelfInitCompleted is written after auto-init succeeds.
	coreStatusSelfInitCompleted = "completed"
)

// MarkSelfInitStarted writes the "started" marker to the physical backend.
// This must be called before beginning auto-initialization so that a crash
// mid-init can be detected on the next startup.
func (c *Core) MarkSelfInitStarted(ctx context.Context) error {
	if c.physical == nil {
		return fmt.Errorf("physical backend missing")
	}
	return c.physical.Put(ctx, &physical.Entry{
		Key:   coreStatusSelfInitKey,
		Value: []byte(coreStatusSelfInitStarted),
	})
}

// MarkSelfInitComplete overwrites the "started" marker with "completed".
// This must be called after auto-initialization finishes successfully.
func (c *Core) MarkSelfInitComplete(ctx context.Context) error {
	if c.physical == nil {
		return fmt.Errorf("physical backend missing")
	}
	return c.physical.Put(ctx, &physical.Entry{
		Key:   coreStatusSelfInitKey,
		Value: []byte(coreStatusSelfInitCompleted),
	})
}

// IsSelfInitComplete reads the auto-init state machine from the physical backend
// and returns whether initialization can be considered complete.
//
// State transitions:
//   - missing marker  → true, nil  (backward compat: old cluster or manual init)
//   - "completed"     → true, nil  (auto-init succeeded)
//   - "started"       → false, err (crash detected mid-init: corrupt state)
//   - anything else   → false, err (unknown value: corrupt state)
func (c *Core) IsSelfInitComplete(ctx context.Context) (bool, error) {
	if c.physical == nil {
		return false, fmt.Errorf("physical backend missing")
	}

	entry, err := c.physical.Get(ctx, coreStatusSelfInitKey)
	if err != nil {
		return false, err
	}

	// Missing marker: old OpenBao version or manual init — assume success.
	if entry == nil {
		return true, nil
	}

	switch string(entry.Value) {
	case coreStatusSelfInitCompleted:
		return true, nil
	case coreStatusSelfInitStarted:
		return false, fmt.Errorf("auto-init detected as %q but never reached %q: possible crash during initialization",
			coreStatusSelfInitStarted, coreStatusSelfInitCompleted)
	default:
		return false, fmt.Errorf("unknown self-init state %q: storage may be corrupt",
			string(entry.Value))
	}
}
