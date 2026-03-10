// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0
package vault

// Auto-init state machine persisted to the security barrier.
// Tracks whether auto-initialization was attempted and completed successfully.
//
// All three methods require the barrier to be initialized and unsealed:
//   - MarkSelfInitStarted  : called after core.Initialize(), barrier just created and open
//   - MarkSelfInitComplete : called after doSelfInit(), barrier open
//   - IsSelfInitComplete   : called in the "if inited" branch, auto-unseal already done
//
// Pattern matches: vault/core.go (c.barrier.Get/Put with logical.StorageEntry)

import (
	"context"
	"fmt"

	"github.com/openbao/openbao/sdk/v2/logical"
)

const (
	// coreStatusSelfInitKey is the entry key for the auto-init state machine.
	//
	// State machine values:
	//   (missing)   : legacy cluster or manual init — success assumed (backward compat)
	//   "started"   : auto-init was attempted but did not complete — corrupt state
	//   "completed" : auto-init finished successfully
	coreStatusSelfInitKey = "core/status/self-init"

	// coreStatusSelfInitStarted is written before auto-init begins.
	// Finding this value at startup means the previous run crashed mid-init.
	coreStatusSelfInitStarted = "started"

	// coreStatusSelfInitCompleted is written after auto-init succeeds.
	coreStatusSelfInitCompleted = "completed"
)

// MarkSelfInitStarted writes the "started" marker to the security barrier.
// This must be called after core.Initialize() so the barrier exists and is open.
// Its purpose is crash detection: if the process dies before MarkSelfInitComplete
// is called, the next startup will find "started" and refuse to proceed.
func (c *Core) MarkSelfInitStarted(ctx context.Context) error {
	if c.barrier == nil {
		return fmt.Errorf("security barrier not available")
	}
	return c.barrier.Put(ctx, &logical.StorageEntry{
		Key:   coreStatusSelfInitKey,
		Value: []byte(coreStatusSelfInitStarted),
	})
}

// MarkSelfInitComplete overwrites the "started" marker with "completed".
// This must be called after auto-initialization finishes successfully.
// The barrier must be open at this point.
func (c *Core) MarkSelfInitComplete(ctx context.Context) error {
	if c.barrier == nil {
		return fmt.Errorf("security barrier not available")
	}
	return c.barrier.Put(ctx, &logical.StorageEntry{
		Key:   coreStatusSelfInitKey,
		Value: []byte(coreStatusSelfInitCompleted),
	})
}

// IsSelfInitComplete reads the auto-init state machine from the security barrier
// and returns whether initialization can be considered complete.
//
// Precondition: the barrier must be unsealed (guaranteed by the "if inited"
// branch in command.Initialize — auto-unseal has already run at that point).
//
// State transitions:
//   - missing marker → true, nil  (backward compat: old cluster or manual init)
//   - "completed"    → true, nil  (auto-init succeeded)
//   - "started"      → false, err (crash detected mid-init: corrupt state)
//   - anything else  → false, err (unknown value: corrupt state)
func (c *Core) IsSelfInitComplete(ctx context.Context) (bool, error) {
	if c.barrier == nil {
		return false, fmt.Errorf("security barrier not available")
	}
	entry, err := c.barrier.Get(ctx, coreStatusSelfInitKey)
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
