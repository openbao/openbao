// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"

	"github.com/openbao/openbao/sdk/v2/logical"
)

const (
	// coreStatusSelfInitKey is the entry key for the self-init state machine.
	//
	// State machine values:
	//   (missing) : self-init succeeded, or legacy cluster, or manual init
	//   "failed"  : self-init was attempted but did not complete — corrupt state
	coreStatusSelfInitKey = "core/status/self-init"

	// coreStatusSelfInitFailed is written before self-init begins.
	// Finding this value at startup means the previous run crashed mid-init.
	coreStatusSelfInitFailed = "failed"
)

// MarkSelfInitStarted writes the coreStatusSelfInitFailed marker to storage.
// Must be called after core.Initialize() as the barrier must be unsealed.
func (c *Core) MarkSelfInitStarted(ctx context.Context) error {
	return c.barrier.Put(ctx, &logical.StorageEntry{
		Key:   coreStatusSelfInitKey,
		Value: []byte(coreStatusSelfInitFailed),
	})
}

// MarkSelfInitComplete removes the self-init marker from storage.
// Its absence indicates successful completion.
// Must be called after self-initialization finishes successfully.
func (c *Core) MarkSelfInitComplete(ctx context.Context) error {
	return c.barrier.Delete(ctx, coreStatusSelfInitKey)
}

// IsSelfInitComplete reads the self-init state machine from storage.
//
// State transitions:
//   - missing marker → true, nil  (self-init succeeded, or legacy cluster, or manual init)
//   - "failed"       → false, err (crash detected mid-init: corrupt state)
//   - anything else  → false, err (unknown value: corrupt state)
func (c *Core) IsSelfInitComplete(ctx context.Context) (bool, error) {
	entry, err := c.barrier.Get(ctx, coreStatusSelfInitKey)
	if err != nil {
		return false, err
	}

	if entry == nil {
		return true, nil
	}

	switch string(entry.Value) {
	case coreStatusSelfInitFailed:
		return false, fmt.Errorf("self-init marker %q found at startup: possible crash during initialization",
			coreStatusSelfInitFailed)
	default:
		return false, fmt.Errorf("unknown self-init state %q: storage may be corrupt",
			string(entry.Value))
	}
}
