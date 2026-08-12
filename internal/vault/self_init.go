// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"errors"
	"fmt"

	"github.com/openbao/openbao/sdk/v2/logical"
)

const (
	// selfInitFailedMarker is present in storage while self-init hasn't yet
	// completed.
	selfInitFailedMarker = "failed"

	// selfInitStatusPath is where selfInitFailedMarker is written.
	selfInitStatusPath = "core/status/self-init"
)

// ErrSelfInitFailed is returned when unsealing a core that detects a self-init
// failure marker.
var ErrSelfInitFailed = errors.New("self-initialization failed")

// MarkSelfInitStarted writes the selfInitFailedMarker to storage. This
// ensures that self-init is considered "failed" if interrupted before we reach
// MarkSelfInitCompleted.
func (c *Core) MarkSelfInitStarted(ctx context.Context) error {
	return c.barrier.Put(ctx, &logical.StorageEntry{
		Key:   selfInitStatusPath,
		Value: []byte(selfInitFailedMarker),
	})
}

// MarkSelfInitCompleted removes the marker written by MarkSelfInitStarted.
func (c *Core) MarkSelfInitCompleted(ctx context.Context) error {
	return c.barrier.Delete(ctx, selfInitStatusPath)
}

// checkSelfInit errors if selfInitFailedMarker or an unknown marker value is
// present at selfInitStatusPath.
func (c *Core) checkSelfInit(ctx context.Context) error {
	entry, err := c.barrier.Get(ctx, selfInitStatusPath)
	if err != nil {
		return err
	}
	if entry == nil {
		// This is the only happy path.
		return nil
	}

	switch string(entry.Value) {
	case selfInitFailedMarker:
		return fmt.Errorf("%w: refusing to unseal", ErrSelfInitFailed)
	default:
		return fmt.Errorf("%w: unknown status %q, is storage corrupted?",
			ErrSelfInitFailed, string(entry.Value))
	}
}
