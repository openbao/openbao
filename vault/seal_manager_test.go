// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"testing"
)

func TestSealManager_ResetInternal(t *testing.T) {
	c, _, _ := TestCoreUnsealed(t)

	// Verify that SM state exists before reset
	if c.sealManager.barrierByNamespace == nil {
		t.Fatal("expected barrierByNamespace to be initialized")
	}

	// Store reference to original barrier map
	originalBarriers := c.sealManager.barrierByNamespace

	// Call ResetInternal
	err := c.sealManager.ResetInternal(context.Background())
	if err != nil {
		t.Fatalf("ResetInternal failed: %v", err)
	}

	// Verify that SM state was reset and setup() reinitializes maps
	if c.sealManager.barrierByNamespace == nil {
		t.Fatal("expected barrierByNamespace to be initialized after reset")
	}

	// Verify that it's a new map
	if c.sealManager.barrierByNamespace == originalBarriers {
		t.Fatal("expected barrierByNamespace to be reinitialized with new map")
	}
}
