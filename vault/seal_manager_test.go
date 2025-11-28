// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"testing"
)

func TestSealManager_Reset(t *testing.T) {
	c, _, _ := TestCoreUnsealed(t)

	// Verify that SM state exists before reset
	if c.sealManager.barrierByNamespace == nil {
		t.Fatal("expected barrierByNamespace to be initialized")
	}

	// Store reference to original barrier map
	originalBarriers := c.sealManager.barrierByNamespace

	// Call Reset
	c.sealManager.Reset(context.Background())

	// Verify that SM state was reset and setup() reinitializes maps
	if c.sealManager.barrierByNamespace == nil {
		t.Fatal("expected barrierByNamespace to be initialized after reset")
	}

	// Verify that it's a new map
	if c.sealManager.barrierByNamespace == originalBarriers {
		t.Fatal("expected barrierByNamespace to be reinitialized")
	}
	if len(c.sealManager.sealsByNamespace) == 0 {
		t.Fatal("expected sealsByNamespace to be reinitialized after reset")
	}
	if len(c.sealManager.unlockInformationByNamespace) == 0 {
		t.Fatal("expected unlockInformationByNamespace to be reinitialized after reset")
	}
	if len(c.sealManager.rotationConfigByNamespace) == 0 {
		t.Fatal("expected rotationConfigByNamespace to be reinitialized after reset")
	}
}
