// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"testing"

	"github.com/openbao/openbao/helper/namespace"
)

func TestSealManager_Resets(t *testing.T) {
	t.Helper()

	c, _, _ := TestCoreUnsealed(t)
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	nsSealCfg := &SealConfig{
		Type:            "shamir",
		SecretShares:    1,
		SecretThreshold: 1,
		StoredShares:    1,
	}

	nsA, keySharesA := createSealableNamespace(t, c, ctx, "a/", nsSealCfg)
	if nsA == nil || len(keySharesA) == 0 {
		t.Fatal("failed to create namespace a/")
	}

	nsB, keySharesB := createSealableNamespace(t, c, ctx, "b/", nsSealCfg)
	if nsB == nil || len(keySharesB) == 0 {
		t.Fatal("failed to create namespace b/")
	}

	// Capture pre-reset state
	c.sealManager.lock.RLock()
	preSeals := len(c.sealManager.sealsByNamespace)
	preRotation := len(c.sealManager.rotationConfigByNamespace)
	preBarriers := c.sealManager.barrierByNamespace.Len()
	c.sealManager.lock.RUnlock()

	if preSeals < 3 {
		t.Fatalf("expected 3 namespaces (root, a and b) before reset, got %d", preSeals)
	}

	// Call Reset() with write lock held
	c.sealManager.lock.Lock()
	c.sealManager.Reset()
	c.sealManager.lock.Unlock()

	// Verify post reset state
	c.sealManager.lock.RLock()
	defer c.sealManager.lock.RUnlock()

	if len(c.sealManager.sealsByNamespace) != 1 {
		t.Fatalf("sealsByNamespace: expected 1, got %d", len(c.sealManager.sealsByNamespace))
	}

	if _, ok := c.sealManager.sealsByNamespace[namespace.RootNamespaceUUID]; !ok {
		t.Fatal("root namespace not found in sealsByNamespace")
	}

	if len(c.sealManager.rotationConfigByNamespace) != 1 {
		t.Fatalf("rotationConfigByNamespace: expected 1, got %d", len(c.sealManager.rotationConfigByNamespace))
	}

	if _, ok := c.sealManager.rotationConfigByNamespace[namespace.RootNamespaceUUID]; !ok {
		t.Fatal("root namespace not found in rotationConfigByNamespace")
	}

	if c.sealManager.barrierByNamespace.Len() != 1 {
		t.Fatalf("barrierByNamespace: expected 1, got %d", c.sealManager.barrierByNamespace.Len())
	}

	_, v, ok := c.sealManager.barrierByNamespace.LongestPrefix("")
	if !ok || v == nil {
		t.Fatal("root barrier not found")
	}

	if len(c.sealManager.unlockInformationByNamespace) != 1 {
		t.Fatalf("unlockInformationByNamespace: expected 1, got %d", len(c.sealManager.unlockInformationByNamespace))
	}

	t.Logf("Reset() cleared: seals %d =1, barriers %d =1, rotation %d =1",
		preSeals, preBarriers, preRotation)
}

// createSealableNamespace creates a namespace with a seal configuration.
func createSealableNamespace(t *testing.T, c *Core, parentCtx context.Context, relPath string, sealCfg *SealConfig) (*namespace.Namespace, [][]byte) {
	t.Helper()

	if c.namespaceStore == nil {
		t.Fatal("namespaceStore not initialized")
	}

	relPath = namespace.Canonicalize(relPath)

	nsEntry, nsKeyShares, err := c.namespaceStore.ModifyNamespaceByPath(parentCtx, relPath, sealCfg, func(ctx context.Context, ns *namespace.Namespace) (*namespace.Namespace, error) {
		return ns, nil
	},
	)
	if err != nil {
		t.Fatalf("failed to create namespace %q: %v", relPath, err)
	}

	if nsEntry == nil {
		t.Fatalf("namespace %q not created", relPath)
	}

	return nsEntry, nsKeyShares
}
