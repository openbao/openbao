// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"testing"

	"github.com/openbao/openbao/helper/namespace"
	"github.com/stretchr/testify/require"
)

func TestSealManager_Resets(t *testing.T) {
	c, _, rootToken := TestCoreUnsealed(t)
	ctx := namespace.RootContext(t.Context())

	nsSealCfg := &SealConfig{
		Type:            "shamir",
		SecretShares:    1,
		SecretThreshold: 1,
		StoredShares:    1,
	}

	require := require.New(t)
	// Create Namespace A using SetNamespace
	nsA := &namespace.Namespace{Path: "a/"}
	_, err := c.namespaceStore.SetNamespace(ctx, nsA, nsSealCfg)
	require.NoError(err)

	// Create Namespace B using SetNamespace
	nsB := &namespace.Namespace{Path: "b/"}
	_, err = c.namespaceStore.SetNamespace(ctx, nsB, nsSealCfg)
	require.NoError(err)

	c.sealManager.lock.RLock()
	preSeals := len(c.sealManager.sealsByNamespace)
	preRotation := len(c.sealManager.rotationConfigByNamespace)
	preBarriers := c.sealManager.barrierByNamespace.Len()
	c.sealManager.lock.RUnlock()

	require.GreaterOrEqual(preSeals, 3, "expected at least 3 namespaces (root, a/ and b/) before seal")

	// Seal the core and this triggers Reset() internally via preSeal
	err = c.Seal(rootToken)
	require.NoError(err)

	// Verify
	c.sealManager.lock.RLock()
	defer c.sealManager.lock.RUnlock()

	require.Equal(1, len(c.sealManager.sealsByNamespace), "sealsByNamespace should be reset to 1")
	_, ok := c.sealManager.sealsByNamespace[namespace.RootNamespaceUUID]
	require.True(ok, "root namespace not found in sealsByNamespace")

	require.Equal(1, len(c.sealManager.rotationConfigByNamespace), "rotationConfigByNamespace should be reset to 1")
	_, ok = c.sealManager.rotationConfigByNamespace[namespace.RootNamespaceUUID]
	require.True(ok, "root namespace not found in rotationConfigByNamespace")

	require.Equal(1, c.sealManager.barrierByNamespace.Len(), "barrierByNamespace should be reset to 1")
	_, v, ok := c.sealManager.barrierByNamespace.LongestPrefix("")
	require.True(ok, "root barrier not found")
	require.NotNil(v, "root barrier is nil")

	require.Equal(1, len(c.sealManager.unlockInformationByNamespace), "unlockInformationByNamespace should be reset to 1")

	t.Logf("Seal() correctly reset SealManager: seals %d→1, barriers %d→1, rotation %d→1",
		preSeals, preBarriers, preRotation)
}
