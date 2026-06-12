// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"testing"

	log "github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/require"

	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/sdk/v2/helper/logging"
	"github.com/openbao/openbao/sdk/v2/physical"
	"github.com/openbao/openbao/sdk/v2/physical/inmem"
	vaultseal "github.com/openbao/openbao/vault/seal"
)

func TestRotateLifecycle(t *testing.T) {
	bc := &SealConfig{
		SecretShares:    1,
		SecretThreshold: 1,
	}
	c, rootKeys, _, _ := TestCoreUnsealedWithConfigs(t, bc, nil)
	require.Lenf(t, rootKeys, 1, "expected %d secret shares for a total of 1 root key, got %d", bc.SecretShares, len(rootKeys))

	ns := &namespace.Namespace{Path: "ns1/"}
	_ = TestCoreCreateUnsealedNamespaces(t, c, ns)
	testRotateLifecycleCommon(t, c.sealManager, namespace.RootNamespace, false)
	testRotateLifecycleCommon(t, c.sealManager, ns, false)
}

func testRotateLifecycleCommon(t *testing.T, sm *SealManager, ns *namespace.Namespace, recovery bool) {
	barrier := sm.NamespaceBarrier(ns.Path)
	require.NotNil(t, barrier)
	min, _ := barrier.KeyLength()
	ctx := namespace.ContextWithNamespace(t.Context(), ns)

	_, err := sm.UpdateRotation(ctx, ns, make([]byte, min), "", recovery)
	require.ErrorContainsf(t, err, "no rotation in progress", "rotation shouldn't be in progress, err: %v", err)

	require.Nil(t, sm.RotationConfig(ns.UUID, recovery))
	require.NoError(t, sm.CancelRotation(ctx, ns.UUID, false))

	newConf := &SealConfig{
		SecretThreshold: 3,
		SecretShares:    5,
	}
	rotationResult, err := sm.InitRotation(ctx, ns, newConf, recovery)
	require.NoError(t, err)
	require.Empty(t, rotationResult)

	conf := sm.RotationConfig(ns.UUID, recovery)
	newConf.Nonce = conf.Nonce
	require.Equal(t, conf, newConf)

	require.NoError(t, sm.CancelRotation(ctx, ns.UUID, recovery))
	require.Empty(t, sm.RotationConfig(ns.UUID, recovery))
}

func TestInitRotation(t *testing.T) {
	c, _, _ := TestCoreUnsealed(t)
	ns := &namespace.Namespace{Path: "ns1/"}
	_ = TestCoreCreateUnsealedNamespaces(t, c, ns)
	testInitRotationCommon(t, c.sealManager, namespace.RootNamespace, false)
	testInitRotationCommon(t, c.sealManager, ns, false)
}

func testInitRotationCommon(t *testing.T, sm *SealManager, ns *namespace.Namespace, recovery bool) {
	ctx := namespace.ContextWithNamespace(t.Context(), ns)
	// Try an invalid config
	badConf := &SealConfig{
		SecretThreshold: 5,
		SecretShares:    1,
	}
	rotationResult, err := sm.InitRotation(ctx, ns, badConf, recovery)
	require.Error(t, err)
	require.Empty(t, rotationResult)

	// Start rotation
	newConf := &SealConfig{
		SecretThreshold: 3,
		SecretShares:    5,
	}

	seal := sm.NamespaceSeal(ns.UUID)
	require.NotNil(t, seal)

	// If recovery key is supported, set newConf to be a recovery seal config
	if seal.RecoveryKeySupported() {
		newConf.Type = seal.RecoveryType()
	}

	rotationResult, err = sm.InitRotation(ctx, ns, newConf, recovery)
	require.NoError(t, err)
	require.Empty(t, rotationResult)

	// Second should fail
	rotationResult, err = sm.InitRotation(ctx, ns, newConf, recovery)
	require.Error(t, err)
	require.Empty(t, rotationResult)
}

func TestUpdateRotation(t *testing.T) {
	bc := &SealConfig{
		SecretShares:    1,
		SecretThreshold: 1,
	}
	c, rootKeys, _, root := TestCoreUnsealedWithConfigs(t, bc, nil)
	testUpdateRotationCommon(t, c, namespace.RootNamespace, rootKeys, root, false)

	ns := &namespace.Namespace{Path: "ns1/"}
	keys := TestCoreCreateUnsealedNamespaces(t, c, ns)
	testUpdateRotationCommon(t, c, ns, keys["ns1/"], root, false)
}

func testUpdateRotationCommon(t *testing.T, c *Core, ns *namespace.Namespace, keys [][]byte, root string, recovery bool) {
	ctx := namespace.ContextWithNamespace(t.Context(), ns)
	seal := c.sealManager.NamespaceSeal(ns.UUID)
	require.NotNil(t, seal)

	var expType string
	if recovery {
		expType = seal.RecoveryType()
	} else {
		expType = seal.BarrierType().String()
	}

	newConf := &SealConfig{
		Type:            expType,
		SecretThreshold: 3,
		SecretShares:    5,
	}
	rotationResult, err := c.sealManager.InitRotation(ctx, ns, newConf, recovery)
	require.NoError(t, err)
	require.Empty(t, rotationResult)

	// Fetch new config with generated nonce
	rotConfig := c.sealManager.RotationConfig(ns.UUID, recovery)
	require.NotNil(t, rotConfig)

	// Provide the root/recovery keys
	var result *RekeyResult
	for _, key := range keys {
		result, err = c.sealManager.UpdateRotation(ctx, ns, key, rotConfig.Nonce, recovery)
		require.NoError(t, err)
		if result != nil {
			break
		}
	}
	require.NotNil(t, result)

	// Should be no config
	require.Nil(t, c.sealManager.RotationConfig(ns.UUID, recovery))

	// SealConfig should update
	var sealConf *SealConfig
	if recovery {
		sealConf, err = seal.RecoveryConfig(ctx)
	} else {
		sealConf, err = seal.BarrierConfig(ctx)
	}
	require.NoError(t, err)
	require.NotNil(t, sealConf)
	require.Equal(t, sealConf, newConf)

	// At this point bail if we are rotating the barrier key with recovery
	// keys, since a new rotation should still be using the same set
	// of recovery keys and we haven't been returned key shares in this mode.
	if !recovery && seal.RecoveryKeySupported() {
		return
	}

	// Attempt unseal if this was not recovery mode
	if !recovery {
		switch ns.UUID {
		case namespace.RootNamespaceUUID:
			require.NoError(t, c.Seal(root))
			for i := 0; i < newConf.SecretThreshold; i++ {
				_, err = TestCoreUnseal(c, TestKeyCopy(result.SecretShares[i]))
				require.NoError(t, err)
			}
			require.False(t, c.Sealed())
		default:
			require.NoError(t, c.namespaceStore.SealNamespace(namespace.RootContext(ctx), ns.Path))
			for i := 0; i < newConf.SecretThreshold; i++ {
				_, err = TestNamespaceUnseal(c, ns, TestKeyCopy(result.SecretShares[i]))
				require.NoError(t, err)
			}
			require.False(t, c.NamespaceSealed(ns))
		}
	}

	// Start another rotation, this time we require a quorum
	newConf = &SealConfig{
		Type:            expType,
		SecretThreshold: 1,
		SecretShares:    1,
	}
	rotationResult, err = c.sealManager.InitRotation(ctx, ns, newConf, recovery)
	require.NoError(t, err)
	require.Empty(t, rotationResult)

	// Fetch new config with generated nonce
	rotConfig = c.sealManager.RotationConfig(ns.UUID, recovery)
	require.NotNil(t, rotConfig)

	// Provide the parts root
	oldResult := result
	for i := range 3 {
		result, err = c.sealManager.UpdateRotation(ctx, ns, TestKeyCopy(oldResult.SecretShares[i]), rotConfig.Nonce, recovery)
		require.NoError(t, err)

		// Should be progress
		if i < 2 {
			rConfig := c.sealManager.RotationConfig(ns.UUID, recovery)
			require.Equal(t, len(rConfig.RotationProgress), i+1)
		}
	}

	require.NotNil(t, result)
	require.Len(t, result.SecretShares, 1)

	// Attempt unseal if this was not recovery mode
	if !recovery {
		switch ns.UUID {
		case namespace.RootNamespaceUUID:
			require.NoError(t, c.Seal(root))
			unsealed, err := TestCoreUnseal(c, result.SecretShares[0])
			require.NoError(t, err)
			require.True(t, unsealed)
		default:
			require.NoError(t, c.namespaceStore.SealNamespace(namespace.RootContext(ctx), ns.Path))
			unsealed, err := TestNamespaceUnseal(c, ns, result.SecretShares[0])
			require.NoError(t, err)
			require.True(t, unsealed)
		}
	}

	// SealConfig should update
	if recovery {
		sealConf, err = seal.RecoveryConfig(ctx)
	} else {
		sealConf, err = seal.BarrierConfig(ctx)
	}
	require.NoError(t, err)
	require.Equal(t, sealConf, newConf)

	// verfiy nonce was removed after rotation.
	require.Empty(t, sealConf.Nonce)
}

func TestRotateInvalid(t *testing.T) {
	bc := &SealConfig{
		SecretShares:    3,
		SecretThreshold: 3,
	}
	c, rootKeys, _, _ := TestCoreUnsealedWithConfigs(t, bc, nil)
	testRotateInvalidCommon(t, c, namespace.RootNamespace, rootKeys, false)

	ns := &namespace.Namespace{Path: "ns1/"}
	keys := TestCoreCreateUnsealedNamespaces(t, c, ns)
	testRotateInvalidCommon(t, c, ns, keys["ns1/"], false)
}

func testRotateInvalidCommon(t *testing.T, c *Core, ns *namespace.Namespace, keys [][]byte, recovery bool) {
	ctx := namespace.ContextWithNamespace(t.Context(), ns)
	newConf := &SealConfig{
		SecretThreshold: 3,
		SecretShares:    5,
	}

	// Start rotation
	rotationResult, err := c.sealManager.InitRotation(ctx, ns, newConf, recovery)
	require.NoError(t, err)
	require.Empty(t, rotationResult)

	// Fetch new config with generated nonce
	rotConfig := c.sealManager.RotationConfig(ns.UUID, recovery)
	require.NotNil(t, rotConfig)

	// Provide invalid nonce
	_, err = c.sealManager.UpdateRotation(ctx, ns, keys[0], "abcd", recovery)
	require.Error(t, err)

	// Corrupt the first byte of the first key so we'll fail once $threshold
	// keys have been provided.
	keys[0][0]++

	// Provide invalid keys
	for i, key := range keys {
		ret, err := c.sealManager.UpdateRotation(ctx, ns, key, rotConfig.Nonce, recovery)
		require.Nil(t, ret)
		if i == 3 {
			require.Error(t, err)
		}
	}

	// Check if progress has been reset
	rotConfig = c.sealManager.RotationConfig(ns.UUID, recovery)
	require.Equalf(t, 0, len(rotConfig.RotationProgress), "rotation progress should be 0, got: %d", len(rotConfig.RotationProgress))
}

func TestRotationStandby(t *testing.T) {
	// Create the first core and initialize it
	logger := logging.NewVaultLogger(log.Trace)

	inm, err := inmem.NewInmemHA(nil, logger)
	require.NoError(t, err)
	inmha, err := inmem.NewInmemHA(nil, logger)
	require.NoError(t, err)

	redirectOriginal := "http://127.0.0.1:8200"
	core, err := NewCore(&CoreConfig{
		Physical:     inm,
		HAPhysical:   inmha.(physical.HABackend),
		RedirectAddr: redirectOriginal,
		DisableCache: true,
	})
	require.NoError(t, err)

	defer core.Shutdown()
	keys, root := TestCoreInit(t, core)
	for _, key := range keys {
		_, err := TestCoreUnseal(core, TestKeyCopy(key))
		require.NoError(t, err)
	}

	// Wait for core to become active
	TestWaitActive(t, core)

	// Create a second core, attached to same in-memory store
	redirectOriginal2 := "http://127.0.0.1:8500"
	core2, err := NewCore(&CoreConfig{
		Physical:     inm,
		HAPhysical:   inmha.(physical.HABackend),
		RedirectAddr: redirectOriginal2,
		DisableCache: true,
	})
	require.NoError(t, err)
	defer core2.Shutdown()
	for _, key := range keys {
		_, err := TestCoreUnseal(core2, TestKeyCopy(key))
		require.NoError(t, err)
	}

	// Rotate the root key
	newConf := &SealConfig{
		SecretShares:    1,
		SecretThreshold: 1,
	}
	_, err = core.sealManager.InitRotation(t.Context(), namespace.RootNamespace, newConf, false)
	require.NoError(t, err)

	// Fetch new config with generated nonce
	rotConfig := core.sealManager.RotationConfig(namespace.RootNamespaceUUID, false)
	require.NotNil(t, rotConfig)

	var rotationResult *RekeyResult
	for _, key := range keys {
		rotationResult, err = core.sealManager.UpdateRotation(t.Context(), namespace.RootNamespace, key, rotConfig.Nonce, false)
		require.NoError(t, err)
	}
	require.NotNil(t, rotationResult)

	// Seal the first core, should step down
	err = core.Seal(root)
	require.NoError(t, err)

	// Wait for core2 to become active
	TestWaitActive(t, core2)

	// Rotate the root key again
	_, err = core2.sealManager.InitRotation(t.Context(), namespace.RootNamespace, newConf, false)
	require.NoError(t, err)

	// Fetch new config with generated nonce
	rotConfig = core2.sealManager.RotationConfig(namespace.RootNamespaceUUID, false)
	require.NotNil(t, rotConfig)

	var rotationResult2 *RekeyResult
	for _, key := range rotationResult.SecretShares {
		rotationResult2, err = core2.sealManager.UpdateRotation(t.Context(), namespace.RootNamespace, key, rotConfig.Nonce, false)
		require.NoError(t, err)
	}
	require.NotNil(t, rotationResult2)
}

// Verifies that if we are using recovery keys to force a rotation of a stored-shares
// barrier that verification is not allowed since the keys aren't returned.
func TestVerficationInvalid(t *testing.T) {
	core, _, _, _ := TestCoreUnsealedWithConfigSealOpts(t,
		&SealConfig{SecretShares: 1, SecretThreshold: 1},
		&SealConfig{SecretShares: 1, SecretThreshold: 1},
		&vaultseal.TestSealOpts{Wrapper: wrapping.WrapperTypeTest})

	_, err := core.sealManager.InitRotation(t.Context(), namespace.RootNamespace, &SealConfig{
		VerificationRequired: true,
	}, false)
	require.ErrorContainsf(t, err, "requiring verification not supported", "unexpected error: %v", err)
}

func TestRotationGenerateRecoveryKey(t *testing.T) {
	core, _, _, _ := TestCoreUnsealedWithConfigSealOpts(t,
		&SealConfig{SecretShares: 1, SecretThreshold: 1},
		&SealConfig{SecretShares: 0, SecretThreshold: 0},
		&vaultseal.TestSealOpts{Wrapper: wrapping.WrapperTypeTest})

	// Rotate (generate) the recovery key
	rotConfig := &SealConfig{
		SecretShares:    5,
		SecretThreshold: 3,
	}

	result, err := core.sealManager.InitRotation(t.Context(), namespace.RootNamespace, rotConfig, true)
	require.NoError(t, err)
	require.Len(t, result.SecretShares, 5)
	require.Empty(t, result.PGPFingerprints)
}

func TestRotateBarrierRootKey(t *testing.T) {
	c1, unsealShares, _, _ := TestCoreUnsealedWithConfigSealOpts(t,
		&SealConfig{SecretShares: 3, SecretThreshold: 2},
		nil,
		&vaultseal.TestSealOpts{Wrapper: vaultseal.WrapperTypeShamir})

	c2, _, _, _ := TestCoreUnsealedWithConfigSealOpts(t,
		&SealConfig{},
		&SealConfig{SecretShares: 3, SecretThreshold: 2},
		&vaultseal.TestSealOpts{Wrapper: wrapping.WrapperTypeTest})

	ns := &namespace.Namespace{Path: "ns1/"}
	unsealKeysNS := TestCoreCreateUnsealedNamespaces(t, c2, ns)

	testRotateBarrierRootKey(t, c1, namespace.RootNamespace, unsealShares)
	testRotateBarrierRootKey(t, c2, ns, unsealKeysNS["ns1/"])
	testRotateBarrierRootKey(t, c2, namespace.RootNamespace, unsealShares)
}

func testRotateBarrierRootKey(t *testing.T, c *Core, ns *namespace.Namespace, unsealShares [][]byte) {
	ctx := namespace.ContextWithNamespace(t.Context(), ns)
	rootCtx := namespace.RootContext(ctx)
	seal := c.sealManager.NamespaceSeal(ns.UUID)
	require.NotNil(t, seal)

	// read stored root key
	storedRootKeyBefore, err := seal.GetStoredKeys(ctx)
	require.NoError(t, err)

	// rotate root key
	require.NoError(t, c.sealManager.RotateBarrierRootKey(rootCtx, ns))

	// read stored root key
	storedRootKeyAfter, err := seal.GetStoredKeys(ctx)
	require.NoError(t, err)
	require.NotEqual(t, storedRootKeyBefore, storedRootKeyAfter, "should rotate stored root key")

	// seal
	if ns.UUID == namespace.RootNamespaceUUID {
		require.NoError(t, c.sealInternal())
		require.True(t, c.Sealed())
	} else {
		require.NoError(t, c.namespaceStore.SealNamespace(rootCtx, ns.Path))
		require.True(t, c.NamespaceSealed(ns))
	}

	switch seal.BarrierType() {
	case vaultseal.WrapperTypeShamir:
		// verify you can unseal using the same
		// unseal key as before rotation
		var unsealed bool
		var err error
		for _, key := range unsealShares {
			if ns.UUID == namespace.RootNamespaceUUID {
				unsealed, err = c.Unseal(TestKeyCopy(key))
			} else {
				unsealed, err = TestNamespaceUnseal(c, ns, key)
			}
			require.NoError(t, err)
			if !unsealed {
				continue
			} else {
				break
			}
		}
		require.False(t, c.Sealed())
	default:
		// unseal with stored keys
		require.NoError(t, c.UnsealWithStoredKeys(ctx))
	}
	require.False(t, c.NamespaceSealed(ns))
}
