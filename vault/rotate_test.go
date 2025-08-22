// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"testing"

	log "github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/require"

	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/sdk/v2/helper/logging"
	"github.com/openbao/openbao/sdk/v2/physical"
	"github.com/openbao/openbao/sdk/v2/physical/inmem"
	"github.com/openbao/openbao/vault/seal"
)

func TestCoreRotateLifecycle(t *testing.T) {
	bc := &SealConfig{
		SecretShares:    1,
		SecretThreshold: 1,
		StoredShares:    1,
	}
	c, rootKeys, _, _ := TestCoreUnsealedWithConfigs(t, bc, nil)
	require.Lenf(t, rootKeys, 1, "expected %d secret shares and %v stored shares for a total of 1 root key, got %d", bc.SecretShares, bc.StoredShares, len(rootKeys))
	testCoreRotateLifecycleCommon(t, c.sealManager, namespace.RootNamespace, false)
}

func testCoreRotateLifecycleCommon(t *testing.T, s *SealManager, ns *namespace.Namespace, recovery bool) {
	barrier := s.NamespaceBarrier(ns.Path)
	require.NotNil(t, barrier)
	min, _ := barrier.KeyLength()
	ctx := namespace.ContextWithNamespace(context.Background(), ns)

	// Verify update not allowed
	_, err := s.UpdateRotation(ctx, ns, make([]byte, min), "", recovery)
	require.ErrorContainsf(t, err, "no rotation in progress", "rotation shouldn't be in progress, err: %v", err)

	// Should be no progress
	_, _, err = s.RotationProgress(ns, recovery, false)
	require.Error(t, err)

	// Should be no config
	conf := s.RotationConfig(ns, recovery)
	require.Nil(t, conf)

	// Cancel should be idempotent
	cancelErr := s.CancelRotation(ns, false)
	require.NoError(t, cancelErr)

	// Start rotation
	newConf := &SealConfig{
		SecretThreshold: 3,
		SecretShares:    5,
	}
	rotationResult, err := s.InitRotation(ctx, ns, newConf, recovery)
	require.NoError(t, err)
	require.Empty(t, rotationResult)

	// Should get config
	conf = s.RotationConfig(ns, recovery)
	newConf.Nonce = conf.Nonce
	require.Equal(t, conf, newConf)

	// Cancel should be clear
	cancelErr = s.CancelRotation(ns, recovery)
	require.NoError(t, cancelErr)

	// Should be no config
	conf = s.RotationConfig(ns, recovery)
	require.Empty(t, conf)
}

func TestCoreInitRotation(t *testing.T) {
	t.Run("init-barrier-rotation", func(t *testing.T) {
		c, _, _ := TestCoreUnsealed(t)
		testCoreInitRotationCommon(t, c.sealManager, namespace.RootNamespace, false)
	})
}

func testCoreInitRotationCommon(t *testing.T, s *SealManager, ns *namespace.Namespace, recovery bool) {
	ctx := namespace.ContextWithNamespace(context.Background(), ns)
	// Try an invalid config
	badConf := &SealConfig{
		SecretThreshold: 5,
		SecretShares:    1,
	}
	rotationResult, err := s.InitRotation(ctx, ns, badConf, recovery)
	require.Error(t, err)
	require.Empty(t, rotationResult)

	// Start rotation
	newConf := &SealConfig{
		SecretThreshold: 3,
		SecretShares:    5,
	}

	seal := s.NamespaceSeal(ns.UUID)
	require.NotNil(t, seal)

	// If recovery key is supported, set newConf to be a recovery seal config
	if seal.RecoveryKeySupported() {
		newConf.Type = seal.RecoveryType()
	}

	rotationResult, err = s.InitRotation(ctx, ns, newConf, recovery)
	require.NoError(t, err)
	require.Empty(t, rotationResult)

	// Second should fail
	rotationResult, err = s.InitRotation(ctx, ns, newConf, recovery)
	require.Error(t, err)
	require.Empty(t, rotationResult)
}

func TestCoreUpdateRotation(t *testing.T) {
	bc := &SealConfig{
		SecretShares:    1,
		SecretThreshold: 1,
	}
	c, rootKeys, _, root := TestCoreUnsealedWithConfigs(t, bc, nil)
	testCoreUpdateRotationCommon(t, c, namespace.RootNamespace, rootKeys, root, false)
}

func testCoreUpdateRotationCommon(t *testing.T, c *Core, ns *namespace.Namespace, keys [][]byte, root string, recovery bool) {
	ctx := namespace.ContextWithNamespace(context.Background(), ns)
	s := c.sealManager

	// Start rotation
	var expType string
	seal := s.NamespaceSeal(ns.UUID)
	require.NotNil(t, seal)
	if recovery {
		expType = seal.RecoveryType()
	} else {
		expType = seal.WrapperType().String()
	}

	newConf := &SealConfig{
		Type:            expType,
		SecretThreshold: 3,
		SecretShares:    5,
	}
	rotationResult, err := s.InitRotation(ctx, ns, newConf, recovery)
	require.NoError(t, err)
	require.Empty(t, rotationResult)

	// Fetch new config with generated nonce
	rotationConfig := s.RotationConfig(ns, recovery)
	require.NotNil(t, rotationConfig)

	// Provide the root/recovery keys
	var result *RekeyResult
	for _, key := range keys {
		result, err = s.UpdateRotation(ctx, ns, key, rotationConfig.Nonce, recovery)
		require.NoError(t, err)
		if result != nil {
			break
		}
	}
	require.NotNil(t, result)

	// Should be no progress
	_, _, err = s.RotationProgress(ns, recovery, false)
	require.Error(t, err)

	// Should be no config
	conf := s.RotationConfig(ns, recovery)
	require.Nil(t, conf)

	// config of the Seal should be updated
	var sealConfig *SealConfig
	var confErr error
	if recovery {
		sealConfig, confErr = seal.RecoveryConfig(ctx)
	} else {
		sealConfig, confErr = seal.Config(ctx)
	}
	require.NoError(t, confErr)
	require.NotNil(t, sealConfig)

	newConf.Nonce = rotationConfig.Nonce
	require.Equal(t, sealConfig, newConf)

	// At this point bail if we are rotating the barrier key with recovery
	// keys, since a new rotation should still be using the same set
	// of recovery keys and we haven't been returned key shares in this mode.
	if !recovery && seal.RecoveryKeySupported() {
		return
	}

	// Attempt unseal if this was not recovery mode
	if !recovery {
		err := c.Seal(root)
		require.NoError(t, err)
		for i := 0; i < newConf.SecretThreshold; i++ {
			_, err = TestCoreUnseal(c, TestKeyCopy(result.SecretShares[i]))
			require.NoError(t, err)
		}
		require.False(t, c.Sealed())
	}

	// Start another rotation, this time we require a quorum!
	newConf = &SealConfig{
		Type:            expType,
		SecretThreshold: 1,
		SecretShares:    1,
	}
	rotationResult, err = s.InitRotation(ctx, ns, newConf, recovery)
	require.NoError(t, err)
	require.Empty(t, rotationResult)

	// Fetch new config with generated nonce
	rotationConfig = s.RotationConfig(ns, recovery)
	require.NotNil(t, rotationConfig)

	// Provide the parts root
	oldResult := result
	for i := range 3 {
		result, err = s.UpdateRotation(ctx, ns, TestKeyCopy(oldResult.SecretShares[i]), rotationConfig.Nonce, recovery)
		require.NoError(t, err)

		// Should be progress
		if i < 2 {
			_, num, err := s.RotationProgress(ns, recovery, false)
			require.NoError(t, err)
			require.Equal(t, num, i+1)
		}
	}

	require.NotNil(t, result)
	require.Len(t, result.SecretShares, 1)

	// Attempt unseal if this was not recovery mode
	if !recovery {
		err := c.Seal(root)
		require.NoError(t, err)

		unsealed, err := TestCoreUnseal(c, result.SecretShares[0])
		require.NoError(t, err)
		require.True(t, unsealed)
	}

	// SealConfig should update
	if recovery {
		sealConfig, confErr = seal.RecoveryConfig(ctx)
	} else {
		sealConfig, confErr = seal.Config(ctx)
	}
	require.NoError(t, confErr)

	newConf.Nonce = rotationConfig.Nonce
	require.Equal(t, sealConfig, newConf)
}

func TestCoreRotateInvalid(t *testing.T) {
	bc := &SealConfig{
		StoredShares:    0,
		SecretShares:    1,
		SecretThreshold: 1,
	}
	c, rootKeys, _, _ := TestCoreUnsealedWithConfigs(t, bc, nil)
	testCoreRotateInvalidCommon(t, c, namespace.RootNamespace, rootKeys, false)
}

func testCoreRotateInvalidCommon(t *testing.T, c *Core, ns *namespace.Namespace, keys [][]byte, recovery bool) {
	ctx := namespace.ContextWithNamespace(context.Background(), ns)
	s := c.sealManager

	newConf := &SealConfig{
		SecretThreshold: 3,
		SecretShares:    5,
	}
	// Start rotation
	rotationResult, err := s.InitRotation(ctx, ns, newConf, recovery)
	require.NoError(t, err)
	require.Empty(t, rotationResult)

	// Fetch new config with generated nonce
	rotConfig := s.RotationConfig(ns, recovery)
	require.NotNil(t, rotConfig)

	// Provide invalid nonce
	_, err = s.UpdateRotation(ctx, ns, keys[0], "abcd", recovery)
	require.Error(t, err)

	// Provide the invalid key
	key := keys[0]
	oldkeystr := fmt.Sprintf("%#v", key)
	key[0]++
	newkeystr := fmt.Sprintf("%#v", key)

	ret, err := s.UpdateRotation(ctx, ns, key, rotConfig.Nonce, recovery)
	require.Nil(t, ret)
	require.Errorf(t, err, "expected error, oldkeystr: %s\nnewkeystr: %s", oldkeystr, newkeystr)

	// Check if progress has been reset
	_, num, rotErr := s.RotationProgress(ns, recovery, false)
	require.NoError(t, rotErr)
	require.Equalf(t, num, 0, "rotation progress should be 0, got: %d", num)
}

func TestCoreRotationStandby(t *testing.T) {
	// Create the first core and initialize it
	ctx := namespace.RootContext(context.Background())
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

	s := core.sealManager
	ns := namespace.RootNamespace
	// Rotate the root key
	newConf := &SealConfig{
		SecretShares:    1,
		SecretThreshold: 1,
	}
	_, err = s.InitRotation(ctx, ns, newConf, false)
	require.NoError(t, err)

	// Fetch new config with generated nonce
	rotConfig := s.RotationConfig(ns, false)
	require.NotNil(t, rotConfig)

	var rotationResult *RekeyResult
	for _, key := range keys {
		rotationResult, err = s.UpdateRotation(ctx, ns, key, rotConfig.Nonce, false)
		require.NoError(t, err)
	}
	require.NotNil(t, rotationResult)

	// Seal the first core, should step down
	err = core.Seal(root)
	require.NoError(t, err)

	// Wait for core2 to become active
	TestWaitActive(t, core2)
	s2 := core2.sealManager

	// Rotate the root key again
	_, err = s2.InitRotation(ctx, ns, newConf, false)
	require.NoError(t, err)

	// Fetch new config with generated nonce
	rotConfig = s2.RotationConfig(ns, false)
	require.NotNil(t, rotConfig)

	var rotationResult2 *RekeyResult
	for _, key := range rotationResult.SecretShares {
		rotationResult2, err = s2.UpdateRotation(ctx, ns, key, rotConfig.Nonce, false)
		require.NoError(t, err)
	}
	require.NotNil(t, rotationResult2)
}

// verifies that if we are using recovery keys to force a rotation of a stored-shares
// barrier that verification is not allowed since the keys aren't returned
func TestRotationVerficationInvalid(t *testing.T) {
	core, _, _, _ := TestCoreUnsealedWithConfigSealOpts(t,
		&SealConfig{StoredShares: 1, SecretShares: 1, SecretThreshold: 1},
		&SealConfig{StoredShares: 1, SecretShares: 1, SecretThreshold: 1},
		&seal.TestSealOpts{StoredKeys: seal.StoredKeysSupportedGeneric})

	_, err := core.sealManager.InitRotation(namespace.RootContext(context.Background()), namespace.RootNamespace, &SealConfig{
		VerificationRequired: true,
		StoredShares:         1,
	}, false)
	require.ErrorContainsf(t, err, "requiring verification not supported", "unexpected error: %v", err)
}

func TestRotationGenerateRecoveryKey(t *testing.T) {
	core, _, _, _ := TestCoreUnsealedWithConfigSealOpts(t,
		&SealConfig{StoredShares: 1, SecretShares: 1, SecretThreshold: 1},
		&SealConfig{SecretShares: 0, SecretThreshold: 0},
		&seal.TestSealOpts{StoredKeys: seal.StoredKeysSupportedGeneric})

	// Rotate (generate) the recovery key
	rotConfig := &SealConfig{
		SecretShares:    5,
		SecretThreshold: 3,
	}

	result, err := core.sealManager.InitRotation(namespace.RootContext(context.Background()), namespace.RootNamespace, rotConfig, true)
	require.NoError(t, err)
	require.Len(t, result.SecretShares, 5)
	require.Empty(t, result.PGPFingerprints)
}
