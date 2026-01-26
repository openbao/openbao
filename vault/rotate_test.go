// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"testing"

	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-uuid"
	"github.com/stretchr/testify/require"

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
	testCoreRotateLifecycleCommon(t, c, false)
}

func testCoreRotateLifecycleCommon(t *testing.T, c *Core, recovery bool) {
	min, _ := c.barrier.KeyLength()
	// Verify update not allowed
	_, err := c.UpdateRotation(context.Background(), make([]byte, min), "", recovery)
	expected := "no barrier rotation in progress"
	if recovery {
		expected = "no recovery rotation in progress"
	}

	require.ErrorContainsf(t, err, expected, "rotation shouldn't be in progress, err: %v", err)

	// Should be no progress
	var progressErr error
	_, _, progressErr = c.RotationProgress(recovery, false)
	require.Error(t, progressErr)

	// Should be no config
	conf := c.RotationConfig(recovery)
	require.Nil(t, conf)

	// Cancel should be idempotent
	err = c.CancelRotation(false)
	require.NoError(t, err)

	// Start rotation
	newConf := &SealConfig{
		SecretThreshold: 3,
		SecretShares:    5,
	}
	rotationResult, err := c.InitRotation(context.Background(), newConf, recovery)
	require.NoError(t, err)
	require.Empty(t, rotationResult)

	// Should get config
	conf = c.RotationConfig(recovery)
	newConf.Nonce = conf.Nonce
	require.Equal(t, conf, newConf)

	// Cancel should be clear
	err = c.CancelRotation(recovery)
	require.NoError(t, err)

	// Should be no config
	conf = c.RotationConfig(recovery)
	require.NoError(t, err)
}

func TestCoreInitRotation(t *testing.T) {
	t.Run("init-barrier-rotation", func(t *testing.T) {
		c, _, _ := TestCoreUnsealed(t)
		testCoreInitRotationCommon(t, c, false)
	})
}

func testCoreInitRotationCommon(t *testing.T, c *Core, recovery bool) {
	// Try an invalid config
	badConf := &SealConfig{
		SecretThreshold: 5,
		SecretShares:    1,
	}
	rotationResult, err := c.InitRotation(context.Background(), badConf, recovery)
	require.Error(t, err)
	require.Empty(t, rotationResult)

	// Start rotation
	newConf := &SealConfig{
		SecretThreshold: 3,
		SecretShares:    5,
	}

	// If recovery key is supported, set newConf to be a recovery seal config
	if c.seal.RecoveryKeySupported() {
		newConf.Type = c.seal.RecoveryType()
	}

	rotationResult, err = c.InitRotation(context.Background(), newConf, recovery)
	require.NoError(t, err)
	require.Empty(t, rotationResult)

	// Second should fail
	rotationResult, err = c.InitRotation(context.Background(), newConf, recovery)
	require.Error(t, err)
	require.Empty(t, rotationResult)
}

func TestCoreUpdateRotation(t *testing.T) {
	bc := &SealConfig{
		SecretShares:    1,
		SecretThreshold: 1,
	}
	c, rootKeys, _, root := TestCoreUnsealedWithConfigs(t, bc, nil)
	testCoreUpdateRotationCommon(t, c, rootKeys, root, false)
}

func testCoreUpdateRotationCommon(t *testing.T, c *Core, keys [][]byte, root string, recovery bool) {
	var err error
	// Start rotation
	var expType string
	if recovery {
		expType = c.seal.RecoveryType()
	} else {
		expType = c.seal.BarrierType().String()
	}

	newConf := &SealConfig{
		Type:            expType,
		SecretThreshold: 3,
		SecretShares:    5,
	}
	rotationResult, hErr := c.InitRotation(context.Background(), newConf, recovery)
	require.NoError(t, hErr)
	require.Empty(t, rotationResult)

	// Fetch new config with generated nonce
	rotConfig := c.RotationConfig(recovery)
	require.NotNil(t, rotConfig)

	// Provide the root/recovery keys
	var result *RekeyResult
	for _, key := range keys {
		result, err = c.UpdateRotation(context.Background(), key, rotConfig.Nonce, recovery)
		require.NoError(t, err)
		if result != nil {
			break
		}
	}
	require.NotNil(t, result)

	// Should be no progress
	_, _, err = c.RotationProgress(recovery, false)
	require.Error(t, err)

	// Should be no config
	conf := c.RotationConfig(recovery)
	require.Nil(t, conf)

	// SealConfig should update
	var sealConf *SealConfig
	if recovery {
		sealConf, err = c.seal.RecoveryConfig(context.Background())
	} else {
		sealConf, err = c.seal.BarrierConfig(context.Background())
	}
	require.NoError(t, err)
	require.NotNil(t, sealConf)

	newConf.Nonce = rotConfig.Nonce
	require.Equal(t, sealConf, newConf)

	// At this point bail if we are rotating the barrier key with recovery
	// keys, since a new rotation should still be using the same set
	// of recovery keys and we haven't been returned key shares in this mode.
	if !recovery && c.seal.RecoveryKeySupported() {
		return
	}

	// Attempt unseal if this was not recovery mode
	if !recovery {
		err = c.Seal(root)
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
	rotationResult, err = c.InitRotation(context.Background(), newConf, recovery)
	require.NoError(t, err)
	require.Empty(t, rotationResult)

	// Fetch new config with generated nonce
	rotConfig = c.RotationConfig(recovery)
	require.NotNil(t, rotConfig)

	// Provide the parts root
	oldResult := result
	for i := range 3 {
		result, err = c.UpdateRotation(context.Background(), TestKeyCopy(oldResult.SecretShares[i]), rotConfig.Nonce, recovery)
		require.NoError(t, err)

		// Should be progress
		if i < 2 {
			_, num, err := c.RotationProgress(recovery, false)
			require.NoError(t, err)
			require.Equal(t, num, i+1)
		}
	}

	require.NotNil(t, result)
	require.Len(t, result.SecretShares, 1)

	// Attempt unseal if this was not recovery mode
	if !recovery {
		err = c.Seal(root)
		require.NoError(t, err)

		unsealed, err := TestCoreUnseal(c, result.SecretShares[0])
		require.NoError(t, err)
		require.True(t, unsealed)
	}

	// SealConfig should update
	if recovery {
		sealConf, err = c.seal.RecoveryConfig(context.Background())
	} else {
		sealConf, err = c.seal.BarrierConfig(context.Background())
	}
	require.NoError(t, err)

	newConf.Nonce = rotConfig.Nonce
	require.Equal(t, sealConf, newConf)
}

func TestCoreRotateInvalid(t *testing.T) {
	bc := &SealConfig{
		StoredShares:    0,
		SecretShares:    1,
		SecretThreshold: 1,
	}
	c, rootKeys, _, _ := TestCoreUnsealedWithConfigs(t, bc, nil)
	testCoreRotateInvalidCommon(t, c, rootKeys, false)
}

func testCoreRotateInvalidCommon(t *testing.T, c *Core, keys [][]byte, recovery bool) {
	newConf := &SealConfig{
		SecretThreshold: 3,
		SecretShares:    5,
	}
	// Start rotation
	rotationResult, err := c.InitRotation(context.Background(), newConf, recovery)
	require.NoError(t, err)
	require.Empty(t, rotationResult)

	// Fetch new config with generated nonce
	rotConfig := c.RotationConfig(recovery)
	require.NotNil(t, rotConfig)

	// Provide invalid nonce
	_, err = c.UpdateRotation(context.Background(), keys[0], "abcd", recovery)
	require.Error(t, err)

	// Provide the invalid key
	key := keys[0]
	oldkeystr := fmt.Sprintf("%#v", key)
	key[0]++
	newkeystr := fmt.Sprintf("%#v", key)

	ret, err := c.UpdateRotation(context.Background(), key, rotConfig.Nonce, recovery)
	require.Nil(t, ret)
	require.Errorf(t, err, "expected error, oldkeystr: %s\nnewkeystr: %s", oldkeystr, newkeystr)

	// Check if progress has been reset
	_, num, rotErr := c.RotationProgress(recovery, false)
	require.NoError(t, rotErr)
	require.Equalf(t, num, 0, "rotation progress should be 0, got: %d", num)
}

func TestCoreRotationStandby(t *testing.T) {
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
	_, err = core.InitRotation(context.Background(), newConf, false)
	require.NoError(t, err)

	// Fetch new config with generated nonce
	rotConfig := core.RotationConfig(false)
	require.NotNil(t, rotConfig)

	var rotationResult *RekeyResult
	for _, key := range keys {
		rotationResult, err = core.UpdateRotation(context.Background(), key, rotConfig.Nonce, false)
		require.NoError(t, err)
	}
	require.NotNil(t, rotationResult)

	// Seal the first core, should step down
	err = core.Seal(root)
	require.NoError(t, err)

	// Wait for core2 to become active
	TestWaitActive(t, core2)

	// Rotate the root key again
	_, err = core2.InitRotation(context.Background(), newConf, false)
	require.NoError(t, err)

	// Fetch new config with generated nonce
	rotConfig = core2.RotationConfig(false)
	require.NotNil(t, rotConfig)

	var rotationResult2 *RekeyResult
	for _, key := range rotationResult.SecretShares {
		rotationResult2, err = core2.UpdateRotation(context.Background(), key, rotConfig.Nonce, false)
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

	nonce, err := uuid.GenerateUUID()
	require.NoError(t, err)

	err = core.initBarrierRotation(&SealConfig{
		VerificationRequired: true,
		StoredShares:         1,
	}, nonce)
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

	result, err := core.InitRotation(context.Background(), rotConfig, true)
	require.NoError(t, err)
	require.Len(t, result.SecretShares, 5)
	require.Empty(t, result.PGPFingerprints)
}
