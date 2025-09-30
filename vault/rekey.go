// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"net/http"

	"github.com/hashicorp/go-uuid"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
	aeadwrapper "github.com/openbao/go-kms-wrapping/wrappers/aead/v2"
	"github.com/openbao/openbao/helper/pgpkeys"
	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/openbao/openbao/sdk/v2/helper/jsonutil"
	"github.com/openbao/openbao/sdk/v2/helper/shamir"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/sdk/v2/physical"
	"github.com/openbao/openbao/vault/seal"
)

const (
	// coreUnsealKeysBackupPath is the path used to backup encrypted unseal
	// keys if specified during a rekey operation. This is outside of the
	// barrier.
	coreBarrierUnsealKeysBackupPath = "core/unseal-keys-backup"

	// coreRecoveryUnsealKeysBackupPath is the path used to backup encrypted
	// recovery keys if specified during a rekey operation. This is outside of
	// the barrier.
	coreRecoveryUnsealKeysBackupPath = "core/recovery-keys-backup"
)

// RekeyResult is used to provide the key parts back after
// they are generated as part of the rekey.
type RekeyResult struct {
	SecretShares         [][]byte
	PGPFingerprints      []string
	Backup               bool
	RecoveryKey          bool
	VerificationRequired bool
	VerificationNonce    string
}

type RekeyVerifyResult struct {
	Complete bool
	Nonce    string
}

// RekeyBackup stores the backup copy of PGP-encrypted keys
type RekeyBackup struct {
	Nonce string
	Keys  map[string][]string
}

// RekeyThreshold returns the secret threshold for the current seal
// config. This threshold can either be the barrier key threshold or
// the recovery key threshold, depending on whether rekey is being
// performed on the recovery key, or whether the seal supports
// recovery keys.
func (c *Core) RekeyThreshold(ctx context.Context, recovery bool) (int, logical.HTTPCodedError) {
	c.stateLock.RLock()
	defer c.stateLock.RUnlock()
	if c.Sealed() {
		return 0, logical.CodedError(http.StatusServiceUnavailable, consts.ErrSealed.Error())
	}
	if c.standby {
		return 0, logical.CodedError(http.StatusBadRequest, consts.ErrStandby.Error())
	}

	c.rotationLock.RLock()
	defer c.rotationLock.RUnlock()

	var config *SealConfig
	var err error
	// If we are rekeying the recovery key, or if the seal supports
	// recovery keys and we are rekeying the barrier key, we use the
	// recovery config as the threshold instead.
	if recovery || c.seal.RecoveryKeySupported() {
		config, err = c.seal.RecoveryConfig(ctx)
	} else {
		config, err = c.seal.BarrierConfig(ctx)
	}
	if err != nil {
		return 0, logical.CodedError(http.StatusInternalServerError, "unable to look up config: %v", err)
	}
	if config == nil {
		return 0, logical.CodedError(http.StatusBadRequest, ErrNotInit.Error())
	}

	return config.SecretThreshold, nil
}

// RekeyProgress is used to return the rekey progress (num shares).
func (c *Core) RekeyProgress(recovery, verification bool) (bool, int, logical.HTTPCodedError) {
	c.stateLock.RLock()
	defer c.stateLock.RUnlock()
	if c.Sealed() {
		return false, 0, logical.CodedError(http.StatusServiceUnavailable, consts.ErrSealed.Error())
	}
	if c.standby {
		return false, 0, logical.CodedError(http.StatusBadRequest, consts.ErrStandby.Error())
	}

	c.rotationLock.RLock()
	defer c.rotationLock.RUnlock()

	var conf *SealConfig
	if recovery {
		conf = c.recoveryRotationConfig
	} else {
		conf = c.rootRotationConfig
	}

	if conf == nil {
		return false, 0, logical.CodedError(http.StatusBadRequest, "rekey operation not in progress")
	}

	if verification {
		return len(conf.VerificationKey) > 0, len(conf.VerificationProgress), nil
	}
	return true, len(conf.RotationProgress), nil
}

// RekeyConfig is used to read the rekey configuration
func (c *Core) RekeyConfig(recovery bool) (*SealConfig, logical.HTTPCodedError) {
	c.stateLock.RLock()
	defer c.stateLock.RUnlock()
	if c.Sealed() {
		return nil, logical.CodedError(http.StatusServiceUnavailable, consts.ErrSealed.Error())
	}
	if c.standby {
		return nil, logical.CodedError(http.StatusBadRequest, consts.ErrStandby.Error())
	}

	c.rotationLock.Lock()
	defer c.rotationLock.Unlock()

	// Copy the seal config if any
	var conf *SealConfig
	if recovery {
		if c.recoveryRotationConfig != nil {
			conf = c.recoveryRotationConfig.Clone()
		}
	} else {
		if c.rootRotationConfig != nil {
			conf = c.rootRotationConfig.Clone()
		}
	}

	return conf, nil
}

// RekeyInit will either initialize the rekey of barrier or recovery key.
// recovery determines whether this is a rekey on the barrier or recovery key.
func (c *Core) RekeyInit(config *SealConfig, recovery bool) logical.HTTPCodedError {
	if recovery {
		return c.RecoveryRekeyInit(config)
	}
	return c.BarrierRekeyInit(config)
}

// BarrierRekeyInit is used to initialize the rekey settings for the barrier key
func (c *Core) BarrierRekeyInit(config *SealConfig) logical.HTTPCodedError {
	switch c.seal.BarrierType() {
	case wrapping.WrapperTypeShamir:
		// As of Vault 1.3 all seals use StoredShares==1.
		if config.StoredShares != 1 {
			c.logger.Warn("shamir stored keys supported, forcing rekey shares/threshold to 1")
			config.StoredShares = 1
		}
	default:
		if config.StoredShares != 1 {
			c.logger.Warn("stored keys supported, forcing rekey shares/threshold to 1")
			config.StoredShares = 1
		}
		config.SecretShares = 1
		config.SecretThreshold = 1

		if len(config.PGPKeys) > 0 {
			return logical.CodedError(http.StatusBadRequest, "PGP key encryption not supported when using stored keys")
		}
		if config.Backup {
			return logical.CodedError(http.StatusBadRequest, "key backup not supported when using stored keys")
		}
	}

	if c.seal.RecoveryKeySupported() {
		if config.VerificationRequired {
			return logical.CodedError(http.StatusBadRequest, "requiring verification not supported when rekeying the barrier key with recovery keys")
		}
		c.logger.Debug("using recovery seal configuration to rekey barrier key")
	}

	// Check if the seal configuration is valid
	if err := config.Validate(); err != nil {
		c.logger.Error("invalid rekey seal configuration", "error", err)
		return logical.CodedError(http.StatusInternalServerError, "invalid rekey seal configuration: %v", err)
	}

	c.stateLock.RLock()
	defer c.stateLock.RUnlock()
	if c.Sealed() {
		return logical.CodedError(http.StatusServiceUnavailable, consts.ErrSealed.Error())
	}
	if c.standby {
		return logical.CodedError(http.StatusBadRequest, consts.ErrStandby.Error())
	}

	c.rotationLock.Lock()
	defer c.rotationLock.Unlock()

	// Prevent multiple concurrent re-keys
	if c.rootRotationConfig != nil {
		return logical.CodedError(http.StatusBadRequest, "rekey already in progress")
	}

	// Copy the configuration
	c.rootRotationConfig = config.Clone()

	// Initialize the nonce
	nonce, err := uuid.GenerateUUID()
	if err != nil {
		c.rootRotationConfig = nil
		return logical.CodedError(http.StatusInternalServerError, "error generating nonce for procedure: %v", err)
	}
	c.rootRotationConfig.Nonce = nonce

	if c.logger.IsInfo() {
		c.logger.Info("rekey initialized", "nonce", c.rootRotationConfig.Nonce, "shares", c.rootRotationConfig.SecretShares, "threshold", c.rootRotationConfig.SecretThreshold, "validation_required", c.rootRotationConfig.VerificationRequired)
	}
	return nil
}

// RecoveryRekeyInit is used to initialize the rekey settings for the recovery key
func (c *Core) RecoveryRekeyInit(config *SealConfig) logical.HTTPCodedError {
	if config.StoredShares > 0 {
		return logical.CodedError(http.StatusBadRequest, "stored shares not supported by recovery key")
	}

	// Check if the seal configuration is valid
	// intentionally invoke the `Validate()` instead of `ValidateRecovery()`
	// deny the request if it does not pass the validation check
	if err := config.Validate(); err != nil {
		c.logger.Error("invalid recovery configuration", "error", err)
		return logical.CodedError(http.StatusInternalServerError, "invalid recovery configuration: %v", err)
	}

	if !c.seal.RecoveryKeySupported() {
		return logical.CodedError(http.StatusBadRequest, "recovery keys not supported")
	}

	c.stateLock.RLock()
	defer c.stateLock.RUnlock()
	if c.Sealed() {
		return logical.CodedError(http.StatusServiceUnavailable, consts.ErrSealed.Error())
	}
	if c.standby {
		return logical.CodedError(http.StatusBadRequest, consts.ErrStandby.Error())
	}

	c.rotationLock.Lock()
	defer c.rotationLock.Unlock()

	// Prevent multiple concurrent re-keys
	if c.recoveryRotationConfig != nil {
		return logical.CodedError(http.StatusBadRequest, "rekey already in progress")
	}

	// Copy the configuration
	c.recoveryRotationConfig = config.Clone()

	// Initialize the nonce
	nonce, err := uuid.GenerateUUID()
	if err != nil {
		c.recoveryRotationConfig = nil
		return logical.CodedError(http.StatusInternalServerError, "error generating nonce for procedure: %v", err)
	}
	c.recoveryRotationConfig.Nonce = nonce

	if c.logger.IsInfo() {
		c.logger.Info("rekey initialized", "nonce", c.recoveryRotationConfig.Nonce, "shares", c.recoveryRotationConfig.SecretShares, "threshold", c.recoveryRotationConfig.SecretThreshold, "validation_required", c.recoveryRotationConfig.VerificationRequired)
	}
	return nil
}

// RekeyUpdate is used to provide a new key part for the barrier or recovery key.
func (c *Core) RekeyUpdate(ctx context.Context, key []byte, nonce string, recovery bool) (*RekeyResult, logical.HTTPCodedError) {
	if recovery {
		return c.RecoveryRekeyUpdate(ctx, key, nonce)
	}
	return c.BarrierRekeyUpdate(ctx, key, nonce)
}

// BarrierRekeyUpdate is used to provide a new key part. Barrier rekey can be done
// with unseal keys, or recovery keys if that's supported and we are storing the barrier
// key.
//
// N.B.: If recovery keys are used to rekey, the new barrier key shares are not returned.
func (c *Core) BarrierRekeyUpdate(ctx context.Context, key []byte, nonce string) (*RekeyResult, logical.HTTPCodedError) {
	// Ensure we are already unsealed
	c.stateLock.RLock()
	defer c.stateLock.RUnlock()
	if c.Sealed() {
		return nil, logical.CodedError(http.StatusServiceUnavailable, consts.ErrSealed.Error())
	}
	if c.standby {
		return nil, logical.CodedError(http.StatusBadRequest, consts.ErrStandby.Error())
	}

	// Verify the key length
	min, max := c.barrier.KeyLength()
	max += shamir.ShareOverhead
	if len(key) < min {
		return nil, logical.CodedError(http.StatusBadRequest, "key is shorter than minimum %d bytes", min)
	}
	if len(key) > max {
		return nil, logical.CodedError(http.StatusBadRequest, "key is longer than maximum %d bytes", max)
	}

	c.rotationLock.Lock()
	defer c.rotationLock.Unlock()

	// Get the seal configuration
	var existingConfig *SealConfig
	var err error
	var useRecovery bool // Determines whether recovery key is being used to rekey the root key
	if c.seal.StoredKeysSupported() == seal.StoredKeysSupportedGeneric && c.seal.RecoveryKeySupported() {
		existingConfig, err = c.seal.RecoveryConfig(ctx)
		useRecovery = true
	} else {
		existingConfig, err = c.seal.BarrierConfig(ctx)
	}
	if err != nil {
		return nil, logical.CodedError(http.StatusInternalServerError, "failed to fetch existing config: %v", err)
	}
	// Ensure the barrier is initialized
	if existingConfig == nil {
		return nil, logical.CodedError(http.StatusBadRequest, ErrNotInit.Error())
	}

	// Ensure a rekey is in progress
	if c.rootRotationConfig == nil {
		return nil, logical.CodedError(http.StatusBadRequest, "no barrier rekey in progress")
	}

	if len(c.rootRotationConfig.VerificationKey) > 0 {
		return nil, logical.CodedError(http.StatusBadRequest, "rekey operation already finished; verification must be performed; nonce for the verification operation is %q", c.rootRotationConfig.VerificationNonce)
	}

	if nonce != c.rootRotationConfig.Nonce {
		return nil, logical.CodedError(http.StatusBadRequest, "incorrect nonce supplied; nonce for this rekey operation is %q", c.rootRotationConfig.Nonce)
	}

	// Check if we already have this piece
	for _, existing := range c.rootRotationConfig.RotationProgress {
		if subtle.ConstantTimeCompare(existing, key) == 1 {
			return nil, logical.CodedError(http.StatusBadRequest, "given key has already been provided during this generation operation")
		}
	}

	// Store this key
	c.rootRotationConfig.RotationProgress = append(c.rootRotationConfig.RotationProgress, key)

	// Check if we don't have enough keys to unlock
	if len(c.rootRotationConfig.RotationProgress) < existingConfig.SecretThreshold {
		if c.logger.IsDebug() {
			c.logger.Debug("cannot rekey yet, not enough keys", "keys", len(c.rootRotationConfig.RotationProgress), "threshold", existingConfig.SecretThreshold)
		}
		return nil, nil
	}

	// Recover the root key or recovery key
	var recoveredKey []byte
	if existingConfig.SecretThreshold == 1 {
		recoveredKey = c.rootRotationConfig.RotationProgress[0]
		c.rootRotationConfig.RotationProgress = nil
	} else {
		recoveredKey, err = shamir.Combine(c.rootRotationConfig.RotationProgress)
		c.rootRotationConfig.RotationProgress = nil
		if err != nil {
			return nil, logical.CodedError(http.StatusInternalServerError, "failed to compute root key: %v", err)
		}
	}

	switch {
	case useRecovery:
		if err := c.seal.VerifyRecoveryKey(ctx, recoveredKey); err != nil {
			c.logger.Error("rekey recovery key verification failed", "error", err)
			return nil, logical.CodedError(http.StatusBadRequest, "recovery key verification failed: %v", err)
		}
	case c.seal.BarrierType() == wrapping.WrapperTypeShamir:
		if c.seal.StoredKeysSupported() == seal.StoredKeysSupportedShamirRoot {
			shamirWrapper := aeadwrapper.NewShamirWrapper()
			testseal := NewDefaultSeal(seal.NewAccess(shamirWrapper))
			testseal.SetCore(c)
			err = shamirWrapper.SetAesGcmKeyBytes(recoveredKey)
			if err != nil {
				return nil, logical.CodedError(http.StatusInternalServerError, "failed to setup unseal key: %v", err)
			}
			cfg, err := c.seal.BarrierConfig(ctx)
			if err != nil {
				return nil, logical.CodedError(http.StatusInternalServerError, "failed to setup test barrier config: %v", err)
			}
			testseal.SetCachedBarrierConfig(cfg)
			stored, err := testseal.GetStoredKeys(ctx)
			if err != nil {
				return nil, logical.CodedError(http.StatusInternalServerError, "failed to read root key: %v", err)
			}
			recoveredKey = stored[0]
		}
		if err := c.barrier.VerifyRoot(recoveredKey); err != nil {
			c.logger.Error("root key verification failed", "error", err)
			return nil, logical.CodedError(http.StatusBadRequest, "rootter key verification failed: %v", err)
		}
	}

	// Generate a new key: for AutoUnseal, this is a new root key; for Shamir,
	// this is a new unseal key, and performBarrierRekey will also generate a
	// new root key.
	newKey, err := c.barrier.GenerateKey(c.secureRandomReader)
	if err != nil {
		c.logger.Error("failed to generate root key", "error", err)
		return nil, logical.CodedError(http.StatusInternalServerError, "root key generation failed: %v", err)
	}

	results := &RekeyResult{
		Backup: c.rootRotationConfig.Backup,
	}
	if c.seal.StoredKeysSupported() != seal.StoredKeysSupportedGeneric {
		// Set result.SecretShares to the new key itself if only a single key
		// part is used -- no Shamir split required.
		if c.rootRotationConfig.SecretShares == 1 {
			results.SecretShares = append(results.SecretShares, newKey)
		} else {
			// Split the new key using the Shamir algorithm
			shares, err := shamir.Split(newKey, c.rootRotationConfig.SecretShares, c.rootRotationConfig.SecretThreshold)
			if err != nil {
				c.logger.Error("failed to generate shares", "error", err)
				return nil, logical.CodedError(http.StatusInternalServerError, "failed to generate shares: %v", err)
			}
			results.SecretShares = shares
		}
	}

	// If PGP keys are passed in, encrypt shares with corresponding PGP keys.
	if len(c.rootRotationConfig.PGPKeys) > 0 {
		hexEncodedShares := make([][]byte, len(results.SecretShares))
		for i := range results.SecretShares {
			hexEncodedShares[i] = []byte(hex.EncodeToString(results.SecretShares[i]))
		}
		results.PGPFingerprints, results.SecretShares, err = pgpkeys.EncryptShares(hexEncodedShares, c.rootRotationConfig.PGPKeys)
		if err != nil {
			return nil, logical.CodedError(http.StatusInternalServerError, "failed to encrypt shares: %v", err)
		}

		// If backup is enabled, store backup info in vault.coreBarrierUnsealKeysBackupPath
		if c.rootRotationConfig.Backup {
			backupInfo := map[string][]string{}
			for i := 0; i < len(results.PGPFingerprints); i++ {
				encShare := bytes.NewBuffer(results.SecretShares[i])
				if backupInfo[results.PGPFingerprints[i]] == nil {
					backupInfo[results.PGPFingerprints[i]] = []string{hex.EncodeToString(encShare.Bytes())}
				} else {
					backupInfo[results.PGPFingerprints[i]] = append(backupInfo[results.PGPFingerprints[i]], hex.EncodeToString(encShare.Bytes()))
				}
			}

			backupVals := &RekeyBackup{
				Nonce: c.rootRotationConfig.Nonce,
				Keys:  backupInfo,
			}
			buf, err := json.Marshal(backupVals)
			if err != nil {
				c.logger.Error("failed to marshal unseal key backup", "error", err)
				return nil, logical.CodedError(http.StatusInternalServerError, "failed to marshal unseal key backup: %v", err)
			}
			pe := &physical.Entry{
				Key:   coreBarrierUnsealKeysBackupPath,
				Value: buf,
			}
			if err = c.physical.Put(ctx, pe); err != nil {
				c.logger.Error("failed to save unseal key backup", "error", err)
				return nil, logical.CodedError(http.StatusInternalServerError, "failed to save unseal key backup: %v", err)
			}
		}
	}

	// If we are requiring validation, return now; otherwise rekey the barrier
	if c.rootRotationConfig.VerificationRequired {
		nonce, err := uuid.GenerateUUID()
		if err != nil {
			c.rootRotationConfig = nil
			return nil, logical.CodedError(http.StatusInternalServerError, "failed to generate verification nonce: %v", err)
		}
		c.rootRotationConfig.VerificationNonce = nonce
		c.rootRotationConfig.VerificationKey = newKey

		results.VerificationRequired = true
		results.VerificationNonce = nonce
		return results, nil
	}

	if err := c.performBarrierRekey(ctx, newKey); err != nil {
		return nil, logical.CodedError(http.StatusInternalServerError, "failed to perform barrier rekey: %v", err)
	}

	c.rootRotationConfig = nil
	return results, nil
}

func (c *Core) performBarrierRekey(ctx context.Context, newSealKey []byte) logical.HTTPCodedError {
	if c.seal.StoredKeysSupported() != seal.StoredKeysSupportedGeneric {
		shamirWrapper, err := c.seal.GetShamirWrapper()
		if err == nil {
			err = shamirWrapper.SetAesGcmKeyBytes(newSealKey)
		}
		if err != nil {
			return logical.CodedError(http.StatusInternalServerError, "failed to update barrier seal key: %v", err)
		}
	}

	newRootKey, err := c.barrier.GenerateKey(c.secureRandomReader)
	if err != nil {
		return logical.CodedError(http.StatusInternalServerError, "failed to perform rekey: %v", err)
	}
	if err := c.seal.SetStoredKeys(ctx, [][]byte{newRootKey}); err != nil {
		c.logger.Error("failed to store keys", "error", err)
		return logical.CodedError(http.StatusInternalServerError, "failed to store keys: %v", err)
	}

	// Rekey the barrier
	if err := c.barrier.RotateRootKey(ctx, newRootKey); err != nil {
		c.logger.Error("failed to rekey barrier", "error", err)
		return logical.CodedError(http.StatusInternalServerError, "failed to rekey barrier: %v", err)
	}
	if c.logger.IsInfo() {
		c.logger.Info("security barrier rekeyed", "stored", c.rootRotationConfig.StoredShares, "shares", c.rootRotationConfig.SecretShares, "threshold", c.rootRotationConfig.SecretThreshold)
	}

	if len(newSealKey) > 0 {
		err := c.barrier.Put(ctx, &logical.StorageEntry{
			Key:   shamirKekPath,
			Value: newSealKey,
		})
		if err != nil {
			c.logger.Error("failed to store new seal key", "error", err)
			return logical.CodedError(http.StatusInternalServerError, "failed to store new seal key: %v", err)
		}
	}

	c.rootRotationConfig.VerificationKey = nil

	if err := c.seal.SetBarrierConfig(ctx, c.rootRotationConfig); err != nil {
		c.logger.Error("error saving rekey seal configuration", "error", err)
		return logical.CodedError(http.StatusInternalServerError, "failed to save rekey seal configuration: %v", err)
	}

	// Write to the canary path, which will force a synchronous truing during
	// replication
	if err := c.barrier.Put(ctx, &logical.StorageEntry{
		Key:   coreKeyringCanaryPath,
		Value: []byte(c.rootRotationConfig.Nonce),
	}); err != nil {
		c.logger.Error("error saving keyring canary", "error", err)
		return logical.CodedError(http.StatusInternalServerError, "failed to save keyring canary: %v", err)
	}

	c.rootRotationConfig.RotationProgress = nil

	return nil
}

// RecoveryRekeyUpdate is used to provide a new key part
func (c *Core) RecoveryRekeyUpdate(ctx context.Context, key []byte, nonce string) (*RekeyResult, logical.HTTPCodedError) {
	// Ensure we are already unsealed
	c.stateLock.RLock()
	defer c.stateLock.RUnlock()
	if c.Sealed() {
		return nil, logical.CodedError(http.StatusServiceUnavailable, consts.ErrSealed.Error())
	}
	if c.standby {
		return nil, logical.CodedError(http.StatusBadRequest, consts.ErrStandby.Error())
	}

	// Verify the key length
	min, max := c.barrier.KeyLength()
	max += shamir.ShareOverhead
	if len(key) < min {
		return nil, logical.CodedError(http.StatusBadRequest, "key is shorter than minimum %d bytes", min)
	}
	if len(key) > max {
		return nil, logical.CodedError(http.StatusBadRequest, "key is longer than maximum %d bytes", max)
	}

	c.rotationLock.Lock()
	defer c.rotationLock.Unlock()

	// Get the seal configuration
	existingConfig, err := c.seal.RecoveryConfig(ctx)
	if err != nil {
		return nil, logical.CodedError(http.StatusInternalServerError, "failed to fetch existing recovery config: %v", err)
	}
	// Ensure the seal is initialized
	if existingConfig == nil {
		return nil, logical.CodedError(http.StatusBadRequest, ErrNotInit.Error())
	}

	// Ensure a rekey is in progress
	if c.recoveryRotationConfig == nil {
		return nil, logical.CodedError(http.StatusBadRequest, "no recovery rekey in progress")
	}

	if len(c.recoveryRotationConfig.VerificationKey) > 0 {
		return nil, logical.CodedError(http.StatusBadRequest, "rekey operation already finished; verification must be performed; nonce for the verification operation is %q", c.recoveryRotationConfig.VerificationNonce)
	}

	if nonce != c.recoveryRotationConfig.Nonce {
		return nil, logical.CodedError(http.StatusBadRequest, "incorrect nonce supplied; nonce for this rekey operation is %q", c.recoveryRotationConfig.Nonce)
	}

	// Check if we already have this piece
	for _, existing := range c.recoveryRotationConfig.RotationProgress {
		if subtle.ConstantTimeCompare(existing, key) == 1 {
			return nil, logical.CodedError(http.StatusBadRequest, "given key has already been provided during this rekey operation")
		}
	}

	// Store this key
	c.recoveryRotationConfig.RotationProgress = append(c.recoveryRotationConfig.RotationProgress, key)

	// Check if we don't have enough keys to unlock
	if len(c.recoveryRotationConfig.RotationProgress) < existingConfig.SecretThreshold {
		if c.logger.IsDebug() {
			c.logger.Debug("cannot rekey yet, not enough keys", "keys", len(c.recoveryRotationConfig.RotationProgress), "threshold", existingConfig.SecretThreshold)
		}
		return nil, nil
	}

	// Recover the root key
	var recoveryKey []byte
	if existingConfig.SecretThreshold == 1 {
		recoveryKey = c.recoveryRotationConfig.RotationProgress[0]
		c.recoveryRotationConfig.RotationProgress = nil
	} else {
		recoveryKey, err = shamir.Combine(c.recoveryRotationConfig.RotationProgress)
		c.recoveryRotationConfig.RotationProgress = nil
		if err != nil {
			return nil, logical.CodedError(http.StatusInternalServerError, "failed to compute recovery key: %v", err)
		}
	}

	// Verify the recovery key
	if err := c.seal.VerifyRecoveryKey(ctx, recoveryKey); err != nil {
		c.logger.Error("recovery key verification failed", "error", err)
		return nil, logical.CodedError(http.StatusBadRequest, "recovery key verification failed: %v", err)
	}

	// Generate a new root key
	newRecoveryKey, err := c.barrier.GenerateKey(c.secureRandomReader)
	if err != nil {
		c.logger.Error("failed to generate recovery key", "error", err)
		return nil, logical.CodedError(http.StatusInternalServerError, "recovery key generation failed: %v", err)
	}

	// Return the root key if only a single key part is used
	results := &RekeyResult{
		Backup: c.recoveryRotationConfig.Backup,
	}

	if c.recoveryRotationConfig.SecretShares == 1 {
		results.SecretShares = append(results.SecretShares, newRecoveryKey)
	} else {
		// Split the root key using the Shamir algorithm
		shares, err := shamir.Split(newRecoveryKey, c.recoveryRotationConfig.SecretShares, c.recoveryRotationConfig.SecretThreshold)
		if err != nil {
			c.logger.Error("failed to generate shares", "error", err)
			return nil, logical.CodedError(http.StatusInternalServerError, "failed to generate shares: %v", err)
		}
		results.SecretShares = shares
	}

	if len(c.recoveryRotationConfig.PGPKeys) > 0 {
		hexEncodedShares := make([][]byte, len(results.SecretShares))
		for i := range results.SecretShares {
			hexEncodedShares[i] = []byte(hex.EncodeToString(results.SecretShares[i]))
		}
		results.PGPFingerprints, results.SecretShares, err = pgpkeys.EncryptShares(hexEncodedShares, c.recoveryRotationConfig.PGPKeys)
		if err != nil {
			return nil, logical.CodedError(http.StatusInternalServerError, "failed to encrypt shares: %v", err)
		}

		if c.recoveryRotationConfig.Backup {
			backupInfo := map[string][]string{}
			for i := 0; i < len(results.PGPFingerprints); i++ {
				encShare := bytes.NewBuffer(results.SecretShares[i])
				if backupInfo[results.PGPFingerprints[i]] == nil {
					backupInfo[results.PGPFingerprints[i]] = []string{hex.EncodeToString(encShare.Bytes())}
				} else {
					backupInfo[results.PGPFingerprints[i]] = append(backupInfo[results.PGPFingerprints[i]], hex.EncodeToString(encShare.Bytes()))
				}
			}

			backupVals := &RekeyBackup{
				Nonce: c.recoveryRotationConfig.Nonce,
				Keys:  backupInfo,
			}
			buf, err := json.Marshal(backupVals)
			if err != nil {
				c.logger.Error("failed to marshal recovery key backup", "error", err)
				return nil, logical.CodedError(http.StatusInternalServerError, "failed to marshal recovery key backup: %v", err)
			}
			pe := &physical.Entry{
				Key:   coreRecoveryUnsealKeysBackupPath,
				Value: buf,
			}
			if err = c.physical.Put(ctx, pe); err != nil {
				c.logger.Error("failed to save unseal key backup", "error", err)
				return nil, logical.CodedError(http.StatusInternalServerError, "failed to save unseal key backup: %v", err)
			}
		}
	}

	// If we are requiring validation, return now; otherwise save the recovery
	// key
	if c.recoveryRotationConfig.VerificationRequired {
		nonce, err := uuid.GenerateUUID()
		if err != nil {
			c.recoveryRotationConfig = nil
			return nil, logical.CodedError(http.StatusInternalServerError, "failed to generate verification nonce: %v", err)
		}
		c.recoveryRotationConfig.VerificationNonce = nonce
		c.recoveryRotationConfig.VerificationKey = newRecoveryKey

		results.VerificationRequired = true
		results.VerificationNonce = nonce
		return results, nil
	}

	if err := c.performRecoveryRekey(ctx, newRecoveryKey); err != nil {
		return nil, logical.CodedError(http.StatusInternalServerError, "failed to perform recovery rekey: %v", err)
	}

	c.recoveryRotationConfig = nil
	return results, nil
}

func (c *Core) performRecoveryRekey(ctx context.Context, newRootKey []byte) logical.HTTPCodedError {
	if err := c.seal.SetRecoveryKey(ctx, newRootKey); err != nil {
		c.logger.Error("failed to set recovery key", "error", err)
		return logical.CodedError(http.StatusInternalServerError, "failed to set recovery key: %v", err)
	}

	c.recoveryRotationConfig.VerificationKey = nil

	if err := c.seal.SetRecoveryConfig(ctx, c.recoveryRotationConfig); err != nil {
		c.logger.Error("error saving rekey seal configuration", "error", err)
		return logical.CodedError(http.StatusInternalServerError, "failed to save rekey seal configuration: %v", err)
	}

	// Write to the canary path, which will force a synchronous truing during
	// replication
	if err := c.barrier.Put(ctx, &logical.StorageEntry{
		Key:   coreKeyringCanaryPath,
		Value: []byte(c.recoveryRotationConfig.Nonce),
	}); err != nil {
		c.logger.Error("error saving keyring canary", "error", err)
		return logical.CodedError(http.StatusInternalServerError, "failed to save keyring canary: %v", err)
	}

	c.recoveryRotationConfig.RotationProgress = nil

	return nil
}

func (c *Core) RekeyVerify(ctx context.Context, key []byte, nonce string, recovery bool) (ret *RekeyVerifyResult, retErr logical.HTTPCodedError) {
	// Ensure we are already unsealed
	c.stateLock.RLock()
	defer c.stateLock.RUnlock()
	if c.Sealed() {
		return nil, logical.CodedError(http.StatusServiceUnavailable, consts.ErrSealed.Error())
	}
	if c.standby {
		return nil, logical.CodedError(http.StatusBadRequest, consts.ErrStandby.Error())
	}

	// Verify the key length
	min, max := c.barrier.KeyLength()
	max += shamir.ShareOverhead
	if len(key) < min {
		return nil, logical.CodedError(http.StatusBadRequest, "key is shorter than minimum %d bytes", min)
	}
	if len(key) > max {
		return nil, logical.CodedError(http.StatusBadRequest, "key is longer than maximum %d bytes", max)
	}

	c.rotationLock.Lock()
	defer c.rotationLock.Unlock()

	config := c.rootRotationConfig
	if recovery {
		config = c.recoveryRotationConfig
	}

	// Ensure a rekey is in progress
	if config == nil {
		return nil, logical.CodedError(http.StatusBadRequest, "no rekey in progress")
	}

	if len(config.VerificationKey) == 0 {
		return nil, logical.CodedError(http.StatusBadRequest, "no rekey verification in progress")
	}

	if nonce != config.VerificationNonce {
		return nil, logical.CodedError(http.StatusBadRequest, "incorrect nonce supplied; nonce for this verify operation is %q", config.VerificationNonce)
	}

	// Check if we already have this piece
	for _, existing := range config.VerificationProgress {
		if subtle.ConstantTimeCompare(existing, key) == 1 {
			return nil, logical.CodedError(http.StatusBadRequest, "given key has already been provided during this verify operation")
		}
	}

	// Store this key
	config.VerificationProgress = append(config.VerificationProgress, key)

	// Check if we don't have enough keys to unlock
	if len(config.VerificationProgress) < config.SecretThreshold {
		if c.logger.IsDebug() {
			c.logger.Debug("cannot verify yet, not enough keys", "keys", len(config.VerificationProgress), "threshold", config.SecretThreshold)
		}
		return nil, nil
	}

	// Schedule the progress for forgetting and rotate the nonce if possible
	defer func() {
		config.VerificationProgress = nil
		if ret != nil && ret.Complete {
			return
		}
		// Not complete, so rotate nonce
		nonce, err := uuid.GenerateUUID()
		if err == nil {
			config.VerificationNonce = nonce
			if ret != nil {
				ret.Nonce = nonce
			}
		}
	}()

	// Recover the root key or recovery key
	var recoveredKey []byte
	if config.SecretThreshold == 1 {
		recoveredKey = config.VerificationProgress[0]
	} else {
		var err error
		recoveredKey, err = shamir.Combine(config.VerificationProgress)
		if err != nil {
			return nil, logical.CodedError(http.StatusInternalServerError, "failed to compute key for verification: %v", err)
		}
	}

	if subtle.ConstantTimeCompare(recoveredKey, config.VerificationKey) != 1 {
		c.logger.Error("rekey verification failed")
		return nil, logical.CodedError(http.StatusBadRequest, "rekey verification failed; incorrect key shares supplied")
	}

	switch recovery {
	case false:
		if err := c.performBarrierRekey(ctx, recoveredKey); err != nil {
			return nil, logical.CodedError(http.StatusInternalServerError, "failed to perform rekey: %v", err)
		}
		c.rootRotationConfig = nil
	default:
		if err := c.performRecoveryRekey(ctx, recoveredKey); err != nil {
			return nil, logical.CodedError(http.StatusInternalServerError, "failed to perform recovery key rekey: %v", err)
		}
		c.recoveryRotationConfig = nil
	}

	res := &RekeyVerifyResult{
		Nonce:    config.VerificationNonce,
		Complete: true,
	}

	return res, nil
}

// RekeyCancel is used to cancel an in-progress rekey
func (c *Core) RekeyCancel(recovery bool) logical.HTTPCodedError {
	c.stateLock.RLock()
	defer c.stateLock.RUnlock()
	if c.Sealed() {
		return logical.CodedError(http.StatusServiceUnavailable, consts.ErrSealed.Error())
	}
	if c.standby {
		return logical.CodedError(http.StatusBadRequest, consts.ErrStandby.Error())
	}

	c.rotationLock.Lock()
	defer c.rotationLock.Unlock()

	// Clear any progress or config
	if recovery {
		c.recoveryRotationConfig = nil
	} else {
		c.rootRotationConfig = nil
	}
	return nil
}

// RekeyVerifyRestart is used to start the verification process over
func (c *Core) RekeyVerifyRestart(recovery bool) logical.HTTPCodedError {
	c.stateLock.RLock()
	defer c.stateLock.RUnlock()
	if c.Sealed() {
		return logical.CodedError(http.StatusServiceUnavailable, consts.ErrSealed.Error())
	}
	if c.standby {
		return logical.CodedError(http.StatusBadRequest, consts.ErrStandby.Error())
	}

	c.rotationLock.Lock()
	defer c.rotationLock.Unlock()

	// Attempt to generate a new nonce, but don't bail if it doesn't succeed
	// (which is extraordinarily unlikely)
	nonce, nonceErr := uuid.GenerateUUID()

	// Clear any progress or config
	if recovery {
		if c.recoveryRotationConfig != nil {
			c.recoveryRotationConfig.VerificationProgress = nil
			if nonceErr == nil {
				c.recoveryRotationConfig.VerificationNonce = nonce
			}
		}
	} else {
		if c.rootRotationConfig != nil {
			c.rootRotationConfig.VerificationProgress = nil
			if nonceErr == nil {
				c.rootRotationConfig.VerificationNonce = nonce
			}
		}
	}

	return nil
}

// RekeyRetrieveBackup is used to retrieve any backed-up PGP-encrypted unseal
// keys
func (c *Core) RekeyRetrieveBackup(ctx context.Context, recovery bool) (*RekeyBackup, logical.HTTPCodedError) {
	if c.Sealed() {
		return nil, logical.CodedError(http.StatusServiceUnavailable, consts.ErrSealed.Error())
	}
	if c.standby {
		return nil, logical.CodedError(http.StatusBadRequest, consts.ErrStandby.Error())
	}

	c.rotationLock.RLock()
	defer c.rotationLock.RUnlock()

	var entry *physical.Entry
	var err error
	if recovery {
		entry, err = c.physical.Get(ctx, coreRecoveryUnsealKeysBackupPath)
	} else {
		entry, err = c.physical.Get(ctx, coreBarrierUnsealKeysBackupPath)
	}
	if err != nil {
		return nil, logical.CodedError(http.StatusInternalServerError, "error getting keys from backup: %v", err)
	}
	if entry == nil {
		return nil, nil
	}

	ret := &RekeyBackup{}
	err = jsonutil.DecodeJSON(entry.Value, ret)
	if err != nil {
		return nil, logical.CodedError(http.StatusInternalServerError, "error decoding backup keys: %v", err)
	}

	return ret, nil
}

// RekeyDeleteBackup is used to delete any backed-up PGP-encrypted unseal keys
func (c *Core) RekeyDeleteBackup(ctx context.Context, recovery bool) logical.HTTPCodedError {
	if c.Sealed() {
		return logical.CodedError(http.StatusServiceUnavailable, consts.ErrSealed.Error())
	}
	if c.standby {
		return logical.CodedError(http.StatusBadRequest, consts.ErrStandby.Error())
	}

	c.rotationLock.Lock()
	defer c.rotationLock.Unlock()

	if recovery {
		err := c.physical.Delete(ctx, coreRecoveryUnsealKeysBackupPath)
		if err != nil {
			return logical.CodedError(http.StatusInternalServerError, "error deleting backup keys: %v", err)
		}
		return nil
	}
	err := c.physical.Delete(ctx, coreBarrierUnsealKeysBackupPath)
	if err != nil {
		return logical.CodedError(http.StatusInternalServerError, "error deleting backup keys: %v", err)
	}
	return nil
}
