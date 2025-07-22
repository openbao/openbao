// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	uuid "github.com/hashicorp/go-uuid"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
	aeadwrapper "github.com/openbao/go-kms-wrapping/wrappers/aead/v2"
	"github.com/openbao/openbao/helper/pgpkeys"
	"github.com/openbao/openbao/sdk/v2/helper/jsonutil"
	"github.com/openbao/openbao/sdk/v2/helper/shamir"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/sdk/v2/physical"
	"github.com/openbao/openbao/vault/seal"
)

// RotationConfig is used to read the rotation configuration
func (c *Core) RotationConfig(recovery bool) *SealConfig {
	c.rekeyLock.Lock()
	defer c.rekeyLock.Unlock()

	// Copy the specified seal config
	if recovery {
		if c.recoveryRekeyConfig != nil {
			return c.recoveryRekeyConfig.Clone()
		}
	} else {
		if c.barrierRekeyConfig != nil {
			return c.barrierRekeyConfig.Clone()
		}
	}

	return nil
}

// RotationThreshold returns the secret threshold for the current seal config.
// This threshold can either be the barrier key threshold or the recovery key
// threshold, depending on whether rotation is being performed on the recovery
// key, or whether the seal supports recovery keys.
func (c *Core) RotationThreshold(ctx context.Context, recovery bool) (int, logical.HTTPCodedError) {
	c.rekeyLock.RLock()
	defer c.rekeyLock.RUnlock()

	var config *SealConfig
	var err error
	// If we are rotating the recovery key, or if the seal supports
	// recovery keys and we are rotating the barrier key, we use the
	// recovery config as the threshold instead.
	if recovery || c.seal.RecoveryKeySupported() {
		config, err = c.seal.RecoveryConfig(ctx)
	} else {
		config, err = c.seal.BarrierConfig(ctx)
	}

	if err != nil {
		return 0, logical.CodedError(http.StatusInternalServerError, fmt.Errorf("unable to look up config: %w", err).Error())
	}

	if config == nil {
		return 0, logical.CodedError(http.StatusBadRequest, ErrNotInit.Error())
	}

	return config.SecretThreshold, nil
}

// RotationProgress is used to return the rotation progress (num shares).
func (c *Core) RotationProgress(recovery, verification bool) (bool, int, error) {
	c.rekeyLock.RLock()
	defer c.rekeyLock.RUnlock()

	var conf *SealConfig
	if recovery {
		conf = c.recoveryRekeyConfig
	} else {
		conf = c.barrierRekeyConfig
	}

	if conf == nil {
		return false, 0, errors.New("rotation operation not in progress")
	}

	if verification {
		return len(conf.VerificationKey) > 0, len(conf.VerificationProgress), nil
	}

	return true, len(conf.RekeyProgress), nil
}

// InitRotation will either initialize the rotation of barrier or recovery key
// depending on the value of recovery parameter.
func (c *Core) InitRotation(ctx context.Context, config *SealConfig, recovery bool) (*RekeyResult, logical.HTTPCodedError) {
	// Initialize the nonce for rotation operation
	nonce, err := uuid.GenerateUUID()
	if err != nil {
		return nil, logical.CodedError(http.StatusInternalServerError, fmt.Errorf("error generating nonce for procedure: %w", err).Error())
	}

	if recovery {
		if c.recoveryRekeyConfig != nil {
			return nil, logical.CodedError(http.StatusBadRequest, "rotation already in progress")
		}

		var initErr logical.HTTPCodedError
		initErr = c.initRecoveryRotation(config, nonce)
		if initErr != nil {
			return nil, initErr
		}

		// if no key shares exist, meaning we've initalized the instance
		// without creating them at time, then return the keys immediately
		existingRecoveryConfig, err := c.seal.RecoveryConfig(ctx)
		if err != nil {
			return nil, logical.CodedError(http.StatusInternalServerError, fmt.Errorf("failed to fetch existing recovery config: %w", err).Error())
		}

		if existingRecoveryConfig == nil {
			return nil, logical.CodedError(http.StatusBadRequest, ErrNotInit.Error())
		}

		if existingRecoveryConfig.SecretShares == 0 {
			newRecoveryKey, result, err := c.generateKey(c.recoveryRekeyConfig, true)
			if err != nil {
				return nil, err
			}

			// If PGP keys are passed in, encrypt shares with corresponding PGP keys.
			if len(c.recoveryRekeyConfig.PGPKeys) > 0 {
				var encryptError error
				result, encryptError = c.pgpEncryptShares(ctx, c.recoveryRekeyConfig, result)
				if encryptError != nil {
					return nil, logical.CodedError(http.StatusInternalServerError, encryptError.Error())
				}
			}

			// If we are requiring validation, return now; otherwise save the recovery key
			if c.recoveryRekeyConfig.VerificationRequired {
				return c.requireVerification(c.recoveryRekeyConfig, result, newRecoveryKey)
			}

			if err := c.performRecoveryRekey(ctx, newRecoveryKey); err != nil {
				return nil, logical.CodedError(http.StatusInternalServerError, fmt.Errorf("failed to perform recovery rotation: %w", err).Error())
			}

			c.recoveryRekeyConfig = nil
			return result, nil
		}

		return nil, nil
	}

	if c.barrierRekeyConfig != nil {
		return nil, logical.CodedError(http.StatusBadRequest, "rotation already in progress")
	}

	return nil, c.initBarrierRotation(config, nonce)
}

// initRecoveryRotation initializes rotation of recovery key.
func (c *Core) initRecoveryRotation(config *SealConfig, nonce string) logical.HTTPCodedError {
	if config.StoredShares > 0 {
		return logical.CodedError(http.StatusBadRequest, "stored shares not supported by recovery key")
	}

	// Check if the seal configuration is valid
	// intentionally invoke the `Validate()` instead of `ValidateRecovery()`
	// deny the request if it does not pass the validation check
	if err := config.Validate(); err != nil {
		c.logger.Error("invalid recovery configuration", "error", err)
		return logical.CodedError(http.StatusInternalServerError, fmt.Errorf("invalid recovery configuration: %w", err).Error())
	}

	if !c.seal.RecoveryKeySupported() {
		return logical.CodedError(http.StatusBadRequest, "recovery keys not supported")
	}

	c.rekeyLock.Lock()
	defer c.rekeyLock.Unlock()

	// Copy the configuration
	c.recoveryRekeyConfig = config.Clone()
	c.recoveryRekeyConfig.Nonce = nonce

	if c.logger.IsInfo() {
		c.logger.Info("rotation initialized", "nonce", c.recoveryRekeyConfig.Nonce, "shares", c.recoveryRekeyConfig.SecretShares, "threshold", c.recoveryRekeyConfig.SecretThreshold, "validation_required", c.recoveryRekeyConfig.VerificationRequired)
	}
	return nil
}

// initBarrierRotation initializes rotation of barrier key.
func (c *Core) initBarrierRotation(config *SealConfig, nonce string) logical.HTTPCodedError {
	if config.StoredShares != 1 {
		c.logger.Warn("stored keys supported, forcing rotation shares/threshold to 1")
		config.StoredShares = 1
	}

	if c.seal.BarrierType() != wrapping.WrapperTypeShamir {
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
			return logical.CodedError(http.StatusBadRequest, "requiring verification not supported when rotating the barrier key with recovery keys")
		}
		c.logger.Debug("using recovery seal configuration to rotate barrier key")
	}

	// Check if the seal configuration is valid
	if err := config.Validate(); err != nil {
		c.logger.Error("invalid rotate seal configuration", "error", err)
		return logical.CodedError(http.StatusInternalServerError, fmt.Errorf("invalid rotate seal configuration: %w", err).Error())
	}

	c.rekeyLock.Lock()
	defer c.rekeyLock.Unlock()

	// Copy the configuration
	c.barrierRekeyConfig = config.Clone()
	c.barrierRekeyConfig.Nonce = nonce

	if c.logger.IsInfo() {
		c.logger.Info("rotation initialized", "nonce", c.barrierRekeyConfig.Nonce, "shares", c.barrierRekeyConfig.SecretShares, "threshold", c.barrierRekeyConfig.SecretThreshold, "verification_required", c.barrierRekeyConfig.VerificationRequired)
	}
	return nil
}

// CancelRotation is used to cancel an in-progress rotation operation.
func (c *Core) CancelRotation(recovery bool) logical.HTTPCodedError {
	c.rekeyLock.Lock()
	defer c.rekeyLock.Unlock()

	// Clear any progress or config
	if recovery {
		c.recoveryRekeyConfig = nil
	} else {
		c.barrierRekeyConfig = nil
	}
	return nil
}

// UpdateRotation is used to provide a new key share for the rotation
// of barrier or recovery key.
func (c *Core) UpdateRotation(ctx context.Context, key []byte, nonce string, recovery bool) (*RekeyResult, logical.HTTPCodedError) {
	c.rekeyLock.Lock()
	defer c.rekeyLock.Unlock()

	var config *SealConfig
	var err error
	var useRecovery bool
	if recovery || (c.seal.StoredKeysSupported() == seal.StoredKeysSupportedGeneric && c.seal.RecoveryKeySupported()) {
		config, err = c.seal.RecoveryConfig(ctx)
		useRecovery = true
	} else {
		config, err = c.seal.BarrierConfig(ctx)
	}

	if err != nil {
		return nil, logical.CodedError(http.StatusInternalServerError, fmt.Errorf("failed to fetch existing config: %w", err).Error())
	}

	if config == nil {
		return nil, logical.CodedError(http.StatusBadRequest, ErrNotInit.Error())
	}

	if recovery {
		if c.recoveryRekeyConfig == nil {
			return nil, logical.CodedError(http.StatusBadRequest, "no recovery rotation in progress")
		}
		return c.updateRecoveryRotation(ctx, config, key, nonce)
	}

	if c.barrierRekeyConfig == nil {
		return nil, logical.CodedError(http.StatusBadRequest, "no barrier rotation in progress")
	}
	return c.updateBarrierRotation(ctx, config, key, nonce, useRecovery)
}

// updateRecoveryRotation is used to provide a new key share for recovery key rotation.
func (c *Core) updateRecoveryRotation(ctx context.Context, config *SealConfig, key []byte, nonce string) (*RekeyResult, logical.HTTPCodedError) {
	recoveryKey, err := c.progressRotation(c.recoveryRekeyConfig, config, key, nonce)
	if err != nil {
		return nil, err
	}

	if recoveryKey == nil {
		return nil, nil
	}

	// Verify the recovery key
	if err := c.seal.VerifyRecoveryKey(ctx, recoveryKey); err != nil {
		c.logger.Error("recovery key verification failed", "error", err)
		return nil, logical.CodedError(http.StatusBadRequest, fmt.Errorf("recovery key verification failed: %w", err).Error())
	}

	newRecoveryKey, result, err := c.generateKey(c.recoveryRekeyConfig, true)
	if err != nil {
		return nil, err
	}

	// If PGP keys are passed in, encrypt shares with corresponding PGP keys.
	if len(c.recoveryRekeyConfig.PGPKeys) > 0 {
		var encryptError error
		result, encryptError = c.pgpEncryptShares(ctx, c.recoveryRekeyConfig, result)
		if encryptError != nil {
			return nil, logical.CodedError(http.StatusInternalServerError, encryptError.Error())
		}
	}

	// If we are requiring validation, return now; otherwise save the recovery key
	if c.recoveryRekeyConfig.VerificationRequired {
		return c.requireVerification(c.recoveryRekeyConfig, result, newRecoveryKey)
	}

	if err := c.performRecoveryRekey(ctx, newRecoveryKey); err != nil {
		return nil, logical.CodedError(http.StatusInternalServerError, fmt.Errorf("failed to perform recovery rotation: %w", err).Error())
	}

	c.recoveryRekeyConfig = nil
	return result, nil
}

// updateBarrierRotation is used to provide a new key share for barrier key rotation.
func (c *Core) updateBarrierRotation(ctx context.Context, config *SealConfig, key []byte, nonce string, useRecovery bool) (*RekeyResult, logical.HTTPCodedError) {
	recoveredKey, err := c.progressRotation(c.barrierRekeyConfig, config, key, nonce)
	if err != nil {
		return nil, err
	}

	if recoveredKey == nil {
		return nil, nil
	}

	switch {
	case useRecovery:
		if err := c.seal.VerifyRecoveryKey(ctx, recoveredKey); err != nil {
			c.logger.Error("recovery key verification failed", "error", err)
			return nil, logical.CodedError(http.StatusBadRequest, fmt.Errorf("recovery key verification failed: %w", err).Error())
		}
	case c.seal.BarrierType() == wrapping.WrapperTypeShamir:
		if c.seal.StoredKeysSupported() == seal.StoredKeysSupportedShamirRoot {
			shamirWrapper := aeadwrapper.NewShamirWrapper()
			testseal := NewDefaultSeal(seal.NewAccess(shamirWrapper))
			testseal.SetCore(c)
			err := shamirWrapper.SetAesGcmKeyBytes(recoveredKey)
			if err != nil {
				return nil, logical.CodedError(http.StatusInternalServerError, fmt.Errorf("failed to setup unseal key: %w", err).Error())
			}

			cfg, err := c.seal.BarrierConfig(ctx)
			if err != nil {
				return nil, logical.CodedError(http.StatusInternalServerError, fmt.Errorf("failed to setup test barrier config: %w", err).Error())
			}
			testseal.SetCachedBarrierConfig(cfg)

			stored, err := testseal.GetStoredKeys(ctx)
			if err != nil {
				return nil, logical.CodedError(http.StatusInternalServerError, fmt.Errorf("failed to read root key: %w", err).Error())
			}
			recoveredKey = stored[0]
		}
		if err := c.barrier.VerifyRoot(recoveredKey); err != nil {
			c.logger.Error("root key verification failed", "error", err)
			return nil, logical.CodedError(http.StatusBadRequest, fmt.Errorf("root key verification failed: %w", err).Error())
		}
	}

	// Generate a new key: for AutoUnseal, this is a new root key; for Shamir,
	// this is a new unseal key, and performBarrierRekey will also generate a
	// new root key.
	newKey, result, err := c.generateKey(c.barrierRekeyConfig, true)
	if err != nil {
		return nil, err
	}

	// If PGP keys are passed in, encrypt shares with corresponding PGP keys.
	if len(c.barrierRekeyConfig.PGPKeys) > 0 {
		var encryptError error
		result, encryptError = c.pgpEncryptShares(ctx, c.barrierRekeyConfig, result)
		if encryptError != nil {
			return nil, logical.CodedError(http.StatusInternalServerError, encryptError.Error())
		}
	}

	// If we are requiring validation, return now; otherwise rotate barrier key
	if c.barrierRekeyConfig.VerificationRequired {
		return c.requireVerification(c.barrierRekeyConfig, result, newKey)
	}

	if err := c.performBarrierRekey(ctx, newKey); err != nil {
		return nil, logical.CodedError(http.StatusInternalServerError, fmt.Errorf("failed to rotate barrier key: %w", err).Error())
	}

	c.barrierRekeyConfig = nil
	return result, nil
}

// progressRotation checks the key rotation progress, verifying if we have
// enough shares to recover the key.
func (c *Core) progressRotation(rotationConfig, existingConfig *SealConfig, key []byte, nonce string) ([]byte, logical.HTTPCodedError) {
	if len(rotationConfig.VerificationKey) > 0 {
		return nil, logical.CodedError(http.StatusBadRequest, fmt.Sprintf("rotation operation already finished; verification must be performed; nonce for the verification operation is %q", rotationConfig.VerificationNonce))
	}

	if nonce != rotationConfig.Nonce {
		return nil, logical.CodedError(http.StatusBadRequest, fmt.Sprintf("incorrect nonce supplied; nonce for rotation operation is %q", rotationConfig.Nonce))
	}

	// Check if we already have this piece
	for _, existing := range rotationConfig.RekeyProgress {
		if subtle.ConstantTimeCompare(existing, key) == 1 {
			return nil, logical.CodedError(http.StatusBadRequest, "given key has already been provided during this rotation operation")
		}
	}

	// Store this key
	rotationConfig.RekeyProgress = append(rotationConfig.RekeyProgress, key)

	// Check if we don't have enough keys to unlock
	if len(rotationConfig.RekeyProgress) < existingConfig.SecretThreshold {
		if c.logger.IsDebug() {
			c.logger.Debug("cannot rotate yet, not enough keys", "keys", len(rotationConfig.RekeyProgress), "threshold", existingConfig.SecretThreshold)
		}
		return nil, nil
	}

	// Recover the key
	var recoveredKey []byte
	if existingConfig.SecretThreshold == 1 {
		recoveredKey = rotationConfig.RekeyProgress[0]
	} else {
		var err error
		recoveredKey, err = shamir.Combine(rotationConfig.RekeyProgress)
		if err != nil {
			return nil, logical.CodedError(http.StatusInternalServerError, fmt.Errorf("failed to compute key: %w", err).Error())
		}
	}

	rotationConfig.RekeyProgress = nil
	return recoveredKey, nil
}

// generateKey generates a new root/recovery key dividing it into desired number of key shares.
func (c *Core) generateKey(rotationConfig *SealConfig, recovery bool) ([]byte, *RekeyResult, logical.HTTPCodedError) {
	// Generate a new root/recovery key
	newKey, err := c.barrier.GenerateKey(c.secureRandomReader)
	if err != nil {
		c.logger.Error("failed to generate key", "error", err)
		return nil, nil, logical.CodedError(http.StatusInternalServerError, fmt.Errorf("key generation failed: %w", err).Error())
	}

	result := &RekeyResult{
		Backup: rotationConfig.Backup,
	}

	if recovery || c.seal.StoredKeysSupported() != seal.StoredKeysSupportedGeneric {
		// Set result.SecretShares to the new key itself if only a single key
		// part is used -- no Shamir split required.
		if rotationConfig.SecretShares == 1 {
			result.SecretShares = append(result.SecretShares, newKey)
		} else {
			// Split the new key using the Shamir algorithm
			shares, err := shamir.Split(newKey, rotationConfig.SecretShares, rotationConfig.SecretThreshold)
			if err != nil {
				c.logger.Error("failed to generate shares", "error", err)
				return nil, nil, logical.CodedError(http.StatusInternalServerError, fmt.Errorf("failed to generate shares: %w", err).Error())
			}
			result.SecretShares = shares
		}
	}
	return newKey, result, nil
}

// pgpEncryptShares encrypts the rotation secret shares using the provided pgp keys.
// If the rotation config also specifies backup, the backup information in saved to storage.
func (c *Core) pgpEncryptShares(ctx context.Context, rotationConfig *SealConfig, rotationResult *RekeyResult) (*RekeyResult, error) {
	hexEncodedShares := make([][]byte, len(rotationResult.SecretShares))
	for i := range rotationResult.SecretShares {
		hexEncodedShares[i] = []byte(hex.EncodeToString(rotationResult.SecretShares[i]))
	}

	var err error
	rotationResult.PGPFingerprints, rotationResult.SecretShares, err = pgpkeys.EncryptShares(hexEncodedShares, rotationConfig.PGPKeys)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt shares: %w", err)
	}

	// If backup is enabled, store backup info in vault.coreBarrierUnsealKeysBackupPath
	if rotationConfig.Backup {
		backupInfo := map[string][]string{}
		for i := 0; i < len(rotationResult.PGPFingerprints); i++ {
			encShare := bytes.NewBuffer(rotationResult.SecretShares[i])
			if backupInfo[rotationResult.PGPFingerprints[i]] == nil {
				backupInfo[rotationResult.PGPFingerprints[i]] = []string{hex.EncodeToString(encShare.Bytes())}
			} else {
				backupInfo[rotationResult.PGPFingerprints[i]] = append(backupInfo[rotationResult.PGPFingerprints[i]], hex.EncodeToString(encShare.Bytes()))
			}
		}

		backupVals := &RekeyBackup{
			Nonce: rotationConfig.Nonce,
			Keys:  backupInfo,
		}
		buf, err := json.Marshal(backupVals)
		if err != nil {
			c.logger.Error("failed to marshal key backup", "error", err)
			return nil, fmt.Errorf("failed to marshal key backup: %w", err)
		}

		pe := &physical.Entry{
			Key:   coreRecoveryUnsealKeysBackupPath,
			Value: buf,
		}
		if err = c.physical.Put(ctx, pe); err != nil {
			c.logger.Error("failed to save unseal key backup", "error", err)
			return nil, fmt.Errorf("failed to save unseal key backup: %w", err)
		}
	}

	return rotationResult, nil
}

// requireVerification sets the verification properties on the rotationConfig
// adds a nonce and required flag and returns the result.
func (c *Core) requireVerification(rotationConfig *SealConfig, rotationResult *RekeyResult, newKey []byte) (*RekeyResult, logical.HTTPCodedError) {
	nonce, err := uuid.GenerateUUID()
	if err != nil {
		rotationConfig = nil
		return nil, logical.CodedError(http.StatusInternalServerError, fmt.Errorf("failed to generate verification nonce: %w", err).Error())
	}
	rotationConfig.VerificationNonce = nonce
	rotationConfig.VerificationKey = newKey

	rotationResult.VerificationRequired = true
	rotationResult.VerificationNonce = nonce
	return rotationResult, nil
}

// VerifyRotation verifies the progress of the verification of the rotation operation.
func (c *Core) VerifyRotation(ctx context.Context, key []byte, nonce string, recovery bool) (ret *RekeyVerifyResult, retErr logical.HTTPCodedError) {
	c.rekeyLock.Lock()
	defer c.rekeyLock.Unlock()

	config := c.barrierRekeyConfig
	if recovery {
		config = c.recoveryRekeyConfig
	}

	// Ensure a rotation is in progress
	if config == nil {
		return nil, logical.CodedError(http.StatusBadRequest, "no rotation in progress")
	}

	if len(config.VerificationKey) == 0 {
		return nil, logical.CodedError(http.StatusBadRequest, "no rotation verification in progress")
	}

	if nonce != config.VerificationNonce {
		return nil, logical.CodedError(http.StatusBadRequest, fmt.Sprintf("incorrect nonce supplied; nonce for this verify operation is %q", config.VerificationNonce))
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
			return nil, logical.CodedError(http.StatusInternalServerError, fmt.Errorf("failed to compute key for verification: %w", err).Error())
		}
	}

	if subtle.ConstantTimeCompare(recoveredKey, config.VerificationKey) != 1 {
		c.logger.Error("rotation verification failed")
		return nil, logical.CodedError(http.StatusBadRequest, "rotation verification failed; incorrect key shares supplied")
	}

	if recovery {
		if err := c.performRecoveryRekey(ctx, recoveredKey); err != nil {
			return nil, logical.CodedError(http.StatusInternalServerError, fmt.Errorf("failed to perform recovery key rotation: %w", err).Error())
		}
		c.recoveryRekeyConfig = nil
	} else {
		if err := c.performBarrierRekey(ctx, recoveredKey); err != nil {
			return nil, logical.CodedError(http.StatusInternalServerError, fmt.Errorf("failed to perform barrier key rotation: %w", err).Error())
		}
		c.barrierRekeyConfig = nil
	}

	return &RekeyVerifyResult{
		Nonce:    config.VerificationNonce,
		Complete: true,
	}, nil
}

// RestartRotationVerification is used to start the rotation verification process over.
func (c *Core) RestartRotationVerification(recovery bool) logical.HTTPCodedError {
	c.rekeyLock.Lock()
	defer c.rekeyLock.Unlock()

	// Attempt to generate a new nonce, but don't bail if it doesn't succeed
	// (which is extraordinarily unlikely)
	nonce, nonceErr := uuid.GenerateUUID()

	// Clear any progress or config
	if recovery {
		if c.recoveryRekeyConfig != nil {
			c.recoveryRekeyConfig.VerificationProgress = nil
			if nonceErr == nil {
				c.recoveryRekeyConfig.VerificationNonce = nonce
			}
		}
	} else {
		if c.barrierRekeyConfig != nil {
			c.barrierRekeyConfig.VerificationProgress = nil
			if nonceErr == nil {
				c.barrierRekeyConfig.VerificationNonce = nonce
			}
		}
	}

	return nil
}

// RetrieveRotationBackup is used to retrieve any backed-up PGP-encrypted unseal keys.
func (c *Core) RetrieveRotationBackup(ctx context.Context, recovery bool) (*RekeyBackup, logical.HTTPCodedError) {
	c.rekeyLock.RLock()
	defer c.rekeyLock.RUnlock()

	var entry *physical.Entry
	var err error
	if recovery {
		entry, err = c.physical.Get(ctx, coreRecoveryUnsealKeysBackupPath)
	} else {
		entry, err = c.physical.Get(ctx, coreBarrierUnsealKeysBackupPath)
	}
	if err != nil {
		return nil, logical.CodedError(http.StatusInternalServerError, fmt.Errorf("error getting keys from backup: %w", err).Error())
	}
	if entry == nil {
		return nil, nil
	}

	ret := &RekeyBackup{}
	err = jsonutil.DecodeJSON(entry.Value, ret)
	if err != nil {
		return nil, logical.CodedError(http.StatusInternalServerError, fmt.Errorf("error decoding backup keys: %w", err).Error())
	}

	return ret, nil
}

// DeleteRotationBackup is used to delete any backed-up PGP-encrypted unseal keys.
func (c *Core) DeleteRotationBackup(ctx context.Context, recovery bool) logical.HTTPCodedError {
	c.rekeyLock.Lock()
	defer c.rekeyLock.Unlock()

	var err error
	if recovery {
		err = c.physical.Delete(ctx, coreRecoveryUnsealKeysBackupPath)
	} else {
		err = c.physical.Delete(ctx, coreBarrierUnsealKeysBackupPath)
	}

	if err != nil {
		return logical.CodedError(http.StatusInternalServerError, fmt.Errorf("error deleting backup keys: %w", err).Error())
	}
	return nil
}
