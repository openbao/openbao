// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"

	uuid "github.com/hashicorp/go-uuid"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
	aeadwrapper "github.com/openbao/go-kms-wrapping/wrappers/aead/v2"
	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/helper/pgpkeys"
	"github.com/openbao/openbao/sdk/v2/helper/jsonutil"
	"github.com/openbao/openbao/sdk/v2/helper/shamir"
	"github.com/openbao/openbao/sdk/v2/logical"
	vaultseal "github.com/openbao/openbao/vault/seal"
)

// setRotationConfig acquires a lock and sets the root or recovery rotation config
// for a given namespace.
func (sm *SealManager) SetRotationConfig(ns *namespace.Namespace, recovery bool, newConfig *SealConfig) error {
	sm.lock.Lock()
	defer sm.lock.Unlock()
	return sm.setRotationConfig(ns, recovery, newConfig)
}

// setRotationConfig sets the root or recovery rotation config for a given namespace.
func (sm *SealManager) setRotationConfig(ns *namespace.Namespace, recovery bool, newConfig *SealConfig) error {
	rotationConfig, ok := sm.rotationConfigByNamespace[ns.UUID]["default"]
	if !ok {
		return ErrNotSealable
	}

	if recovery {
		rotationConfig.recoveryConfig = newConfig
	} else {
		rotationConfig.rootConfig = newConfig
	}

	return nil
}

// RotationConfig acquires a read lock and reads the rotation config of
// a given namespace.
func (sm *SealManager) RotationConfig(ns *namespace.Namespace, recovery bool) *SealConfig {
	sm.lock.RLock()
	defer sm.lock.RUnlock()
	return sm.rotationConfig(ns, recovery)
}

// rotationConfig reads the rotation config of a given namespace.
func (sm *SealManager) rotationConfig(ns *namespace.Namespace, recovery bool) *SealConfig {
	rotationConfig, ok := sm.rotationConfigByNamespace[ns.UUID]["default"]
	if !ok {
		return nil
	}

	// Return the specified seal config
	if recovery {
		if rotationConfig.recoveryConfig != nil {
			return rotationConfig.recoveryConfig
		}
	} else {
		if rotationConfig.rootConfig != nil {
			return rotationConfig.rootConfig
		}
	}

	return nil
}

// RotationThreshold returns the secret threshold for the current seal config.
// This threshold can either be the barrier key threshold or the recovery key
// threshold, depending on whether rotation is being performed on the recovery
// key, or whether the seal supports recovery keys.
func (sm *SealManager) RotationThreshold(ctx context.Context, ns *namespace.Namespace, recovery bool) (int, logical.HTTPCodedError) {
	sm.lock.RLock()
	defer sm.lock.RUnlock()

	seal := sm.namespaceSeal(ns.UUID)
	if seal == nil {
		return 0, logical.CodedError(http.StatusBadRequest, ErrNotSealable.Error())
	}

	var config *SealConfig
	var err error
	// If we are rotating the recovery key, or if the seal supports
	// recovery keys and we are rotating the barrier key, we use the
	// recovery config as the threshold instead.
	if recovery || seal.RecoveryKeySupported() {
		config, err = seal.RecoveryConfig(ctx)
	} else {
		config, err = seal.Config(ctx)
	}

	if err != nil {
		return 0, logical.CodedError(http.StatusInternalServerError, "unable to look up config: %w", err)
	}

	if config == nil {
		return 0, logical.CodedError(http.StatusBadRequest, ErrNotInit.Error())
	}

	return config.SecretThreshold, nil
}

// RotationProgress is used to return the rotation progress (num shares).
func (sm *SealManager) RotationProgress(ns *namespace.Namespace, recovery, verification bool) (bool, int, logical.HTTPCodedError) {
	sm.lock.RLock()
	defer sm.lock.RUnlock()

	rotationConfig, ok := sm.rotationConfigByNamespace[ns.UUID]["default"]
	if !ok {
		return false, 0, logical.CodedError(http.StatusBadRequest, ErrNotSealable.Error())
	}

	var config *SealConfig
	if recovery {
		if rotationConfig.recoveryConfig != nil {
			config = rotationConfig.recoveryConfig
		}
	} else {
		if rotationConfig.rootConfig != nil {
			config = rotationConfig.rootConfig
		}
	}

	if config == nil {
		return false, 0, logical.CodedError(http.StatusBadRequest, "rotation not in progress")
	}

	if verification {
		return len(config.VerificationKey) > 0, len(config.VerificationProgress), nil
	}

	return true, len(config.RotationProgress), nil
}

// validateRotationConfig validates properties of recovery or root rotation config.
func (sm *SealManager) validateRotationConfig(ns *namespace.Namespace, newConfig *SealConfig, recovery bool) (Seal, logical.HTTPCodedError) {
	currentRotationConfig := sm.rotationConfig(ns, recovery)
	if currentRotationConfig != nil {
		return nil, logical.CodedError(http.StatusBadRequest, "rotation already in progress")
	}

	seal := sm.namespaceSeal(ns.UUID)
	if seal == nil {
		return nil, logical.CodedError(http.StatusBadRequest, ErrNotSealable.Error())
	}

	if recovery {
		if newConfig.StoredShares > 0 {
			return nil, logical.CodedError(http.StatusBadRequest, "stored shares not supported by recovery key")
		}

		if !seal.RecoveryKeySupported() {
			return nil, logical.CodedError(http.StatusBadRequest, "recovery keys not supported")
		}

		// Check if the seal configuration is valid
		// intentionally invoke the `Validate()` instead of `ValidateRecovery()`
		// deny the request if it does not pass the validation check
		if err := newConfig.Validate(); err != nil {
			sm.logger.Error("invalid recovery configuration", "error", err)
			return nil, logical.CodedError(http.StatusInternalServerError, "invalid recovery configuration: %w", err)
		}
	} else {
		if newConfig.StoredShares != 1 {
			sm.logger.Warn("stored keys supported, forcing rotation shares/threshold to 1")
			newConfig.StoredShares = 1
		}

		if seal.WrapperType() != wrapping.WrapperTypeShamir {
			newConfig.SecretShares = 1
			newConfig.SecretThreshold = 1

			if len(newConfig.PGPKeys) > 0 {
				return nil, logical.CodedError(http.StatusBadRequest, "PGP key encryption not supported when using stored keys")
			}
			if newConfig.Backup {
				return nil, logical.CodedError(http.StatusBadRequest, "key backup not supported when using stored keys")
			}
		}

		if seal.RecoveryKeySupported() {
			if newConfig.VerificationRequired {
				return nil, logical.CodedError(http.StatusBadRequest, "requiring verification not supported when rotating the barrier key with recovery keys")
			}
			sm.logger.Debug("using recovery seal configuration to rotate barrier key")
		}

		// Check if the seal configuration is valid
		if err := newConfig.Validate(); err != nil {
			sm.logger.Error("invalid rotate seal configuration", "error", err)
			return nil, logical.CodedError(http.StatusInternalServerError, "invalid rotate seal configuration: %w", err)
		}
	}

	return seal, nil
}

// InitRotation will either initialize the rotation of barrier or recovery key
// depending on the value of recovery parameter.
func (sm *SealManager) InitRotation(ctx context.Context, ns *namespace.Namespace, newConfig *SealConfig, recovery bool) (*RekeyResult, logical.HTTPCodedError) {
	sm.lock.Lock()
	defer sm.lock.Unlock()

	seal, validationErr := sm.validateRotationConfig(ns, newConfig, recovery)
	if validationErr != nil {
		return nil, validationErr
	}

	// Initialize the nonce for rotation operation
	nonce, err := uuid.GenerateUUID()
	if err != nil {
		return nil, logical.CodedError(http.StatusInternalServerError, "error generating nonce for procedure: %w", err)
	}

	// Copy the configuration
	config := newConfig.Clone()
	config.Nonce = nonce
	if err := sm.setRotationConfig(ns, recovery, config); err != nil {
		return nil, logical.CodedError(http.StatusInternalServerError, "failed to update rotate config: %w", err)
	}

	if sm.logger.IsInfo() {
		sm.logger.Info("rotation initialized", "namespace", ns.Path, "nonce", config.Nonce, "shares", config.SecretShares, "threshold", config.SecretThreshold, "validation_required", config.VerificationRequired)
	}

	if recovery {
		// if no key shares exist, meaning we've initialized the instance
		// without creating them at time, then return the keys immediately
		return sm.rotateRecoveryNoKeyShares(ctx, ns, seal, config)
	}

	//nolint:nilnil // we do not return any keys, nor we fail at something.
	return nil, nil
}

// rotateRecoveryNoKeyShares verifies that recovery config exists and if its
// `SecretShares` property value is set as 0, immediately returns back
// new rotated recovery key shares.
func (sm *SealManager) rotateRecoveryNoKeyShares(ctx context.Context, ns *namespace.Namespace, seal Seal, config *SealConfig) (*RekeyResult, logical.HTTPCodedError) {
	existingRecoveryConfig, err := seal.RecoveryConfig(ctx)
	if err != nil {
		return nil, logical.CodedError(http.StatusInternalServerError, "failed to fetch existing recovery config: %w", err)
	}

	if existingRecoveryConfig == nil {
		return nil, logical.CodedError(http.StatusBadRequest, ErrNotInit.Error())
	}

	if existingRecoveryConfig.SecretShares == 0 {
		newRecoveryKey, result, err := sm.generateKey(ns, config, seal, true)
		if err != nil {
			return nil, err
		}

		// If PGP keys are passed in, encrypt shares with corresponding PGP keys.
		if len(config.PGPKeys) > 0 {
			var encryptError error
			result, encryptError = sm.pgpEncryptShares(ctx, ns, config, result)
			if encryptError != nil {
				return nil, logical.CodedError(http.StatusInternalServerError, encryptError.Error())
			}
		}

		// If we are requiring validation, return now
		// otherwise save the recovery key
		if config.VerificationRequired {
			return sm.requireVerification(config, result, newRecoveryKey)
		}

		if err := sm.performRecoveryRotation(ctx, ns, newRecoveryKey, config, seal); err != nil {
			return nil, logical.CodedError(http.StatusInternalServerError, fmt.Errorf("failed to perform recovery rotation: %w", err).Error())
		}

		// reset rotation config
		if err := sm.setRotationConfig(ns, true, nil); err != nil {
			return nil, logical.CodedError(http.StatusInternalServerError, err.Error())
		}

		return result, nil
	}

	//nolint:nilnil // we do not return any keys, nor we fail at something.
	return nil, nil
}

func (sm *SealManager) performRecoveryRotation(ctx context.Context, ns *namespace.Namespace, newRootKey []byte, rotationConfig *SealConfig, seal Seal) logical.HTTPCodedError {
	if err := seal.SetRecoveryKey(ctx, newRootKey); err != nil {
		sm.logger.Error("failed to set recovery key", "error", err)
		return logical.CodedError(http.StatusInternalServerError, "failed to set recovery key: %w", err)
	}

	rotationConfig.VerificationKey = nil

	if err := seal.SetRecoveryConfig(ctx, rotationConfig); err != nil {
		sm.logger.Error("error saving rotate seal configuration", "error", err)
		return logical.CodedError(http.StatusInternalServerError, "failed to save rotate seal configuration: %w", err)
	}

	// Write to the canary path, which will force a synchronous truing during
	// replication
	keyringCanaryPath := namespaceLogicalStoragePath(ns) + coreKeyringCanaryPath
	barrier := sm.StorageAccessForPath(keyringCanaryPath)
	if err := barrier.Put(ctx, keyringCanaryPath, []byte(rotationConfig.Nonce)); err != nil {
		sm.logger.Error("error saving keyring canary", "error", err)
		return logical.CodedError(http.StatusInternalServerError, "failed to save keyring canary: %w", err)
	}

	rotationConfig.RotationProgress = nil
	return nil
}

func (sm *SealManager) performRootRotation(ctx context.Context, ns *namespace.Namespace, newSealKey []byte, rotationConfig *SealConfig, seal Seal) logical.HTTPCodedError {
	if seal.StoredKeysSupported() != vaultseal.StoredKeysSupportedGeneric {
		shamirWrapper, err := seal.GetShamirWrapper()
		if err == nil {
			err = shamirWrapper.SetAesGcmKeyBytes(newSealKey)
		}
		if err != nil {
			return logical.CodedError(http.StatusInternalServerError, "failed to update barrier seal key: %w", err)
		}
	}

	barrier := sm.namespaceBarrier(ns.Path)
	if barrier == nil {
		return logical.CodedError(http.StatusBadRequest, ErrNotSealable.Error())
	}

	newRootKey, err := barrier.GenerateKey(sm.core.secureRandomReader)
	if err != nil {
		return logical.CodedError(http.StatusInternalServerError, "failed to perform rotation: %w", err)
	}

	if err := seal.SetStoredKeys(ctx, [][]byte{newRootKey}); err != nil {
		sm.logger.Error("failed to store keys", "error", err)
		return logical.CodedError(http.StatusInternalServerError, "failed to store keys: %w", err)
	}

	// Rotate the barrier
	if err := barrier.RotateRootKey(ctx, newRootKey); err != nil {
		sm.logger.Error("failed to rotate root key", "error", err)
		return logical.CodedError(http.StatusInternalServerError, "failed to rotate root key: %w", err)
	}

	if sm.logger.IsInfo() {
		sm.logger.Info("root key rotated", "namespace", ns.Path, "stored", rotationConfig.StoredShares, "shares", rotationConfig.SecretShares, "threshold", rotationConfig.SecretThreshold)
	}

	kekPath := namespaceLogicalStoragePath(ns) + shamirKekPath
	storage := sm.StorageAccessForPath(kekPath)
	if len(newSealKey) > 0 {
		err := storage.Put(ctx, kekPath, newSealKey)
		if err != nil {
			sm.logger.Error("failed to store new seal key", "error", err)
			return logical.CodedError(http.StatusInternalServerError, "failed to store new seal key: %w", err)
		}
	}

	rotationConfig.VerificationKey = nil

	if err := seal.SetConfig(ctx, rotationConfig); err != nil {
		sm.logger.Error("error saving rotate seal configuration", "error", err)
		return logical.CodedError(http.StatusInternalServerError, "failed to save rotate seal configuration: %w", err)
	}

	// Write to the canary path, which will force a synchronous truing during
	// replication
	keyringCanaryPath := namespaceLogicalStoragePath(ns) + coreKeyringCanaryPath
	storage = sm.StorageAccessForPath(keyringCanaryPath)
	if err := storage.Put(ctx, keyringCanaryPath, []byte(rotationConfig.Nonce)); err != nil {
		sm.logger.Error("error saving keyring canary", "error", err)
		return logical.CodedError(http.StatusInternalServerError, "failed to save keyring canary: %w", err)
	}

	rotationConfig.RotationProgress = nil
	return nil
}

// CancelRotation is used to cancel an in-progress rotation operation.
func (sm *SealManager) CancelRotation(ns *namespace.Namespace, recovery bool) logical.HTTPCodedError {
	sm.lock.Lock()
	defer sm.lock.Unlock()

	err := sm.setRotationConfig(ns, recovery, nil)
	if err != nil {
		return logical.CodedError(http.StatusBadRequest, err.Error())
	}
	return nil
}

// UpdateRotation is used to provide a new key share for the rotation
// of barrier or recovery key.
func (sm *SealManager) UpdateRotation(ctx context.Context, ns *namespace.Namespace, key []byte, nonce string, recovery bool) (*RekeyResult, logical.HTTPCodedError) {
	sm.lock.Lock()
	defer sm.lock.Unlock()

	seal := sm.namespaceSeal(ns.UUID)
	if seal == nil {
		return nil, logical.CodedError(http.StatusBadRequest, ErrNotSealable.Error())
	}

	var config *SealConfig
	var err error
	var useRecovery bool
	if recovery || (seal.StoredKeysSupported() == vaultseal.StoredKeysSupportedGeneric && seal.RecoveryKeySupported()) {
		config, err = seal.RecoveryConfig(ctx)
		useRecovery = true
	} else {
		config, err = seal.Config(ctx)
	}

	if err != nil {
		return nil, logical.CodedError(http.StatusInternalServerError, "failed to fetch existing config: %w", err)
	}

	if config == nil {
		return nil, logical.CodedError(http.StatusBadRequest, ErrNotInit.Error())
	}

	rotationConfig := sm.rotationConfig(ns, recovery)
	if rotationConfig == nil {
		return nil, logical.CodedError(http.StatusBadRequest, "no rotation in progress")
	}

	recoveryKey, rotErr := sm.progressRotation(rotationConfig, config, key, nonce)
	if rotErr != nil {
		return nil, rotErr
	}

	if recoveryKey == nil {
		return nil, nil
	}

	if recovery || useRecovery {
		// Verify the recovery key
		if err := seal.VerifyRecoveryKey(ctx, recoveryKey); err != nil {
			sm.logger.Error("recovery key verification failed", "error", err)
			return nil, logical.CodedError(http.StatusBadRequest, "recovery key verification failed: %w", err)
		}
	}

	var result *RekeyResult
	if recovery {
		result, rotErr = sm.updateRecoveryRotation(ctx, ns, seal, rotationConfig)
	} else {
		result, rotErr = sm.updateRootRotation(ctx, ns, seal, rotationConfig, recoveryKey)
	}

	return result, rotErr
}

// updateRecoveryRotation updates the recovery key rotation with provided new key share.
func (sm *SealManager) updateRecoveryRotation(ctx context.Context, ns *namespace.Namespace, seal Seal, rotationConfig *SealConfig) (*RekeyResult, logical.HTTPCodedError) {
	newRecoveryKey, result, err := sm.generateKey(ns, rotationConfig, seal, true)
	if err != nil {
		return nil, err
	}

	// If PGP keys are passed in, encrypt shares with corresponding PGP keys.
	if len(rotationConfig.PGPKeys) > 0 {
		var encryptError error
		result, encryptError = sm.pgpEncryptShares(ctx, ns, rotationConfig, result)
		if encryptError != nil {
			return nil, logical.CodedError(http.StatusInternalServerError, encryptError.Error())
		}
	}

	// If we are requiring validation, return now; otherwise save the recovery key
	if rotationConfig.VerificationRequired {
		return sm.requireVerification(rotationConfig, result, newRecoveryKey)
	}

	if err := sm.performRecoveryRotation(ctx, ns, newRecoveryKey, rotationConfig, seal); err != nil {
		return nil, logical.CodedError(http.StatusInternalServerError, "failed to perform recovery rotation: %w", err)
	}

	// reset rotation config
	if err := sm.setRotationConfig(ns, true, nil); err != nil {
		return nil, logical.CodedError(http.StatusInternalServerError, err.Error())
	}

	return result, nil
}

// updateRootRotation updates the root key rotation with provided new key share.
func (sm *SealManager) updateRootRotation(ctx context.Context, ns *namespace.Namespace, seal Seal, rotationConfig *SealConfig, recoveryKey []byte) (*RekeyResult, logical.HTTPCodedError) {
	if seal.WrapperType() == wrapping.WrapperTypeShamir {
		if seal.StoredKeysSupported() == vaultseal.StoredKeysSupportedShamirRoot {
			shamirWrapper := aeadwrapper.NewShamirWrapper()
			testseal := NewDefaultSeal(vaultseal.NewAccess(shamirWrapper))
			testseal.SetCore(sm.core)
			if ns.ID != namespace.RootNamespaceID {
				testseal.SetMetaPrefix(namespaceLogicalStoragePath(ns))
			}

			err := shamirWrapper.SetAesGcmKeyBytes(recoveryKey)
			if err != nil {
				return nil, logical.CodedError(http.StatusInternalServerError, "failed to setup unseal key: %w", err)
			}

			cfg, err := seal.Config(ctx)
			if err != nil {
				return nil, logical.CodedError(http.StatusInternalServerError, "failed to setup test barrier config: %w", err)
			}
			testseal.SetCachedConfig(cfg)

			stored, err := testseal.GetStoredKeys(ctx)
			if err != nil {
				return nil, logical.CodedError(http.StatusInternalServerError, "failed to read root key: %w", err)
			}
			recoveryKey = stored[0]
		}

		barrier := sm.namespaceBarrier(ns.Path)
		if barrier == nil {
			return nil, logical.CodedError(http.StatusBadRequest, ErrNotSealable.Error())
		}

		if err := barrier.VerifyRoot(recoveryKey); err != nil {
			sm.logger.Error("root key verification failed", "error", err)
			return nil, logical.CodedError(http.StatusBadRequest, "root key verification failed: %w", err)
		}
	}

	// Generate a new key: for AutoUnseal, this is a new root key; for Shamir,
	// this is a new unseal key, and performRootRotation will also generate a
	// new root key.
	newKey, result, err := sm.generateKey(ns, rotationConfig, seal, true)
	if err != nil {
		return nil, err
	}

	// If PGP keys are passed in, encrypt shares with corresponding PGP keys.
	if len(rotationConfig.PGPKeys) > 0 {
		var encryptError error
		result, encryptError = sm.pgpEncryptShares(ctx, ns, rotationConfig, result)
		if encryptError != nil {
			return nil, logical.CodedError(http.StatusInternalServerError, encryptError.Error())
		}
	}

	// If we are requiring validation, return now; otherwise rotate barrier key
	if rotationConfig.VerificationRequired {
		return sm.requireVerification(rotationConfig, result, newKey)
	}

	if err := sm.performRootRotation(ctx, ns, newKey, rotationConfig, seal); err != nil {
		return nil, logical.CodedError(http.StatusInternalServerError, "failed to rotate barrier key: %w", err)
	}

	// reset rotation config
	if err := sm.setRotationConfig(ns, false, nil); err != nil {
		return nil, logical.CodedError(http.StatusInternalServerError, err.Error())
	}

	return result, nil
}

// progressRotation checks the key rotation progress, verifying if we have
// enough shares to recover the key.
func (sm *SealManager) progressRotation(rotationConfig, existingConfig *SealConfig, key []byte, nonce string) ([]byte, logical.HTTPCodedError) {
	if len(rotationConfig.VerificationKey) > 0 {
		return nil, logical.CodedError(http.StatusBadRequest, "rotation already finished; verification must be performed; nonce for the verification operation is %q", rotationConfig.VerificationNonce)
	}

	if nonce != rotationConfig.Nonce {
		return nil, logical.CodedError(http.StatusBadRequest, "incorrect nonce supplied; nonce for rotation is %q", rotationConfig.Nonce)
	}

	// Check if we already have this piece
	for _, existing := range rotationConfig.RotationProgress {
		if subtle.ConstantTimeCompare(existing, key) == 1 {
			return nil, logical.CodedError(http.StatusBadRequest, "given key has already been provided during this rotation")
		}
	}

	// Store this key
	rotationConfig.RotationProgress = append(rotationConfig.RotationProgress, key)

	// Check if we don't have enough keys to unlock
	if len(rotationConfig.RotationProgress) < existingConfig.SecretThreshold {
		if sm.logger.IsDebug() {
			sm.logger.Debug("cannot rotate yet, not enough keys", "keys", len(rotationConfig.RotationProgress), "threshold", existingConfig.SecretThreshold)
		}
		return nil, nil
	}

	// Recover the key
	var recoveredKey []byte
	if existingConfig.SecretThreshold == 1 {
		recoveredKey = rotationConfig.RotationProgress[0]
		rotationConfig.RotationProgress = nil
	} else {
		var err error
		recoveredKey, err = shamir.Combine(rotationConfig.RotationProgress)
		rotationConfig.RotationProgress = nil
		if err != nil {
			return nil, logical.CodedError(http.StatusInternalServerError, "failed to compute key: %w", err)
		}
	}

	return recoveredKey, nil
}

// generateKey generates a new root/recovery key dividing it into desired number
// of key shares.
func (sm *SealManager) generateKey(ns *namespace.Namespace, rotationConfig *SealConfig, seal Seal, recovery bool) ([]byte, *RekeyResult, logical.HTTPCodedError) {
	barrier := sm.namespaceBarrier(ns.Path)
	if barrier == nil {
		return nil, nil, logical.CodedError(http.StatusBadRequest, ErrNotSealable.Error())
	}

	// Generate a new root/recovery key
	newKey, err := barrier.GenerateKey(sm.core.secureRandomReader)
	if err != nil {
		sm.logger.Error("failed to generate key", "error", err)
		return nil, nil, logical.CodedError(http.StatusInternalServerError, "key generation failed: %w", err)
	}

	result := &RekeyResult{
		Backup: rotationConfig.Backup,
	}

	if recovery || seal.StoredKeysSupported() != vaultseal.StoredKeysSupportedGeneric {
		// Set result.SecretShares to the new key itself if only a single key
		// part is used -- no Shamir split required.
		if rotationConfig.SecretShares == 1 {
			result.SecretShares = append(result.SecretShares, newKey)
		} else {
			// Split the new key using the Shamir algorithm
			shares, err := shamir.Split(newKey, rotationConfig.SecretShares, rotationConfig.SecretThreshold)
			if err != nil {
				sm.logger.Error("failed to generate shares", "error", err)
				return nil, nil, logical.CodedError(http.StatusInternalServerError, "failed to generate shares: %w", err)
			}
			result.SecretShares = shares
		}
	}
	return newKey, result, nil
}

// pgpEncryptShares encrypts the rotation secret shares using the provided pgp keys.
// If the rotation config also specifies backup, the backup information in saved to
// the storage.
func (sm *SealManager) pgpEncryptShares(ctx context.Context, ns *namespace.Namespace, rotationConfig *SealConfig, rotationResult *RekeyResult) (*RekeyResult, error) {
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
			sm.logger.Error("failed to marshal key backup", "error", err)
			return nil, fmt.Errorf("failed to marshal key backup: %w", err)
		}

		path := namespaceLogicalStoragePath(ns) + coreBarrierUnsealKeysBackupPath
		barrier := sm.StorageAccessForPath(path)
		if err = barrier.Put(ctx, path, buf); err != nil {
			sm.logger.Error("failed to save unseal key backup", "error", err)
			return nil, fmt.Errorf("failed to save unseal key backup: %w", err)
		}
	}

	return rotationResult, nil
}

// requireVerification sets the verification properties on the
// rotationConfig adding nonce and required flag, returns the result.
func (sm *SealManager) requireVerification(rotationConfig *SealConfig, rotationResult *RekeyResult, newKey []byte) (*RekeyResult, logical.HTTPCodedError) {
	nonce, err := uuid.GenerateUUID()
	if err != nil {
		rotationConfig = nil
		return nil, logical.CodedError(http.StatusInternalServerError, "failed to generate verification nonce: %w", err)
	}
	rotationConfig.VerificationNonce = nonce
	rotationConfig.VerificationKey = newKey

	rotationResult.VerificationRequired = true
	rotationResult.VerificationNonce = nonce
	return rotationResult, nil
}

// VerifyRotation verifies the progress of the verification of the rotation operation.
func (sm *SealManager) VerifyRotation(ctx context.Context, ns *namespace.Namespace, key []byte, nonce string, recovery bool) (ret *RekeyVerifyResult, retErr logical.HTTPCodedError) {
	sm.lock.Lock()
	defer sm.lock.Unlock()

	rotationConfig := sm.rotationConfig(ns, recovery)

	// Ensure a rotation is in progress
	if rotationConfig == nil {
		return nil, logical.CodedError(http.StatusBadRequest, "no rotation in progress")
	}

	if len(rotationConfig.VerificationKey) == 0 {
		return nil, logical.CodedError(http.StatusBadRequest, "no rotation verification in progress")
	}

	if nonce != rotationConfig.VerificationNonce {
		return nil, logical.CodedError(http.StatusBadRequest, "incorrect nonce supplied; nonce for this verify operation is %q", rotationConfig.VerificationNonce)
	}

	// Check if we already have this piece
	for _, existing := range rotationConfig.VerificationProgress {
		if subtle.ConstantTimeCompare(existing, key) == 1 {
			return nil, logical.CodedError(http.StatusBadRequest, "given key has already been provided during this verify operation")
		}
	}

	// Store this key
	rotationConfig.VerificationProgress = append(rotationConfig.VerificationProgress, key)

	// Check if we don't have enough keys to unlock
	if len(rotationConfig.VerificationProgress) < rotationConfig.SecretThreshold {
		if sm.logger.IsDebug() {
			sm.logger.Debug("cannot verify yet, not enough keys", "keys", len(rotationConfig.VerificationProgress), "threshold", rotationConfig.SecretThreshold)
		}
		return nil, nil
	}

	// Defer reset of progress and rotation of the nonce
	defer func() {
		rotationConfig.VerificationProgress = nil
		if ret != nil && ret.Complete {
			return
		}
		// Not complete, so rotate nonce
		nonce, err := uuid.GenerateUUID()
		if err == nil {
			rotationConfig.VerificationNonce = nonce
			if ret != nil {
				ret.Nonce = nonce
			}
		}
	}()

	// Recover the root key or recovery key
	var recoveredKey []byte
	if rotationConfig.SecretThreshold == 1 {
		recoveredKey = rotationConfig.VerificationProgress[0]
	} else {
		var err error
		recoveredKey, err = shamir.Combine(rotationConfig.VerificationProgress)
		if err != nil {
			return nil, logical.CodedError(http.StatusInternalServerError, "failed to compute key for verification: %w", err)
		}
	}

	if subtle.ConstantTimeCompare(recoveredKey, rotationConfig.VerificationKey) != 1 {
		sm.logger.Error("rotation verification failed")
		return nil, logical.CodedError(http.StatusBadRequest, "rotation verification failed; incorrect key shares supplied")
	}

	seal := sm.namespaceSeal(ns.UUID)
	if seal == nil {
		return nil, logical.CodedError(http.StatusBadRequest, ErrNotSealable.Error())
	}

	if recovery {
		if err := sm.performRecoveryRotation(ctx, ns, recoveredKey, rotationConfig, seal); err != nil {
			return nil, logical.CodedError(http.StatusInternalServerError, "failed to perform recovery key rotation: %w", err)
		}
	} else {
		if err := sm.performRootRotation(ctx, ns, recoveredKey, rotationConfig, seal); err != nil {
			return nil, logical.CodedError(http.StatusInternalServerError, "failed to perform barrier key rotation: %w", err)
		}
	}

	// reset rotation config
	if err := sm.setRotationConfig(ns, recovery, nil); err != nil {
		return nil, logical.CodedError(http.StatusInternalServerError, err.Error())
	}

	return &RekeyVerifyResult{
		Nonce:    rotationConfig.VerificationNonce,
		Complete: true,
	}, nil
}

// RestartRotationVerification is used to restart the rotation verification process.
func (sm *SealManager) RestartRotationVerification(ns *namespace.Namespace, recovery bool) logical.HTTPCodedError {
	sm.lock.Lock()
	defer sm.lock.Unlock()

	// Attempt to generate a new nonce, but don't bail if it doesn't succeed
	// (which is extraordinarily unlikely)
	nonce, nonceErr := uuid.GenerateUUID()
	rotationConfig := sm.rotationConfig(ns, recovery)

	// Clear any progress or config
	if rotationConfig != nil {
		rotationConfig.VerificationProgress = nil
		if nonceErr == nil {
			rotationConfig.VerificationNonce = nonce
		}
	}

	return nil
}

// RetrieveRotationBackup is used to retrieve any backed-up PGP-encrypted
// unseal keys.
func (sm *SealManager) RetrieveRotationBackup(ctx context.Context, ns *namespace.Namespace, recovery bool) (*RekeyBackup, logical.HTTPCodedError) {
	sm.lock.Lock()
	defer sm.lock.Unlock()

	var path string
	if recovery {
		path = namespaceLogicalStoragePath(ns) + coreRecoveryUnsealKeysBackupPath
	} else {
		path = namespaceLogicalStoragePath(ns) + coreBarrierUnsealKeysBackupPath
	}

	barrier := sm.StorageAccessForPath(path)
	entry, err := barrier.Get(ctx, path)
	if err != nil {
		return nil, logical.CodedError(http.StatusInternalServerError, "error getting keys from backup: %w", err)
	}
	if entry == nil {
		return nil, nil
	}

	ret := &RekeyBackup{}
	if err = jsonutil.DecodeJSON(entry, ret); err != nil {
		return nil, logical.CodedError(http.StatusInternalServerError, "error decoding backup keys: %w", err)
	}

	return ret, nil
}

// DeleteRotationBackup is used to delete any backed-up PGP-encrypted unseal keys.
func (sm *SealManager) DeleteRotationBackup(ctx context.Context, ns *namespace.Namespace, recovery bool) logical.HTTPCodedError {
	sm.lock.Lock()
	defer sm.lock.Unlock()

	path := namespaceLogicalStoragePath(ns)
	if recovery {
		path += coreRecoveryUnsealKeysBackupPath
	} else {
		path += coreBarrierUnsealKeysBackupPath
	}

	barrier := sm.namespaceBarrier(ns.Path)
	if err := barrier.Delete(ctx, path); err != nil {
		return logical.CodedError(http.StatusInternalServerError, "error deleting backup keys: %w", err)
	}

	return nil
}
