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
	"time"

	uuid "github.com/hashicorp/go-uuid"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/helper/pgpkeys"
	"github.com/openbao/openbao/sdk/v2/helper/jsonutil"
	"github.com/openbao/openbao/sdk/v2/helper/shamir"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/vault/barrier"
	vaultseal "github.com/openbao/openbao/vault/seal"
)

// These variables hold the config and shares we have until we reach
// enough to verify the appropriate root key.
type rotationConfig struct {
	rootConfig     *SealConfig
	recoveryConfig *SealConfig
}

// RotationConfig acquires a read lock and reads the rotation config of
// a given namespace.
func (sm *SealManager) RotationConfig(nsUUID string, recovery bool) *SealConfig {
	sm.lock.RLock()
	defer sm.lock.RUnlock()
	return sm.rotationConfig(nsUUID, recovery)
}

// RotationConfig returns the rotation config of the namespace
// with the given UUID.
func (sm *SealManager) rotationConfig(nsUUID string, recovery bool) *SealConfig {
	rotationConfig, ok := sm.rotationConfigByNamespace[nsUUID]
	if !ok {
		return nil
	}

	// Return requested seal config.
	if recovery {
		return rotationConfig.recoveryConfig
	}
	return rotationConfig.rootConfig
}

// setRotationConfig sets the root or recovery rotation config for a given namespace.
func (sm *SealManager) setRotationConfig(nsUUID string, recovery bool, newConfig *SealConfig) error {
	config, ok := sm.rotationConfigByNamespace[nsUUID]
	if !ok {
		config = &rotationConfig{}
		sm.rotationConfigByNamespace[nsUUID] = config
	}

	if recovery {
		config.recoveryConfig = newConfig
	} else {
		config.rootConfig = newConfig
	}

	return nil
}

// RotateBarrierRootKey rotates the barrier root key, doesn't require reconstruction
// of the unseal key to perform rotation, rotates root key independent from recovery
// key shares or Shamir (KEK).
func (sm *SealManager) RotateBarrierRootKey(ctx context.Context, ns *namespace.Namespace) error {
	sm.lock.Lock()
	defer sm.lock.Unlock()

	b := sm.namespaceBarrier(ns.Path)
	if b == nil {
		return ErrNotSealable
	}

	newRootKey, err := b.GenerateKey()
	if err != nil {
		return fmt.Errorf("failed to generate new root key: %v", err)
	}

	seal := sm.sealByNamespace[ns.UUID]
	if seal == nil {
		return ErrNotSealable
	}

	if err := seal.SetStoredKeys(ctx, [][]byte{newRootKey}); err != nil {
		return fmt.Errorf("failed to store keys: %v", err)
	}

	return b.RotateRootKey(ctx, newRootKey)
}

// RotateBarrierKey rotates the barrier key.
// Returns an error if the given namespace is not a sealable namespace.
func (sm *SealManager) RotateBarrierKey(ctx context.Context, ns *namespace.Namespace) error {
	sm.lock.RLock()
	defer sm.lock.RUnlock()

	b := sm.namespaceBarrier(ns.Path)
	if b == nil {
		return ErrNotSealable
	}

	newTerm, err := b.Rotate(ctx)
	if err != nil {
		return fmt.Errorf("failed to create new encryption key: %w", err)
	}
	sm.logger.Info("installed new encryption key")

	// In HA mode, we need to an upgrade path for the standby instances
	// we are using the same key rotate grace period for all namespaces for now.
	if sm.core.ha != nil && sm.core.KeyRotateGracePeriod() > 0 {
		// Create the upgrade path to the new term
		if err := b.CreateUpgrade(ctx, newTerm); err != nil {
			sm.logger.Error("failed to create new upgrade", "term", newTerm, "error", err, "namespace", ns.Path)
		}

		// Schedule the destroy of the upgrade path
		time.AfterFunc(sm.core.KeyRotateGracePeriod(), func() {
			sm.logger.Debug("cleaning up upgrade keys", "waited", sm.core.KeyRotateGracePeriod())
			if err := b.DestroyUpgrade(sm.core.activeContext.Load(), newTerm); err != nil {
				sm.logger.Error("failed to destroy upgrade", "term", newTerm, "error", err, "namespace", ns.Path)
			}
		})
	}

	return nil
}

// InitRotation will either initialize the rotation of barrier or recovery key
// depending on the value of recovery parameter.
func (sm *SealManager) InitRotation(ctx context.Context, ns *namespace.Namespace, newConfig *SealConfig, recovery bool) (*RekeyResult, error) {
	sm.lock.Lock()
	defer sm.lock.Unlock()

	seal, err := sm.validateRotationConfig(ns, newConfig, recovery)
	if err != nil {
		return nil, err
	}

	// Initialize the nonce for rotation operation
	nonce, err := uuid.GenerateUUID()
	if err != nil {
		return nil, logical.CodedError(http.StatusInternalServerError, "error generating nonce for procedure: %w", err)
	}

	// Copy the configuration
	config := newConfig.Clone()
	config.Nonce = nonce
	if err := sm.setRotationConfig(ns.UUID, recovery, config); err != nil {
		return nil, logical.CodedError(http.StatusInternalServerError, "failed to update rotate config: %w", err)
	}

	sm.logger.Info("rotation initialized", "namespace", ns.Path, "nonce", config.Nonce, "shares", config.SecretShares, "threshold", config.SecretThreshold, "validation_required", config.VerificationRequired)

	if recovery {
		// if no key shares exist, meaning we've initialized the instance
		// without creating them at time, then return the keys immediately
		return sm.rotateRecoveryNoKeyShares(ctx, ns, seal, config)
	}

	//nolint:nilnil // we do not return any keys, nor we fail at something.
	return nil, nil
}

// CancelRotation is used to cancel an in-progress rotation operation.
func (sm *SealManager) CancelRotation(ctx context.Context, nsUUID string, recovery bool) error {
	sm.lock.Lock()
	defer sm.lock.Unlock()

	return sm.setRotationConfig(nsUUID, recovery, nil)
}

// UpdateRotation is used to provide a new key share for the rotation
// of barrier or recovery key.
func (sm *SealManager) UpdateRotation(ctx context.Context, ns *namespace.Namespace, key []byte, nonce string, recovery bool) (*RekeyResult, error) {
	sm.lock.Lock()
	defer sm.lock.Unlock()

	seal := sm.sealByNamespace[ns.UUID]
	if seal == nil {
		return nil, ErrNotSealable
	}

	var config *SealConfig
	var err error
	// We are rotating recovery keys or rotating root key while running auto seal.
	if recovery || seal.RecoveryKeySupported() {
		config, err = seal.RecoveryConfig(ctx)
	} else {
		config, err = seal.BarrierConfig(ctx)
	}

	if err != nil {
		return nil, logical.CodedError(http.StatusInternalServerError, "failed to fetch existing config: %w", err)
	}

	if config == nil {
		return nil, ErrNotInit
	}

	rotationConfig := sm.rotationConfig(ns.UUID, recovery)
	if rotationConfig == nil {
		return nil, errors.New("no rotation in progress")
	}

	recoveryKey, err := sm.progressRotation(rotationConfig, config, key, nonce)
	if err != nil {
		return nil, err
	}

	if recoveryKey == nil {
		return nil, nil
	}

	if recovery || seal.RecoveryKeySupported() {
		if err := seal.VerifyRecoveryKey(ctx, recoveryKey); err != nil {
			sm.logger.Error("recovery key verification failed", "error", err)
			return nil, fmt.Errorf("recovery key verification failed: %w", err)
		}
	}

	if recovery {
		return sm.updateRecoveryRotation(ctx, ns, seal, rotationConfig)
	}

	return sm.updateRootRotation(ctx, ns, seal, rotationConfig, recoveryKey)
}

// progressRotation checks the key rotation progress, verifying if we have
// enough shares to recover the key.
func (sm *SealManager) progressRotation(rotationConfig, existingConfig *SealConfig, key []byte, nonce string) ([]byte, error) {
	if len(rotationConfig.VerificationKey) > 0 {
		return nil, fmt.Errorf("rotation already finished; verification must be performed; nonce for the verification operation is %q", rotationConfig.VerificationNonce)
	}

	if nonce != rotationConfig.Nonce {
		return nil, fmt.Errorf("incorrect nonce supplied; nonce for rotation is %q", rotationConfig.Nonce)
	}

	// Check if we already have this piece
	found := false
	for _, existing := range rotationConfig.RotationProgress {
		found = found || subtle.ConstantTimeCompare(existing, key) == 1
		if found {
			return nil, errors.New("given key has already been provided during this rotation")
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

// updateRecoveryRotation updates the recovery key rotation with provided new key share.
func (sm *SealManager) updateRecoveryRotation(ctx context.Context, ns *namespace.Namespace, seal Seal, rotationConfig *SealConfig) (*RekeyResult, error) {
	newRecoveryKey, result, err := sm.generateKey(ns.Path, rotationConfig)
	if err != nil {
		return nil, err
	}

	// If PGP keys are passed in, encrypt shares with corresponding PGP keys.
	if len(rotationConfig.PGPKeys) > 0 {
		var err error
		result, err = sm.pgpEncryptShares(ctx, ns, rotationConfig, result, true)
		if err != nil {
			return nil, logical.CodedError(http.StatusInternalServerError, err.Error())
		}
	}

	// If we are requiring validation, return now; otherwise save the recovery key
	if rotationConfig.VerificationRequired {
		return sm.requireVerification(rotationConfig, result, newRecoveryKey)
	}

	if err := sm.performRecoveryRotation(ctx, newRecoveryKey, rotationConfig, seal); err != nil {
		return nil, err
	}

	// reset rotation config
	if err := sm.setRotationConfig(ns.UUID, true, nil); err != nil {
		return nil, logical.CodedError(http.StatusInternalServerError, err.Error())
	}

	return result, nil
}

// updateRootRotation updates the root key rotation with provided new key share.
func (sm *SealManager) updateRootRotation(ctx context.Context, ns *namespace.Namespace, seal Seal, rotationConfig *SealConfig, recoveryKey []byte) (*RekeyResult, error) {
	var newSealKey []byte
	result := &RekeyResult{}

	if seal.BarrierType() == vaultseal.WrapperTypeShamir {
		shamirWrapper := vaultseal.NewShamirWrapper()
		if err := shamirWrapper.SetAesGcmKeyBytes(recoveryKey); err != nil {
			return nil, logical.CodedError(http.StatusInternalServerError, "failed to setup unseal key: %w", err)
		}

		testseal := NewDefaultSeal(vaultseal.NewAccess(shamirWrapper))
		testseal.SetCore(sm.core)

		if ns.ID != namespace.RootNamespaceID {
			testseal.SetMetaPrefix(NamespaceStoragePathPrefix(ns))
		}

		cfg, err := seal.BarrierConfig(ctx)
		if err != nil {
			return nil, logical.CodedError(http.StatusInternalServerError, "failed to setup test barrier config: %w", err)
		}
		testseal.SetCachedBarrierConfig(cfg)

		stored, err := testseal.GetStoredKeys(ctx)
		if err != nil {
			return nil, logical.CodedError(http.StatusInternalServerError, "failed to read root key: %w", err)
		}
		recoveryKey = stored[0]

		barrier := sm.namespaceBarrier(ns.Path)
		if barrier == nil {
			return nil, ErrNotSealable
		}

		if err := barrier.VerifyRoot(recoveryKey); err != nil {
			sm.logger.Error("root key verification failed", "error", err)
			return nil, fmt.Errorf("root key verification failed: %w", err)
		}

		// Generate new unseal keys if running shamir seal.
		newSealKey, result, err = sm.generateKey(ns.Path, rotationConfig)
		if err != nil {
			return nil, err
		}
	}

	// If PGP keys are passed in, encrypt shares with corresponding PGP keys.
	if len(rotationConfig.PGPKeys) > 0 {
		var encryptError error
		result, encryptError = sm.pgpEncryptShares(ctx, ns, rotationConfig, result, false)
		if encryptError != nil {
			return nil, logical.CodedError(http.StatusInternalServerError, encryptError.Error())
		}
	}

	// If we are requiring validation, return now; otherwise rotate barrier key
	if rotationConfig.VerificationRequired {
		return sm.requireVerification(rotationConfig, result, newSealKey)
	}

	if err := sm.performRootRotation(ctx, ns, newSealKey, rotationConfig, seal); err != nil {
		return nil, err
	}

	// reset rotation config
	if err := sm.setRotationConfig(ns.UUID, false, nil); err != nil {
		return nil, logical.CodedError(http.StatusInternalServerError, err.Error())
	}

	return result, nil
}

func (sm *SealManager) performRootRotation(ctx context.Context, ns *namespace.Namespace, newSealKey []byte, rotationConfig *SealConfig, seal Seal) error {
	isShamirSeal := seal.BarrierType() == vaultseal.WrapperTypeShamir
	if isShamirSeal {
		shamirWrapper, err := seal.GetShamirWrapper()
		if err == nil {
			err = shamirWrapper.SetAesGcmKeyBytes(newSealKey)
		}
		if err != nil {
			return logical.CodedError(http.StatusInternalServerError, "failed to update barrier seal key: %w", err)
		}
	}

	b := sm.namespaceBarrier(ns.Path)
	if b == nil {
		return ErrNotSealable
	}

	newRootKey, err := b.GenerateKey()
	if err != nil {
		return logical.CodedError(http.StatusInternalServerError, "failed to perform rotation: %w", err)
	}

	if err := seal.SetStoredKeys(ctx, [][]byte{newRootKey}); err != nil {
		sm.logger.Error("failed to store keys", "error", err)
		return logical.CodedError(http.StatusInternalServerError, "failed to store keys: %w", err)
	}

	// Rotate the barrier
	if err := b.RotateRootKey(ctx, newRootKey); err != nil {
		sm.logger.Error("failed to rotate root key", "error", err)
		return logical.CodedError(http.StatusInternalServerError, "failed to rotate root key: %w", err)
	}

	sm.logger.Info("root key rotated", "namespace", ns.Path, "shares", rotationConfig.SecretShares, "threshold", rotationConfig.SecretThreshold)

	if isShamirSeal {
		if len(newSealKey) > 0 {
			err := b.Put(ctx, &logical.StorageEntry{
				Key:   barrier.ShamirKekPath,
				Value: newSealKey,
			})
			if err != nil {
				sm.logger.Error("failed to store new seal key", "error", err)
				return logical.CodedError(http.StatusInternalServerError, "failed to store new seal key: %w", err)
			}
		}

		rotationConfig.VerificationKey = nil

		if err := seal.SetBarrierConfig(ctx, rotationConfig); err != nil {
			sm.logger.Error("error saving rotate seal configuration", "error", err)
			return logical.CodedError(http.StatusInternalServerError, "failed to save rotate seal configuration: %w", err)
		}
	}

	rotationConfig.RotationProgress = nil
	return nil
}

func (sm *SealManager) performRecoveryRotation(ctx context.Context, newRootKey []byte, rotationConfig *SealConfig, seal Seal) error {
	if err := seal.SetRecoveryKey(ctx, newRootKey); err != nil {
		sm.logger.Error("failed to set recovery key", "error", err)
		return logical.CodedError(http.StatusInternalServerError, "failed to set recovery key: %w", err)
	}

	rotationConfig.VerificationKey = nil

	if err := seal.SetRecoveryConfig(ctx, rotationConfig); err != nil {
		sm.logger.Error("error saving rotate seal configuration", "error", err)
		return logical.CodedError(http.StatusInternalServerError, "failed to save rotate seal configuration: %w", err)
	}

	rotationConfig.RotationProgress = nil
	return nil
}

// validateRotationConfig validates properties of recovery or barrier rotation config.
func (sm *SealManager) validateRotationConfig(ns *namespace.Namespace, newConfig *SealConfig, recovery bool) (Seal, error) {
	currRotConfig := sm.rotationConfig(ns.UUID, recovery)
	if currRotConfig != nil {
		return nil, errors.New("rotation already in progress")
	}

	seal := sm.sealByNamespace[ns.UUID]
	if seal == nil {
		return nil, ErrNotSealable
	}

	if recovery {
		if !seal.RecoveryKeySupported() {
			return nil, errors.New("recovery keys not supported")
		}

		// Check if the seal configuration is valid
		// intentionally invoke the `Validate()` instead of `ValidateRecovery()`
		// deny the request if it does not pass the validation check
		if err := newConfig.Validate(); err != nil {
			sm.logger.Error("invalid recovery configuration", "error", err)
			return nil, logical.CodedError(http.StatusInternalServerError, "invalid recovery configuration: %w", err)
		}
	} else {
		if seal.BarrierType() != wrapping.WrapperTypeShamir {
			newConfig.SecretShares = 1
			newConfig.SecretThreshold = 1

			if len(newConfig.PGPKeys) > 0 {
				return nil, errors.New("PGP key encryption not supported when using stored keys")
			}
			if newConfig.Backup {
				return nil, errors.New("key backup not supported when using stored keys")
			}
		}

		if seal.RecoveryKeySupported() {
			if newConfig.VerificationRequired {
				return nil, errors.New("requiring verification not supported when rotating the barrier key with recovery keys")
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

// rotateRecoveryNoKeyShares verifies that recovery config exists and if its
// `SecretShares` property value is set as 0, immediately returns back
// new rotated recovery key shares.
func (sm *SealManager) rotateRecoveryNoKeyShares(ctx context.Context, ns *namespace.Namespace, seal Seal, rotConfig *SealConfig) (*RekeyResult, error) {
	existingRecoveryConfig, err := seal.RecoveryConfig(ctx)
	if err != nil {
		return nil, logical.CodedError(http.StatusInternalServerError, "failed to fetch existing recovery config: %w", err)
	}

	if existingRecoveryConfig == nil {
		return nil, ErrNotInit
	}

	if existingRecoveryConfig.SecretShares == 0 {
		newRecoveryKey, result, err := sm.generateKey(ns.Path, rotConfig)
		if err != nil {
			return nil, err
		}

		// If PGP keys are passed in, encrypt shares with corresponding PGP keys.
		if len(rotConfig.PGPKeys) > 0 {
			result, err = sm.pgpEncryptShares(ctx, ns, rotConfig, result, true)
			if err != nil {
				return nil, logical.CodedError(http.StatusInternalServerError, err.Error())
			}
		}

		// If we are requiring validation, return now
		// otherwise save the recovery key
		if rotConfig.VerificationRequired {
			return sm.requireVerification(rotConfig, result, newRecoveryKey)
		}

		if err := sm.performRecoveryRotation(ctx, newRecoveryKey, rotConfig, seal); err != nil {
			return nil, logical.CodedError(http.StatusInternalServerError, fmt.Errorf("failed to perform recovery rotation: %w", err).Error())
		}

		// reset rotation config
		if err := sm.setRotationConfig(ns.UUID, true, nil); err != nil {
			return nil, logical.CodedError(http.StatusInternalServerError, err.Error())
		}

		return result, nil
	}

	//nolint:nilnil // we do not return any keys, nor we fail at something.
	return nil, nil
}

// generateKey generates a new root/recovery key dividing it into desired number
// of key shares.
func (sm *SealManager) generateKey(nsPath string, rotationConfig *SealConfig) ([]byte, *RekeyResult, error) {
	barrier := sm.namespaceBarrier(nsPath)
	if barrier == nil {
		return nil, nil, ErrNotSealable
	}

	// Generate a new root/recovery key
	newKey, err := barrier.GenerateKey()
	if err != nil {
		sm.logger.Error("failed to generate key", "error", err)
		return nil, nil, logical.CodedError(http.StatusInternalServerError, "key generation failed: %w", err)
	}

	result := &RekeyResult{
		Backup: rotationConfig.Backup,
	}

	// Set result.SecretShares to the new key itself if only a single key
	// part is used -- no Shamir split required.
	if rotationConfig.SecretShares == 1 {
		result.SecretShares = append(result.SecretShares, newKey)
	} else {
		// Split the new key using the Shamir algorithm
		shares, err := shamir.Split(newKey, rotationConfig.SecretShares, rotationConfig.SecretThreshold)
		if err != nil {
			sm.logger.Error("failed to split shamir shares", "error", err)
			return nil, nil, logical.CodedError(http.StatusInternalServerError, "failed to split shamir shares: %v", err)
		}
		result.SecretShares = shares
	}

	return newKey, result, nil
}

// pgpEncryptShares encrypts the rotation secret shares using the provided pgp keys.
// If the rotation config also specifies backup, the backup information is saved to
// the storage.
func (sm *SealManager) pgpEncryptShares(ctx context.Context, ns *namespace.Namespace, rotationConfig *SealConfig, rotationResult *RekeyResult, recovery bool) (*RekeyResult, error) {
	hexEncodedShares := make([][]byte, len(rotationResult.SecretShares))
	for i := range rotationResult.SecretShares {
		hexEncodedShares[i] = []byte(hex.EncodeToString(rotationResult.SecretShares[i]))
	}

	var err error
	rotationResult.PGPFingerprints, rotationResult.SecretShares, err = pgpkeys.EncryptShares(hexEncodedShares, rotationConfig.PGPKeys)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt shares: %w", err)
	}

	// If backup is enabled, store backup info in
	// coreBarrierUnsealKeysBackupPath or coreRecoveryUnsealKeysBackupPath
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

		entry := &logical.StorageEntry{
			Key:   coreBarrierUnsealKeysBackupPath,
			Value: buf,
		}

		if recovery {
			entry.Key = coreRecoveryUnsealKeysBackupPath
		}

		barrier := sm.namespaceBarrier(ns.Path)
		if err = barrier.Put(ctx, entry); err != nil {
			sm.logger.Error("failed to save unseal key backup", "error", err)
			return nil, fmt.Errorf("failed to save unseal key backup: %w", err)
		}
	}

	return rotationResult, nil
}

// requireVerification sets the verification properties on the
// rotationConfig adding nonce and required flag, returns the result.
func (sm *SealManager) requireVerification(rotationConfig *SealConfig, rotationResult *RekeyResult, newKey []byte) (*RekeyResult, error) {
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
func (sm *SealManager) VerifyRotation(ctx context.Context, ns *namespace.Namespace, key []byte, nonce string, recovery bool) (ret *RekeyVerifyResult, err error) {
	sm.lock.Lock()
	defer sm.lock.Unlock()

	rotationConfig := sm.rotationConfig(ns.UUID, recovery)

	// Ensure a rotation is in progress
	if rotationConfig == nil {
		return nil, errors.New("no rotation in progress")
	}

	if len(rotationConfig.VerificationKey) == 0 {
		return nil, errors.New("no rotation verification in progress")
	}

	if nonce != rotationConfig.VerificationNonce {
		return nil, fmt.Errorf("incorrect nonce supplied; nonce for this verify operation is %q", rotationConfig.VerificationNonce)
	}

	// Check if we already have this piece
	found := false
	for _, existing := range rotationConfig.RotationProgress {
		found = found || subtle.ConstantTimeCompare(existing, key) == 1
		if found {
			return nil, errors.New("given key has already been provided during this verify operation")
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
		return nil, errors.New("rotation verification failed; incorrect key shares supplied")
	}

	seal := sm.sealByNamespace[ns.UUID]
	if seal == nil {
		return nil, ErrNotSealable
	}

	if recovery {
		if err := sm.performRecoveryRotation(ctx, recoveredKey, rotationConfig, seal); err != nil {
			return nil, logical.CodedError(http.StatusInternalServerError, "failed to perform recovery key rotation: %w", err)
		}
	} else {
		if err := sm.performRootRotation(ctx, ns, recoveredKey, rotationConfig, seal); err != nil {
			return nil, logical.CodedError(http.StatusInternalServerError, "failed to perform barrier key rotation: %w", err)
		}
	}

	// reset rotation config
	if err := sm.setRotationConfig(ns.UUID, recovery, nil); err != nil {
		return nil, logical.CodedError(http.StatusInternalServerError, err.Error())
	}

	return &RekeyVerifyResult{
		Nonce:    rotationConfig.VerificationNonce,
		Complete: true,
	}, nil
}

// RestartRotationVerification is used to restart the rotation verification process.
func (sm *SealManager) RestartRotationVerification(nsUUID string, recovery bool) error {
	sm.lock.Lock()
	defer sm.lock.Unlock()

	// Attempt to generate a new nonce, but don't bail if it doesn't succeed
	// (which is extremely unlikely).
	nonce, nonceErr := uuid.GenerateUUID()
	rotationConfig := sm.rotationConfig(nsUUID, recovery)

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
func (sm *SealManager) RetrieveRotationBackup(ctx context.Context, nsPath string, recovery bool) (*RekeyBackup, error) {
	sm.lock.Lock()
	defer sm.lock.Unlock()

	path := coreBarrierUnsealKeysBackupPath
	if recovery {
		path = coreRecoveryUnsealKeysBackupPath
	}

	barrier := sm.namespaceBarrier(nsPath)
	entry, err := barrier.Get(ctx, path)
	if err != nil {
		return nil, logical.CodedError(http.StatusInternalServerError, "error getting keys from backup: %w", err)
	}
	if entry == nil {
		return nil, nil
	}

	ret := &RekeyBackup{}
	if err = jsonutil.DecodeJSON(entry.Value, ret); err != nil {
		return nil, logical.CodedError(http.StatusInternalServerError, "error decoding backup keys: %w", err)
	}

	return ret, nil
}

// DeleteRotationBackup is used to delete any backed-up PGP-encrypted unseal keys.
func (sm *SealManager) DeleteRotationBackup(ctx context.Context, nsPath string, recovery bool) error {
	sm.lock.Lock()
	defer sm.lock.Unlock()

	path := coreBarrierUnsealKeysBackupPath
	if recovery {
		path = coreRecoveryUnsealKeysBackupPath
	}

	barrier := sm.namespaceBarrier(nsPath)
	if err := barrier.Delete(ctx, path); err != nil {
		return logical.CodedError(http.StatusInternalServerError, "error deleting backup keys: %w", err)
	}

	return nil
}
