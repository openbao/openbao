// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"net/http"

	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/openbao/openbao/sdk/v2/helper/shamir"
	"github.com/openbao/openbao/sdk/v2/logical"
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

	return c.sealManager.RotationThreshold(ctx, namespace.RootNamespace, recovery)
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

	return c.sealManager.RotationProgress(namespace.RootNamespace, recovery, verification)
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

	return c.sealManager.RotationConfig(namespace.RootNamespace, recovery), nil
}

// RekeyInit will either initialize the rekey of barrier or recovery key.
// recovery determines whether this is a rekey on the barrier or recovery key.
func (c *Core) RekeyInit(ctx context.Context, config *SealConfig, recovery bool) logical.HTTPCodedError {
	if recovery {
		return c.RecoveryRekeyInit(ctx, config)
	}
	return c.BarrierRekeyInit(ctx, config)
}

// BarrierRekeyInit is used to initialize the rekey settings for the barrier key
func (c *Core) BarrierRekeyInit(ctx context.Context, config *SealConfig) logical.HTTPCodedError {
	c.stateLock.RLock()
	defer c.stateLock.RUnlock()
	if c.Sealed() {
		return logical.CodedError(http.StatusServiceUnavailable, consts.ErrSealed.Error())
	}
	if c.standby {
		return logical.CodedError(http.StatusBadRequest, consts.ErrStandby.Error())
	}

	_, err := c.sealManager.InitRotation(ctx, namespace.RootNamespace, config, false)
	return err
}

// RecoveryRekeyInit is used to initialize the rekey settings for the recovery key
func (c *Core) RecoveryRekeyInit(ctx context.Context, config *SealConfig) logical.HTTPCodedError {
	c.stateLock.RLock()
	defer c.stateLock.RUnlock()
	if c.Sealed() {
		return logical.CodedError(http.StatusServiceUnavailable, consts.ErrSealed.Error())
	}
	if c.standby {
		return logical.CodedError(http.StatusBadRequest, consts.ErrStandby.Error())
	}

	_, err := c.sealManager.InitRotation(ctx, namespace.RootNamespace, config, true)
	return err
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

	return c.sealManager.UpdateRotation(ctx, namespace.RootNamespace, key, nonce, false)
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

	return c.sealManager.UpdateRotation(ctx, namespace.RootNamespace, key, nonce, true)
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

	return c.sealManager.VerifyRotation(ctx, namespace.RootNamespace, key, nonce, recovery)
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

	return c.sealManager.CancelRotation(namespace.RootNamespace, recovery)
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

	return c.sealManager.RestartRotationVerification(namespace.RootNamespace, recovery)
}

// RekeyRetrieveBackup is used to retrieve any backed-up PGP-encrypted
// unseal keys
func (c *Core) RekeyRetrieveBackup(ctx context.Context, recovery bool) (*RekeyBackup, logical.HTTPCodedError) {
	if c.Sealed() {
		return nil, logical.CodedError(http.StatusServiceUnavailable, consts.ErrSealed.Error())
	}
	if c.standby {
		return nil, logical.CodedError(http.StatusBadRequest, consts.ErrStandby.Error())
	}

	return c.sealManager.RetrieveRotationBackup(ctx, namespace.RootNamespace, recovery)
}

// RekeyDeleteBackup is used to delete any backed-up PGP-encrypted
// unseal keys
func (c *Core) RekeyDeleteBackup(ctx context.Context, recovery bool) logical.HTTPCodedError {
	if c.Sealed() {
		return logical.CodedError(http.StatusServiceUnavailable, consts.ErrSealed.Error())
	}
	if c.standby {
		return logical.CodedError(http.StatusBadRequest, consts.ErrStandby.Error())
	}

	return c.sealManager.DeleteRotationBackup(ctx, namespace.RootNamespace, recovery)
}
