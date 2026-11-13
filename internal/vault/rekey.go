// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"net/http"

	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/v2/internal/helper/namespace"
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

func (c *Core) rekeyStateLock() (func(), logical.HTTPCodedError) {
	c.stateLock.RLock()
	if c.Sealed() {
		c.stateLock.RUnlock()
		return nil, logical.CodedError(http.StatusServiceUnavailable, consts.ErrSealed.Error())
	}
	if c.standby.Load() {
		c.stateLock.RUnlock()
		return nil, logical.CodedError(http.StatusBadRequest, consts.ErrStandby.Error())
	}

	return c.stateLock.RUnlock, nil
}

// RekeyThreshold returns the secret threshold for the current seal
// config. This threshold can either be the barrier key threshold or
// the recovery key threshold, depending on whether rekey is being
// performed on the recovery key, or whether the seal supports
// recovery keys.
func (c *Core) RekeyThreshold(ctx context.Context, recovery bool) (int, logical.HTTPCodedError) {
	unlock, httpErr := c.rekeyStateLock()
	if httpErr != nil {
		return 0, httpErr
	}
	defer unlock()

	seal := c.sealManager.NamespaceSeal(namespace.RootNamespaceUUID)
	if seal == nil {
		return 0, logical.CodedError(http.StatusBadRequest, ErrNotInit.Error())
	}

	var config *SealConfig
	var err error
	// If we are rekeying the recovery key, or if the seal supports
	// recovery keys and we are rekeying the barrier key, we use the
	// recovery config as the threshold instead.
	if recovery || seal.RecoveryKeySupported() {
		config, err = seal.RecoveryConfig(ctx)
	} else {
		config, err = seal.BarrierConfig(ctx)
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
func (c *Core) RekeyProgress(recovery, verification bool) (int, logical.HTTPCodedError) {
	conf, err := c.RekeyConfig(recovery)
	if err != nil {
		return 0, err
	}
	if conf == nil {
		return 0, logical.CodedError(http.StatusBadRequest, "rekey operation not in progress")
	}

	return c.sealManager.RotationProgress(namespace.RootNamespaceUUID, recovery, verification), nil
}

// RekeyConfig is used to read the rekey configuration.
func (c *Core) RekeyConfig(recovery bool) (*SealConfig, logical.HTTPCodedError) {
	unlock, httpErr := c.rekeyStateLock()
	if httpErr != nil {
		return nil, httpErr
	}
	defer unlock()

	return c.sealManager.RotationConfig(namespace.RootNamespaceUUID, recovery), nil
}

// RekeyInit will either initialize the rekey of barrier or recovery key.
// recovery determines whether this is a rekey on the barrier or recovery key.
func (c *Core) RekeyInit(ctx context.Context, config *SealConfig, recovery bool) logical.HTTPCodedError {
	unlock, httpErr := c.rekeyStateLock()
	if httpErr != nil {
		return httpErr
	}
	defer unlock()

	_, err := c.sealManager.InitRotation(ctx, namespace.RootNamespace, config, recovery, false)
	return err
}

// RekeyUpdate is used to provide a new key part for the barrier or recovery key.
// Barrier rekey can be done with barrier keys, or recovery keys if that's supported
// and we are storing the barrier key.
func (c *Core) RekeyUpdate(ctx context.Context, key []byte, nonce string, recovery bool) (*RekeyResult, logical.HTTPCodedError) {
	unlock, httpErr := c.rekeyStateLock()
	if httpErr != nil {
		return nil, httpErr
	}
	defer unlock()

	return c.sealManager.UpdateRotation(ctx, namespace.RootNamespace, key, nonce, recovery)
}

func (c *Core) RekeyVerify(ctx context.Context, key []byte, nonce string, recovery bool) (ret *RekeyVerifyResult, retErr logical.HTTPCodedError) {
	unlock, httpErr := c.rekeyStateLock()
	if httpErr != nil {
		return nil, httpErr
	}
	defer unlock()

	return c.sealManager.VerifyRotation(ctx, namespace.RootNamespace, key, nonce, recovery)
}

// RekeyCancel is used to cancel an in-progress rekey.
func (c *Core) RekeyCancel(recovery bool) logical.HTTPCodedError {
	unlock, httpErr := c.rekeyStateLock()
	if httpErr != nil {
		return httpErr
	}
	defer unlock()

	c.sealManager.CancelRotation(namespace.RootNamespaceUUID, recovery)
	return nil
}

// RekeyVerifyRestart is used to start the verification process over.
func (c *Core) RekeyVerifyRestart(recovery bool) logical.HTTPCodedError {
	unlock, httpErr := c.rekeyStateLock()
	if httpErr != nil {
		return httpErr
	}
	defer unlock()

	c.sealManager.RestartRotationVerification(namespace.RootNamespaceUUID, recovery)
	return nil
}

// RekeyRetrieveBackup is used to retrieve any backed-up PGP-encrypted unseal keys.
func (c *Core) RekeyRetrieveBackup(ctx context.Context, recovery bool) (*RekeyBackup, logical.HTTPCodedError) {
	if c.Sealed() {
		return nil, logical.CodedError(http.StatusServiceUnavailable, consts.ErrSealed.Error())
	}
	if c.standby.Load() {
		return nil, logical.CodedError(http.StatusBadRequest, consts.ErrStandby.Error())
	}

	return c.sealManager.RetrieveRotationBackup(ctx, namespace.RootNamespace, recovery)
}

// RekeyDeleteBackup is used to delete any backed-up PGP-encrypted unseal keys.
func (c *Core) RekeyDeleteBackup(ctx context.Context, recovery bool) logical.HTTPCodedError {
	if c.Sealed() {
		return logical.CodedError(http.StatusServiceUnavailable, consts.ErrSealed.Error())
	}
	if c.standby.Load() {
		return logical.CodedError(http.StatusBadRequest, consts.ErrStandby.Error())
	}

	return c.sealManager.DeleteRotationBackup(ctx, namespace.RootNamespace.Path, recovery)
}
