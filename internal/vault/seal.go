// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"

	"google.golang.org/protobuf/proto"

	"github.com/openbao/openbao/sdk/v2/helper/jsonutil"
	"github.com/openbao/openbao/sdk/v2/physical"

	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"github.com/openbao/openbao/v2/internal/vault/barrier"
	"github.com/openbao/openbao/v2/internal/vault/seal"
)

const (
	// sealConfigPath is a path to the entry storing primary or recovery Shamir
	// share configuration with provider identity. In legacy cases a location of
	// primary configuration or dummy auto-unseal provider metadata.
	// For the root namespace, this record is readable while sealed.
	sealConfigPath = "core/seal-config"

	// legacyRecoverySealConfigPath is a path to the legacy recovery-share
	// configuration, retained for backward-compatible reads and cleanup.
	legacyRecoverySealConfigPath = "core/recovery-config"

	// recoveryKeyPath is the path to recovery-key material.
	recoveryKeyPath = "core/recovery-key"

	// StoredBarrierKeysPath stores barrier root keys wrapped by the
	// configured seal, including Shamir and auto-unseal mechanisms.
	StoredBarrierKeysPath = "core/hsm/barrier-unseal-keys"
)

type Seal interface {
	SetCore(*Core)
	Init(context.Context) error
	SetMetaPrefix(string)
	Finalize(context.Context) error
	SetStoredKeys(context.Context, [][]byte) error
	GetStoredKeys(context.Context) ([][]byte, error)
	WrapperType() wrapping.WrapperType           // SealAccess
	Config(context.Context) (*SealConfig, error) // SealAccess
	SetConfig(context.Context, *SealConfig) error
	SetCachedConfig(*SealConfig)
	SetConfigAccess(barrier.SecurityBarrier)
	RecoveryKeySupported() bool // SealAccess
	RecoveryKey(context.Context) ([]byte, error)
	SetRecoveryKey(context.Context, []byte) error
	VerifyRecoveryKey(context.Context, []byte) error // SealAccess
	GetAccess() seal.Access                          // SealAccess
	GetShamirWrapper() (*seal.ShamirWrapper, error)
}

type defaultSeal struct {
	access seal.Access

	core       *Core
	metaPrefix string

	config       atomic.Pointer[SealConfig]
	configAccess StorageAccess
}

var _ Seal = (*defaultSeal)(nil)

func NewDefaultSeal(lowLevel seal.Access) Seal {
	return &defaultSeal{access: lowLevel}
}

func (d *defaultSeal) checkCore() error {
	if d.core == nil {
		return errors.New("seal does not have a core set")
	}
	return nil
}

func (d *defaultSeal) GetAccess() seal.Access {
	return d.access
}

func (d *defaultSeal) SetAccess(access seal.Access) {
	d.access = access
}

func (d *defaultSeal) SetCore(core *Core) {
	d.core = core
	// By default, we assume that seal config information is stored in
	// plain text right on the physical storage, as is the case for the
	// root namespace. For per-namespace seals, this can be overridden by
	// [Seal.SetConfigAccess].
	d.configAccess = &directStorageAccess{physical: core.physical}
}

func (d *defaultSeal) Init(ctx context.Context) error {
	return nil
}

func (d *defaultSeal) SetMetaPrefix(metaPrefix string) {
	d.metaPrefix = metaPrefix
}

func (d *defaultSeal) Finalize(ctx context.Context) error {
	return nil
}

func (d *defaultSeal) WrapperType() wrapping.WrapperType {
	return seal.WrapperTypeShamir
}

func (d *defaultSeal) RecoveryKeySupported() bool {
	return false
}

func (d *defaultSeal) SetStoredKeys(ctx context.Context, keys [][]byte) error {
	return writeStoredKeys(ctx, d.core.physical, d.metaPrefix, d.access, keys)
}

func (d *defaultSeal) GetStoredKeys(ctx context.Context) ([][]byte, error) {
	return readStoredKeys(ctx, d.core.physical, d.metaPrefix, d.access)
}

func (d *defaultSeal) Config(ctx context.Context) (*SealConfig, error) {
	cfg := d.config.Load()
	if cfg != nil {
		return cfg.Clone(), nil
	}

	if err := d.checkCore(); err != nil {
		return nil, err
	}

	// Fetch the seal configuration
	valueBytes, err := d.configAccess.Get(ctx, d.metaPrefix+sealConfigPath)
	if err != nil {
		d.core.logger.Error("failed to read seal configuration", "error", err)
		return nil, fmt.Errorf("failed to check seal configuration: %w", err)
	}

	// If the seal configuration is missing, we are not initialized
	if valueBytes == nil {
		d.core.logger.Info("seal configuration missing, not initialized")
		return nil, nil
	}

	var conf SealConfig

	// Decode the barrier entry
	if err := jsonutil.DecodeJSON(valueBytes, &conf); err != nil {
		d.core.logger.Error("failed to decode seal configuration", "error", err)
		return nil, fmt.Errorf("failed to decode seal configuration: %w", err)
	}

	switch conf.Type {
	// This case should not be valid for other types as only this is the default
	case "":
		conf.Type = d.WrapperType().String()
	case d.WrapperType().String():
	default:
		d.core.logger.Error("barrier wrapper type does not match expected wrapper type", "barrier_wrapper_type", conf.Type, "loaded_wrapper_type", d.WrapperType().String())
		return nil, fmt.Errorf("barrier wrapper type of %q does not match expected wrapper type of %q", conf.Type, d.WrapperType())
	}

	if conf.Purpose != "" && conf.Purpose != Primary {
		d.core.logger.Error("seal purpose does not match loaded purpose", "seal_type", conf.Type, "loaded_type", conf.Purpose)
		return nil, fmt.Errorf("seal purpose of %q does not match loaded purpose of %q", conf.Type, conf.Purpose)
	}

	conf.Purpose = Primary
	if err := conf.Validate(); err != nil {
		d.core.logger.Error("invalid seal configuration", "error", err)
		return nil, fmt.Errorf("seal validation failed: %w", err)
	}

	d.SetCachedConfig(&conf)
	return conf.Clone(), nil
}

func (d *defaultSeal) SetConfig(ctx context.Context, config *SealConfig) error {
	if err := d.checkCore(); err != nil {
		return err
	}

	// Provide a way to wipe out the cached value (also prevents actually
	// saving a nil config)
	if config == nil {
		d.config.Store(nil)
		return nil
	}

	clone := config.Clone()
	clone.Type = seal.WrapperTypeShamir.String()
	clone.Purpose = Primary

	// If we are doing a raft unseal we do not want to persist the barrier config
	// because storage isn't setup yet.
	if d.core.isRaftUnseal() {
		d.config.Store(clone)
		return nil
	}

	// Encode the seal configuration
	buf, err := json.Marshal(clone)
	if err != nil {
		return fmt.Errorf("failed to encode seal configuration: %w", err)
	}

	if err := d.configAccess.Put(ctx, d.metaPrefix+sealConfigPath, buf); err != nil {
		d.core.logger.Error("failed to write seal configuration", "error", err)
		return fmt.Errorf("failed to write seal configuration: %w", err)
	}

	d.SetCachedConfig(clone)
	return nil
}

func (d *defaultSeal) SetCachedConfig(config *SealConfig) {
	d.config.Store(config)
}

func (d *defaultSeal) SetConfigAccess(barrier barrier.SecurityBarrier) {
	d.configAccess = &secureStorageAccess{barrier: barrier}
}

func (d *defaultSeal) RecoveryKey(ctx context.Context) ([]byte, error) {
	return nil, errors.New("recovery not supported")
}

func (d *defaultSeal) VerifyRecoveryKey(ctx context.Context, key []byte) error {
	return errors.New("recovery not supported")
}

func (d *defaultSeal) SetRecoveryKey(ctx context.Context, key []byte) error {
	return errors.New("recovery not supported")
}

func (d *defaultSeal) GetShamirWrapper() (*seal.ShamirWrapper, error) {
	// defaultSeal is meant to be for Shamir seals, so it should always have a ShamirWrapper.
	// Nonetheless, NewDefaultSeal does not check, so let's play it safe.
	w, ok := d.GetAccess().GetWrapper().(*seal.ShamirWrapper)
	if !ok {
		return nil, fmt.Errorf("expected defaultSeal to have a ShamirWrapper, but found a %T instead", d.GetAccess().GetWrapper())
	}
	return w, nil
}

type ErrEncrypt struct {
	Err error
}

var _ error = &ErrEncrypt{}

func (e *ErrEncrypt) Error() string {
	return e.Err.Error()
}

func (e *ErrEncrypt) Is(target error) bool {
	_, ok := target.(*ErrEncrypt)
	return ok || errors.Is(e.Err, target)
}

type ErrDecrypt struct {
	Err error
}

var _ error = &ErrDecrypt{}

func (e *ErrDecrypt) Error() string {
	return e.Err.Error()
}

func (e *ErrDecrypt) Is(target error) bool {
	_, ok := target.(*ErrDecrypt)
	return ok || errors.Is(e.Err, target)
}

func writeStoredKeys(ctx context.Context, storage physical.Backend, metaPrefix string, encryptor seal.Access, keys [][]byte) error {
	if keys == nil {
		return errors.New("keys were nil")
	}
	if len(keys) == 0 {
		return errors.New("no keys provided")
	}

	buf, err := json.Marshal(keys)
	if err != nil {
		return fmt.Errorf("failed to encode keys for storage: %w", err)
	}

	// Encrypt and marshal the keys
	blobInfo, err := encryptor.Encrypt(ctx, buf, nil)
	if err != nil {
		return &ErrEncrypt{Err: fmt.Errorf("failed to encrypt keys for storage: %w", err)}
	}

	value, err := proto.Marshal(blobInfo)
	if err != nil {
		return fmt.Errorf("failed to marshal value for storage: %w", err)
	}

	// Store the seal configuration.
	pe := &physical.Entry{
		Key:   metaPrefix + StoredBarrierKeysPath, // TODO(SEALHA): will we need to store more than one set of keys?
		Value: value,
	}

	if err := storage.Put(ctx, pe); err != nil {
		return fmt.Errorf("failed to write keys to storage: %w", err)
	}

	return nil
}

func readStoredKeys(ctx context.Context, storage physical.Backend, metaPrefix string, encryptor seal.Access) ([][]byte, error) {
	pe, err := storage.Get(ctx, metaPrefix+StoredBarrierKeysPath)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch stored keys: %w", err)
	}

	// This is not strictly an error; we may not have any stored keys, for
	// instance, if we're not initialized
	if pe == nil {
		return nil, nil
	}

	blobInfo := &wrapping.BlobInfo{}
	if err := proto.Unmarshal(pe.Value, blobInfo); err != nil {
		return nil, fmt.Errorf("failed to proto decode stored keys: %w", err)
	}

	pt, err := encryptor.Decrypt(ctx, blobInfo, nil)
	if err != nil {
		if strings.Contains(err.Error(), "message authentication failed") {
			return nil, &ErrInvalidKey{Reason: fmt.Sprintf("failed to decrypt keys from storage: %v", err)}
		}
		return nil, &ErrDecrypt{Err: fmt.Errorf("failed to decrypt keys from storage: %w", err)}
	}

	// Decode the barrier entry
	var keys [][]byte
	if err := json.Unmarshal(pt, &keys); err != nil {
		return nil, fmt.Errorf("failed to decode stored keys: %v", err)
	}

	return keys, nil
}
