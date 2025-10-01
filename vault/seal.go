// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"

	aeadwrapper "github.com/openbao/go-kms-wrapping/wrappers/aead/v2"
	"google.golang.org/protobuf/proto"

	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/sdk/v2/helper/jsonutil"
	"github.com/openbao/openbao/sdk/v2/physical"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"github.com/openbao/openbao/vault/seal"
)

const (
	// sealConfigPath is the path used to store our seal configuration.
	// This value is stored in plaintext, since we must be able to read it even
	// with the Vault sealed. This is required so that we know how many secret
	// parts must be used to reconstruct the unseal key.
	sealConfigPath = "core/seal-config"

	// recoverySealConfigPath is the path to the recovery key seal configuration.
	// This is stored in plaintext so that we can perform auto-unseal.
	recoverySealConfigPath = "core/recovery-config"

	// recoveryKeyPath is the path to the recovery key
	recoveryKeyPath = "core/recovery-key"

	// StoredBarrierKeysPath is the path used for storing HSM-encrypted unseal keys
	StoredBarrierKeysPath = "core/hsm/barrier-unseal-keys"

	// hsmStoredIVPath is the path to the initialization vector for stored keys
	hsmStoredIVPath = "core/hsm/iv"
)

const (
	RecoveryTypeUnsupported = "unsupported"
	RecoveryTypeShamir      = "shamir"
)

type Seal interface {
	SetCore(*Core)
	Init(context.Context) error
	SetMetaPrefix(string)
	Finalize(context.Context) error
	StoredKeysSupported() seal.StoredKeysSupport // SealAccess
	Wrapable() bool
	SetStoredKeys(context.Context, [][]byte) error
	GetStoredKeys(context.Context) ([][]byte, error)
	WrapperType() wrapping.WrapperType           // SealAccess
	Config(context.Context) (*SealConfig, error) // SealAccess
	SetConfig(context.Context, *SealConfig) error
	SetCachedConfig(*SealConfig)
	RecoveryKeySupported() bool // SealAccess
	RecoveryType() string
	RecoveryConfig(context.Context) (*SealConfig, error) // SealAccess
	RecoveryKey(context.Context) ([]byte, error)
	SetRecoveryConfig(context.Context, *SealConfig) error
	SetCachedRecoveryConfig(*SealConfig)
	SetRecoveryKey(context.Context, []byte) error
	VerifyRecoveryKey(context.Context, []byte) error // SealAccess
	GetAccess() seal.Access                          // SealAccess
	GetShamirWrapper() (*aeadwrapper.ShamirWrapper, error)
}

type defaultSeal struct {
	access     seal.Access
	config     atomic.Value
	core       *Core
	metaPrefix string
}

var _ Seal = (*defaultSeal)(nil)

func NewDefaultSeal(lowLevel seal.Access) Seal {
	ret := &defaultSeal{
		access: lowLevel,
	}
	ret.config.Store((*SealConfig)(nil))
	return ret
}

func (d *defaultSeal) Wrapable() bool {
	return false
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
	return wrapping.WrapperTypeShamir
}

func (d *defaultSeal) StoredKeysSupported() seal.StoredKeysSupport {
	return seal.StoredKeysSupportedShamirRoot
}

func (d *defaultSeal) RecoveryKeySupported() bool {
	return false
}

func (d *defaultSeal) SetStoredKeys(ctx context.Context, keys [][]byte) error {
	return writeStoredKeys(ctx, d.core.physical, d.metaPrefix, d.access, keys)
}

func (d *defaultSeal) GetStoredKeys(ctx context.Context) ([][]byte, error) {
	keys, err := readStoredKeys(ctx, d.core.physical, d.metaPrefix, d.access)
	return keys, err
}

func (d *defaultSeal) Config(ctx context.Context) (*SealConfig, error) {
	cfg := d.config.Load().(*SealConfig)
	if cfg != nil {
		return cfg.Clone(), nil
	}

	if err := d.checkCore(); err != nil {
		return nil, err
	}

	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	var barrier StorageAccess
	parentPath, exists := ns.ParentPath()
	if exists {
		barrier = &secureStorageAccess{barrier: d.core.sealManager.namespaceBarrierByLongestPrefix(parentPath)}
	} else {
		barrier = &directStorageAccess{physical: d.core.physical}
	}

	// Fetch the seal configuration
	valueBytes, err := barrier.Get(ctx, d.metaPrefix+sealConfigPath)
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

	// Decode the seal config entry
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
		d.core.logger.Error("seal type does not match expected type", "seal_type", conf.Type, "loaded_seal_type", d.WrapperType())
		return nil, fmt.Errorf("seal type of %q does not match expected type of %q", conf.Type, d.WrapperType())
	}

	// Check for a valid seal configuration
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
		d.config.Store((*SealConfig)(nil))
		return nil
	}

	config.Type = d.WrapperType().String()

	// If we are doing a raft unseal we do not want to persist the seal config
	// because storage isn't setup yet.
	if d.core.isRaftUnseal() {
		d.config.Store(config.Clone())
		return nil
	}

	// Encode the seal configuration
	buf, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to encode seal configuration: %w", err)
	}

	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return err
	}

	var barrier StorageAccess
	parentPath, exists := ns.ParentPath()
	if exists {
		barrier = &secureStorageAccess{barrier: d.core.sealManager.namespaceBarrierByLongestPrefix(parentPath)}
	} else {
		barrier = &directStorageAccess{physical: d.core.physical}
	}

	if err := barrier.Put(ctx, d.metaPrefix+sealConfigPath, buf); err != nil {
		d.core.logger.Error("failed to write seal configuration", "error", err)
		return fmt.Errorf("failed to write seal configuration: %w", err)
	}

	d.SetCachedConfig(config.Clone())

	return nil
}

func (d *defaultSeal) SetCachedConfig(config *SealConfig) {
	d.config.Store(config)
}

func (d *defaultSeal) RecoveryType() string {
	return RecoveryTypeUnsupported
}

func (d *defaultSeal) RecoveryConfig(ctx context.Context) (*SealConfig, error) {
	return nil, errors.New("recovery not supported")
}

func (d *defaultSeal) RecoveryKey(ctx context.Context) ([]byte, error) {
	return nil, errors.New("recovery not supported")
}

func (d *defaultSeal) SetRecoveryConfig(ctx context.Context, config *SealConfig) error {
	return errors.New("recovery not supported")
}

func (d *defaultSeal) SetCachedRecoveryConfig(config *SealConfig) {}

func (d *defaultSeal) VerifyRecoveryKey(ctx context.Context, key []byte) error {
	return errors.New("recovery not supported")
}

func (d *defaultSeal) SetRecoveryKey(ctx context.Context, key []byte) error {
	return errors.New("recovery not supported")
}

func (d *defaultSeal) GetShamirWrapper() (*aeadwrapper.ShamirWrapper, error) {
	// defaultSeal is meant to be for Shamir seals, so it should always have a ShamirWrapper.
	// Nonetheless, NewDefaultSeal does not check, so let's play it safe.
	w, ok := d.GetAccess().GetWrapper().(*aeadwrapper.ShamirWrapper)
	if !ok {
		return nil, fmt.Errorf("expected defaultSeal to have a ShamirWrapper, but found a %T instead", d.GetAccess().GetWrapper())
	}
	return w, nil
}

// SealConfig is used to describe the seal configuration
type SealConfig struct {
	// The type, for sanity checking
	Type string `json:"type" mapstructure:"type"`

	// SecretShares is the number of shares the secret is split into. This is
	// the N value of Shamir.
	SecretShares int `json:"secret_shares" mapstructure:"secret_shares"`

	// SecretThreshold is the number of parts required to open the vault. This
	// is the T value of Shamir.
	SecretThreshold int `json:"secret_threshold" mapstructure:"secret_threshold"`

	// PGPKeys is the array of public PGP keys used, if requested, to encrypt
	// the output unseal tokens. If provided, it sets the value of
	// SecretShares. Ordering is important.
	PGPKeys []string `json:"pgp_keys" mapstructure:"pgp_keys"`

	// Nonce is a nonce generated by Vault used to ensure that when unseal keys
	// are submitted for a rotation, the operation itself is the one intended.
	Nonce string `json:"nonce" mapstructure:"nonce"`

	// Backup indicates whether or not a backup of PGP-encrypted unseal keys
	// should be stored at coreUnsealKeysBackupPath after successful rotation.
	Backup bool `json:"backup" mapstructure:"backup"`

	// How many keys to store, for seals that support storage.  Always 0 or 1.
	StoredShares uint `json:"stored_shares" mapstructure:"stored_shares"`

	// Stores the progress of the rotation (key shares).
	RotationProgress [][]byte `json:"-"`

	// VerificationRequired indicates that after a rotation validation must be
	// performed (via providing shares from the new key) before the new key is
	// actually installed. This is omitted from JSON as we don't persist the
	// new key, it lives only in memory.
	VerificationRequired bool `json:"-"`

	// VerificationKey is the new key that we will roll to after successful
	// validation
	VerificationKey []byte `json:"-"`

	// VerificationNonce stores the current operation nonce for verification
	VerificationNonce string `json:"-"`

	// Stores the progress of the verification operation (key shares)
	VerificationProgress [][]byte `json:"-"`
}

// baseValidate is used as a shared base between `Validate` and `ValidateRecovery`
// functions
func (s *SealConfig) baseValidate() error {
	if s.SecretShares > 1 && s.SecretThreshold < 2 {
		return errors.New("threshold must be greater than one for multiple shares")
	}
	if s.SecretShares > 255 {
		return errors.New("shares must be less than 256")
	}
	if s.SecretThreshold > 255 {
		return errors.New("threshold must be less than 256")
	}
	if s.SecretThreshold > s.SecretShares {
		return errors.New("threshold cannot be larger than shares")
	}
	if s.StoredShares > 1 {
		return errors.New("stored keys cannot be larger than 1")
	}
	if len(s.PGPKeys) > 0 {
		if len(s.PGPKeys) != s.SecretShares {
			return errors.New("count mismatch between number of provided PGP keys and number of shares")
		}
		for _, keystring := range s.PGPKeys {
			data, err := base64.StdEncoding.DecodeString(keystring)
			if err != nil {
				return fmt.Errorf("error decoding given PGP key: %w", err)
			}
			_, err = openpgp.ReadEntity(packet.NewReader(bytes.NewBuffer(data)))
			if err != nil {
				return fmt.Errorf("error parsing given PGP key: %w", err)
			}
		}
	}
	return nil
}

// Validate is used to sanity check the (barrier) seal configuration
func (s *SealConfig) Validate() error {
	if s.SecretShares < 1 {
		return errors.New("shares must be at least one")
	}
	if s.SecretThreshold < 1 {
		return errors.New("threshold must be at least one")
	}

	return s.baseValidate()
}

// ValidateRecovery is used to sanity check the (recovery) seal configuration
func (s *SealConfig) ValidateRecovery() error {
	return s.baseValidate()
}

func (s *SealConfig) Clone() *SealConfig {
	ret := &SealConfig{
		Type:                 s.Type,
		SecretShares:         s.SecretShares,
		SecretThreshold:      s.SecretThreshold,
		Nonce:                s.Nonce,
		Backup:               s.Backup,
		StoredShares:         s.StoredShares,
		VerificationRequired: s.VerificationRequired,
		VerificationNonce:    s.VerificationNonce,
	}
	if len(s.PGPKeys) > 0 {
		ret.PGPKeys = make([]string, len(s.PGPKeys))
		copy(ret.PGPKeys, s.PGPKeys)
	}
	if len(s.VerificationKey) > 0 {
		ret.VerificationKey = make([]byte, len(s.VerificationKey))
		copy(ret.VerificationKey, s.VerificationKey)
	}
	return ret
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

	// Decode the stored keys entry
	var keys [][]byte
	if err := json.Unmarshal(pt, &keys); err != nil {
		return nil, fmt.Errorf("failed to decode stored keys: %v", err)
	}

	return keys, nil
}
