// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	mathrand "math/rand"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/proto"

	log "github.com/hashicorp/go-hclog"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"github.com/openbao/openbao/sdk/v2/physical"
	"github.com/openbao/openbao/v2/internal/vault/barrier"
	"github.com/openbao/openbao/v2/internal/vault/seal"
)

var autoSealUnavailableDuration = []string{"seal", "unreachable", "time"}

// autoSeal wraps and unwraps stored barrier root keys using an external KMS
// or HSM solution and locally manages recovery configuration and its key.
type autoSeal struct {
	seal.Access

	wrapperType wrapping.WrapperType
	core        *Core
	name        string
	logger      log.Logger
	metaPrefix  string

	config       atomic.Pointer[SealConfig]
	configAccess StorageAccess

	healthCheckEnabled           bool
	healthCheckTimeout           time.Duration
	healthCheckInterval          time.Duration
	healthCheckIntervalUnhealthy time.Duration

	healthCheckLock sync.Mutex
	healthCheckStop chan struct{}
}

// Ensure we are implementing the Seal interface
var _ Seal = (*autoSeal)(nil)

func NewAutoSeal(lowLevel seal.Access, name string) (*autoSeal, error) {
	ret := &autoSeal{
		Access: lowLevel,
		name:   name,
	}

	// Having the wrapper type in a field is just a convenience since Seal.BarrierType()
	// does not return an error.
	var err error
	ret.wrapperType, err = ret.Type(context.Background())
	if err != nil {
		return nil, err
	}

	return ret, nil
}

func NewAutoSealWithHealthCheck(
	lowLevel seal.Access,
	name string,
	enabled bool,
	timeout, interval, intervalUnhealthy time.Duration,
) (*autoSeal, error) {
	d, err := NewAutoSeal(lowLevel, name)
	if err != nil {
		return nil, err
	}

	d.healthCheckEnabled = enabled
	d.healthCheckTimeout = timeout
	d.healthCheckInterval = interval
	d.healthCheckIntervalUnhealthy = intervalUnhealthy

	return d, nil
}

func (d *autoSeal) Name() string {
	return d.name
}

func (d *autoSeal) GetAccess() seal.Access {
	return d.Access
}

func (d *autoSeal) checkCore() error {
	if d.core == nil {
		return errors.New("seal does not have a core set")
	}
	return nil
}

func (d *autoSeal) SetCore(core *Core) {
	d.core = core
	if d.logger == nil {
		d.logger = d.core.WithNamedLogger("autoseal")
	}

	// By default, we assume that seal config information is stored in
	// plain text right on the physical storage, as is the case for the
	// root namespace. For per-namespace seals, this can be overridden by
	// [Seal.SetConfigAccess].
	d.configAccess = &directStorageAccess{physical: core.physical}
}

func (d *autoSeal) Init(ctx context.Context) error {
	return d.Access.Init(ctx)
}

func (d *autoSeal) MetaPrefix() string {
	return d.metaPrefix
}

func (d *autoSeal) SetMetaPrefix(metaPrefix string) {
	d.metaPrefix = metaPrefix
}

func (d *autoSeal) Finalize(ctx context.Context) error {
	return d.Access.Finalize(ctx)
}

func (d *autoSeal) WrapperType() wrapping.WrapperType {
	return d.wrapperType
}

func (d *autoSeal) GetShamirWrapper() (*seal.ShamirWrapper, error) {
	return nil, errors.New("autoSeal does not use a ShamirWrapper")
}

func (d *autoSeal) RecoveryKeySupported() bool {
	return true
}

// SetStoredKeys uses the autoSeal.Access.Encrypts method to wrap the keys.
// The stored entry does not need to be seal wrapped in this case.
func (d *autoSeal) SetStoredKeys(ctx context.Context, keys [][]byte) error {
	return writeStoredKeys(ctx, d, d.core.physical, keys)
}

// GetStoredKeys retrieves the key shares by unwrapping the encrypted key
// using the autoseal.
func (d *autoSeal) GetStoredKeys(ctx context.Context) ([][]byte, error) {
	return readStoredKeys(ctx, d, d.core.physical)
}

func (d *autoSeal) upgradeStoredKeys(ctx context.Context) error {
	pe, err := d.core.physical.Get(ctx, encryptedRootPath(d.Name()))
	if err != nil {
		return fmt.Errorf("failed to fetch stored keys: %w", err)
	}

	if pe == nil {
		pe, err = d.core.physical.Get(ctx, deprecatedStoredBarrierKeysPath)
		if err != nil {
			return fmt.Errorf("failed to fetch legacy stored keys: %w", err)
		}
	}

	if pe == nil {
		return errors.New("no stored keys found")
	}

	blobInfo := &wrapping.BlobInfo{}
	if err := proto.Unmarshal(pe.Value, blobInfo); err != nil {
		return fmt.Errorf("failed to proto decode stored keys: %w", err)
	}

	keyId, err := d.KeyId(ctx)
	if err != nil {
		return err
	}
	if blobInfo.KeyInfo != nil && blobInfo.KeyInfo.KeyId != keyId {
		d.logger.Info("upgrading stored keys")

		pt, err := d.Decrypt(ctx, blobInfo, nil)
		if err != nil {
			return fmt.Errorf("failed to decrypt encrypted stored keys: %w", err)
		}

		// Decode the barrier entry
		var keys [][]byte
		if err := json.Unmarshal(pt, &keys); err != nil {
			return fmt.Errorf("failed to decode stored keys: %w", err)
		}

		if err := d.SetStoredKeys(ctx, keys); err != nil {
			return fmt.Errorf("failed to save upgraded stored keys: %w", err)
		}
	}
	return nil
}

// UpgradeKeys re-encrypts and saves the stored keys and the recovery key
// with the current key if the current KeyId is different from the KeyId
// the stored keys and the recovery key are encrypted with. The provided
// Context must be non-nil.
func (d *autoSeal) UpgradeKeys(ctx context.Context) error {
	// Many of the seals update their keys to the latest KeyId when Encrypt
	// is called.
	if _, err := d.Encrypt(ctx, []byte("a"), nil); err != nil {
		return err
	}

	if err := d.upgradeRecoveryKey(ctx); err != nil {
		return err
	}
	if err := d.upgradeStoredKeys(ctx); err != nil {
		return err
	}
	return nil
}

func (d *autoSeal) SetConfigAccess(barrier barrier.SecurityBarrier) {
	d.configAccess = &secureStorageAccess{barrier: barrier}
}

// Config returns the recovery config on recoverySealConfigPath.
func (d *autoSeal) Config(ctx context.Context) (*SealConfig, error) {
	if config := d.config.Load(); config != nil {
		return config.Clone(), nil
	}

	if err := d.checkCore(); err != nil {
		return nil, err
	}

	sealType := "recovery"
	valueBytes, err := d.configAccess.Get(ctx, d.metaPrefix+recoverySealConfigPath(d.Name()))
	if err != nil {
		d.logger.Error("failed to read seal configuration", "seal_type", sealType, "error", err)
		return nil, fmt.Errorf("failed to read %q seal configuration: %w", sealType, err)
	}

	// If the seal configuration is missing, we are not initialized
	if valueBytes == nil {
		valueBytes, err = d.configAccess.Get(ctx, d.metaPrefix+deprecatedRecoverySealConfigPath)
		if err != nil {
			d.logger.Error("failed to read legacy seal configuration", "seal_type", sealType, "error", err)
			return nil, fmt.Errorf("failed to read legacy %q seal configuration: %w", sealType, err)
		}
		if valueBytes == nil {
			d.logger.Info("seal configuration missing, not initialized", "seal_type", sealType)
			return nil, nil
		}
	}

	conf := &SealConfig{}
	if err := json.Unmarshal(valueBytes, conf); err != nil {
		d.logger.Error("failed to decode seal configuration", "seal_type", sealType, "error", err)
		return nil, fmt.Errorf("failed to decode %q seal configuration: %w", sealType, err)
	}

	switch conf.Name {
	case "":
		conf.Name = fmt.Sprintf("%s-recovery", d.Name())
	case fmt.Sprintf("%s-recovery", d.Name()):
	default:
		d.core.logger.Error("recovery seal name does not match expected name", "recovery_seal_name", conf.Name, "loaded_seal_name", d.Name())
		return nil, fmt.Errorf("recovery seal name of %q does not match expected name of %q", conf.Name, d.Name())
	}

	if conf.Purpose != "" && conf.Purpose != Recovery {
		d.logger.Error("recovery seal purpose does not match loaded purpose", "seal_type", conf.Type, "loaded_type", conf.Purpose)
		return nil, fmt.Errorf("recovery seal purpose of %q does not match loaded purpose of %q", conf.Type, conf.Purpose)
	}

	conf.Purpose = Recovery
	if err := conf.Validate(); err != nil {
		d.logger.Error("invalid seal configuration", "seal_type", sealType, "error", err)
		return nil, fmt.Errorf("%q seal validation failed: %w", sealType, err)
	}

	d.config.Store(conf)
	return conf.Clone(), nil
}

// SetConfig writes the recovery configuration to the physical storage
// and sets it as the seal's config.
func (d *autoSeal) SetConfig(ctx context.Context, conf *SealConfig) error {
	if err := d.checkCore(); err != nil {
		return err
	}

	if conf == nil {
		d.config.Store(nil)
		return nil
	}

	conf.Purpose = Recovery
	// Left for backwards compatibility.
	conf.Type = "shamir"
	conf.Name = fmt.Sprintf("%s-recovery", d.Name())

	// Encode the seal configuration
	buf, err := json.Marshal(conf)
	if err != nil {
		return fmt.Errorf("failed to encode recovery seal configuration: %w", err)
	}

	if err := d.configAccess.Put(ctx, d.metaPrefix+recoverySealConfigPath(d.Name()), buf); err != nil {
		d.logger.Error("failed to write recovery seal configuration", "error", err)
		return fmt.Errorf("failed to write recovery seal configuration: %w", err)
	}

	d.config.Store(conf.Clone())

	return nil
}

func (d *autoSeal) SetCachedConfig(config *SealConfig) {
	d.config.Store(config)
}

func (d *autoSeal) VerifyRecoveryKey(ctx context.Context, key []byte) error {
	if key == nil {
		return errors.New("recovery key to verify is nil")
	}

	pt, err := d.getRecoveryKeyInternal(ctx)
	if err != nil {
		return err
	}

	if subtle.ConstantTimeCompare(key, pt) != 1 {
		return errors.New("recovery key does not match submitted values")
	}

	return nil
}

func (d *autoSeal) SetRecoveryKey(ctx context.Context, key []byte) error {
	if err := d.checkCore(); err != nil {
		return err
	}

	if key == nil {
		return errors.New("recovery key to store is nil")
	}

	// Encrypt and marshal the keys
	blobInfo, err := d.Encrypt(ctx, key, nil)
	if err != nil {
		return fmt.Errorf("failed to encrypt keys for storage: %w", err)
	}

	value, err := proto.Marshal(blobInfo)
	if err != nil {
		return fmt.Errorf("failed to marshal value for storage: %w", err)
	}

	pe := &physical.Entry{
		Key:   d.metaPrefix + recoveryKeyPath(d.Name()),
		Value: value,
	}

	if err := d.core.physical.Put(ctx, pe); err != nil {
		d.logger.Error("failed to write recovery key", "error", err)
		return fmt.Errorf("failed to write recovery key: %w", err)
	}

	return nil
}

func (d *autoSeal) RecoveryKey(ctx context.Context) ([]byte, error) {
	return d.getRecoveryKeyInternal(ctx)
}

func (d *autoSeal) getRecoveryKeyInternal(ctx context.Context) ([]byte, error) {
	pe, err := d.core.physical.Get(ctx, d.metaPrefix+recoveryKeyPath(d.Name()))
	if err != nil {
		d.logger.Error("failed to read recovery key", "error", err)
		return nil, fmt.Errorf("failed to read recovery key: %w", err)
	}
	if pe == nil {
		pe, err = d.core.physical.Get(ctx, d.metaPrefix+deprecatedRecoveryKeyPath)
		if err != nil {
			d.logger.Error("failed to read legacy recovery key", "error", err)
			return nil, fmt.Errorf("failed to read legacy recovery key: %w", err)
		}
		if pe == nil {
			d.logger.Warn("no recovery key found")
			return nil, errors.New("no recovery key found")
		}
	}

	blobInfo := &wrapping.BlobInfo{}
	if err := proto.Unmarshal(pe.Value, blobInfo); err != nil {
		return nil, fmt.Errorf("failed to proto decode stored keys: %w", err)
	}

	pt, err := d.Decrypt(ctx, blobInfo, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt encrypted stored keys: %w", err)
	}

	return pt, nil
}

// upgradeRecoveryKey retrieves recovery key, compares it to the
// current seal encryption key and upgrades if they mismatch.
func (d *autoSeal) upgradeRecoveryKey(ctx context.Context) error {
	pe, err := d.core.physical.Get(ctx, d.metaPrefix+recoveryKeyPath(d.Name()))
	if err != nil {
		return fmt.Errorf("failed to fetch recovery key: %w", err)
	}
	if pe == nil {
		pe, err = d.core.physical.Get(ctx, d.metaPrefix+deprecatedRecoveryKeyPath)
		if err != nil {
			d.logger.Error("failed to fetch legacy recovery key", "error", err)
			return fmt.Errorf("failed to fetch legacy recovery key: %w", err)
		}

		if pe == nil {
			recoveryConfig, err := d.Config(ctx)
			if err != nil {
				return err
			}
			if recoveryConfig == nil {
				return errors.New("no recovery config found")
			}

			// Check if we haven't yet generated recovery key shares.
			if recoveryConfig.SecretShares == 0 {
				// Assume upgrade has passed as there's nothing to upgrade for now.
				return nil
			}
			return errors.New("no recovery key found")
		}
	}

	blobInfo := &wrapping.BlobInfo{}
	if err := proto.Unmarshal(pe.Value, blobInfo); err != nil {
		return fmt.Errorf("failed to proto decode recovery key: %w", err)
	}

	keyId, err := d.KeyId(ctx)
	if err != nil {
		return err
	}

	if blobInfo.KeyInfo != nil && blobInfo.KeyInfo.KeyId != keyId {
		d.logger.Info("upgrading recovery key")

		pt, err := d.Decrypt(ctx, blobInfo, nil)
		if err != nil {
			return fmt.Errorf("failed to decrypt encrypted recovery key: %w", err)
		}
		if err := d.SetRecoveryKey(ctx, pt); err != nil {
			return fmt.Errorf("failed to save upgraded recovery key: %w", err)
		}
	}
	return nil
}

// StartHealthCheck starts a goroutine that tests the health of the auto-unseal
// backend at a configured interval. If unhealthy, logs a warning on the
// condition and begins testing at a separately configurable interval until
// healthy again.
func (d *autoSeal) StartHealthCheck() {
	if !d.healthCheckEnabled {
		return
	}

	d.StopHealthCheck()
	d.healthCheckLock.Lock()
	defer d.healthCheckLock.Unlock()

	healthCheck := time.NewTicker(d.healthCheckInterval)
	d.healthCheckStop = make(chan struct{})
	healthCheckStop := d.healthCheckStop
	ctx := d.core.activeContext.Load()

	go func() {
		lastTestOk := true
		lastSeenOk := time.Now()

		fail := func(msg string, args ...any) {
			d.logger.Warn(msg, args...)
			if lastTestOk {
				healthCheck.Reset(d.healthCheckIntervalUnhealthy)
			}
			lastTestOk = false
			d.core.MetricSink().SetGauge(autoSealUnavailableDuration, float32(time.Since(lastSeenOk).Milliseconds()))
		}
		for {
			select {
			case <-healthCheckStop:
				if healthCheck != nil {
					healthCheck.Stop()
				}
				healthCheckStop = nil
				return
			case t := <-healthCheck.C:
				func() {
					ctx, cancel := context.WithTimeout(ctx, d.healthCheckTimeout)
					defer cancel()

					testVal := fmt.Sprintf("Heartbeat %d", mathrand.Intn(1000))
					ciphertext, err := d.Encrypt(ctx, []byte(testVal), nil)

					if err != nil {
						fail("failed to encrypt seal health test value, seal backend may be unreachable", "error", err)
					} else {
						func() {
							ctx, cancel := context.WithTimeout(ctx, d.healthCheckTimeout)
							defer cancel()
							plaintext, err := d.Decrypt(ctx, ciphertext, nil)
							if err != nil {
								fail("failed to decrypt seal health test value, seal backend may be unreachable", "error", err)
							}
							if !bytes.Equal([]byte(testVal), plaintext) {
								fail("seal health test value failed to decrypt to expected value")
							} else {
								d.logger.Debug("seal health test passed")
								if !lastTestOk {
									d.logger.Info("seal backend is now healthy again", "downtime", t.Sub(lastSeenOk).String())
									healthCheck.Reset(d.healthCheckInterval)
								}
								lastTestOk = true
								lastSeenOk = t
								d.core.MetricSink().SetGauge(autoSealUnavailableDuration, 0)
							}
						}()
					}
				}()
			}
		}
	}()
}

func (d *autoSeal) StopHealthCheck() {
	d.healthCheckLock.Lock()
	defer d.healthCheckLock.Unlock()
	if d.healthCheckStop != nil {
		close(d.healthCheckStop)
		d.healthCheckStop = nil
	}
}
