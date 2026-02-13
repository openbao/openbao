// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"path"
	"sync"
	"time"

	"github.com/armon/go-radix"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-uuid"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/sdk/v2/helper/shamir"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/vault/barrier"
	vaultseal "github.com/openbao/openbao/vault/seal"
)

var ErrNotSealable = errors.New("namespace is not sealable")

// ErrInvalidKey is returned if there is a user-based error with a provided
// unseal key. This will be shown to the user, so should not contain
// information that is sensitive.
type ErrInvalidKey struct {
	Reason string
}

func (e *ErrInvalidKey) Error() string {
	return fmt.Sprintf("invalid key: %v", e.Reason)
}

// These variables hold the config and shares we have until we reach
// enough to verify the appropriate root key.
type rotationConfig struct {
	rootConfig     *SealConfig
	recoveryConfig *SealConfig
}

// These variables hold the unseal key parts to reconstruct the key and
// operation nonce.
type unlockInformation struct {
	Parts [][]byte
	Nonce string
}

// SealManager couples namespaces to storage barriers and their seals, managing
// barrier/seal/rotation/config state for all namespaces, including root.
type SealManager struct {
	core *Core

	lock sync.RWMutex
	// invalidated atomic.Bool

	sealByNamespace              map[string]Seal
	unlockInformationByNamespace map[string]*unlockInformation
	rotationConfigByNamespace    map[string]*rotationConfig
	barrierByNamespace           *radix.Tree

	// logger is the server logger copied over from core
	logger hclog.Logger
}

// NewSealManager creates a new seal manager with core reference and logger.
func NewSealManager(core *Core, logger hclog.Logger) *SealManager {
	return &SealManager{
		core:                         core,
		sealByNamespace:              make(map[string]Seal),
		unlockInformationByNamespace: make(map[string]*unlockInformation),
		rotationConfigByNamespace:    make(map[string]*rotationConfig),
		logger:                       logger,
	}
}

// SetupSealManager is called on core creation to initialize the seal manager.
func (c *Core) SetupSealManager() {
	sealLogger := c.baseLogger.Named("seals")
	c.AddLogger(sealLogger)
	c.sealManager = NewSealManager(c, sealLogger)
	c.sealManager.Reset()
}

// Reset clears all internal state, leaving only the root namespace's seal.
func (sm *SealManager) Reset() {
	sm.barrierByNamespace = radix.NewFromMap(map[string]interface{}{
		"": sm.core.barrier,
	})

	sm.sealByNamespace = map[string]Seal{
		namespace.RootNamespaceUUID: sm.core.seal,
	}

	sm.unlockInformationByNamespace = map[string]*unlockInformation{
		namespace.RootNamespaceUUID: {},
	}

	sm.rotationConfigByNamespace = map[string]*rotationConfig{
		namespace.RootNamespaceUUID: {},
	}
}

// SetSeal creates a seal using provided config and sets and initializes it
// as a seal of a provided namespace, creating the barrier and persisting config.
func (sm *SealManager) SetSeal(ctx context.Context, sealConfig *SealConfig, ns *namespace.Namespace, writeToStorage bool) error {
	sm.lock.Lock()
	defer sm.lock.Unlock()

	// TODO(wslabosz): should we always enforce stored shares?
	sealConfig.StoredShares = 1
	if err := sealConfig.Validate(); err != nil {
		return fmt.Errorf("invalid seal configuration: %w", err)
	}

	metaPrefix := NamespaceStoragePathPrefix(ns)

	// Seal type would depend on the provided arguments
	defaultSeal := NewDefaultSeal(vaultseal.NewAccess(vaultseal.NewShamirWrapper()))
	defaultSeal.SetCore(sm.core)
	defaultSeal.SetMetaPrefix(metaPrefix)

	// At this point, the namespace's barrier is still the parent's barrier,
	// hence we can just query that without computing the actual parent.
	defaultSeal.SetConfigAccess(sm.namespaceBarrierByLongestPrefix(ns.Path))

	ctx = namespace.ContextWithNamespace(ctx, ns)
	if err := defaultSeal.Init(ctx); err != nil {
		return fmt.Errorf("error initializing seal: %w", err)
	}

	sm.barrierByNamespace.Insert(ns.Path, barrier.NewAESGCMBarrier(sm.core.physical, metaPrefix))
	sm.sealByNamespace[ns.UUID] = defaultSeal
	sm.unlockInformationByNamespace[ns.UUID] = &unlockInformation{}
	sm.rotationConfigByNamespace[ns.UUID] = &rotationConfig{
		rootConfig:     nil,
		recoveryConfig: nil,
	}

	if writeToStorage {
		if err := defaultSeal.SetBarrierConfig(ctx, sealConfig); err != nil {
			return fmt.Errorf("failed to set barrier config: %w", err)
		}
	}

	return nil
}

// RemoveNamespace removes the given namespace from the SealManager's internal state.
func (sm *SealManager) RemoveNamespace(ns *namespace.Namespace) {
	sm.lock.Lock()
	defer sm.lock.Unlock()

	if _, ok := sm.sealByNamespace[ns.UUID]; !ok {
		return
	}

	delete(sm.sealByNamespace, ns.UUID)
	delete(sm.unlockInformationByNamespace, ns.UUID)
	delete(sm.rotationConfigByNamespace, ns.UUID)
	sm.barrierByNamespace.Delete(ns.Path)
}

// NamespaceView returns the BarrierView that applies to the given namespace.
// Remember that this method does not take in an existing storage type and is
// likely wrong to call within the context of a transaction.
func (c *Core) NamespaceView(ns *namespace.Namespace) barrier.View {
	b := c.sealManager.NamespaceBarrierByLongestPrefix(ns.Path)
	return NamespaceScopedView(b, ns)
}

// NamespaceBarrierByLongestPrefix acquires a read lock, and returns the barrier
// of a namespace matching the longest prefix of the provided path, going up to
// the root namespace.
func (sm *SealManager) NamespaceBarrierByLongestPrefix(nsPath string) barrier.SecurityBarrier {
	sm.lock.RLock()
	defer sm.lock.RUnlock()

	return sm.namespaceBarrierByLongestPrefix(nsPath)
}

// namespaceBarrierByLongestPrefix returns the barrier of a namespace matching
// the longest prefix of the provided path, going up to the root namespace.
func (sm *SealManager) namespaceBarrierByLongestPrefix(nsPath string) barrier.SecurityBarrier {
	_, v, exists := sm.barrierByNamespace.LongestPrefix(nsPath)
	if !exists {
		return nil
	}
	return v.(barrier.SecurityBarrier)
}

// NamespaceBarrier acquires a read lock and returns a barrier
// of a namespace with provided path.
func (sm *SealManager) NamespaceBarrier(nsPath string) barrier.SecurityBarrier {
	sm.lock.RLock()
	defer sm.lock.RUnlock()

	return sm.namespaceBarrier(nsPath)
}

// namespaceBarrier returns a namespace's barrier by namespace path.
func (sm *SealManager) namespaceBarrier(nsPath string) barrier.SecurityBarrier {
	v, exists := sm.barrierByNamespace.Get(nsPath)
	if !exists {
		return nil
	}

	return v.(barrier.SecurityBarrier)
}

// NamespaceSeal returns a namespace's seal by namespace UUID.
func (sm *SealManager) NamespaceSeal(nsUUID string) Seal {
	sm.lock.RLock()
	defer sm.lock.RUnlock()

	return sm.sealByNamespace[nsUUID]
}

// ResetUnsealProcess removes the current unlock parts from memory,
// to reset the unsealing process of a specified namespace.
func (sm *SealManager) ResetUnsealProcess(nsUUID string) {
	sm.lock.Lock()
	defer sm.lock.Unlock()

	delete(sm.unlockInformationByNamespace, nsUUID)
}

// NamespaceUnlockInformation returns the unlock information
// of a namespace with the given UUID.
func (sm *SealManager) NamespaceUnlockInformation(nsUUID string) *unlockInformation {
	sm.lock.RLock()
	defer sm.lock.RUnlock()

	return sm.unlockInformationByNamespace[nsUUID]
}

// NamespaceRotationConfig returns the rotation config of the namespace
// with the given UUID.
func (sm *SealManager) NamespaceRotationConfig(nsUUID string) *rotationConfig {
	sm.lock.RLock()
	defer sm.lock.RUnlock()

	return sm.rotationConfigByNamespace[nsUUID]
}

// SealStatus returns the seal status of a namespace, including its unlock
// progress.
func (sm *SealManager) SealStatus(ctx context.Context, ns *namespace.Namespace) (*SealStatusResponse, error) {
	sm.lock.RLock()
	defer sm.lock.RUnlock()

	// Verify that seal exists for a namespace
	seal := sm.sealByNamespace[ns.UUID]
	if seal == nil {
		return nil, ErrNotSealable
	}

	// Check barrier
	b := sm.namespaceBarrier(ns.Path)
	if b == nil {
		return nil, ErrNotSealable
	}

	init, err := b.Initialized(ctx)
	if err != nil {
		sm.logger.Error("namespace barrier init check failed", "namespace", ns.Path, "error", err)
		return nil, err
	}
	if !init {
		sm.logger.Info("namespace security barrier not initialized", "namespace", ns.Path)
		return nil, barrier.ErrBarrierNotInit
	}

	// Verify seal configuration
	sealConfig, err := seal.BarrierConfig(ctx)
	if err != nil {
		return nil, err
	}
	if sealConfig == nil {
		return nil, errors.New("namespace barrier reports initialized but no seal configuration found")
	}

	var progress int
	var nonce string
	info := sm.unlockInformationByNamespace[ns.UUID]
	if info != nil {
		progress, nonce = len(info.Parts), info.Nonce
	}

	return &SealStatusResponse{
		Type:             sealConfig.Type,
		Initialized:      init,
		Sealed:           b.Sealed(),
		T:                sealConfig.SecretThreshold,
		N:                sealConfig.SecretShares,
		Progress:         progress,
		Nonce:            nonce,
		RecoverySeal:     seal.RecoveryKeySupported(),
		RecoverySealType: seal.RecoveryType(),
	}, nil
}

// unsealFragment verifies and records one part of the unseal shares,
// and attempts to unseal the namespace.
func (sm *SealManager) unsealFragment(ctx context.Context, ns *namespace.Namespace, b barrier.SecurityBarrier, key []byte) (bool, error) {
	sm.logger.Debug("namespace unseal key supplied")
	sm.lock.Lock()
	defer sm.lock.Unlock()

	// Check if already unsealed
	if !b.Sealed() {
		return true, nil
	}

	// Verify the key length
	min, max := b.KeyLength()
	max += shamir.ShareOverhead
	if len(key) < min {
		return false, &ErrInvalidKey{fmt.Sprintf("key is shorter than minimum %d bytes", min)}
	}
	if len(key) > max {
		return false, &ErrInvalidKey{fmt.Sprintf("key is longer than maximum %d bytes", max)}
	}

	newKey, err := sm.recordUnsealPart(ns, key)
	if !newKey || err != nil {
		return false, err
	}

	seal := sm.sealByNamespace[ns.UUID]
	if seal == nil {
		return false, ErrNotSealable
	}

	// getUnsealKey returns either a recovery key (in the case of an autoseal)
	// or an unseal key (new-style shamir).
	combinedKey, err := sm.getUnsealKey(ctx, seal, ns)
	if err != nil || combinedKey == nil {
		return false, err
	}

	rootKey, err := sm.unsealKeyToRootKey(ctx, seal, combinedKey, false, true)
	if err != nil {
		return false, err
	}

	// Attempt to unseal
	if err := b.Unseal(ctx, rootKey); err != nil {
		return false, err
	}

	sm.logger.Info("unsealed namespace", "namespace", ns.Path)

	return true, nil
}

// recordUnsealPart takes in a key fragment, and returns true if it's a new fragment.
func (sm *SealManager) recordUnsealPart(ns *namespace.Namespace, key []byte) (bool, error) {
	info, exists := sm.unlockInformationByNamespace[ns.UUID]
	if exists {
		for _, existing := range info.Parts {
			if subtle.ConstantTimeCompare(existing, key) == 1 {
				return false, nil
			}
		}
	} else {
		uuid, err := uuid.GenerateUUID()
		if err != nil {
			return false, err
		}
		info = &unlockInformation{Nonce: uuid}
		sm.unlockInformationByNamespace[ns.UUID] = info
	}

	// Store this key
	info.Parts = append(info.Parts, key)
	return true, nil
}

// getUnsealKey uses key fragments recorded by recordUnsealPart and
// returns the combined key if the key share threshold is met.
// If the key fragments are part of a recovery key, also verify that
// it matches the stored recovery key on disk.
func (sm *SealManager) getUnsealKey(ctx context.Context, seal Seal, ns *namespace.Namespace) ([]byte, error) {
	var sealConfig *SealConfig
	var err error

	raftInfo := sm.core.raftInfo.Load()

	switch {
	case seal.RecoveryKeySupported():
		sealConfig, err = seal.RecoveryConfig(ctx)
	case sm.core.isRaftUnseal():
		// Ignore follower's seal config and refer to leader's barrier
		// configuration.
		sealConfig = raftInfo.leaderBarrierConfig
	default:
		sealConfig, err = seal.BarrierConfig(ctx)
	}

	if err != nil {
		return nil, err
	}
	if sealConfig == nil {
		return nil, errors.New("namespace barrier reports initialized but no seal configuration found")
	}

	info := sm.unlockInformationByNamespace[ns.UUID]
	if info == nil {
		return nil, errors.New("no unlock information found for namespace")
	}

	// Check if we don't have enough keys to unlock, proceed through the rest of
	// the call only if we have met the threshold
	if len(info.Parts) < sealConfig.SecretThreshold {
		sm.logger.Debug("cannot unseal namespace, not enough keys", "keys", len(info.Parts),
			"threshold", sealConfig.SecretThreshold, "nonce", info.Nonce)
		return nil, nil
	}

	defer func() {
		delete(sm.unlockInformationByNamespace, ns.UUID)
	}()

	// Recover the split key. recoveredKey is the shamir combined
	// key, or the single provided key if the threshold is 1.
	var unsealKey []byte
	if sealConfig.SecretThreshold == 1 {
		unsealKey = make([]byte, len(info.Parts[0]))
		copy(unsealKey, info.Parts[0])
	} else {
		unsealKey, err = shamir.Combine(info.Parts)
		if err != nil {
			return nil, &ErrInvalidKey{fmt.Sprintf("failed to compute combined key: %v", err)}
		}
	}

	if seal.RecoveryKeySupported() {
		if err := seal.VerifyRecoveryKey(ctx, unsealKey); err != nil {
			return nil, &ErrInvalidKey{fmt.Sprintf("failed to verify recovery key: %v", err)}
		}
	}

	return unsealKey, nil
}

// unsealKeyToRootKey takes a key provided by the user, either a recovery key
// if using an autoseal or an unseal key with Shamir. It returns a nil error
// if the key is valid and an error otherwise. It also returns the root key
// that can be used to unseal the barrier.
// If useTestSeal is true, seal will not be modified; this is used when not
// invoked as part of an unseal process. Otherwise in the non-legacy shamir
// case the combinedKey will be set in the seal, which means subsequent attempts
// to use the seal to read the root key will succeed, assuming combinedKey is
// valid.
// If allowMissing is true, a failure to find the root key in storage results
// in a nil error and a nil root key being returned.
func (sm *SealManager) unsealKeyToRootKey(ctx context.Context, seal Seal, combinedKey []byte, useTestSeal bool, allowMissing bool) ([]byte, error) {
	switch seal.StoredKeysSupported() {
	case vaultseal.StoredKeysSupportedGeneric:
		if err := seal.VerifyRecoveryKey(ctx, combinedKey); err != nil {
			return nil, fmt.Errorf("recovery key verification failed: %w", err)
		}
	case vaultseal.StoredKeysSupportedShamirRoot:
		if useTestSeal {
			testseal := NewDefaultSeal(vaultseal.NewAccess(vaultseal.NewShamirWrapper()))
			testseal.SetCore(sm.core)
			cfg, err := seal.BarrierConfig(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to setup test barrier config: %w", err)
			}
			if cfg == nil {
				return nil, errors.New("namespace barrier reports initialized but no seal configuration found")
			}
			testseal.SetCachedBarrierConfig(cfg)
			seal = testseal
		}

		shamirWrapper, err := seal.GetShamirWrapper()
		if err != nil {
			return nil, err
		}

		if err = shamirWrapper.SetAesGcmKeyBytes(combinedKey); err != nil {
			return nil, &ErrInvalidKey{fmt.Sprintf("failed to setup unseal key: %v", err)}
		}
	default:
		return nil, errors.New("invalid seal")
	}

	storedKeys, err := seal.GetStoredKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve stored keys: %w", err)
	}

	if allowMissing && storedKeys == nil {
		return nil, nil
	}

	if len(storedKeys) != 1 {
		return nil, fmt.Errorf("expected exactly one stored key, got %d", len(storedKeys))
	}

	return storedKeys[0], nil
}

// AuthenticateRootKey verifies the root key retrieved from a combined unseal
// key against the namespace's barrier.
func (sm *SealManager) AuthenticateRootKey(ctx context.Context, ns *namespace.Namespace, combinedKey []byte) error {
	sm.lock.RLock()
	defer sm.lock.RUnlock()

	seal := sm.sealByNamespace[ns.UUID]
	if seal == nil {
		return ErrNotSealable
	}

	rootKey, err := sm.unsealKeyToRootKey(ctx, seal, combinedKey, false, false)
	if err != nil {
		return fmt.Errorf("unable to authenticate: %w", err)
	}

	b := sm.namespaceBarrier(ns.Path)
	if b == nil {
		return ErrNotSealable
	}

	if err := b.VerifyRoot(rootKey); err != nil {
		return fmt.Errorf("root key verification failed: %w", err)
	}

	return nil
}

func (sm *SealManager) InitializeBarrier(ctx context.Context, ns *namespace.Namespace) ([][]byte, error) {
	sm.lock.RLock()
	defer sm.lock.RUnlock()

	seal := sm.sealByNamespace[ns.UUID]
	if seal == nil {
		return nil, ErrNotSealable
	}

	b := sm.namespaceBarrier(ns.Path)
	if b == nil {
		return nil, ErrNotSealable
	}

	sealConfig, err := seal.BarrierConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve seal config: %w", err)
	}
	if sealConfig == nil {
		return nil, errors.New("namespace barrier reports initialized but no seal configuration found")
	}

	var sealKey []byte
	var sealKeyShares [][]byte

	if sealConfig.StoredShares == 1 && seal.BarrierType() == wrapping.WrapperTypeShamir {
		sealKey, sealKeyShares, err = sm.core.generateShares(sealConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to generate namespace seal key: %w", err)
		}
	}

	// TODO(wslabosz): should we declare separate random readers per namespace?
	barrierKey, err := b.GenerateKey(sm.core.secureRandomReader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate namespace barrier key: %w", err)
	}

	if err := b.Initialize(ctx, barrierKey, sealKey, sm.core.secureRandomReader); err != nil {
		return nil, fmt.Errorf("failed to initialize namespace barrier: %w", err)
	}

	if err := b.Unseal(ctx, barrierKey); err != nil {
		return nil, fmt.Errorf("failed to unseal namespace barrier: %w", err)
	}

	switch seal.StoredKeysSupported() {
	case vaultseal.StoredKeysSupportedShamirRoot:
		shamirWrapper, err := seal.GetShamirWrapper()
		if err != nil {
			return nil, fmt.Errorf("unable to get shamir wrapper: %w", err)
		}
		if err := shamirWrapper.SetAesGcmKeyBytes(sealKey); err != nil {
			return nil, fmt.Errorf("failed to set seal key: %w", err)
		}
	case vaultseal.StoredKeysSupportedGeneric:
	default:
		return nil, fmt.Errorf("unsupported stored keys type encountered: %w", err)
	}

	if err := seal.SetStoredKeys(ctx, [][]byte{barrierKey}); err != nil {
		return nil, fmt.Errorf("failed to store keys: %w", err)
	}

	return sealKeyShares, nil
}

// RotateBarrierKey rotates the barrier key of the given namespace.
// It will return an error if the given namespace is not a sealable namespace.
func (sm *SealManager) RotateBarrierKey(ctx context.Context, ns *namespace.Namespace) error {
	sm.lock.RLock()
	defer sm.lock.RUnlock()

	b := sm.namespaceBarrier(ns.Path)
	if b == nil {
		return ErrNotSealable
	}

	newTerm, err := b.Rotate(ctx, sm.core.secureRandomReader)
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
			if err := b.DestroyUpgrade(sm.core.activeContext, newTerm); err != nil {
				sm.logger.Error("failed to destroy upgrade", "term", newTerm, "error", err, "namespace", ns.Path)
			}
		})
	}

	// Write to the canary path, which will force a synchronous truing
	// during replication
	keyringCanaryEntry := &logical.StorageEntry{
		Key:   path.Join(NamespaceStoragePathPrefix(ns), coreKeyringCanaryPath),
		Value: fmt.Appendf(nil, "new-rotation-term-%d", newTerm),
	}

	if err := b.Put(ctx, keyringCanaryEntry); err != nil {
		sm.logger.Error("error saving keyring canary", "error", err, "namespace", ns.Path)
		return fmt.Errorf("failed to save keyring canary: %w", err)
	}

	return nil
}
