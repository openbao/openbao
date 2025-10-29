// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/armon/go-radix"
	"github.com/hashicorp/go-hclog"
	uuid "github.com/hashicorp/go-uuid"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
	aeadwrapper "github.com/openbao/go-kms-wrapping/wrappers/aead/v2"
	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/sdk/v2/helper/shamir"
	"github.com/openbao/openbao/sdk/v2/logical"
	vaultseal "github.com/openbao/openbao/vault/seal"
	"github.com/openbao/openbao/version"
)

var ErrNotSealable = errors.New("namespace is not sealable")

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

// SealManager is used to provide storage for the seals.
// It's a singleton that associates seals (configs) to the namespaces.
// It is also responsible for managing the seal state on the namespaces.
type SealManager struct {
	core *Core

	lock sync.RWMutex
	// invalidated atomic.Bool
	rotationConfigByNamespace map[string]map[string]*rotationConfig
	barrierByNamespace        *radix.Tree

	// logger is the server logger copied over from core
	logger hclog.Logger
}

// NewSealManager creates a new seal manager with core reference and logger.
func NewSealManager(core *Core, logger hclog.Logger) *SealManager {
	return &SealManager{
		core:                      core,
		logger:                    logger,
		rotationConfigByNamespace: make(map[string]map[string]*rotationConfig),
	}
}

// SetupSealManager is used to initialize the seal manager
// on vault core creation.
func (c *Core) SetupSealManager() {
	sealLogger := c.baseLogger.Named("seal")
	c.AddLogger(sealLogger)
	c.sealManager = NewSealManager(c, sealLogger)
	c.sealManager.setup()
}

// setup is used to initialize the internal structs of a sealManager.
func (sm *SealManager) setup() {
	sm.barrierByNamespace = radix.NewFromMap(map[string]interface{}{
		"": sm.core.barrier,
	})
	sm.rotationConfigByNamespace = make(map[string]map[string]*rotationConfig)
}

// Reset seals all namespaces (except root) and calls the
// `(*SealManager) setupSealManager` to overwrite the internal
// storage of a sealManger with a default values for root namespace.
func (sm *SealManager) Reset(ctx context.Context) error {
	if sm.core.namespaceStore == nil {
		return nil
	}

	unlock, err := sm.core.namespaceStore.lockWithInvalidation(ctx, false)
	if err != nil {
		return err
	}
	defer unlock()

	// providing root namespace to the function, but it will be omitted from actual sealing
	if err := sm.core.namespaceStore.sealNamespaceLocked(ctx, namespace.RootNamespace); err != nil {
		return err
	}

	sm.lock.Lock()
	defer sm.lock.Unlock()
	sm.setup()
	return nil
}

// SetSeal creates a seal using provided config and sets and initializes it
// as a seal of a provided namespace, creating the barrier and persisting config.
func (sm *SealManager) SetSeal(ctx context.Context, sealConfig *SealConfig, ns *Namespace, writeToStorage bool) error {
	sm.lock.Lock()
	defer sm.lock.Unlock()

	sealConfig.StoredShares = 1
	if err := sealConfig.Validate(); err != nil {
		return fmt.Errorf("invalid seal configuration: %w", err)
	}

	metaPrefix := namespaceLogicalStoragePath(ns.Namespace)

	// Seal type would depend on the provided arguments
	defaultSeal := NewDefaultSeal(vaultseal.NewAccess(aeadwrapper.NewShamirWrapper()))
	defaultSeal.SetCore(sm.core)
	defaultSeal.SetMetaPrefix(metaPrefix)

	// At this point, the namespace's barrier is still the parent's barrier,
	// hence we can just query that without computing the actual parent.
	defaultSeal.SetConfigAccess(sm.namespaceBarrierByLongestPrefix(ns.Path))

	ctx = namespace.ContextWithNamespace(ctx, ns.Namespace)
	if err := defaultSeal.Init(ctx); err != nil {
		return fmt.Errorf("error initializing seal: %w", err)
	}

	barrier := NewAESGCMBarrier(sm.core.physical, metaPrefix)

	// Store seal information in the namespace wrapper
	ns.sealLock.Lock()
	ns.seal = defaultSeal
	ns.sealConfig = sealConfig
	ns.barrier = barrier
	ns.unsealProgress = 0
	ns.unsealKeys = nil
	ns.unsealNonce = ""
	ns.sealLock.Unlock()

	sm.barrierByNamespace.Insert(ns.Path, barrier)

	if writeToStorage {
		if err := defaultSeal.SetConfig(ctx, sealConfig); err != nil {
			return fmt.Errorf("failed to set barrier config: %w", err)
		}
	}

	return nil
}

// RemoveNamespace removes the given namespace from the SealManager's internal state.
func (sm *SealManager) RemoveNamespace(ns *Namespace) {
	sm.lock.Lock()
	defer sm.lock.Unlock()

	if ns == nil || ns.Namespace == nil {
		return
	}

	// Clear seal state from namespace
	ns.sealLock.Lock()
	ns.seal = nil
	ns.sealConfig = nil
	ns.barrier = nil
	ns.unsealKeys = nil
	ns.unsealProgress = 0
	ns.unsealNonce = ""
	ns.sealLock.Unlock()

	sm.barrierByNamespace.Delete(ns.Path)
}

// NamespaceView finds the correct barrier to use for the namespace
// and returns BarrierView restricted to the logical.Storage space
// of the given namespace.
func (c *Core) NamespaceView(ns *namespace.Namespace) BarrierView {
	barrier := c.sealManager.NamespaceBarrierByLongestPrefix(ns.Path)
	return NamespaceView(barrier, ns)
}

// NamespaceBarrierByLongestPrefix acquires a read lock, and returns barrier of
// a namespace matching the longest prefix of the provided path, going up to root
// namespace.
func (sm *SealManager) NamespaceBarrierByLongestPrefix(nsPath string) SecurityBarrier {
	sm.lock.RLock()
	defer sm.lock.RUnlock()

	return sm.namespaceBarrierByLongestPrefix(nsPath)
}

// namespaceBarrierByLongestPrefix returns barrier of a namespace matching the
// longest prefix of the provided path, going up to root namespace.
func (sm *SealManager) namespaceBarrierByLongestPrefix(nsPath string) SecurityBarrier {
	_, v, exists := sm.barrierByNamespace.LongestPrefix(nsPath)
	if !exists {
		return nil
	}
	return v.(SecurityBarrier)
}

// NamespaceBarrier acquires a read lock and returns a barrier
// of a namespace with provided path.
func (sm *SealManager) NamespaceBarrier(nsPath string) SecurityBarrier {
	sm.lock.RLock()
	defer sm.lock.RUnlock()

	return sm.namespaceBarrier(nsPath)
}

// namespaceBarrier returns a barrier of a namespace with provided path.
func (sm *SealManager) namespaceBarrier(nsPath string) SecurityBarrier {
	v, exists := sm.barrierByNamespace.Get(nsPath)
	if !exists {
		return nil
	}

	return v.(SecurityBarrier)
}

// NamespaceSeal acquires a read lock and returns a seal of a namespace.
// TODO(wslabosz): adjust with parallel unsealing
func (sm *SealManager) NamespaceSeal(nsUUID string) Seal {
	sm.lock.RLock()
	defer sm.lock.RUnlock()

	return sm.namespaceSeal(nsUUID)
}

// namespaceSeal returns a seal of a namespace with provided uuid.
func (sm *SealManager) namespaceSeal(nsUUID string) Seal {
	// Seal is now stored in the namespace object itself
	// This is a transitional method - in the future, callers should
	// access the namespace directly
	ns, err := sm.core.namespaceStore.GetNamespace(context.Background(), nsUUID)
	if err != nil || ns == nil {
		return nil
	}

	// Note: This is a temporary approach. Ideally, SealManager should
	// receive the Namespace wrapper directly in most operations.
	ns.sealLock.RLock()
	seal := ns.seal
	ns.sealLock.RUnlock()

	return seal
}

// ResetUnsealProcess removes the current unlock parts from memory,
// to reset the unsealing process of a specified namespace.
func (sm *SealManager) ResetUnsealProcess(ns *Namespace) {
	if ns == nil {
		return
	}

	ns.sealLock.Lock()
	defer ns.sealLock.Unlock()

	ns.unsealKeys = nil
	ns.unsealProgress = 0
	ns.unsealNonce = ""
}

// NamespaceUnlockInformation acquires a read lock and returns the
// number of keys provided so far of a namespace.
// TODO(wslabosz): adjust with parallel unsealing
func (sm *SealManager) NamespaceUnlockInformation(ns *Namespace) *unlockInformation {
	if ns == nil {
		return nil
	}

	ns.sealLock.RLock()
	defer ns.sealLock.RUnlock()

	if ns.unsealProgress == 0 && ns.unsealNonce == "" && len(ns.unsealKeys) == 0 {
		return nil
	}

	return &unlockInformation{
		Parts: ns.unsealKeys,
		Nonce: ns.unsealNonce,
	}
}

// GetSealStatus returns back seal status of a namespace with unlock progress information.
func (sm *SealManager) GetSealStatus(ctx context.Context, ns *Namespace) (*SealStatusResponse, error) {
	sm.lock.RLock()
	defer sm.lock.RUnlock()

	if ns == nil || ns.Namespace == nil {
		return nil, ErrNotSealable
	}

	// Read seal information from namespace
	ns.sealLock.RLock()
	seal := ns.seal
	barrier := ns.barrier
	sealConfig := ns.sealConfig
	progress := ns.unsealProgress
	nonce := ns.unsealNonce
	ns.sealLock.RUnlock()

	// Verify that any kind of seal exists for a namespace
	if seal == nil {
		return nil, ErrNotSealable
	}

	// Check the barrier first
	if barrier == nil {
		return nil, ErrNotSealable
	}

	init, err := barrier.Initialized(ctx)
	if err != nil {
		sm.logger.Error("namespace barrier init check failed", "namespace", ns.Path, "error", err)
		return nil, err
	}
	if !init {
		sm.logger.Info("namespace security barrier not initialized", "namespace", ns.Path)
		return nil, ErrBarrierNotInit
	}

	// Verify the seal configuration
	if sealConfig == nil {
		var err error
		sealConfig, err = seal.Config(ctx)
		if err != nil {
			return nil, err
		}
	}
	if sealConfig == nil {
		return nil, errors.New("namespace barrier reports initialized but no seal configuration found")
	}

	s := &SealStatusResponse{
		Type:        sealConfig.Type,
		Initialized: init,
		Sealed:      barrier.Sealed(),
		T:           sealConfig.SecretThreshold,
		N:           sealConfig.SecretShares,
		Progress:    progress,
		Nonce:       nonce,
		Version:     version.GetVersion().VersionNumber(),
		BuildDate:   version.BuildDate,
	}

	return s, nil
}

// UnsealNamespace unseals the barrier of the given namespace
func (sm *SealManager) UnsealNamespace(ctx context.Context, ns *Namespace, key []byte) (bool, error) {
	sm.lock.Lock()
	defer sm.lock.Unlock()

	if ns == nil || ns.Namespace == nil {
		return false, ErrNotSealable
	}

	ns.sealLock.RLock()
	barrier := ns.barrier
	ns.sealLock.RUnlock()

	if barrier == nil {
		return false, ErrNotSealable
	}

	return sm.unsealFragment(ctx, ns, barrier, key)
}

// unsealFragment verifies and records one part of the unseal shares,
// and attempts to unseal the namespace
func (sm *SealManager) unsealFragment(ctx context.Context, ns *Namespace, barrier SecurityBarrier, key []byte) (bool, error) {
	sm.logger.Debug("namespace unseal key supplied")

	// Check if already unsealed
	if !barrier.Sealed() {
		return true, nil
	}

	// Verify the key length
	min, max := barrier.KeyLength()
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

	ns.sealLock.RLock()
	seal := ns.seal
	ns.sealLock.RUnlock()

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
	if err := barrier.Unseal(ctx, rootKey); err != nil {
		return false, err
	}

	sm.logger.Info("unsealed namespace", "namespace", ns.Path)

	return true, nil
}

// recordUnsealPart takes in a key fragment, and returns true if it's a new fragment.
func (sm *SealManager) recordUnsealPart(ns *Namespace, key []byte) (bool, error) {
	if ns == nil {
		return false, errors.New("namespace is nil")
	}

	ns.sealLock.Lock()
	defer ns.sealLock.Unlock()

	// Check for duplicate
	for _, existing := range ns.unsealKeys {
		if subtle.ConstantTimeCompare(existing, key) == 1 {
			return false, nil
		}
	}

	// Generate nonce if first part
	if ns.unsealNonce == "" {
		u, err := uuid.GenerateUUID()
		if err != nil {
			return false, err
		}
		ns.unsealNonce = u
	}

	// Store this key
	ns.unsealKeys = append(ns.unsealKeys, key)
	ns.unsealProgress = len(ns.unsealKeys)

	return true, nil
}

// getUnsealKey uses key fragments recorded by recordUnsealPart and
// returns the combined key if the key share threshold is met.
// If the key fragments are part of a recovery key, also verify that
// it matches the stored recovery key on disk.
func (sm *SealManager) getUnsealKey(ctx context.Context, seal Seal, ns *Namespace) ([]byte, error) {
	var sealConfig *SealConfig
	var err error

	raftInfo := sm.core.raftInfo.Load().(*raftInformation)

	switch {
	case seal.RecoveryKeySupported():
		sealConfig, err = seal.RecoveryConfig(ctx)
	case sm.core.isRaftUnseal():
		// Ignore follower's seal config and refer to leader's barrier
		// configuration.
		sealConfig = raftInfo.leaderBarrierConfig
	default:
		sealConfig, err = seal.Config(ctx)
	}

	if err != nil {
		return nil, err
	}
	if sealConfig == nil {
		return nil, errors.New("failed to obtain seal/recovery configuration")
	}

	// Get unlock information from namespace
	ns.sealLock.RLock()
	parts := make([][]byte, len(ns.unsealKeys))
	copy(parts, ns.unsealKeys)
	nonce := ns.unsealNonce
	progress := ns.unsealProgress
	ns.sealLock.RUnlock()

	if progress == 0 {
		return nil, errors.New("no unlock information found for namespace")
	}

	// Check if we don't have enough keys to unlock, proceed through the rest of
	// the call only if we have met the threshold
	if len(parts) < sealConfig.SecretThreshold {
		sm.logger.Debug("cannot unseal namespace, not enough keys", "keys", len(parts),
			"threshold", sealConfig.SecretThreshold, "nonce", nonce)
		return nil, nil
	}

	// Clear unseal information after threshold is met
	defer func() {
		ns.sealLock.Lock()
		ns.unsealKeys = nil
		ns.unsealProgress = 0
		ns.unsealNonce = ""
		ns.sealLock.Unlock()
	}()

	// Recover the split key. recoveredKey is the shamir combined
	// key, or the single provided key if the threshold is 1.
	var unsealKey []byte
	if sealConfig.SecretThreshold == 1 {
		unsealKey = make([]byte, len(parts[0]))
		copy(unsealKey, parts[0])
	} else {
		unsealKey, err = shamir.Combine(parts)
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
			testseal := NewDefaultSeal(vaultseal.NewAccess(aeadwrapper.NewShamirWrapper()))
			testseal.SetCore(sm.core)
			cfg, err := seal.Config(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to setup test barrier config: %w", err)
			}
			testseal.SetCachedConfig(cfg)
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

// AuthenticateRootKey verifies retrieved root key (using unseal key)
// using the namespace barrier
func (sm *SealManager) AuthenticateRootKey(ctx context.Context, ns *Namespace, combinedKey []byte) error {
	sm.lock.RLock()
	defer sm.lock.RUnlock()

	if ns == nil || ns.Namespace == nil {
		return ErrNotSealable
	}

	ns.sealLock.RLock()
	nsSeal := ns.seal
	nsBarrier := ns.barrier
	ns.sealLock.RUnlock()

	if nsSeal == nil {
		return ErrNotSealable
	}

	rootKey, err := sm.unsealKeyToRootKey(ctx, nsSeal, combinedKey, false, false)
	if err != nil {
		return fmt.Errorf("unable to authenticate: %w", err)
	}

	if nsBarrier == nil {
		return ErrNotSealable
	}

	if err := nsBarrier.VerifyRoot(rootKey); err != nil {
		return fmt.Errorf("root key verification failed: %w", err)
	}

	return nil
}

func (sm *SealManager) InitializeBarrier(ctx context.Context, ns *Namespace) ([][]byte, error) {
	sm.lock.RLock()
	defer sm.lock.RUnlock()

	if ns == nil || ns.Namespace == nil {
		return nil, ErrNotSealable
	}

	ns.sealLock.RLock()
	nsSeal := ns.seal
	nsBarrier := ns.barrier
	ns.sealLock.RUnlock()

	if nsSeal == nil {
		return nil, ErrNotSealable
	}

	sealConfig, err := nsSeal.Config(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve seal config: %w", err)
	}

	nsBarrierKey, _, err := sm.core.generateShares(sealConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to generate namespace barrier key: %w", err)
	}

	var nsSealKey []byte
	var nsSealKeyShares [][]byte

	if sealConfig.StoredShares == 1 && nsSeal.WrapperType() == wrapping.WrapperTypeShamir {
		nsSealKey, nsSealKeyShares, err = sm.core.generateShares(sealConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to generate namespace seal key: %w", err)
		}
	}

	if nsBarrier == nil {
		return nil, ErrNotSealable
	}

	if err := nsBarrier.Initialize(ctx, nsBarrierKey, nsSealKey, sm.core.secureRandomReader); err != nil {
		return nil, fmt.Errorf("failed to initialize namespace barrier: %w", err)
	}

	if err := nsBarrier.Unseal(ctx, nsBarrierKey); err != nil {
		return nil, fmt.Errorf("failed to unseal namespace barrier: %w", err)
	}

	if err := sm.core.namespaceStore.initializeNamespace(ctx, ns.Namespace); err != nil {
		return nil, fmt.Errorf("failed to initialize namespace: %w", err)
	}

	if err := sm.core.namespaceStore.SealNamespace(ctx, ns.Path); err != nil {
		return nil, fmt.Errorf("failed to seal namespace: %w", err)
	}

	switch nsSeal.StoredKeysSupported() {
	case vaultseal.StoredKeysSupportedShamirRoot:
		shamirWrapper, err := nsSeal.GetShamirWrapper()
		if err != nil {
			return nil, fmt.Errorf("unable to get shamir wrapper: %w", err)
		}
		if err := shamirWrapper.SetAesGcmKeyBytes(nsSealKey); err != nil {
			return nil, fmt.Errorf("failed to set seal key: %w", err)
		}
	case vaultseal.StoredKeysSupportedGeneric:
	default:
		return nil, fmt.Errorf("unsupported stored keys type encountered: %w", err)
	}

	keysToStore := [][]byte{nsBarrierKey}
	if err := nsSeal.SetStoredKeys(ctx, keysToStore); err != nil {
		return nil, fmt.Errorf("failed to store keys: %w", err)
	}

	return nsSealKeyShares, nil
}

// RotateNamespaceBarrierKey rotates the barrier key of the given namespace.
// It will return an error if the given namespace is not a sealable namespace.
func (sm *SealManager) RotateNamespaceBarrierKey(ctx context.Context, ns *Namespace) error {
	sm.lock.RLock()
	defer sm.lock.RUnlock()

	if ns == nil || ns.Namespace == nil {
		return ErrNotSealable
	}

	ns.sealLock.RLock()
	barrier := ns.barrier
	ns.sealLock.RUnlock()

	if barrier == nil {
		return ErrNotSealable
	}

	newTerm, err := barrier.Rotate(ctx, sm.core.secureRandomReader)
	if err != nil {
		return fmt.Errorf("failed to create new encryption key: %w", err)
	}
	sm.logger.Info("installed new encryption key")

	// In HA mode, we need to an upgrade path for the standby instances
	// we are using the same key rotate grace period for all namespaces for now.
	if sm.core.ha != nil && sm.core.KeyRotateGracePeriod() > 0 {
		// Create the upgrade path to the new term
		if err := barrier.CreateUpgrade(ctx, newTerm); err != nil {
			sm.logger.Error("failed to create new upgrade", "term", newTerm, "error", err, "namespace", ns.Path)
		}

		// Schedule the destroy of the upgrade path
		time.AfterFunc(sm.core.KeyRotateGracePeriod(), func() {
			sm.logger.Debug("cleaning up upgrade keys", "waited", sm.core.KeyRotateGracePeriod())
			if err := barrier.DestroyUpgrade(sm.core.activeContext, newTerm); err != nil {
				sm.logger.Error("failed to destroy upgrade", "term", newTerm, "error", err, "namespace", ns.Path)
			}
		})
	}

	// Write to the canary path, which will force a synchronous truing
	// during replication
	keyringCanaryEntry := &logical.StorageEntry{
		Key:   namespaceLogicalStoragePath(ns.Namespace) + coreKeyringCanaryPath,
		Value: fmt.Appendf(nil, "new-rotation-term-%d", newTerm),
	}

	if err := barrier.Put(ctx, keyringCanaryEntry); err != nil {
		sm.logger.Error("error saving keyring canary", "error", err, "namespace", ns.Path)
		return fmt.Errorf("failed to save keyring canary: %w", err)
	}

	return nil
}
