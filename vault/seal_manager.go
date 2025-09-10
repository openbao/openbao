// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/armon/go-radix"
	"github.com/hashicorp/go-hclog"
	uuid "github.com/hashicorp/go-uuid"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
	aeadwrapper "github.com/openbao/go-kms-wrapping/wrappers/aead/v2"
	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/sdk/v2/helper/shamir"
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

	// this additional map[string] layer on both seals and
	// unlockInformation is a map of distinct (named) seals
	sealsByNamespace             map[string]map[string]Seal
	unlockInformationByNamespace map[string]map[string]*unlockInformation
	rotationConfigByNamespace    map[string]map[string]*rotationConfig
	barrierByNamespace           *radix.Tree
	barrierByStoragePath         *radix.Tree

	// logger is the server logger copied over from core
	logger hclog.Logger
}

// NewSealManager creates a new seal manager with core reference and logger.
func NewSealManager(core *Core, logger hclog.Logger) *SealManager {
	return &SealManager{
		core:                         core,
		sealsByNamespace:             make(map[string]map[string]Seal),
		unlockInformationByNamespace: make(map[string]map[string]*unlockInformation),
		rotationConfigByNamespace:    make(map[string]map[string]*rotationConfig),
		logger:                       logger,
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

// setup is used to initialize the internal structsof a sealManager.
func (sm *SealManager) setup() {
	sm.barrierByNamespace = radix.NewFromMap(map[string]interface{}{
		"": sm.core.barrier,
	})
	sm.barrierByStoragePath = radix.NewFromMap(map[string]interface{}{
		"":             sm.core.barrier,
		sealConfigPath: nil,
	})

	sm.sealsByNamespace[namespace.RootNamespaceUUID] = map[string]Seal{"default": sm.core.seal}
	sm.unlockInformationByNamespace[namespace.RootNamespaceUUID] = map[string]*unlockInformation{}
	sm.rotationConfigByNamespace[namespace.RootNamespaceUUID] = map[string]*rotationConfig{
		"default": {
			rootConfig:     nil,
			recoveryConfig: nil,
		},
	}
}

// Reset seals all namespaces (beside root) and calls the
// `(*SealManager) setupSealManager` to overwrite the internal
// storage of a sealManger with a default values for root namespace.
func (sm *SealManager) Reset(ctx context.Context) error {
	// starting from root, but it will be omitted
	err := sm.SealNamespace(namespace.RootContext(ctx), namespace.RootNamespace)
	if err != nil {
		return err
	}

	sm.lock.Lock()
	defer sm.lock.Unlock()

	sm.setup()

	return nil
}

// SetSeal creates a seal using provided config and sets and initializes it
// as a seal of a provided namespace, creating the barrier and persisting config.
func (sm *SealManager) SetSeal(ctx context.Context, sealConfig *SealConfig, ns *namespace.Namespace, writeToStorage bool) error {
	sm.lock.Lock()
	defer sm.lock.Unlock()

	sealConfig.StoredShares = 1
	if err := sealConfig.Validate(); err != nil {
		return fmt.Errorf("invalid seal configuration: %w", err)
	}

	metaPrefix := namespaceBarrierPrefix + ns.UUID + "/"

	// Seal type would depend on the provided arguments
	defaultSeal := NewDefaultSeal(vaultseal.NewAccess(aeadwrapper.NewShamirWrapper()))
	defaultSeal.SetCore(sm.core)
	defaultSeal.SetMetaPrefix(metaPrefix)

	ctx = namespace.ContextWithNamespace(ctx, ns)
	if err := defaultSeal.Init(ctx); err != nil {
		return fmt.Errorf("error initializing seal: %w", err)
	}

	barrier := NewAESGCMBarrier(sm.core.physical, metaPrefix)

	sm.barrierByNamespace.Insert(ns.Path, barrier)
	sm.barrierByStoragePath.Insert(metaPrefix, barrier)

	parentPath, ok := ns.ParentPath()
	if ok {
		_, parentBarrier, exists := sm.barrierByNamespace.LongestPrefix(parentPath)
		if exists {
			sm.barrierByStoragePath.Insert(metaPrefix+sealConfigPath, parentBarrier.(SecurityBarrier))
		}
	}

	sm.sealsByNamespace[ns.UUID] = map[string]Seal{"default": defaultSeal}
	sm.unlockInformationByNamespace[ns.UUID] = map[string]*unlockInformation{}
	sm.rotationConfigByNamespace[ns.UUID] = map[string]*rotationConfig{
		"default": {
			rootConfig:     nil,
			recoveryConfig: nil,
		},
	}

	if writeToStorage {
		if err := defaultSeal.SetConfig(ctx, sealConfig); err != nil {
			return fmt.Errorf("failed to set barrier config: %w", err)
		}
	}

	return nil
}

// RemoveNamespace removes the given namespace from the SealManager's internal state.
func (sm *SealManager) RemoveNamespace(ns *namespace.Namespace) {
	nsSeal := sm.NamespaceSeal(ns.UUID)
	if nsSeal == nil {
		return
	}

	sm.sealsByNamespace[ns.UUID] = nil
	sm.unlockInformationByNamespace[ns.UUID] = nil
	sm.rotationConfigByNamespace[ns.UUID] = nil
	sm.barrierByNamespace.Delete(ns.Path)
	sm.barrierByStoragePath.Delete(nsSeal.MetaPrefix())
	sm.barrierByStoragePath.Delete(nsSeal.MetaPrefix() + sealConfigPath)
}

// StorageAccessForPath takes a path string and returns back a storage access interface
// which is either a SecurityBarrier existing "on a specified path", or a direct storage
// physical backend whenever there's no security barrier, and we need to access the storage
// layer directly (e.g. reading entries that are cannot be encrypted by the barrier).
func (sm *SealManager) StorageAccessForPath(path string) StorageAccess {
	_, v, _ := sm.barrierByStoragePath.LongestPrefix(path)
	if v == nil {
		return &directStorageAccess{physical: sm.core.physical}
	}
	barrier := v.(SecurityBarrier)
	return &secureStorageAccess{barrier: barrier}
}

// SealNamespace seals the barrier of the given namespace and all of its children.
func (sm *SealManager) SealNamespace(ctx context.Context, nsToSeal *namespace.Namespace) error {
	sm.lock.RLock()
	defer sm.lock.RUnlock()

	var errs error
	sm.barrierByNamespace.WalkPrefix(nsToSeal.Path, func(namespacePath string, barrier any) bool {
		// always omit the root namespace
		if namespacePath == "" {
			return false
		}

		s := barrier.(SecurityBarrier)
		if s.Sealed() {
			return false
		}

		ns, err := sm.core.namespaceStore.getNamespaceByPathLocked(ctx, namespacePath, false)
		if err != nil {
			errs = errors.Join(errs, err)
		}
		if ns == nil {
			errs = errors.Join(errs, fmt.Errorf("namespace not found for path: %s", namespacePath))
		}

		ctx = namespace.ContextWithNamespace(ctx, ns)
		if err := sm.core.namespaceStore.clearNamespacePolicies(ctx, ns, false); err != nil {
			errs = errors.Join(errs, err)
		}
		if err := sm.core.namespaceStore.UnloadNamespaceCredentials(ctx, ns); err != nil {
			errs = errors.Join(errs, err)
		}
		if err := sm.core.namespaceStore.UnloadNamespaceMounts(ctx, ns); err != nil {
			errs = errors.Join(errs, err)
		}
		if err = s.Seal(); err != nil {
			errs = errors.Join(errs, err)
		}

		return false
	})

	return errs
}

// NamespaceBarrierByLongestPrefix acquires a read lock, and returns barrier of a
// namespace matching the longest prefix of the provided path, going up to root
// namespace.
func (sm *SealManager) NamespaceBarrierByLongestPrefix(nsPath string) SecurityBarrier {
	_, v, _ := sm.barrierByNamespace.LongestPrefix(nsPath)
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

// NamespaceSeal acquires a read lock and returns a seal of a namespace with
// provided uuid.
// TODO(wslabosz): adjust with parallel unsealing
func (sm *SealManager) NamespaceSeal(nsUUID string) Seal {
	sm.lock.RLock()
	defer sm.lock.RUnlock()

	return sm.namespaceSeal(nsUUID)
}

// NamespaceSeal returns a seal of a namespace with provided uuid.
func (sm *SealManager) namespaceSeal(nsUUID string) Seal {
	s, exists := sm.sealsByNamespace[nsUUID]["default"]
	if !exists {
		return nil
	}

	return s
}

// ResetUnsealProcess removes the current unlock parts from memory,
// to reset the unsealing process of a specified namespace.
func (sm *SealManager) ResetUnsealProcess(nsUUID string) {
	sm.lock.Lock()
	defer sm.lock.Unlock()

	sm.unlockInformationByNamespace[nsUUID]["default"] = nil
}

// NamespaceUnlockInformation acquires a read lock and returns the
// number of keys provided so far of a namespace with provided uuid.
// TODO(wslabosz): adjust with parallel unsealing
func (sm *SealManager) NamespaceUnlockInformation(nsUUID string) *unlockInformation {
	sm.lock.RLock()
	defer sm.lock.RUnlock()

	return sm.namespaceUnlockInformation(nsUUID)
}

// namespaceUnlockInformation returns an unlock information of a namespace
// with provided uuid.
func (sm *SealManager) namespaceUnlockInformation(nsUUID string) *unlockInformation {
	info, exists := sm.unlockInformationByNamespace[nsUUID]["default"]
	if !exists {
		return nil
	}

	return info
}

// GetSealStatus returns back seal status of a namespace with unlock progress information.
func (sm *SealManager) GetSealStatus(ctx context.Context, ns *namespace.Namespace) (*SealStatusResponse, error) {
	sm.lock.RLock()
	defer sm.lock.RUnlock()

	// Verify that any kind of seal exists for a namespace
	seal := sm.namespaceSeal(ns.UUID)
	if seal == nil {
		return nil, ErrNotSealable
	}

	// Check the barrier first
	barrier := sm.namespaceBarrier(ns.Path)
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
	sealConf, err := seal.Config(ctx)
	if err != nil {
		return nil, err
	}
	if sealConf == nil {
		return nil, errors.New("namespace barrier reports initialized but no seal configuration found")
	}

	var progress int
	var nonce string
	info := sm.namespaceUnlockInformation(ns.UUID)
	if info != nil {
		progress, nonce = len(info.Parts), info.Nonce
	}

	s := &SealStatusResponse{
		Type:        sealConf.Type,
		Initialized: init,
		Sealed:      barrier.Sealed(),
		T:           sealConf.SecretThreshold,
		N:           sealConf.SecretShares,
		Progress:    progress,
		Nonce:       nonce,
		Version:     version.GetVersion().VersionNumber(),
		BuildDate:   version.BuildDate,
	}

	return s, nil
}

// UnsealNamespace unseals the barrier of the given namespace
func (sm *SealManager) UnsealNamespace(ctx context.Context, ns *namespace.Namespace, key []byte) (bool, error) {
	sm.lock.Lock()
	defer sm.lock.Unlock()

	barrier := sm.namespaceBarrier(ns.Path)
	if barrier == nil {
		return false, ErrNotSealable
	}

	return sm.unsealFragment(ctx, ns, barrier, key)
}

// unsealFragment verifies and records one part of the unseal shares,
// and attempts to unseal the namespace
func (sm *SealManager) unsealFragment(ctx context.Context, ns *namespace.Namespace, barrier SecurityBarrier, key []byte) (bool, error) {
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

	seal := sm.namespaceSeal(ns.UUID)
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
func (sm *SealManager) recordUnsealPart(ns *namespace.Namespace, key []byte) (bool, error) {
	info, exists := sm.unlockInformationByNamespace[ns.UUID]["default"]
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
		sm.unlockInformationByNamespace[ns.UUID]["default"] = info
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

	info := sm.namespaceUnlockInformation(ns.UUID)
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
		delete(sm.unlockInformationByNamespace[ns.UUID], "default")
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
func (sm *SealManager) AuthenticateRootKey(ctx context.Context, ns *namespace.Namespace, combinedKey []byte) error {
	sm.lock.RLock()
	defer sm.lock.RUnlock()

	nsSeal := sm.namespaceSeal(ns.UUID)
	if nsSeal == nil {
		return ErrNotSealable
	}

	rootKey, err := sm.unsealKeyToRootKey(ctx, nsSeal, combinedKey, false, false)
	if err != nil {
		return fmt.Errorf("unable to authenticate: %w", err)
	}

	nsBarrier := sm.namespaceBarrier(ns.Path)
	if nsBarrier == nil {
		return ErrNotSealable
	}

	if err := nsBarrier.VerifyRoot(rootKey); err != nil {
		return fmt.Errorf("root key verification failed: %w", err)
	}

	return nil
}

// NamespaceView finds the correct barrier to use for the namespace
// and returns BarrierView restricted to the data of the given namespace.
func (c *Core) NamespaceView(ns *namespace.Namespace) BarrierView {
	barrier := c.sealManager.NamespaceBarrierByLongestPrefix(ns.Path)
	return NamespaceView(barrier, ns)
}

func (sm *SealManager) InitializeBarrier(ctx context.Context, ns *namespace.Namespace) ([][]byte, error) {
	sm.lock.RLock()
	defer sm.lock.RUnlock()

	nsSeal := sm.namespaceSeal(ns.UUID)
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

	nsBarrier := sm.namespaceBarrier(ns.Path)
	if nsBarrier == nil {
		return nil, ErrNotSealable
	}

	if err := nsBarrier.Initialize(ctx, nsBarrierKey, nsSealKey, sm.core.secureRandomReader); err != nil {
		return nil, fmt.Errorf("failed to initialize namespace barrier: %w", err)
	}

	if err := nsBarrier.Unseal(ctx, nsBarrierKey); err != nil {
		return nil, fmt.Errorf("failed to unseal namespace barrier: %w", err)
	}

	if err := sm.core.namespaceStore.initializeNamespace(ctx, ns); err != nil {
		return nil, fmt.Errorf("failed to initialize namespace: %w", err)
	}

	if err := sm.SealNamespace(ctx, ns); err != nil {
		return nil, fmt.Errorf("failed to seal namespace barrier: %w", err)
	}

	results := &InitResult{
		SecretShares: [][]byte{},
	}

	switch nsSeal.StoredKeysSupported() {
	case vaultseal.StoredKeysSupportedShamirRoot:
		keysToStore := [][]byte{nsBarrierKey}
		shamirWrapper, err := nsSeal.GetShamirWrapper()
		if err != nil {
			return nil, fmt.Errorf("unable to get shamir wrapper: %w", err)
		}
		if err := shamirWrapper.SetAesGcmKeyBytes(nsSealKey); err != nil {
			return nil, fmt.Errorf("failed to set seal key: %w", err)
		}
		if err := nsSeal.SetStoredKeys(ctx, keysToStore); err != nil {
			return nil, fmt.Errorf("failed to store keys: %w", err)
		}
		results.SecretShares = nsSealKeyShares
	case vaultseal.StoredKeysSupportedGeneric:
		keysToStore := [][]byte{nsBarrierKey}
		if err := nsSeal.SetStoredKeys(ctx, keysToStore); err != nil {
			return nil, fmt.Errorf("failed to store keys: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported stored keys type encountered: %w", err)
	}

	return nsSealKeyShares, nil
}

// RegisterNamespace is used to register the seals (by looking up the seal configs)
// of namespaces after core unseal.
func (sm *SealManager) RegisterNamespace(ctx context.Context, ns *namespace.Namespace) (bool, error) {
	// Get the storage path for this namespace's seal config
	sealConfigPath := sm.core.NamespaceView(ns).SubView(sealConfigPath).Prefix()

	// Get access via the parent barrier
	storage := sm.StorageAccessForPath(sealConfigPath)
	configBytes, err := storage.Get(namespace.ContextWithNamespace(ctx, ns), sealConfigPath)
	if err != nil {
		return false, err
	}

	// No seal config found - not sealable namespace
	if configBytes == nil {
		return false, nil
	}

	var sealConfig SealConfig
	if err := json.Unmarshal(configBytes, &sealConfig); err != nil {
		return false, fmt.Errorf("failed to decode namespace seal config: %w", err)
	}

	return true, sm.SetSeal(ctx, &sealConfig, ns, false)
}

// RotateNamespaceBarrierKey rotates the barrier key of the given namespace.
// It will return an error if the given namespace is not a sealable namespace.
func (sm *SealManager) RotateNamespaceBarrierKey(ctx context.Context, namespace *namespace.Namespace) error {
	nsBarrier := sm.NamespaceBarrier(namespace.Path)
	if nsBarrier == nil {
		return ErrNotSealable
	}

	_, err := nsBarrier.Rotate(ctx, sm.core.secureRandomReader)
	return err
}
