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
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/sdk/v2/physical"
	vaultseal "github.com/openbao/openbao/vault/seal"
	"github.com/openbao/openbao/version"
)

var (
	ErrNotSealable               = errors.New("namespace is not sealable")
	ErrUnlockInformationNotFound = errors.New("no unlock information found for namespace")
)

// SealManager is used to provide storage for the seals.
// It's a singleton that associates seals (configs) to the namespaces.
// It is also responsible for managing the seal state on the namespaces.
type SealManager struct {
	core *Core

	lock sync.RWMutex
	// invalidated atomic.Bool

	entries *radix.Tree

	// logger is the server logger copied over from core
	logger hclog.Logger
}

type sealableNamespace struct {
	barrier  SecurityBarrier
	seals    map[string]Seal
	progress map[string]*unsealProgress
}

// NewSealManager creates a new seal manager with core reference and logger.
func NewSealManager(core *Core, logger hclog.Logger) *SealManager {
	return &SealManager{
		core:    core,
		logger:  logger,
		entries: radix.New(),
	}
}

// setupSealManager is used to initialize the seal manager
// when the vault is being unsealed.
func (c *Core) setupSealManager() {
	logger := c.baseLogger.Named("seal")
	c.AddLogger(logger)

	c.sealManager = NewSealManager(c, logger)

	// Add the root namespace by default.
	c.sealManager.entries.Insert("", &sealableNamespace{
		barrier:  c.barrier,
		seals:    map[string]Seal{"default": c.seal},
		progress: map[string]*unsealProgress{},
	})
}

// teardownSealManager is used to remove seal manager
// when the vault is being sealed.
func (c *Core) teardownSealManager() error {
	// seal all namespaces
	// TODO: this probably does not work out of the box
	// c.sealManager.SealNamespace(namespace.RootNamespace)
	c.sealManager = nil
	return nil
}

// TODO(wslabosz): add logs
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

	if err := defaultSeal.Init(ctx); err != nil {
		return fmt.Errorf("error initializing seal: %w", err)
	}

	sm.entries.Insert(ns.Path, &sealableNamespace{
		barrier:  NewAESGCMBarrier(sm.core.physical, metaPrefix),
		seals:    map[string]Seal{"default": defaultSeal},
		progress: map[string]*unsealProgress{},
	})

	if writeToStorage {
		if err := defaultSeal.SetConfig(ctx, sealConfig); err != nil {
			return fmt.Errorf("failed to set barrier config: %w", err)
		}
	}

	return nil
}

// StorageAccessForPath takes a path string and returns back a storage access interface
// which is either a SecurityBarrier existing "on a specified path", or a direct storage
// physical backend whenever there's no security barrier, and we need to access the storage
// layer directly (e.g. reading entries that are cannot be encrypted by the barrier).
func (sm *SealManager) StorageAccessForPath(ctx context.Context, path string) (StorageAccess, error) {
	// Interpolate absolute storage path -> namespace path
	ns, path, err := sm.core.NamespaceByStoragePath(ctx, path)
	if err != nil {
		return nil, err
	}

	_, v, _ := sm.entries.LongestPrefix(ns.Path)
	sealable := v.(*sealableNamespace)

	if path != sealConfigPath {
		// Not the seal config path, just use the namespace's closest barrier.
		return &secureStorageAccess{barrier: sealable.barrier}, nil
	}

	if parentPath, _ := ns.ParentPath(); parentPath == "" {
		// Root namespace -> direct access to physical needed.
		return &directStorageAccess{physical: sm.core.physical}, nil
	} else {
		// Otherwise, use the parent namespace's barrier.
		_, v, _ = sm.entries.LongestPrefix(parentPath)
		parentSealable := v.(*sealableNamespace)
		return &secureStorageAccess{barrier: parentSealable.barrier}, nil
	}
}

// SealNamespace seals the barriers of the given namespace and all of its children.
func (sm *SealManager) SealNamespace(ctx context.Context, ns *namespace.Namespace) error {
	sm.lock.RLock()
	defer sm.lock.RUnlock()

	var errs error
	sm.entries.WalkPrefix(ns.Path, func(p string, v any) bool {
		barrier := v.(sealableNamespace).barrier
		if barrier.Sealed() {
			return false
		}
		descendantNamespace, err := sm.core.namespaceStore.getNamespaceByPathLocked(ctx, namespace.Canonicalize(p), false)
		if err != nil {
			errs = errors.Join(errs, err)
		}
		if descendantNamespace == nil {
			errs = errors.Join(errs, fmt.Errorf("namespace not found for path: %s", p))
		}
		if err := sm.core.namespaceStore.clearNamespacePolicies(ctx, descendantNamespace, false); err != nil {
			errs = errors.Join(errs, err)
		}
		if err := sm.core.namespaceStore.UnloadNamespaceCredentials(ctx, descendantNamespace); err != nil {
			errs = errors.Join(errs, err)
		}
		if err := sm.core.namespaceStore.UnloadNamespaceMounts(ctx, descendantNamespace); err != nil {
			errs = errors.Join(errs, err)
		}
		if err = barrier.Seal(); err != nil {
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
	sm.lock.RLock()
	defer sm.lock.RUnlock()

	_, v, _ := sm.entries.LongestPrefix(nsPath)
	return v.(*sealableNamespace).barrier
}

// NamespaceBarrier acquires a read lock and returns a barrier
// of a namespace with provided path.
func (sm *SealManager) NamespaceBarrier(nsPath string) (SecurityBarrier, error) {
	sm.lock.RLock()
	defer sm.lock.RUnlock()

	v, ok := sm.entries.Get(nsPath)
	if !ok {
		return nil, ErrNotSealable
	}

	return v.(*sealableNamespace).barrier, nil
}

// NamespaceSeal acquires a read lock and returns a seal of a namespace with
// provided uuid.
// TODO(wslabosz): adjust with parallel unsealing
func (sm *SealManager) NamespaceSeal(nsPath string) (Seal, SecurityBarrier, error) {
	sm.lock.RLock()
	defer sm.lock.RUnlock()

	v, ok := sm.entries.Get(nsPath)
	if !ok {
		return nil, nil, ErrNotSealable
	}

	sealable := v.(*sealableNamespace)
	return sealable.seals["default"], sealable.barrier, nil
}

func (sm *SealManager) GetSealStatus(ctx context.Context, ns *namespace.Namespace) (*SealStatusResponse, error) {
	sm.lock.RLock()
	defer sm.lock.RUnlock()

	v, ok := sm.entries.Get(ns.Path)
	if !ok {
		return nil, ErrNotSealable
	}

	sealable := v.(*sealableNamespace)
	// For now, always use the default seal (which we know exists).
	defaultSeal := sealable.seals["default"]

	init, err := sealable.barrier.Initialized(ctx)
	if err != nil {
		sm.logger.Error("namespace barrier init check failed", "namespace", ns.Path, "error", err)
		return nil, err
	}
	if !init {
		sm.logger.Info("namespace security barrier not initialized", "namespace", ns.Path)
		return nil, ErrBarrierNotInit
	}

	// Verify the seal configuration
	sealConf, err := defaultSeal.Config(ctx)
	if err != nil {
		return nil, err
	}
	if sealConf == nil {
		return nil, errors.New("namespace barrier reports initialized but no seal configuration found")
	}

	progress, nonce := 0, ""
	if info, ok := sealable.progress["default"]; ok {
		progress, nonce = len(info.Parts), info.Nonce
	}

	s := &SealStatusResponse{
		Type:        sealConf.Type,
		Initialized: init,
		Sealed:      sealable.barrier.Sealed(),
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

	v, ok := sm.entries.Get(ns.Path)
	if !ok {
		return false, ErrNotSealable
	}

	return sm.unsealFragment(ctx, ns, v.(*sealableNamespace), key)
}

// unsealFragment verifies and records one part of the unseal shares,
// and attempts to unseal the namespace
func (sm *SealManager) unsealFragment(ctx context.Context, ns *namespace.Namespace, sealable *sealableNamespace, key []byte) (bool, error) {
	sm.logger.Debug("namespace unseal key supplied")

	// Check if already unsealed
	if !sealable.barrier.Sealed() {
		return true, nil
	}

	// Verify the key length
	min, max := sealable.barrier.KeyLength()
	max += shamir.ShareOverhead
	if len(key) < min {
		return false, &ErrInvalidKey{fmt.Sprintf("key is shorter than minimum %d bytes", min)}
	}
	if len(key) > max {
		return false, &ErrInvalidKey{fmt.Sprintf("key is longer than maximum %d bytes", max)}
	}

	newKey, err := sealable.recordUnsealPart(ns, key)
	if !newKey || err != nil {
		return false, err
	}

	// For now, always use the default seal (which we know exists).
	seal := sealable.seals["default"]

	// getUnsealKey returns either a recovery key (in the case of an autoseal)
	// or an unseal key (new-style shamir).
	combinedKey, err := sealable.getUnsealKey(ctx, seal)
	if err != nil || combinedKey == nil {
		return false, err
	}

	rootKey, err := sm.unsealKeyToRootKey(ctx, seal, combinedKey, false, true)
	if err != nil {
		return false, err
	}

	// Attempt to unseal
	if err := sealable.barrier.Unseal(ctx, rootKey); err != nil {
		return false, err
	}

	sm.logger.Info("unsealed namespace", "namespace", ns.Path)

	return true, nil
}

// recordUnsealPart takes in a key fragment, and returns true if it's a new fragment.
func (s *sealableNamespace) recordUnsealPart(ns *namespace.Namespace, key []byte) (bool, error) {
	progress, exists := s.progress["default"]
	if exists {
		for _, existing := range progress.Parts {
			if subtle.ConstantTimeCompare(existing, key) == 1 {
				return false, nil
			}
		}
	} else {
		uuid, err := uuid.GenerateUUID()
		if err != nil {
			return false, err
		}
		progress = &unsealProgress{Nonce: uuid}
		s.progress["default"] = progress
	}

	// Store this key
	progress.Parts = append(progress.Parts, key)
	return true, nil
}

// getUnsealKey uses key fragments recorded by recordUnsealPart and
// returns the combined key if the key share threshold is met.
// If the key fragments are part of a recovery key, also verify that
// it matches the stored recovery key on disk.
func (s *sealableNamespace) getUnsealKey(ctx context.Context, seal Seal) ([]byte, error) {
	sealConfig, err := seal.Config(ctx)
	if err != nil {
		return nil, err
	}
	if sealConfig == nil {
		return nil, errors.New("failed to obtain seal configuration")
	}

	progress := s.progress["default"]
	if progress == nil {
		return nil, ErrUnlockInformationNotFound
	}

	// Check if we don't have enough keys to unlock, proceed through the rest of
	// the call only if we have met the threshold
	if len(progress.Parts) < sealConfig.SecretThreshold {
		return nil, nil
	}

	defer func() {
		delete(s.progress, "default")
	}()

	// Recover the split key. recoveredKey is the shamir combined
	// key, or the single provided key if the threshold is 1.
	var unsealKey []byte
	if sealConfig.SecretThreshold == 1 {
		unsealKey = make([]byte, len(progress.Parts[0]))
		copy(unsealKey, progress.Parts[0])
	} else {
		unsealKey, err = shamir.Combine(progress.Parts)
		if err != nil {
			return nil, &ErrInvalidKey{fmt.Sprintf("failed to compute combined key: %v", err)}
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

	v, ok := sm.entries.Get(ns.Path)
	if !ok {
		return ErrNotSealable
	}

	sealable := v.(*sealableNamespace)
	defaultSeal := sealable.seals["default"]

	rootKey, err := sm.unsealKeyToRootKey(ctx, defaultSeal, combinedKey, false, false)
	if err != nil {
		return fmt.Errorf("unable to authenticate: %w", err)
	}

	if err := sealable.barrier.VerifyRoot(rootKey); err != nil {
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

// RemoveNamespace removes the given namespace and all of its children from the
// SealManager's internal state.
func (sm *SealManager) RemoveNamespace(ns *namespace.Namespace) error {
	sm.lock.Lock()
	defer sm.lock.Unlock()

	sm.entries.DeletePrefix(ns.Path)
	return nil
}

func (sm *SealManager) InitializeBarrier(ctx context.Context, ns *namespace.Namespace) ([][]byte, error) {
	sm.lock.RLock()
	defer sm.lock.RUnlock()

	v, ok := sm.entries.Get(ns.Path)
	if !ok {
		return nil, ErrNotSealable
	}

	sealable := v.(*sealableNamespace)
	defaultSeal := sealable.seals["default"]

	sealConfig, err := defaultSeal.Config(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve seal config: %w", err)
	}

	nsBarrierKey, _, err := sm.core.generateShares(sealConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to generate namespace barrier key: %w", err)
	}

	var nsSealKey []byte
	var nsSealKeyShares [][]byte

	if sealConfig.StoredShares == 1 && defaultSeal.WrapperType() == wrapping.WrapperTypeShamir {
		nsSealKey, nsSealKeyShares, err = sm.core.generateShares(sealConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to generate namespace seal key: %w", err)
		}
	}

	if err := sealable.barrier.Initialize(ctx, nsBarrierKey, nsSealKey, sm.core.secureRandomReader); err != nil {
		return nil, fmt.Errorf("failed to initialize namespace barrier: %w", err)
	}

	if err := sealable.barrier.Unseal(ctx, nsBarrierKey); err != nil {
		return nil, fmt.Errorf("failed to unseal namespace barrier: %w", err)
	}

	// TODO: Seal the barrier again

	results := &InitResult{
		SecretShares: [][]byte{},
	}

	switch defaultSeal.StoredKeysSupported() {
	case vaultseal.StoredKeysSupportedShamirRoot:
		keysToStore := [][]byte{nsBarrierKey}
		shamirWrapper, err := defaultSeal.GetShamirWrapper()
		if err != nil {
			return nil, fmt.Errorf("unable to get shamir wrapper: %w", err)
		}
		if err := shamirWrapper.SetAesGcmKeyBytes(nsSealKey); err != nil {
			return nil, fmt.Errorf("failed to set seal key: %w", err)
		}
		if err := defaultSeal.SetStoredKeys(ctx, keysToStore); err != nil {
			return nil, fmt.Errorf("failed to store keys: %w", err)
		}
		results.SecretShares = nsSealKeyShares
	case vaultseal.StoredKeysSupportedGeneric:
		keysToStore := [][]byte{nsBarrierKey}
		if err := defaultSeal.SetStoredKeys(ctx, keysToStore); err != nil {
			return nil, fmt.Errorf("failed to store keys: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported stored keys type encountered: %w", err)
	}

	return nsSealKeyShares, nil
}

func (sm *SealManager) RegisterNamespace(ctx context.Context, ns *namespace.Namespace) (bool, error) {
	ctx = namespace.ContextWithNamespace(ctx, ns)

	// Get the storage path for this namespace's seal config
	sealConfigPath := sm.core.NamespaceView(ns).SubView(sealConfigPath).Prefix()

	// Get access via the parent barrier
	storage, err := sm.StorageAccessForPath(ctx, sealConfigPath)
	if err != nil {
		return false, err
	}

	configBytes, err := storage.Get(ctx, sealConfigPath)
	if err != nil {
		return false, err
	}

	// No seal config found - unsealed namespace
	if configBytes == nil {
		return false, nil
	}

	var sealConfig SealConfig
	if err := json.Unmarshal(configBytes, &sealConfig); err != nil {
		return false, fmt.Errorf("failed to decode namespace seal config: %w", err)
	}

	if err := sm.SetSeal(ctx, &sealConfig, ns, false); err != nil {
		return true, err
	}

	return true, nil
}

// RotateNamespaceBarrierKey rotates the barrier key of the given namespace.
// It will return an error if the given namespace is not a sealable namespace.
func (sm *SealManager) RotateNamespaceBarrierKey(ctx context.Context, namespace *namespace.Namespace) error {
	barrier, err := sm.NamespaceBarrier(namespace.Path)
	if err != nil {
		return err
	}

	_, err = barrier.Rotate(ctx, sm.core.secureRandomReader)
	return err
}

type StorageAccess interface {
	Put(context.Context, string, []byte) error
	Get(context.Context, string) ([]byte, error)
	Delete(context.Context, string) error
	ListPage(context.Context, string, string, int) ([]string, error)
}

var (
	_ StorageAccess = (*directStorageAccess)(nil)
	_ StorageAccess = (*secureStorageAccess)(nil)
)

type directStorageAccess struct {
	physical physical.Backend
}

func (p *directStorageAccess) Put(ctx context.Context, path string, value []byte) error {
	pe := &physical.Entry{
		Key:   path,
		Value: value,
	}
	return p.physical.Put(ctx, pe)
}

func (p *directStorageAccess) Get(ctx context.Context, path string) ([]byte, error) {
	pe, err := p.physical.Get(ctx, path)
	if err != nil {
		return nil, err
	}
	if pe == nil {
		return nil, nil
	}
	return pe.Value, nil
}

func (p *directStorageAccess) Delete(ctx context.Context, key string) error {
	return p.physical.Delete(ctx, key)
}

func (p *directStorageAccess) ListPage(ctx context.Context, prefix string, after string, limit int) ([]string, error) {
	return p.physical.ListPage(ctx, prefix, after, limit)
}

type secureStorageAccess struct {
	barrier SecurityBarrier
}

func (b *secureStorageAccess) Put(ctx context.Context, path string, value []byte) error {
	se := &logical.StorageEntry{
		Key:   path,
		Value: value,
	}
	return b.barrier.Put(ctx, se)
}

func (b *secureStorageAccess) Get(ctx context.Context, path string) ([]byte, error) {
	se, err := b.barrier.Get(ctx, path)
	if err != nil {
		return nil, err
	}
	if se == nil {
		return nil, nil
	}
	return se.Value, nil
}

func (b *secureStorageAccess) Delete(ctx context.Context, key string) error {
	return b.barrier.Delete(ctx, key)
}

func (b *secureStorageAccess) ListPage(ctx context.Context, prefix string, after string, limit int) ([]string, error) {
	return b.barrier.ListPage(ctx, prefix, after, limit)
}
