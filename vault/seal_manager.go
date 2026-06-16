// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"sync"

	"github.com/armon/go-radix"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/go-uuid"
	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/sdk/v2/helper/shamir"
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
	barrierByNamespacePath       *radix.Tree

	// logger is the server logger copied over from core
	logger hclog.Logger
}

// NewSealManager creates a new seal manager with core reference and logger.
func NewSealManager(core *Core, logger hclog.Logger) *SealManager {
	return &SealManager{
		core: core,
		barrierByNamespacePath: radix.NewFromMap(map[string]interface{}{
			"": core.barrier,
		}),
		sealByNamespace: map[string]Seal{
			namespace.RootNamespaceUUID: core.seal,
		},
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

// sealAll seals barriers of all namespaces and resets seal manager state.
func (sm *SealManager) sealAll() error {
	var errs error
	sm.barrierByNamespacePath.Walk(func(path string, b interface{}) bool {
		if b != nil {
			errs = errors.Join(errs, b.(barrier.SecurityBarrier).Seal())
		}
		return false
	})

	sm.Reset()
	return errs
}

// Reset clears rotation and unlock internal states.
func (sm *SealManager) Reset() {
	sm.unlockInformationByNamespace = map[string]*unlockInformation{}
	sm.rotationConfigByNamespace = map[string]*rotationConfig{}
}

// SetSeal creates a seal with provided config and sets it as provided namespace seal;
// Initializes seal, creating security barrier and persisting seal config.
func (sm *SealManager) SetSeal(ctx context.Context, sealConfig *SealConfig, ns *namespace.Namespace, writeToStorage bool) error {
	sm.lock.Lock()
	defer sm.lock.Unlock()

	// Check if we have the seal present; if so, don't set any seal
	// information as we don't want to overwrite what we have.
	if _, ok := sm.sealByNamespace[ns.UUID]; ok {
		return nil
	}

	if err := sealConfig.Validate(); err != nil {
		return fmt.Errorf("invalid seal configuration: %w", err)
	}

	metaPrefix := NamespaceStoragePathPrefix(ns)

	// Seal type would depend on the provided arguments
	defaultSeal := NewDefaultSeal(vaultseal.NewAccess(vaultseal.NewShamirWrapper()))
	defaultSeal.SetCore(sm.core)
	defaultSeal.SetMetaPrefix(metaPrefix)

	// The configuration access should always at least use the parent's seal
	// configuration information.
	parent, ok := ns.ParentPath()
	if !ok {
		return fmt.Errorf("cannot seal the root namespace via this approach")
	}
	parentBarrier := sm.namespaceBarrierByLongestPrefix(parent)
	defaultSeal.SetConfigAccess(parentBarrier)

	ctx = namespace.ContextWithNamespace(ctx, ns)
	if err := defaultSeal.Init(ctx); err != nil {
		return fmt.Errorf("error initializing seal: %w", err)
	}

	nsBarrier := barrier.NewAESGCMBarrier(sm.core.physical, ns)
	sm.barrierByNamespacePath.Insert(ns.Path, nsBarrier)
	sm.sealByNamespace[ns.UUID] = defaultSeal

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
	sm.barrierByNamespacePath.Delete(ns.Path)
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
	_, v, exists := sm.barrierByNamespacePath.LongestPrefix(nsPath)
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
	v, exists := sm.barrierByNamespacePath.Get(nsPath)
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

// UnsealNamespace unseals the barrier of the given namespace
// using provided key shares.
func (sm *SealManager) UnsealNamespace(ctx context.Context, ns *namespace.Namespace, key []byte) (bool, error) {
	sm.lock.Lock()
	defer sm.lock.Unlock()

	sm.logger.Debug("namespace unseal key supplied")

	barrier := sm.namespaceBarrier(ns.Path)
	if barrier == nil {
		return false, ErrNotSealable
	}

	// Check if already unsealed
	if !barrier.Sealed() {
		return true, nil
	}

	seal := sm.sealByNamespace[ns.UUID]
	if seal == nil {
		return false, ErrNotSealable
	}

	combinedKey, err := sm.unsealFragment(ctx, ns, seal, barrier, key)
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

// unsealFragment verifies and records one part of the unseal shares,
// and attempts to unseal the namespace.
func (sm *SealManager) unsealFragment(ctx context.Context, ns *namespace.Namespace, seal Seal, b barrier.SecurityBarrier, key []byte) ([]byte, error) {
	// Verify the key length
	min, max := b.KeyLength()
	max += shamir.ShareOverhead
	if len(key) < min {
		return nil, &ErrInvalidKey{fmt.Sprintf("key is shorter than minimum %d bytes", min)}
	}
	if len(key) > max {
		return nil, &ErrInvalidKey{fmt.Sprintf("key is longer than maximum %d bytes", max)}
	}

	newKey, err := sm.recordUnsealPart(ns, key)
	if !newKey || err != nil {
		return nil, err
	}

	// getUnsealKey returns either a recovery key
	// (in the case of an autoseal) or an unseal key (shamir).
	return sm.getUnsealKey(ctx, seal, ns)
}

// recordUnsealPart takes in a key fragment, and returns true if it's a new fragment.
func (sm *SealManager) recordUnsealPart(ns *namespace.Namespace, key []byte) (bool, error) {
	info := sm.unlockInformationByNamespace[ns.UUID]
	if info != nil {
		found := false
		for _, existing := range info.Parts {
			found = found || subtle.ConstantTimeCompare(existing, key) == 1
		}

		if found {
			return false, nil
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
	switch seal.BarrierType() {
	case vaultseal.WrapperTypeShamir:
		if useTestSeal {
			ns, err := namespace.FromContext(ctx)
			if err != nil {
				return nil, err
			}

			testseal := NewDefaultSeal(vaultseal.NewAccess(vaultseal.NewShamirWrapper()))
			testseal.SetCore(sm.core)
			testseal.SetMetaPrefix(NamespaceStoragePathPrefix(ns))
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
		if err := seal.VerifyRecoveryKey(ctx, combinedKey); err != nil {
			return nil, fmt.Errorf("recovery key verification failed: %w", err)
		}
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

	rootKey, err := sm.unsealKeyToRootKey(ctx, seal, combinedKey, true, false)
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

	if seal.BarrierType() == vaultseal.WrapperTypeShamir {
		sealKey, sealKeyShares, err = sm.core.generateShares(sealConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to generate namespace seal key: %w", err)
		}
	}

	barrierKey, err := b.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate namespace barrier key: %w", err)
	}

	if err := b.Initialize(ctx, barrierKey, sealKey); err != nil {
		return nil, fmt.Errorf("failed to initialize namespace barrier: %w", err)
	}

	if err := b.Unseal(ctx, barrierKey); err != nil {
		return nil, fmt.Errorf("failed to unseal namespace barrier: %w", err)
	}

	if seal.BarrierType() == vaultseal.WrapperTypeShamir {
		shamirWrapper, err := seal.GetShamirWrapper()
		if err != nil {
			return nil, fmt.Errorf("unable to get shamir wrapper: %w", err)
		}
		if err := shamirWrapper.SetAesGcmKeyBytes(sealKey); err != nil {
			return nil, fmt.Errorf("failed to set seal key: %w", err)
		}
	}

	if err := seal.SetStoredKeys(ctx, [][]byte{barrierKey}); err != nil {
		return nil, fmt.Errorf("failed to store keys: %w", err)
	}

	return sealKeyShares, nil
}

// UnsealWithRootKey is used for standby<->active key sharing, passing root
// keys via the request forwarding mechanism.
func (sm *SealManager) UnsealWithRootKey(ctx context.Context, ns *namespace.Namespace, rootKey []byte) error {
	sm.lock.Lock()
	defer sm.lock.Unlock()

	sm.logger.Debug("namespace root key supplied")

	barrier := sm.namespaceBarrier(ns.Path)
	if barrier == nil {
		return ErrNotSealable
	}

	// Check if already unsealed
	if !barrier.Sealed() {
		return nil
	}

	if err := barrier.Unseal(ctx, rootKey); err != nil {
		return err
	}

	sm.logger.Info("unsealed namespace", "namespace", ns.Path)

	return nil
}

// NamespacesWithKeys is a list of namespace UUIDs which have been unsealed.
func (sm *SealManager) NamespacesWithKeys() []string {
	sm.lock.RLock()
	defer sm.lock.RUnlock()

	var namespaces []string
	sm.barrierByNamespacePath.Walk(func(_ string, b interface{}) bool {
		if b == nil {
			return false
		}

		nsBarrier := b.(barrier.SecurityBarrier)
		ns := nsBarrier.Namespace()
		if nsBarrier.Sealed() || ns.UUID == namespace.RootNamespaceUUID {
			// Skip sealed or root namespaces
			return false
		}

		namespaces = append(namespaces, ns.UUID)
		return false
	})

	return namespaces
}

// NamespacesMissingKeys is a list of namespace UUIDs which are currently sealed.
func (sm *SealManager) NamespacesMissingKeys() []string {
	sm.lock.RLock()
	defer sm.lock.RUnlock()

	var namespaces []string
	sm.barrierByNamespacePath.Walk(func(_ string, b interface{}) bool {
		if b == nil {
			return false
		}

		nsBarrier := b.(barrier.SecurityBarrier)
		ns := nsBarrier.Namespace()
		if !nsBarrier.Sealed() || ns.UUID == namespace.RootNamespaceUUID {
			// Skip unsealed or root namespaces.
			return false
		}

		namespaces = append(namespaces, ns.UUID)
		return false
	})

	return namespaces
}

// GetRootKey yields the underlying root key of the barrier for the given
// namespace.
func (sm *SealManager) GetRootKey(ctx context.Context, ns *namespace.Namespace) ([]byte, error) {
	sm.lock.Lock()
	defer sm.lock.Unlock()

	if ns.ID == namespace.RootNamespaceID {
		return nil, errors.New("refusing to return root namespace's root key")
	}

	v, exists := sm.barrierByNamespacePath.Get(ns.Path)
	if !exists {
		return nil, ErrNotInit
	}

	b := v.(barrier.SecurityBarrier)
	keyring, err := b.Keyring()
	if err != nil {
		return nil, err
	}

	return keyring.RootKey(), nil
}

// NamespacesWithKeys returns the list of namespaces with keys locally known
// by this node and are thus unsealed. This ignores non-sealed namespaces.
func (c *Core) NamespacesWithKeys() []string {
	c.stateLock.RLock()
	defer c.stateLock.RUnlock()

	activeCtx := c.activeContext.Load()
	if c.Sealed() || activeCtx.Err() != nil {
		return nil
	}

	return c.sealManager.NamespacesWithKeys()
}

// NamespacesMissingKeys returns the list of namespaces which are currently
// sealed and thus missing root keys.
func (c *Core) NamespacesMissingKeys() []string {
	c.stateLock.RLock()
	defer c.stateLock.RUnlock()

	activeCtx := c.activeContext.Load()
	if c.Sealed() || activeCtx.Err() != nil {
		return nil
	}

	return c.sealManager.NamespacesMissingKeys()
}

// namespaceUnsealKeyPath contain a formatting directive to allow binding the
// actual namespace's UUID to the AAD of the encryption context. These paths
// should not be used by actual system paths and are synthetically used by the
// external encryption exposed by the barrier.
const namespaceUnsealKeyPath = "[internal]core/namespace/forwarded-root-key/%v"

// SetNamespaceKeys loads keys sent via GRPC from the other node, which may
// be an active or standby node. Keys for namespaces which are already
// unsealed are ignored, though we try to filter these out to prevent them
// appearing on the wire.
//
// Most operations use the node's active context, but we check for rpc
// cancellation and bail early if necessary.
func (c *Core) SetNamespaceKeys(rpcCtx context.Context, keys map[string][]byte) error {
	c.stateLock.RLock()
	defer c.stateLock.RUnlock()

	activeCtx := c.activeContext.Load()
	if c.Sealed() || activeCtx.Err() != nil {
		return errors.New("instance is sealed or context is not yet active")
	}

	// We don't want to continue past rpcCtx, but also need to be terminated
	// by active context cancellation. Use the same trick as request
	// handling.
	ctx, cancel := context.WithCancel(activeCtx)
	stop := context.AfterFunc(rpcCtx, cancel)
	defer stop()

	var err error
	for uuid, encRootKey := range keys {
		rootKey, decErr := c.barrier.Decrypt(ctx, fmt.Sprintf(namespaceUnsealKeyPath, uuid), encRootKey)
		if decErr != nil {
			err = multierror.Append(err, fmt.Errorf("for namespace %v: failed to decrypt root key: %w", uuid, decErr))
			continue
		}

		ns, nsErr := c.namespaceStore.GetNamespace(ctx, uuid)
		if nsErr != nil {
			err = multierror.Append(err, fmt.Errorf("for namespace %v: %w", uuid, nsErr))
			continue
		}

		if ns.ManuallySealed {
			c.logger.Debug("skipping unsealing namespace which has been manually sealed", "path", ns.Path, "uuid", uuid)
			continue
		}

		// Because we have a root key here, we can't call UnsealNamespace(...)
		// as that expects a key share.
		if unsealErr := c.sealManager.UnsealWithRootKey(ctx, ns, rootKey); unsealErr != nil {
			err = multierror.Append(err, fmt.Errorf("for namespace %v: %w", uuid, unsealErr))
			continue
		}

		go func() {
			if err := c.namespaceStore.postNamespaceUnseal(c.activeContext.Load(), ns); err != nil {
				c.logger.Error("failed to load namespace after unseal", "error", err, "ns", uuid)
			}
		}()
	}

	return err
}

// NamespaceKeys returns the root keys for the given namespaces, encrypted
// with the barrier keyring. This ensures that, as long as the root barrier
// keyring's integrity remains, even keys over a compromised GRPC connection
// should remain secure, though we enforce TLS for GRPC everywhere.
func (c *Core) NamespaceKeys(rpcCtx context.Context, namespaces []string) (map[string][]byte, error) {
	c.stateLock.RLock()
	defer c.stateLock.RUnlock()

	activeCtx := c.activeContext.Load()
	if c.Sealed() || activeCtx.Err() != nil {
		return nil, errors.New("instance is sealed or context is not yet active")
	}

	// We don't want to continue past rpcCtx, but also need to be terminated
	// by active context cancellation. Use the same trick as request
	// handling.
	ctx, cancel := context.WithCancel(activeCtx)
	stop := context.AfterFunc(rpcCtx, cancel)
	defer stop()

	var errs error
	rootKeys := make(map[string][]byte, len(namespaces))

	for _, uuid := range namespaces {
		ns, err := c.namespaceStore.GetNamespace(ctx, uuid)
		switch {
		case err != nil:
			errs = multierror.Append(errs, fmt.Errorf("for namespace %v: %w", uuid, err))
			continue
		case ns == nil:
			continue
		}

		rootKey, err := c.sealManager.GetRootKey(ctx, ns)
		switch {
		case errors.Is(err, barrier.ErrBarrierSealed):
			continue
		case err != nil:
			errs = multierror.Append(errs, fmt.Errorf("for namespace %v: %w", uuid, err))
			continue
		}

		encRootKey, err := c.barrier.Encrypt(ctx, fmt.Sprintf(namespaceUnsealKeyPath, uuid), rootKey)
		if err != nil {
			errs = multierror.Append(errs, fmt.Errorf("for namespace %v: failed to encrypt root key: %w", uuid, err))
		}

		rootKeys[uuid] = encRootKey
	}

	return rootKeys, errs
}
