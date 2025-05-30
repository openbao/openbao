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
		barrierByNamespace:           radix.New(),
		barrierByStoragePath:         radix.New(),
		logger:                       logger,
	}
}

// setupSealManager is used to initialize the seal manager
// when the vault is being unsealed.
func (c *Core) setupSealManager() {
	sealLogger := c.baseLogger.Named("seal")
	c.AddLogger(sealLogger)
	c.sealManager = NewSealManager(c, sealLogger)
	c.sealManager.barrierByNamespace.Insert("", c.barrier)
	c.sealManager.barrierByStoragePath.Insert("", c.barrier)
	c.sealManager.barrierByStoragePath.Insert("core/seal-config", nil)

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
func (sm *SealManager) SetSeal(ctx context.Context, sealConfig *SealConfig, ns *namespace.Namespace) error {
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

	barrier := NewAESGCMBarrier(sm.core.physical, metaPrefix)

	// barrier.Initialize(ctx context.Context, rootKey []byte, sealKey []byte, random io.Reader)
	sm.barrierByNamespace.Insert(ns.Path, barrier)
	sm.barrierByStoragePath.Insert(metaPrefix, barrier)
	parentBarrier := sm.ParentNamespaceBarrier(ns)
	if parentBarrier != nil {
		sm.barrierByStoragePath.Insert(metaPrefix+sealConfigPath, parentBarrier)
	}

	sm.sealsByNamespace[ns.UUID] = map[string]Seal{"default": defaultSeal}
	sm.unlockInformationByNamespace[ns.UUID] = map[string]*unlockInformation{}
	err := defaultSeal.SetConfig(ctx, sealConfig)
	if err != nil {
		return fmt.Errorf("failed to set barrier config: %w", err)
	}

	return nil
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

// SealNamespace seals the barriers of the given namespace and all of its children.
func (sm *SealManager) SealNamespace(ns *namespace.Namespace) error {
	var errs error
	sm.barrierByNamespace.WalkPrefix(ns.Path, func(p string, v any) bool {
		s := v.(SecurityBarrier)
		if s.Sealed() {
			return false
		}
		err := s.Seal()
		if err != nil {
			errs = errors.Join(errs, err)
		}

		return false
	})

	return errs
}

func (sm *SealManager) ParentNamespaceBarrier(ns *namespace.Namespace) SecurityBarrier {
	parentPath, ok := ns.ParentPath()
	if !ok {
		return nil
	}

	return sm.NamespaceBarrier(parentPath)
}

func (sm *SealManager) NamespaceBarrier(nsPath string) SecurityBarrier {
	// this should acquire a lock
	_, v, _ := sm.barrierByNamespace.LongestPrefix(nsPath)
	barrier := v.(SecurityBarrier)

	return barrier
}

// SecretProgress returns the number of keys provided so far. Lock
// should only be false if the caller is already holding the read
// statelock (such as calls originating from switchedLockHandleRequest).
func (sm *SealManager) SecretProgress(ns *namespace.Namespace, lock bool) (int, string) {
	if lock {
		sm.lock.RLock()
		defer sm.lock.RUnlock()
	}
	switch sm.unlockInformationByNamespace[ns.UUID]["default"] {
	case nil:
		return 0, ""
	default:
		return len(sm.unlockInformationByNamespace[ns.UUID]["default"].Parts), sm.unlockInformationByNamespace[ns.UUID]["default"].Nonce
	}
}

func (sm *SealManager) GetSealStatus(ctx context.Context, ns *namespace.Namespace, lock bool) (*SealStatusResponse, error) {
	// Check the barrier first
	barrier := sm.NamespaceBarrier(ns.Path)

	init, err := barrier.Initialized(ctx)
	if err != nil {
		sm.logger.Error("namespace barrier init check failed", "namespace", ns.Path, "error", err)
		return nil, err
	}
	if !init {
		sm.logger.Info("namespace security barrier not initialized", "namespace", ns.Path)
		return nil, nil
	}

	seal := sm.sealsByNamespace[ns.UUID]["default"]
	// Verify the seal configuration
	sealConf, err := seal.Config(ctx)
	if err != nil {
		return nil, err
	}
	if sealConf == nil {
		return nil, errors.New("namespace barrier reports initialized but no seal configuration found")
	}

	progress, nonce := sm.SecretProgress(ns, lock)

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
func (sm *SealManager) UnsealNamespace(ctx context.Context, ns *namespace.Namespace, key []byte) error {
	v, exists := sm.barrierByNamespace.Get(ns.Path)
	if !exists {
		return errors.New("barrier for the namespace doesn't exist")
	}

	s := v.(SecurityBarrier)
	return sm.unsealFragment(ctx, ns, s, key)
}

func (sm *SealManager) unsealFragment(ctx context.Context, ns *namespace.Namespace, barrier SecurityBarrier, key []byte) error {
	sm.lock.Lock()
	defer sm.lock.Unlock()

	sm.logger.Debug("namespace unseal key supplied")

	// Check if already unsealed
	if !barrier.Sealed() {
		return nil
	}

	// Verify the key length
	min, max := barrier.KeyLength()
	max += shamir.ShareOverhead
	if len(key) < min {
		return &ErrInvalidKey{fmt.Sprintf("key is shorter than minimum %d bytes", min)}
	}
	if len(key) > max {
		return &ErrInvalidKey{fmt.Sprintf("key is longer than maximum %d bytes", max)}
	}

	newKey, err := sm.recordUnsealPart(ns, key)
	if !newKey || err != nil {
		return err
	}

	seal := sm.sealsByNamespace[ns.UUID]["default"]

	// getUnsealKey returns either a recovery key (in the case of an autoseal)
	// or an unseal key (new-style shamir).
	combinedKey, err := sm.getUnsealKey(ctx, seal, ns)
	if err != nil || combinedKey == nil {
		return err
	}

	// allow missing?
	rootKey, err := sm.unsealKeyToRootKey(ctx, seal, combinedKey, true)
	if err != nil {
		return err
	}

	// Attempt to unlock
	if err := barrier.Unseal(ctx, rootKey); err != nil {
		return err
	}

	sm.logger.Debug("namespace is unsealed")

	return nil
}

// recordUnsealPart takes in a key fragment, and returns true if it's a new fragment.
func (sm *SealManager) recordUnsealPart(ns *namespace.Namespace, key []byte) (bool, error) {
	// Check if we already have this piece
	if sm.unlockInformationByNamespace[ns.UUID]["default"] != nil {
		for _, existing := range sm.unlockInformationByNamespace[ns.UUID]["default"].Parts {
			if subtle.ConstantTimeCompare(existing, key) == 1 {
				return false, nil
			}
		}
	} else {
		uuid, err := uuid.GenerateUUID()
		if err != nil {
			return false, err
		}
		sm.unlockInformationByNamespace[ns.UUID]["default"] = &unlockInformation{
			Nonce: uuid,
		}
	}

	// Store this key
	sm.unlockInformationByNamespace[ns.UUID]["default"].Parts = append(sm.unlockInformationByNamespace[ns.UUID]["default"].Parts, key)
	return true, nil
}

// getUnsealKey uses key fragments recorded by recordUnsealPart and
// returns the combined key if the key share threshold is met.
// If the key fragments are part of a recovery key, also verify that
// it matches the stored recovery key on disk.
func (sm *SealManager) getUnsealKey(ctx context.Context, seal Seal, ns *namespace.Namespace) ([]byte, error) {
	sealConfig, err := seal.Config(ctx)
	if err != nil {
		return nil, err
	}
	if sealConfig == nil {
		return nil, errors.New("failed to obtain seal configuration")
	}

	// Check if we don't have enough keys to unlock, proceed through the rest of
	// the call only if we have met the threshold
	if len(sm.unlockInformationByNamespace[ns.UUID]["default"].Parts) < sealConfig.SecretThreshold {
		sm.logger.Debug("cannot unseal namespace, not enough keys", "keys", len(sm.unlockInformationByNamespace[ns.UUID]["default"].Parts),
			"threshold", sealConfig.SecretThreshold, "nonce", sm.unlockInformationByNamespace[ns.UUID]["default"].Nonce)
		return nil, nil
	}

	defer func() {
		sm.unlockInformationByNamespace[ns.UUID]["default"] = nil
	}()

	// Recover the split key. recoveredKey is the shamir combined
	// key, or the single provided key if the threshold is 1.
	var unsealKey []byte
	if sealConfig.SecretThreshold == 1 {
		unsealKey = make([]byte, len(sm.unlockInformationByNamespace[ns.UUID]["default"].Parts[0]))
		copy(unsealKey, sm.unlockInformationByNamespace[ns.UUID]["default"].Parts[0])
	} else {
		unsealKey, err = shamir.Combine(sm.unlockInformationByNamespace[ns.UUID]["default"].Parts)
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
// If allowMissing is true, a failure to find the root key in storage results
// in a nil error and a nil root key being returned.
func (sm *SealManager) unsealKeyToRootKey(ctx context.Context, seal Seal, combinedKey []byte, allowMissing bool) ([]byte, error) {
	if seal.StoredKeysSupported() == vaultseal.StoredKeysSupportedShamirRoot {
		shamirWrapper, err := seal.GetShamirWrapper()
		if err != nil {
			return nil, err
		}

		err = shamirWrapper.SetAesGcmKeyBytes(combinedKey)
		if err != nil {
			return nil, &ErrInvalidKey{fmt.Sprintf("failed to setup unseal key: %v", err)}
		}

		storedKeys, err := seal.GetStoredKeys(ctx)
		if storedKeys == nil && err == nil && allowMissing {
			return nil, nil
		}

		if err == nil && len(storedKeys) != 1 {
			err = fmt.Errorf("expected exactly one stored key, got %d", len(storedKeys))
		}
		if err != nil {
			return nil, fmt.Errorf("unable to retrieve stored keys: %w", err)
		}
		return storedKeys[0], nil
	}

	return nil, errors.New("invalid seal")
}

// NamespaceView finds the correct barrier to use for the namespace and returns
// the a BarrierView restricted to the data of the given namespace.
func (c *Core) NamespaceView(ns *namespace.Namespace) BarrierView {
	barrier := c.sealManager.NamespaceBarrier(ns.Path)
	return NamespaceView(barrier, ns)
}

// RemoveNamespace removes the given namespace and all of its children from the
// SealManager's internal state.
func (sm *SealManager) RemoveNamespace(ns *namespace.Namespace) error {
	sm.barrierByNamespace.DeletePrefix(ns.Path)
	return nil
}

func (sm *SealManager) InitializeBarrier(ctx context.Context, ns *namespace.Namespace) ([][]byte, error) {
	nsSeal := sm.sealsByNamespace[ns.UUID]["default"]
	if nsSeal == nil {
		return nil, errors.New("namespace is not sealable")
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

	var nsSecurityBarrier SecurityBarrier

	if nsBarrier, found := sm.barrierByNamespace.Get(ns.Path); found {
		nsSecurityBarrier = nsBarrier.(SecurityBarrier)
		if err := nsSecurityBarrier.Initialize(ctx, nsBarrierKey, nsSealKey, sm.core.secureRandomReader); err != nil {
			return nil, fmt.Errorf("failed to initialize namespace barrier: %w", err)
		}
	} else {
		return nil, fmt.Errorf("namespace barrier not found: %w", err)
	}

	if err := nsSecurityBarrier.Unseal(ctx, nsBarrierKey); err != nil {
		return nil, fmt.Errorf("failed to unseal namespace barrier: %w", err)
	}

	// TODO: Seal the barrier again

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

func (sm *SealManager) ExtractSealConfigs(seals interface{}) ([]*SealConfig, error) {
	sealsArray, ok := seals.([]interface{})
	var sealConfigs []*SealConfig
	if !ok {
		return nil, fmt.Errorf("seals is not an array")
	}

	for _, seal := range sealsArray {
		sealMap, ok := seal.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("seal is not a map")
		}

		byteSeal, err := json.Marshal(sealMap)
		if err != nil {
			return nil, err
		}

		var sealConfig SealConfig
		err = json.Unmarshal(byteSeal, &sealConfig)
		if err != nil {
			return nil, err
		}

		sealConfigs = append(sealConfigs, &sealConfig)
	}
	return sealConfigs, nil
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
