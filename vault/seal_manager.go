package vault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/armon/go-radix"
	"github.com/hashicorp/go-hclog"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
	aeadwrapper "github.com/openbao/go-kms-wrapping/wrappers/aead/v2"
	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/sdk/v2/physical"
	"github.com/openbao/openbao/vault/seal"
	vaultseal "github.com/openbao/openbao/vault/seal"
)

// SealManager is used to provide storage for the seals.
// It's a singleton that associates seals (configs) to the namespaces.
type SealManager struct {
	core *Core

	// lock        sync.RWMutex
	// invalidated atomic.Bool

	sealsByNamespace     map[string][]Seal
	barrierByNamespace   *radix.Tree
	barrierByStoragePath *radix.Tree

	// logger is the server logger copied over from core
	logger hclog.Logger
}

// NewSealManager creates a new seal manager with core reference and logger.
func NewSealManager(core *Core, logger hclog.Logger) (*SealManager, error) {
	return &SealManager{
		core:                 core,
		sealsByNamespace:     make(map[string][]Seal),
		barrierByNamespace:   radix.New(),
		barrierByStoragePath: radix.New(),
		logger:               logger,
	}, nil
}

// setupSealManager is used to initialize the seal manager
// when the vault is being unsealed.
func (c *Core) setupSealManager() error {
	var err error
	sealLogger := c.baseLogger.Named("seal")
	c.AddLogger(sealLogger)
	c.sealManager, err = NewSealManager(c, sealLogger)
	c.sealManager.barrierByNamespace.Insert("", c.barrier)
	c.sealManager.barrierByStoragePath.Insert("", c.barrier)
	c.sealManager.barrierByStoragePath.Insert("core/seal-config", nil)
	return err
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
	sm.sealsByNamespace[ns.UUID] = []Seal{defaultSeal}
	if err := defaultSeal.SetConfig(ctx, sealConfig); err != nil {
		return fmt.Errorf("failed to set config: %w", err)
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

	_, v, _ := sm.barrierByNamespace.LongestPrefix(parentPath)
	barrier := v.(SecurityBarrier)
	return barrier
}

func (sm *SealManager) NamespaceBarrier(ns *namespace.Namespace) SecurityBarrier {
	_, v, _ := sm.barrierByNamespace.LongestPrefix(ns.Path)
	barrier := v.(SecurityBarrier)

	return barrier
}

// UnsealNamespace unseals the barrier of the given namespace
// TODO(wslabosz): as the seals is a shamir, we should track the progress of the unsealing
func (sm *SealManager) UnsealNamespace(ctx context.Context, path string, key []byte) error {
	v, exists := sm.barrierByNamespace.Get(path)
	if !exists {
		return errors.New("barrier for the namespace doesn't exist")
	}

	s := v.(SecurityBarrier)
	if !s.Sealed() {
		return nil
	}

	err := s.Unseal(ctx, key)
	return err
}

// NamespaceView finds the correct barrier to use for the namespace and returns
// the a BarrierView restricted to the data of the given namespace.
func (c *Core) NamespaceView(ns *namespace.Namespace) BarrierView {
	barrier := c.sealManager.NamespaceBarrier(ns)
	return NamespaceView(barrier, ns)
}

// RemoveNamespace removes the given namespace and all of its children from the
// SealManager's internal state.
func (sm *SealManager) RemoveNamespace(ns *namespace.Namespace) error {
	sm.barrierByNamespace.DeletePrefix(ns.Path)
	return nil
}

func (sm *SealManager) InitializeBarrier(ctx context.Context, ns *namespace.Namespace) ([][]byte, error) {
	nsSeal := sm.sealsByNamespace[ns.UUID][0]
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
	case seal.StoredKeysSupportedShamirRoot:
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
	case seal.StoredKeysSupportedGeneric:
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
