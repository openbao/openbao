package vault

import (
	"context"
	"errors"
	"fmt"

	"github.com/armon/go-radix"
	"github.com/hashicorp/go-hclog"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
	aeadwrapper "github.com/openbao/go-kms-wrapping/wrappers/aead/v2"
	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/vault/seal"
	vaultseal "github.com/openbao/openbao/vault/seal"
)

// SealManager is used to provide storage for the seals.
// It's a singleton that associates seals (configs) to the namespaces.
type SealManager struct {
	core *Core

	// lock        sync.RWMutex
	// invalidated atomic.Bool

	sealsByNamespace   map[string][]*Seal
	barrierByNamespace *radix.Tree

	// logger is the server logger copied over from core
	logger hclog.Logger
}

// NewSealManager creates a new seal manager with core reference and logger.
func NewSealManager(ctx context.Context, core *Core, logger hclog.Logger) (*SealManager, error) {
	return &SealManager{
		core:               core,
		sealsByNamespace:   make(map[string][]*Seal),
		barrierByNamespace: radix.New(),
		logger:             logger,
	}, nil
}

// setupSealManager is used to initialize the seal manager
// when the vault is being unsealed.
func (c *Core) setupSealManager(ctx context.Context) error {
	var err error
	sealLogger := c.baseLogger.Named("seal")
	c.AddLogger(sealLogger)
	c.sealManager, err = NewSealManager(ctx, c, sealLogger)
	c.sealManager.barrierByNamespace.Insert("", c.barrier)
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

	// Seal type would depend on the provided arguments
	defaultSeal := NewDefaultSeal(vaultseal.NewAccess(aeadwrapper.NewShamirWrapper()))
	defaultSeal.SetCore(sm.core)

	if err := defaultSeal.Init(ctx); err != nil {
		return fmt.Errorf("error initializing seal: %w", err)
	}

	barrier, err := NewAESGCMBarrier(sm.core.physical, namespaceBarrierPrefix+ns.UUID+"/")
	if err != nil {
		return fmt.Errorf("failed to construct namespace barrier: %w", err)
	}
	// barrier.Initialize(ctx context.Context, rootKey []byte, sealKey []byte, random io.Reader)
	sm.barrierByNamespace.Insert(ns.Path, barrier)
	sm.sealsByNamespace[ns.UUID] = []*Seal{&defaultSeal}
	err = defaultSeal.SetBarrierConfig(ctx, sealConfig, ns)
	if err != nil {
		return fmt.Errorf("failed to set barrier config: %w", err)
	}

	return nil
}

// SealNamespace seals the barriers of the given namespace and all of its children.
func (sm *SealManager) SealNamespace(ns *namespace.Namespace) error {
	var errs error
	sm.barrierByNamespace.WalkPrefix(ns.Path, func(p string, v any) bool {
		s := v.(SecurityBarrier)
		err := s.Seal()
		if err != nil {
			errs = errors.Join(errs, err)
		}

		return false
	})

	return errs
}

// NamespaceView finds the correct barrier to use for the namespace and returns
// the a BarrierView restricted to the data of the given namespace.
func (c *Core) NamespaceView(ns *namespace.Namespace) BarrierView {
	// TODO: NamespaceView is called somewhere before sealManager is
	// initialized. Figure out if we can fix the init sequence to make this go
	// away
	if c.sealManager == nil {
		return NamespaceView(c.barrier, ns)
	}
	_, v, _ := c.sealManager.barrierByNamespace.LongestPrefix(ns.Path)
	barrier := v.(SecurityBarrier)
	return NamespaceView(barrier, ns)
}

// RemoveNamespace removes the given namespace and all of its children from the
// SealManager's internal state.
func (sm *SealManager) RemoveNamespace(ns *namespace.Namespace) error {
	sm.barrierByNamespace.DeletePrefix(ns.Path)
	return nil
}

func (sm *SealManager) InitializeBarrier(ctx context.Context, ns *namespace.Namespace) ([][]byte, error) {
	nsSeal := *sm.sealsByNamespace[ns.UUID][0]

	sealConfig, err := nsSeal.BarrierConfig(ctx, ns)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve seal config: %w", err)
	}

	nsBarrierKey, _, err := sm.core.generateShares(sealConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to generate namespace barrier key: %w", err)
	}

	var nsSealKey []byte
	var nsSealKeyShares [][]byte

	if nsSeal == nil {
		return nil, fmt.Errorf("unable to retrieve seal: %w", err)
	}

	if sealConfig.StoredShares == 1 && nsSeal.BarrierType() == wrapping.WrapperTypeShamir {
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
