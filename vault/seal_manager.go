package vault

import (
	"context"
	"fmt"

	"github.com/hashicorp/go-hclog"
	aeadwrapper "github.com/openbao/go-kms-wrapping/wrappers/aead/v2"
	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/sdk/v2/logical"
	vaultseal "github.com/openbao/openbao/vault/seal"
)

// SealManager is used to provide storage for the seals.
// It's a singleton that associates seals (configs) to the namespaces.
type SealManager struct {
	core    *Core
	storage logical.Storage

	// lock        sync.RWMutex
	// invalidated atomic.Bool

	sealsByNamespace map[string][]*Seal

	// logger is the server logger copied over from core
	logger hclog.Logger
}

// NewSealManager creates a new seal manager with core reference and logger.
func NewSealManager(ctx context.Context, core *Core, logger hclog.Logger) (*SealManager, error) {
	return &SealManager{
		core:             core,
		storage:          core.barrier,
		sealsByNamespace: make(map[string][]*Seal),
		logger:           logger,
	}, nil
}

// setupSealManager is used to initialize the seal manager
// when the vault is being unsealed.
func (c *Core) setupSealManager(ctx context.Context) error {
	var err error
	sealLogger := c.baseLogger.Named("seal")
	c.AddLogger(sealLogger)
	c.sealManager, err = NewSealManager(ctx, c, sealLogger)
	return err
}

// teardownSealManager is used to remove seal manager
// when the vault is being sealed.
func (c *Core) teardownSealManager() error {
	c.sealManager = nil
	return nil
}

// TODO(wslabosz): add logs
func (sm *SealManager) SetSeal(ctx context.Context, sealConfig *SealConfig, ns *namespace.Namespace) error {
	if err := sealConfig.Validate(); err != nil {
		return fmt.Errorf("invalid seal configuration: %w", err)
	}

	// Seal type would depend on the provided arguments
	defaultSeal := NewDefaultSeal(vaultseal.NewAccess(aeadwrapper.NewShamirWrapper()))
	defaultSeal.SetCore(sm.core)

	if err := defaultSeal.Init(ctx); err != nil {
		return fmt.Errorf("error initializing seal: %w", err)
	}

	sm.sealsByNamespace[ns.UUID] = []*Seal{&defaultSeal}
	err := defaultSeal.SetBarrierConfig(ctx, sealConfig, ns)
	if err != nil {
		return fmt.Errorf("failed to set barrier config: %w", err)
	}

	return nil
}
