package vault

import (
	"context"
	"crypto/sha256"
	"fmt"

	"github.com/openbao/openbao/audit"
	"github.com/openbao/openbao/sdk/v2/helper/salt"
	"github.com/openbao/openbao/sdk/v2/logical"
	coreAudit "github.com/openbao/openbao/vault/audit"
	"github.com/openbao/openbao/vault/policy"
	"github.com/openbao/openbao/vault/routing"
)

// NewAuditBackend is used to create and configure a new audit backend by name.
func (c *Core) NewAuditBackend(ctx context.Context, entry *routing.MountEntry, view logical.Storage, conf map[string]string) (audit.Backend, error) {
	f, ok := c.auditBackends[entry.Type]
	if !ok {
		return nil, fmt.Errorf("unknown backend type: %q", entry.Type)
	}
	saltConfig := &salt.Config{
		HMAC:     sha256.New,
		HMACType: "hmac-sha256",
		Location: salt.DefaultLocation,
	}

	be, err := f(ctx, &audit.BackendConfig{
		SaltView:   view,
		SaltConfig: saltConfig,
		Config:     conf,
	})
	if err != nil {
		return nil, err
	}
	if be == nil {
		return nil, fmt.Errorf("nil backend returned from %q factory function", entry.Type)
	}

	auditLogger := c.baseLogger.Named("audit-backend")

	switch entry.Type {
	case "file":
		key := "audit_file|" + entry.Path
		if auditLogger.IsDebug() {
			auditLogger.Debug("adding reload function", "path", entry.Path)
			if entry.Options != nil {
				auditLogger.Debug("file backend options", "path", entry.Path, "file_path", entry.Options["file_path"])
			}
		}

		c.reloadFuncsLock.Lock()

		c.reloadFuncs[key] = append(c.reloadFuncs[key], func() error {
			if auditLogger.IsInfo() {
				auditLogger.Info("reloading file audit backend", "path", entry.Path)
			}
			return be.Reload(ctx)
		})

		c.reloadFuncsLock.Unlock()
	case "socket":
		if auditLogger.IsDebug() {
			if entry.Options != nil {
				auditLogger.Debug("socket backend options", "path", entry.Path, "address", entry.Options["address"], "socket type", entry.Options["socket_type"])
			}
		}
	case "syslog":
		if auditLogger.IsDebug() {
			if entry.Options != nil {
				auditLogger.Debug("syslog backend options", "path", entry.Path, "facility", entry.Options["facility"], "tag", entry.Options["tag"])
			}
		}
	}

	return be, err
}

// setupAudits is used to load and initialize the audit backends while
// also setting up audit broker.
func (c *Core) setupAudits(ctx context.Context) error {
	logger := c.baseLogger.Named("audit")
	c.AddLogger(logger)

	var err error
	var auditPostUnsealFuncs []func()
	c.audit, auditPostUnsealFuncs, err = coreAudit.NewAuditTable(ctx, c, c.router, c.systemBarrierView, logger)
	if err != nil {
		return err
	}

	c.postUnsealFuncs = append(c.postUnsealFuncs, auditPostUnsealFuncs...)
	return nil
}

// RemoveAuditReloadFunc removes the reload func from the working set.
// The audit lock needs to be held before calling this.
func (c *Core) RemoveAuditReloadFunc(entry *routing.MountEntry) {
	switch entry.Type {
	case "file":
		key := "audit_file|" + entry.Path
		c.reloadFuncsLock.Lock()

		if c.logger.IsDebug() {
			c.baseLogger.Debug("removing audit reload function", "path", entry.Path)
		}

		delete(c.reloadFuncs, key)
		c.reloadFuncsLock.Unlock()
	}
}

func (c *Core) ReloadAuditLogs() {
	// Ensure we are already unsealed
	c.stateLock.RLock()
	defer c.stateLock.RUnlock()

	if c.Sealed() || (c.standby.Load() && !c.StandbyReadsEnabled()) || c.activeContext == nil {
		return
	}

	if err := c.audit.HandleAuditLogSetup(c.activeContext, c.rawConfig.Load(), c.standby.Load()); err != nil {
		c.logger.Error("failed to set up audit logs on reload", "error", err)
	}
}

// teardownAudit is used before we seal the vault to reset the audit
// backends to their unloaded state. This is reversed by loadAudits.
func (c *Core) teardownAudits() error {
	if c.audit == nil {
		return nil
	}

	c.audit.Lock()
	defer c.audit.Unlock()

	for _, entry := range c.audit.Mt.Entries {
		c.RemoveAuditReloadFunc(entry)
	}

	c.audit = nil
	return nil
}

func (c *Core) setupQuotas(ctx context.Context) error {
	if c.quotaManager == nil {
		return nil
	}

	return c.quotaManager.Setup(ctx, c.systemBarrierView)
}

// setupPolicyStore is used to initialize the policy store
// when the vault is being unsealed.
func (c *Core) setupPolicyStore(ctx context.Context) error {
	// Create the policy store
	var err error
	sysView := &dynamicSystemView{core: c}
	psLogger := c.baseLogger.Named("policy")
	c.AddLogger(psLogger)
	c.policyStore, err = policy.NewStore(ctx, c, c.systemBarrierView, sysView, psLogger)
	if err != nil {
		return err
	}

	// Ensure that the default policy exists, and if not, create it
	return c.policyStore.LoadDefaultPolicies(ctx)
}

// teardownPolicyStore is used to reverse setupPolicyStore
// when the vault is being sealed.
func (c *Core) teardownPolicyStore() error {
	c.policyStore = nil
	return nil
}
