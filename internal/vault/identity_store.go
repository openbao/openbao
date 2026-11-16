package vault

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/errwrap"
	"github.com/openbao/openbao/v2/internal/helper/namespace"
	ident "github.com/openbao/openbao/v2/internal/vault/identity"
)

func (c *Core) IdentityStore() *ident.IdentityStore {
	return c.identityStore
}

func (c *Core) loadIdentityStoreArtifacts(ctx context.Context, readOnly bool) error {
	if c.identityStore == nil {
		c.logger.Warn("identity store is not setup, skipping loading")
		return nil
	}

	loadFunc := func(context.Context) error {
		allNs, err := c.ListNamespaces(ctx)
		if err != nil {
			return fmt.Errorf("failed to list namespaces: %w", err)
		}

		for _, ns := range allNs {
			if err = c.loadIdentityStoreArtifactsForNamespace(ctx, ns, readOnly); err != nil {
				return err
			}
		}

		return nil
	}

	// Load everything when memdb is set to operate on lower cased names
	err := loadFunc(ctx)
	switch {
	case err == nil:
		// If it succeeds, all is well
		return nil
	case !errwrap.Contains(err, ident.ErrDuplicateIdentityName.Error()):
		return err
	}

	c.identityStore.Logger().Warn("enabling case sensitive identity names")

	// Set identity store to operate on case sensitive identity names
	c.identityStore.DisableLowerCasedNames(true)

	// Swap the memdb instance by the one which operates on case sensitive
	// names, hence obviating the need to unload anything that's already
	// loaded.
	if err := c.identityStore.ResetDB(ctx); err != nil {
		return err
	}

	// Attempt to load identity artifacts once more after memdb is reset to
	// accept case sensitive names
	return loadFunc(ctx)
}

func (c *Core) loadIdentityStoreArtifactsForNamespace(ctx context.Context, ns *namespace.Namespace, readOnly bool) error {
	if ns.Tainted {
		c.logger.Info("skipping loading entities for tainted namespace", "ns", ns.ID)
		return nil
	}

	ctx = namespace.ContextWithNamespace(ctx, ns)

	warnAndSkip := func() {
		c.logger.Warn("skipping identity store loading for namespace whose setup did not complete; "+
			"use recovery mode to remove the corrupt entry if this persists",
			"namespace_id", ns.ID)
	}

	if err := c.identityStore.LoadEntities(ctx, readOnly); err != nil {
		if errors.Is(err, ident.ErrNamespaceNotInIdentityStore) {
			warnAndSkip()
			return nil
		}
		return err
	}
	if err := c.identityStore.LoadGroups(ctx, readOnly); err != nil {
		if errors.Is(err, ident.ErrNamespaceNotInIdentityStore) {
			warnAndSkip()
			return nil
		}
		return err
	}

	return c.identityStore.LoadOIDCClients(ctx)
}
