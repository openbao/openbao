// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"strings"
	"time"

	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/sdk/v2/physical"
	"github.com/openbao/openbao/vault/quotas"
)

func (c *Core) Invalidate(key string) {
	// Skip invalidations if we're not the standby. The InmemHA backend in
	// particular dispatches invalidations on every node which isn't
	// necessary as the active can invalidate itself.
	if !c.standby.Load() {
		return
	}

	if c.Sealed() {
		return
	}

	c.stateLock.RLock()
	activeContext := c.activeContext
	c.stateLock.RUnlock()
	if activeContext == nil {
		return
	}

	ctx, cancel := context.WithTimeout(activeContext, 2*time.Second)
	defer cancel()

	err := c.invalidateInternal(ctx, key)
	if err != nil {
		if activeContext.Err() != nil {
			// active context is cancelled, so we can ignore this error
			return
		}
		c.logger.Error("cache invalidation failed, restarting core", "key", key, "error", err.Error())
		c.restart()
	}
}

func (c *Core) invalidateInternal(ctx context.Context, key string) error {
	c.physicalCache.Invalidate(ctx, key)

	namespacedKey := key
	ns := namespace.RootNamespace
	namespaceUUID := namespace.RootNamespaceUUID

	if keySuffix, ok := strings.CutPrefix(key, namespaceBarrierPrefix); ok {
		namespaceUUID, namespacedKey, _ = strings.Cut(keySuffix, "/")
		var err error
		ns, err = c.namespaceStore.GetNamespace(ctx, namespaceUUID)
		if err != nil {
			return err
		}
		if ns == nil {
			c.logger.Debug("error while invalidating cache: could not find namespace", "key", key)
			// We can't find the namespace, this can happen for two reasons:
			// 1. The namespace was deleted already
			// 2. The namespace has just been created (and the core/namespaces/<uuid> key was not yet invalidated)
			// We will also receive a invalidation request for the core/namespaces/<uuid> key in both cases, so we are fine
			return nil
		}
	}

	ctx = namespace.ContextWithNamespace(ctx, ns)

	switch {
	case strings.HasPrefix(namespacedKey, namespaceStoreSubPath):
		c.namespaceStore.invalidate(ctx, "")

		ctx := physical.CacheRefreshContext(ctx, true)
		namespaceUUID = strings.TrimPrefix(namespacedKey, namespaceStoreSubPath)

		c.stateLock.RLock()
		policyStore := c.policyStore
		c.stateLock.RUnlock()

		if policyStore != nil {
			policyStore.invalidateNamespace(ctx, namespaceUUID)
		}

		c.mountInvalidationWorker.invalidateNamespaceMounts(namespaceUUID)

	case strings.HasPrefix(namespacedKey, systemBarrierPrefix+policyACLSubPath):
		policyType := PolicyTypeACL // for now it is safe to assume type is ACL

		c.stateLock.RLock()
		policyStore := c.policyStore
		c.stateLock.RUnlock()

		if policyStore != nil {
			policyStore.invalidate(ctx, strings.TrimPrefix(namespacedKey, systemBarrierPrefix+policyACLSubPath), policyType)
		}

	case strings.HasPrefix(namespacedKey, systemBarrierPrefix+quotas.StoragePrefix):
		c.quotaManager.Invalidate(strings.TrimPrefix(key, systemBarrierPrefix+quotas.StoragePrefix))

	case key == coreAuditConfigPath || key == coreLocalAuditConfigPath:
		c.invalidateAudits()

	case namespacedKey == coreMountConfigPath || namespacedKey == coreLocalMountConfigPath ||
		namespacedKey == coreAuthConfigPath || namespacedKey == coreLocalAuthConfigPath:
		c.mountInvalidationWorker.invalidateLegacyMounts(key)

	case strings.HasPrefix(namespacedKey, coreMountConfigPath+"/") || strings.HasPrefix(namespacedKey, coreLocalMountConfigPath+"/") ||
		strings.HasPrefix(namespacedKey, coreAuthConfigPath+"/") || strings.HasPrefix(namespacedKey, coreLocalAuthConfigPath+"/"):
		c.mountInvalidationWorker.invalidateMount(namespaceUUID, namespacedKey)

	case namespacedKey == rootKeyPath ||
		namespacedKey == legacyRootKeyPath ||
		namespacedKey == keyringPath ||
		namespacedKey == shamirKekPath ||
		namespacedKey == StoredBarrierKeysPath ||
		strings.HasPrefix(namespacedKey, keyringUpgradePrefix):

		// Invalidating keyring uses the same logic as the HA startup code,
		// just started in a background goroutine.
		c.invalidateKeyrings(namespacedKey)
	case c.router.Invalidate(ctx, key):
	// if router.Invalidate returns true, a matching plugin was found and the invalidation is therefore dispatched

	default:
		c.logger.Warn("no idea how to invalidate cache. Maybe it's not cached and this is fine, maybe not", "key", key)
	}

	return nil
}
