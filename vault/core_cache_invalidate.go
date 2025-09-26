// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"strings"
	"time"

	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/vault/quotas"
)

func (c *Core) Invalidate(key string) {
	c.stateLock.RLock()
	ctx := c.activeContext
	c.stateLock.RUnlock()
	if ctx == nil {
		return
	}

	ctx, cancel := context.WithTimeout(c.activeContext, 2*time.Second)
	defer cancel()

	err := c.invalidateInternal(ctx, key)
	if err != nil {
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
		c.policyStore.invalidateNamespace(ctx, strings.TrimPrefix(namespacedKey, namespaceStoreSubPath))

	case strings.HasPrefix(namespacedKey, systemBarrierPrefix+policyACLSubPath):
		policyType := PolicyTypeACL // for now it is safe to assume type is ACL
		c.policyStore.invalidate(ctx, strings.TrimPrefix(namespacedKey, systemBarrierPrefix+policyACLSubPath), policyType)

	case strings.HasPrefix(namespacedKey, systemBarrierPrefix+quotas.StoragePrefix):
		c.quotaManager.Invalidate(strings.TrimPrefix(key, systemBarrierPrefix+quotas.StoragePrefix))

	case c.router.Invalidate(ctx, key):
	// if router.Invalidate returns true, a matching plugin was found and the invalidation is therefore dispatched

	case key == coreAuditConfigPath || key == coreLocalAuditConfigPath:
		c.invalidateAudits()

	default:
		c.logger.Warn("no idea how to invalidate cache. Maybe it's not cached and this is fine, maybe not", "key", key)
	}

	return nil
}
