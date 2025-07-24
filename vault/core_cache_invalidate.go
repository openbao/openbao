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
	ctx, cancel := context.WithTimeout(c.activeContext, 2*time.Second)
	defer cancel()

	err := c.invalidateInternal(ctx, key)
	if err != nil {
		c.logger.Error("cache invalidation failed", "key", key, "error", err.Error())
		// TODO(phil9909): It's not save to continue, restart the core
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
			c.logger.Debug("error while invalidating cache: could not find namespace", "key", key, "error", err.Error())
			// We can't find the namespace, this can happen for two reasons:
			// 1. The namespace was deleted already
			// 2. The namespace has just been created (and the core/namespaces/<uuid> key was not yet invalidated)
			// We will also recive a invalidation request for the core/namespaces/<uuid> key in both cases, so we are fine
			return nil
		}
	}

	ctx = namespace.ContextWithNamespace(ctx, ns)

	switch {
	case strings.HasPrefix(namespacedKey, namespaceStoreSubPath):
		err := c.namespaceStore.invalidate(ctx, "")
		if err != nil {
			return err
		}

		err = c.policyStore.invalidateNamespace(ctx, strings.TrimPrefix(namespacedKey, namespaceStoreSubPath))
		if err != nil {
			return err
		}

	case strings.HasPrefix(namespacedKey, systemBarrierPrefix+policyACLSubPath):
		policyType := PolicyTypeACL // for now it is safe to assume type is ACL
		err := c.policyStore.invalidate(ctx, strings.TrimPrefix(namespacedKey, systemBarrierPrefix+policyACLSubPath), policyType)
		if err != nil {
			return err
		}

	case strings.HasPrefix(namespacedKey, systemBarrierPrefix+quotas.StoragePrefix):
		c.quotaManager.Invalidate(strings.TrimPrefix(key, systemBarrierPrefix+quotas.StoragePrefix))

	case c.router.Invalidate(ctx, key):
		// if router.Invalidate returns true, a matching plugin was found and the invalidation is therefore dispatched

	default:
		c.logger.Warn("no idea how to invalidate cache. Maybe it's not cached and this is fine, maybe not", "key", key)
	}

	return ctx.Err()
}
