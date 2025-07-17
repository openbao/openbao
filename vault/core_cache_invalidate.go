// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"strings"

	"github.com/openbao/openbao/helper/namespace"
)

func (c *Core) Invalidate(key string) {
	ctx := c.activeContext

	namespacedKey := key
	ns := namespace.RootNamespace
	namespaceUUID := namespace.RootNamespaceUUID

	if keySuffix, ok := strings.CutPrefix(key, namespaceBarrierPrefix); ok {
		namespaceUUID, namespacedKey, _ = strings.Cut(keySuffix, "/")
		var err error
		ns, err = c.namespaceStore.GetNamespace(ctx, namespaceUUID)

		if err != nil {
			c.logger.Error("error while invalidating cache: could not find namespace", "key", key, "error", err.Error())
			// We can't find the namespace, but let's still try to invalidate the cache
			ns = namespace.RootNamespace
		}
	}

	ctx = namespace.ContextWithNamespace(ctx, ns)

	switch {
	case strings.HasPrefix(namespacedKey, namespaceStoreSubPath):
		c.namespaceStore.invalidate(ctx, "")

	case strings.HasPrefix(namespacedKey, systemBarrierPrefix+policyACLSubPath):
		policyType := PolicyTypeACL // for now it is safe to assume type is ACL
		c.policyStore.invalidate(ctx, strings.TrimPrefix(namespacedKey, systemBarrierPrefix+policyACLSubPath), policyType)

	default:
		c.logger.Warn("no idea how to invalidate cache. Maybe it's not cached and this is fine, maybe not", "key", key)
	}
}
