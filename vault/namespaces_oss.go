// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"strings"

	"github.com/openbao/openbao/helper/namespace"
)

func (c *Core) NamespaceByID(ctx context.Context, nsID string) (*namespace.Namespace, error) {
	ns, err := c.namespaceStore.GetNamespaceByAccessor(ctx, nsID)
	if err != nil {
		return nil, err
	}

	if ns == nil {
		return nil, nil
	}

	return ns.Namespace, nil
}

func (c *Core) ListNamespaces(ctx context.Context) ([]*namespace.Namespace, error) {
	return c.namespaceStore.ListAllNamespaces(ctx, true)
}

func (c *Core) NamespaceByPath(ctx context.Context, path string) (*namespace.Namespace, string) {
	ctxNs, err := namespace.FromContext(ctx)
	if err != nil {
		ctxNs = namespace.RootNamespace
	}
	combinedPath := ctxNs.Path + path
	prefix, entry, _ := c.namespaceStore.namespacesByPath.LongestPrefix(combinedPath)
	return entry.Namespace, strings.TrimPrefix(combinedPath, prefix)
}
