// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"

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
