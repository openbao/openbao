// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"

	"github.com/openbao/openbao/v2/internal/helper/namespace"
)

// NamespaceByID returns back a namespace using its accessor (nsID).
func (c *Core) NamespaceByID(ctx context.Context, nsID string) (*namespace.Namespace, error) {
	return c.namespaceStore.GetNamespaceByAccessor(ctx, nsID)
}

// ListNamespaces returns back a list of all namespaces including root.
func (c *Core) ListNamespaces(ctx context.Context) ([]*namespace.Namespace, error) {
	return c.namespaceStore.ListNamespaces(ctx, ListNamespaceOpts{
		Recursive:     true,
		IncludeParent: true,
	})
}
