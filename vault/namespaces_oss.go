// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
)

// NamespaceByID returns back a namespace using its accessor (nsID).
func (c *Core) NamespaceByID(ctx context.Context, nsID string) (*Namespace, error) {
	return c.namespaceStore.GetNamespaceByAccessor(ctx, nsID)
}

// ListNamespaces returns back a list of all namespaces including root.
func (c *Core) ListNamespaces(ctx context.Context) ([]*Namespace, error) {
	baseNamespaces, err := c.namespaceStore.ListAllNamespaces(ctx, true, false)
	if err != nil {
		return nil, err
	}

	// Wrap each ns
	wrappers := make([]*Namespace, len(baseNamespaces))
	for i, base := range baseNamespaces {
		wrappers[i] = &Namespace{
			Namespace: base,
		}
	}
	return wrappers, nil
}
