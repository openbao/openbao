// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"path"

	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func (c *Core) NamespaceByID(ctx context.Context, nsID string) (*namespace.Namespace, error) {
	ns, err := c.namespaceStore.GetNamespaceByAccessor(ctx, nsID)
	if err != nil {
		return nil, err
	}

	return ns, nil
}

// ListNamespaces returns back a list of all namespaces, including root, skipping
// all sealed namespaces.
func (c *Core) ListNamespaces(ctx context.Context) ([]*namespace.Namespace, error) {
	return c.namespaceStore.ListAllNamespaces(ctx, true, false)
}

func NamespaceView(barrier logical.Storage, ns *namespace.Namespace) BarrierView {
	if ns.ID == namespace.RootNamespaceID {
		return NewBarrierView(barrier, "")
	}

	return NewBarrierView(barrier, path.Join(namespaceBarrierPrefix, ns.UUID)+"/")
}

// NamespaceByPath returns the namespace and the path prefix for the given path.
// Note, that it is on the caller to ensure that the namespace is resolved, as NamespaceByPath otherwise resolves to root.
func (c *Core) NamespaceByPath(ctx context.Context, path string) (*namespace.Namespace, string) {
	return c.namespaceStore.GetNamespaceByLongestPrefix(ctx, path)
}
