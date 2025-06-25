// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

var pathInternalUINamespacesRead = func(b *SystemBackend) framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
		// Short-circuit here if there's no client token provided
		if req.ClientToken == "" {
			return nil, errors.New("client token empty")
		}

		// Load the ACL policies so we can check for access and filter namespaces
		_, te, entity, _, err := b.Core.fetchACLTokenEntryAndEntity(ctx, req)
		if err != nil {
			return nil, err
		}
		if entity != nil && entity.Disabled {
			b.logger.Warn("permission denied as the entity on the token is disabled")
			return nil, logical.ErrPermissionDenied
		}
		if te != nil && te.EntityID != "" && entity == nil {
			b.logger.Warn("permission denied as the entity on the token is invalid")
			return nil, logical.ErrPermissionDenied
		}

		parent, err := namespace.FromContext(ctx)
		if err != nil {
			return nil, err
		}

		list, err := b.Core.namespaceStore.ListNamespaces(ctx, false, false)
		if err != nil {
			return nil, errors.New("failed to list namespaces")
		}

		var nsList []string
		for _, entry := range list {
			relativePath := parent.TrimmedPath(entry.Path)
			nsList = append(nsList, relativePath)
		}

		return logical.ListResponse(nsList), nil
	}
}

// tuneMount is used to set config on a mount point
func (b *SystemBackend) tuneMountTTLs(ctx context.Context, path string, me *MountEntry, newDefault, newMax time.Duration) error {
	zero := time.Duration(0)

	switch {
	case newDefault == zero && newMax == zero:
		// No checks needed

	case newDefault == zero && newMax != zero:
		// No default/max conflict, no checks needed

	case newDefault != zero && newMax == zero:
		// No default/max conflict, no checks needed

	case newDefault != zero && newMax != zero:
		if newMax < newDefault {
			return fmt.Errorf("backend max lease TTL of %d would be less than backend default lease TTL of %d", int(newMax.Seconds()), int(newDefault.Seconds()))
		}
	}

	origMax := me.Config.MaxLeaseTTL
	origDefault := me.Config.DefaultLeaseTTL

	me.Config.MaxLeaseTTL = newMax
	me.Config.DefaultLeaseTTL = newDefault

	// Update the mount table
	var err error
	switch {
	case strings.HasPrefix(path, credentialRoutePrefix):
		err = b.Core.persistAuth(ctx, nil, b.Core.auth, &me.Local, me.UUID)
	default:
		err = b.Core.persistMounts(ctx, nil, b.Core.mounts, &me.Local, me.UUID)
	}
	if err != nil {
		me.Config.MaxLeaseTTL = origMax
		me.Config.DefaultLeaseTTL = origDefault
		return errors.New("failed to update mount table, rolling back TTL changes")
	}
	if b.Core.logger.IsInfo() {
		b.Core.logger.Info("mount tuning of leases successful", "path", path)
	}

	return nil
}
