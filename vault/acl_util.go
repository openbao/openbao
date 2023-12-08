// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

//go:build !enterprise

package vault

import (
	"context"

	"github.com/lf-edge/openbao/helper/identity"
	"github.com/lf-edge/openbao/sdk/logical"
)

func (c *Core) performEntPolicyChecks(ctx context.Context, acl *ACL, te *logical.TokenEntry, req *logical.Request, inEntity *identity.Entity, opts *PolicyCheckOpts, ret *AuthResults) {
	ret.Allowed = true
}
