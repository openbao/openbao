// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"

	"github.com/openbao/openbao/helper/namespace"
)

func (ps *PolicyStore) getACLView(*namespace.Namespace) BarrierView {
	return ps.aclView
}

func (ps *PolicyStore) getBarrierView(ns *namespace.Namespace, _ PolicyType) BarrierView {
	return ps.getACLView(ns)
}

func (ps *PolicyStore) loadACLPolicyNamespaces(ctx context.Context, policyName, policyText string) error {
	return ps.loadACLPolicyInternal(namespace.RootContext(ctx), policyName, policyText)
}
