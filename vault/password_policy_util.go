// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/openbao/openbao/helper/namespace"
)

const (
	passwordPolicySubPath = "sys/password_policy/"
)

// retrievePasswordPolicy retrieves a password policy from the logical storage
func (d dynamicSystemView) retrievePasswordPolicy(ctx context.Context, policyName string) (*passwordPolicyConfig, error) {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	storage := d.core.NamespaceView(ns).SubView(passwordPolicySubPath)
	entry, err := storage.Get(ctx, policyName)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	policyCfg := &passwordPolicyConfig{}
	err = json.Unmarshal(entry.Value, &policyCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal stored data: %w", err)
	}

	return policyCfg, nil
}
