// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

//go:build !enterprise

package vault

import (
	"context"

	"github.com/lf-edge/openbao/sdk/framework"
	"github.com/lf-edge/openbao/sdk/logical"
)

func (b *SystemBackend) verifyDROperationToken(f framework.OperationFunc, lock bool) framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
		return f(ctx, req, d)
	}
}
