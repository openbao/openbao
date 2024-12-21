// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package mock

import (
	"context"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// pathInternal is used to test viewing internal backend values. In this case,
// it is used to test the invalidate func.
func pathInternal(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "internal",
		Fields: map[string]*framework.FieldSchema{
			"value": {Type: framework.TypeString},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathInternalUpdate,
			},
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathInternalRead,
			},
		},
	}
}

func (b *backend) pathInternalUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	value := data.Get("value").(string)
	b.internal = value
	// Return the secret
	return nil, nil
}

func (b *backend) pathInternalRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	// Return the secret
	return &logical.Response{
		Data: map[string]interface{}{
			"value": b.internal,
		},
	}, nil
}
