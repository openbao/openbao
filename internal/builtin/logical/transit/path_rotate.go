// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package transit

import (
	"context"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/helper/keysutil"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func (b *backend) pathRotate() *framework.Path {
	return &framework.Path{
		Pattern: "keys/" + framework.GenericNameRegex("name") + "/rotate",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixTransit,
			OperationVerb:   "rotate",
			OperationSuffix: "key",
		},

		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the key",
			},
			"external_key_ref": {
				Type: framework.TypeString,
				Description: `Reference to the external key to use. This follows
the format <config name>:<key name>, uniquely identifying the key configured
under sys/external-keys/configs/<config name>/keys/<key name>.`,
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathRotateWrite,
			},
		},

		HelpSynopsis:    pathRotateHelpSyn,
		HelpDescription: pathRotateHelpDesc,
	}
}

func (b *backend) pathRotateWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	txRollback, err := logical.StartTxStorage(ctx, req)
	if err != nil {
		return nil, err
	}
	defer txRollback()

	name := d.Get("name").(string)

	// Get the policy
	p, _, err := b.GetPolicyExclusive(ctx, keysutil.PolicyRequest{
		Storage: req.Storage,
		Name:    name,
	}, b.GetRandomReader())
	if err != nil {
		return nil, err
	}
	if p == nil {
		return logical.ErrorResponse("key not found"), logical.ErrInvalidRequest
	}
	defer p.Unlock()

	externalKeyRef := d.Get("external_key_ref").(string)
	if p.Type == keysutil.KeyType_ExternalKey {
		if externalKeyRef == "" {
			return logical.ErrorResponse("must provide external_key_ref to rotate policy of type external-key"), logical.ErrInvalidRequest
		}

		if _, err := b.System().GetExternalKey(ctx, externalKeyRef); err != nil {
			return logical.ErrorResponse("failed to fetch external key: %s", err), logical.ErrInvalidRequest
		}

		p.ExternalKeyRef = externalKeyRef
	} else if externalKeyRef != "" {
		return logical.ErrorResponse("cannot use external_key_ref on key of type %v", p.Type.String()), logical.ErrInvalidRequest
	}

	// Rotate the policy
	err = p.Rotate(ctx, req.Storage, b.GetRandomReader())
	if err != nil {
		return nil, err
	}

	if err := logical.EndTxStorage(ctx, req); err != nil {
		return nil, err
	}

	return b.formatKeyPolicy(p, nil)
}

const pathRotateHelpSyn = `Rotate named encryption key`

const pathRotateHelpDesc = `
This path is used to rotate the named key. After rotation,
new encryption requests using this name will use the new key,
but decryption will still be supported for older versions.
`
