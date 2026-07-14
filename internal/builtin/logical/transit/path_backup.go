// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package transit

import (
	"context"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func (b *backend) pathBackup() *framework.Path {
	return &framework.Path{
		Pattern: "backup/" + framework.GenericNameRegex("name"),

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixTransit,
			OperationVerb:   "back-up",
			OperationSuffix: "key",
		},

		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the key",
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathBackupRead,
			},
		},

		HelpSynopsis:    pathBackupHelpSyn,
		HelpDescription: pathBackupHelpDesc,
	}
}

func (b *backend) pathBackupRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	backup, err := b.lm.BackupPolicy(ctx, req.Storage, d.Get("name").(string))
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"backup": backup,
		},
	}, nil
}

const (
	pathBackupHelpSyn  = `Backup the named key`
	pathBackupHelpDesc = `This path is used to backup the named key.`
)
