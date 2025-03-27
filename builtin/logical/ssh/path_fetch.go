// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ssh

import (
	"context"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func pathFetchPublicKey(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: `public_key`,

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixSSH,
			OperationSuffix: "public-key",
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathFetchPublicKey,
			},
		},

		HelpSynopsis:    `Retrieve the public key.`,
		HelpDescription: `This allows the public key of the SSH CA certificate that this backend has been configured with to be fetched. This is a raw response endpoint without JSON encoding; use -format=raw or an external tool (e.g., curl) to fetch this value.`,
	}
}

func (b *backend) pathFetchPublicKey(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	var publicKeyEntry *keyStorageEntry
	if err := logical.WithTransaction(ctx, req.Storage, func(storage logical.Storage) error {
		var err error
		publicKeyEntry, err = caKey(ctx, storage, caPublicKey)
		return err
	}); err != nil {
		return nil, err
	}

	if publicKeyEntry == nil || publicKeyEntry.Key == "" {
		return nil, nil
	}

	response := &logical.Response{
		Data: map[string]interface{}{
			logical.HTTPContentType: "text/plain",
			logical.HTTPRawBody:     []byte(publicKeyEntry.Key),
			logical.HTTPStatusCode:  200,
		},
	}

	return response, nil
}
