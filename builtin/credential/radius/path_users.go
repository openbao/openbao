// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package radius

import (
	"context"
	"fmt"
	"strings"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/helper/policyutil"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func pathUsersList(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "users/?$",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixRadius,
			OperationSuffix: "users",
			Navigation:      true,
			ItemType:        "User",
		},

		Fields: map[string]*framework.FieldSchema{
			"after": {
				Type:        framework.TypeString,
				Description: `Optional entry to list begin listing after, not required to exist.`,
			},
			"limit": {
				Type:        framework.TypeInt,
				Description: `Optional number of entries to return; defaults to all entries.`,
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{
				Callback: b.pathUserList,
			},
		},

		HelpSynopsis:    pathUserHelpSyn,
		HelpDescription: pathUserHelpDesc,
	}
}

func pathUsers(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: `users/(?P<name>.+)`,

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixRadius,
			OperationSuffix: "user",
			Action:          "Create",
			ItemType:        "User",
		},

		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the RADIUS user.",
			},

			"policies": {
				Type:        framework.TypeCommaStringSlice,
				Description: "Comma-separated list of policies associated to the user.",
				DisplayAttrs: &framework.DisplayAttributes{
					Description: "A list of policies associated to the user.",
				},
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathUserDelete,
			},
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathUserRead,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathUserWrite,
			},
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.pathUserWrite,
			},
		},

		ExistenceCheck: b.userExistenceCheck,

		HelpSynopsis:    pathUserHelpSyn,
		HelpDescription: pathUserHelpDesc,
	}
}

func (b *backend) userExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	userEntry, err := b.user(ctx, req.Storage, data.Get("name").(string))
	if err != nil {
		return false, err
	}

	return userEntry != nil, nil
}

func (b *backend) user(ctx context.Context, s logical.Storage, username string) (*UserEntry, error) {
	if username == "" {
		return nil, fmt.Errorf("missing username")
	}

	entry, err := s.Get(ctx, "user/"+strings.ToLower(username))
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var result UserEntry
	if err := entry.DecodeJSON(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

func (b *backend) pathUserDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	err := req.Storage.Delete(ctx, "user/"+d.Get("name").(string))
	if err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) pathUserRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	user, err := b.user(ctx, req.Storage, d.Get("name").(string))
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"policies": user.Policies,
		},
	}, nil
}

func (b *backend) pathUserWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	policies := policyutil.ParsePolicies(d.Get("policies"))
	for _, policy := range policies {
		if policy == "root" {
			return logical.ErrorResponse("root policy cannot be granted by an auth method"), nil
		}
	}

	// Store it
	entry, err := logical.StorageEntryJSON("user/"+d.Get("name").(string), &UserEntry{
		Policies: policies,
	})
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) pathUserList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	after := data.Get("after").(string)
	limit := data.Get("limit").(int)
	if limit <= 0 {
		limit = -1
	}

	users, err := req.Storage.ListPage(ctx, "user/", after, limit)
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(users), nil
}

type UserEntry struct {
	Policies []string
}

const pathUserHelpSyn = `
Manage users allowed to authenticate.
`

const pathUserHelpDesc = `
This endpoint allows you to create, read, update, and delete configuration
for RADIUS users that are allowed to authenticate, and associate policies to
them.

Deleting a user will not revoke auth for prior authenticated users.
To do this, do a revoke token by path on "auth/radius/login/<username>"
for the usernames you want revoked.
`
