// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package userpass

import (
	"context"
	"fmt"
	"strings"
	"time"

	sockaddr "github.com/hashicorp/go-sockaddr"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/helper/tokenutil"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func pathUsersList(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "users/?",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixUserpass,
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
	p := &framework.Path{
		Pattern: "users/" + framework.GenericNameRegex("username"),

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixUserpass,
			OperationSuffix: "user",
			Action:          "Create",
			ItemType:        "User",
		},

		Fields: map[string]*framework.FieldSchema{
			"username": {
				Type:        framework.TypeString,
				Description: "Username for this user.",
			},

			"password": {
				Type:        framework.TypeString,
				Description: "Password for this user.",
				DisplayAttrs: &framework.DisplayAttributes{
					Sensitive: true,
				},
			},

			"policies": {
				Type:        framework.TypeCommaStringSlice,
				Description: tokenutil.DeprecationText("token_policies"),
				Deprecated:  true,
			},

			"ttl": {
				Type:        framework.TypeDurationSecond,
				Description: tokenutil.DeprecationText("token_ttl"),
				Deprecated:  true,
			},

			"max_ttl": {
				Type:        framework.TypeDurationSecond,
				Description: tokenutil.DeprecationText("token_max_ttl"),
				Deprecated:  true,
			},

			"bound_cidrs": {
				Type:        framework.TypeCommaStringSlice,
				Description: tokenutil.DeprecationText("token_bound_cidrs"),
				Deprecated:  true,
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

	tokenutil.AddTokenFields(p.Fields)
	return p
}

func (b *backend) userExistenceCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	userEntry, err := b.user(ctx, req.Storage, d.Get("username").(string))
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

	if result.TokenTTL == 0 && result.TTL > 0 {
		result.TokenTTL = result.TTL
	}
	if result.TokenMaxTTL == 0 && result.MaxTTL > 0 {
		result.TokenMaxTTL = result.MaxTTL
	}
	if len(result.TokenPolicies) == 0 && len(result.Policies) > 0 {
		result.TokenPolicies = result.Policies
	}
	if len(result.TokenBoundCIDRs) == 0 && len(result.BoundCIDRs) > 0 {
		result.TokenBoundCIDRs = result.BoundCIDRs
	}

	return &result, nil
}

func (b *backend) setUser(ctx context.Context, s logical.Storage, username string, userEntry *UserEntry) error {
	entry, err := logical.StorageEntryJSON("user/"+username, userEntry)
	if err != nil {
		return err
	}

	return s.Put(ctx, entry)
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

func (b *backend) pathUserDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	err := req.Storage.Delete(ctx, "user/"+strings.ToLower(d.Get("username").(string)))
	if err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) pathUserRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	user, err := b.user(ctx, req.Storage, strings.ToLower(d.Get("username").(string)))
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, nil
	}

	data := map[string]interface{}{}
	user.PopulateTokenData(data)

	// Add backwards compat data
	if user.TTL > 0 {
		data["ttl"] = int64(user.TTL.Seconds())
	}
	if user.MaxTTL > 0 {
		data["max_ttl"] = int64(user.MaxTTL.Seconds())
	}
	if len(user.Policies) > 0 {
		data["policies"] = data["token_policies"]
	}
	if len(user.BoundCIDRs) > 0 {
		data["bound_cidrs"] = user.BoundCIDRs
	}

	return &logical.Response{
		Data: data,
	}, nil
}

func (b *backend) userCreateUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	txRollback, err := logical.StartTxStorage(ctx, req)
	if err != nil {
		return nil, err
	}
	defer txRollback()

	username := strings.ToLower(d.Get("username").(string))
	userEntry, err := b.user(ctx, req.Storage, username)
	if err != nil {
		return nil, err
	}
	// Due to existence check, user will only be nil if it's a create operation
	if userEntry == nil {
		userEntry = &UserEntry{}
	}

	if err := userEntry.ParseTokenFields(req, d); err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}

	if _, ok := d.GetOk("password"); ok {
		userErr, intErr := b.updateUserPassword(req, d, userEntry)
		if intErr != nil {
			return nil, intErr
		}
		if userErr != nil {
			return logical.ErrorResponse(userErr.Error()), logical.ErrInvalidRequest
		}
	}

	// handle upgrade cases
	{
		if err := tokenutil.UpgradeValue(d, "policies", "token_policies", &userEntry.Policies, &userEntry.TokenPolicies); err != nil {
			return logical.ErrorResponse(err.Error()), nil
		}

		if err := tokenutil.UpgradeValue(d, "ttl", "token_ttl", &userEntry.TTL, &userEntry.TokenTTL); err != nil {
			return logical.ErrorResponse(err.Error()), nil
		}

		if err := tokenutil.UpgradeValue(d, "max_ttl", "token_max_ttl", &userEntry.MaxTTL, &userEntry.TokenMaxTTL); err != nil {
			return logical.ErrorResponse(err.Error()), nil
		}

		if err := tokenutil.UpgradeValue(d, "bound_cidrs", "token_bound_cidrs", &userEntry.BoundCIDRs, &userEntry.TokenBoundCIDRs); err != nil {
			return logical.ErrorResponse(err.Error()), nil
		}
	}
	if err := b.setUser(ctx, req.Storage, username, userEntry); err != nil {
		return nil, err
	}

	if err := logical.EndTxStorage(ctx, req); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) pathUserWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	password := d.Get("password").(string)
	if req.Operation == logical.CreateOperation && password == "" {
		return logical.ErrorResponse("missing password"), logical.ErrInvalidRequest
	}
	return b.userCreateUpdate(ctx, req, d)
}

type UserEntry struct {
	tokenutil.TokenParams

	// PasswordHash is a bcrypt hash of the password.
	PasswordHash []byte

	Policies []string

	// Duration after which the user will be revoked unless renewed
	TTL time.Duration

	// Maximum duration for which user can be valid
	MaxTTL time.Duration

	BoundCIDRs []*sockaddr.SockAddrMarshaler
}

const pathUserHelpSyn = `
Manage users allowed to authenticate.
`

const pathUserHelpDesc = `
This endpoint allows you to create, read, update, and delete users
that are allowed to authenticate.

Deleting a user will not revoke auth for prior authenticated users
with that name. To do this, do a revoke on "login/<username>" for
the username you want revoked. If you don't need to revoke login immediately,
then the next renew will cause the lease to expire.
`
