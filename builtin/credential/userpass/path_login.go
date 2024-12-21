// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package userpass

import (
	"context"
	"fmt"
	"strings"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/helper/cidrutil"
	"github.com/openbao/openbao/sdk/v2/helper/policyutil"
	"github.com/openbao/openbao/sdk/v2/logical"
	"golang.org/x/crypto/bcrypt"
)

func pathLogin(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "login/" + framework.GenericNameRegex("username"),

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixUserpass,
			OperationVerb:   "login",
		},

		Fields: map[string]*framework.FieldSchema{
			"username": {
				Type:        framework.TypeString,
				Description: "Username of the user.",
			},

			"password": {
				Type:        framework.TypeString,
				Description: "Password for this user.",
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathLogin,
			},
			logical.AliasLookaheadOperation: &framework.PathOperation{
				Callback: b.pathLoginAliasLookahead,
			},
		},

		HelpSynopsis:    pathLoginSyn,
		HelpDescription: pathLoginDesc,
	}
}

func (b *backend) pathLoginAliasLookahead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	username := d.Get("username").(string)
	if username == "" {
		return nil, fmt.Errorf("missing username")
	}

	return &logical.Response{
		Auth: &logical.Auth{
			Alias: &logical.Alias{
				Name: username,
			},
		},
	}, nil
}

func (b *backend) pathLogin(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	username := strings.ToLower(d.Get("username").(string))

	password := d.Get("password").(string)
	if password == "" {
		return nil, fmt.Errorf("missing password")
	}

	// Get the user and validate auth
	user, userError := b.user(ctx, req.Storage, username)

	var userPassword []byte
	// If there was an error or it's nil, we fake a password for the bcrypt
	// check so as not to have a timing leak. Specifics of the underlying
	// storage still leaks a bit but generally much more in the noise compared
	// to bcrypt.
	if user != nil && userError == nil {
		if len(user.PasswordHash) == 0 {
			return nil, fmt.Errorf("invalid user entry: refusing to process pre-Vault v0.2 record")
		}

		userPassword = user.PasswordHash
	} else {
		// This is still acceptable as bcrypt will still make sure it takes
		// a long time, it's just nicer to be random if possible
		userPassword = []byte("dummy")
	}

	// Check for a password match.
	passwordBytes := []byte(password)
	if err := bcrypt.CompareHashAndPassword(userPassword, passwordBytes); err != nil {
		// The failed login info of existing users alone are tracked as only
		// existing user's failed login information is stored in storage for optimization
		if user == nil || userError != nil {
			return logical.ErrorResponse("invalid username or password"), nil
		}
		return logical.ErrorResponse("invalid username or password"), logical.ErrInvalidCredentials
	}

	if userError != nil {
		return nil, userError
	}
	if user == nil {
		return logical.ErrorResponse("invalid username or password"), nil
	}

	// Check for a CIDR match.
	if len(user.TokenBoundCIDRs) > 0 {
		if req.Connection == nil {
			b.Logger().Warn("token bound CIDRs found but no connection information available for validation")
			return nil, logical.ErrPermissionDenied
		}
		if !cidrutil.RemoteAddrIsOk(req.Connection.RemoteAddr, user.TokenBoundCIDRs) {
			return nil, logical.ErrPermissionDenied
		}
	}

	auth := &logical.Auth{
		Metadata: map[string]string{
			"username": username,
		},
		DisplayName: username,
		Alias: &logical.Alias{
			Name: username,
		},
	}
	if err := user.PopulateTokenAuth(auth, req); err != nil {
		return nil, fmt.Errorf("failed to populate auth information: %w", err)
	}

	return &logical.Response{
		Auth: auth,
	}, nil
}

func (b *backend) pathLoginRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// Get the user
	user, err := b.user(ctx, req.Storage, req.Auth.Metadata["username"])
	if err != nil {
		return nil, err
	}
	if user == nil {
		// User no longer exists, do not renew
		return nil, nil
	}

	if !policyutil.EquivalentPolicies(user.TokenPolicies, req.Auth.TokenPolicies) {
		return nil, fmt.Errorf("policies have changed, not renewing")
	}

	resp := &logical.Response{Auth: req.Auth}
	resp.Auth.Period = user.TokenPeriod
	resp.Auth.TTL = user.TokenTTL
	resp.Auth.MaxTTL = user.TokenMaxTTL
	return resp, nil
}

const pathLoginSyn = `
Log in with a username and password.
`

const pathLoginDesc = `
This endpoint authenticates using a username and password.
`
