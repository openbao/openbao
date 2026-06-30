// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ldap

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/helper/cidrutil"
	"github.com/openbao/openbao/sdk/v2/helper/policyutil"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func pathLogin(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: `login/(?P<username>.+)`,

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixLDAP,
			OperationVerb:   "login",
		},

		Fields: map[string]*framework.FieldSchema{
			"username": {
				Type:        framework.TypeString,
				Description: "DN (distinguished name) to be used for login.",
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
		return nil, errors.New("missing username")
	}

	// _Some_ LDAP backends will silently trim spaces, leading to an
	// authentication lockout bypass if not adjusted in the alias.
	// We normalize the username to avoid this, as _presumably_ users
	// do not normally begin/end with leading space.
	//
	// See HCSEC-2025-16 / CVE-2025-6004 for more information.
	username = strings.TrimSpace(username)

	cfg, err := b.Config(ctx, req)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return logical.ErrorResponse("auth method not configured"), nil
	}

	// Likewise, if the configuration uses a lower-case username, set that
	// as our alias.
	if cfg.CaseSensitiveNames != nil && !*cfg.CaseSensitiveNames {
		username = strings.ToLower(username)
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
	cfg, err := b.Config(ctx, req)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return logical.ErrorResponse("auth method not configured"), nil
	}

	// Check for a CIDR match.
	if len(cfg.TokenBoundCIDRs) > 0 {
		if req.Connection == nil {
			b.Logger().Warn("token bound CIDRs found but no connection information available for validation")
			return nil, logical.ErrPermissionDenied
		}
		if !cidrutil.RemoteAddrIsOk(req.Connection.RemoteAddr, cfg.TokenBoundCIDRs) {
			return nil, logical.ErrPermissionDenied
		}
	}

	username := d.Get("username").(string)
	password := d.Get("password").(string)

	// See notes in pathLoginAliasLookahead(...) for more information. This
	// is a hack specifically for HCSEC-2025-20 / CVE-2025-6013.
	username = strings.TrimSpace(username)
	if cfg.CaseSensitiveNames != nil && !*cfg.CaseSensitiveNames {
		username = strings.ToLower(username)
	}

	effectiveUsername, policies, resp, groupNames, err := b.Login(ctx, req, username, password, cfg.UsernameAsAlias)
	if err != nil || (resp != nil && resp.IsError()) {
		return resp, err
	}

	auth := &logical.Auth{
		Metadata: map[string]string{
			"username": username,
		},
		InternalData: map[string]interface{}{
			"password": password,
		},
		DisplayName: username,
		Alias: &logical.Alias{
			Name: effectiveUsername,
			Metadata: map[string]string{
				"name": username,
			},
		},
	}

	if err := cfg.PopulateTokenAuth(auth, req); err != nil {
		return nil, fmt.Errorf("failed to populate auth information: %w", err)
	}

	// Add in configured policies from mappings
	if len(policies) > 0 {
		auth.Policies = append(auth.Policies, policies...)
	}

	resp.Auth = auth

	for _, groupName := range groupNames {
		if groupName == "" {
			continue
		}
		resp.Auth.GroupAliases = append(resp.Auth.GroupAliases, &logical.Alias{
			Name: groupName,
		})
	}
	return resp, nil
}

func (b *backend) pathLoginRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	cfg, err := b.Config(ctx, req)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return logical.ErrorResponse("auth method not configured"), nil
	}

	username := req.Auth.Metadata["username"]
	password := req.Auth.InternalData["password"].(string)

	_, loginPolicies, resp, groupNames, err := b.Login(ctx, req, username, password, cfg.UsernameAsAlias)
	if err != nil || (resp != nil && resp.IsError()) {
		return resp, err
	}

	finalPolicies := cfg.TokenPolicies
	if len(loginPolicies) > 0 {
		finalPolicies = append(finalPolicies, loginPolicies...)
	}

	if !policyutil.EquivalentPolicies(finalPolicies, req.Auth.TokenPolicies) {
		return nil, errors.New("policies have changed, not renewing")
	}

	resp.Auth = req.Auth
	resp.Auth.Period = cfg.TokenPeriod
	resp.Auth.TTL = cfg.TokenTTL
	resp.Auth.MaxTTL = cfg.TokenMaxTTL

	// Remove old aliases
	resp.Auth.GroupAliases = nil

	for _, groupName := range groupNames {
		resp.Auth.GroupAliases = append(resp.Auth.GroupAliases, &logical.Alias{
			Name: groupName,
		})
	}

	return resp, nil
}

const pathLoginSyn = `
Log in with a username and password.
`

const pathLoginDesc = `
This endpoint authenticates using a username and password. Please be sure to
read the note on escaping from the path-help for the 'config' endpoint.
`
