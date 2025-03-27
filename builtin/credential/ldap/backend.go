// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ldap

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/go-secure-stdlib/strutil"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/helper/ldaputil"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const (
	operationPrefixLDAP = "ldap"
	errUserBindFailed   = "ldap operation failed: failed to bind as user"
)

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := Backend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

func Backend() *backend {
	var b backend
	b.Backend = &framework.Backend{
		Help: backendHelp,

		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{
				"login/*",
			},

			SealWrapStorage: []string{
				"config",
			},
		},

		Paths: []*framework.Path{
			pathConfig(&b),
			pathGroups(&b),
			pathGroupsList(&b),
			pathUsers(&b),
			pathUsersList(&b),
			pathLogin(&b),
		},

		AuthRenew:   b.pathLoginRenew,
		BackendType: logical.TypeCredential,
	}

	return &b
}

type backend struct {
	*framework.Backend
}

func (b *backend) Login(ctx context.Context, req *logical.Request, username string, password string, usernameAsAlias bool) (string, []string, *logical.Response, []string, error) {
	txRollback, err := logical.StartTxStorage(ctx, req)
	if err != nil {
		return "", nil, nil, nil, err
	}
	defer txRollback()

	cfg, err := b.Config(ctx, req)
	if err != nil {
		return "", nil, nil, nil, err
	}
	if cfg == nil {
		return "", nil, logical.ErrorResponse("ldap backend not configured"), nil, nil
	}

	if cfg.DenyNullBind && len(password) == 0 {
		return "", nil, logical.ErrorResponse("password cannot be of zero length when passwordless binds are being denied"), nil, nil
	}

	ldapClient := ldaputil.Client{
		Logger: b.Logger(),
		LDAP:   ldaputil.NewLDAP(),
	}

	c, err := ldapClient.DialLDAP(cfg.ConfigEntry)
	if err != nil {
		return "", nil, logical.ErrorResponse(err.Error()), nil, nil
	}
	if c == nil {
		return "", nil, logical.ErrorResponse("invalid connection returned from LDAP dial"), nil, nil
	}

	// Clean connection
	defer c.Close()

	userBindDN, err := ldapClient.GetUserBindDN(cfg.ConfigEntry, c, username)
	if err != nil {
		if b.Logger().IsDebug() {
			b.Logger().Debug("error getting user bind DN", "error", err)
		}
		return "", nil, logical.ErrorResponse(errUserBindFailed), nil, logical.ErrInvalidCredentials
	}

	if b.Logger().IsDebug() {
		b.Logger().Debug("user binddn fetched", "username", username, "binddn", userBindDN)
	}

	// Try to bind as the login user. This is where the actual authentication takes place.
	if len(password) > 0 {
		err = c.Bind(userBindDN, password)
	} else {
		err = c.UnauthenticatedBind(userBindDN)
	}
	if err != nil {
		if b.Logger().IsDebug() {
			b.Logger().Debug("ldap bind failed", "error", err)
		}
		return "", nil, logical.ErrorResponse(errUserBindFailed), nil, logical.ErrInvalidCredentials
	}

	// We re-bind to the BindDN if it's defined because we assume
	// the BindDN should be the one to search, not the user logging in.
	if cfg.BindDN != "" && cfg.BindPassword != "" {
		if err := c.Bind(cfg.BindDN, cfg.BindPassword); err != nil {
			if b.Logger().IsDebug() {
				b.Logger().Debug("error while attempting to re-bind with the BindDN User", "error", err)
			}
			return "", nil, logical.ErrorResponse("ldap operation failed: failed to re-bind with the BindDN user"), nil, logical.ErrInvalidCredentials
		}
		if b.Logger().IsDebug() {
			b.Logger().Debug("re-bound to original binddn")
		}
	}

	userDN, err := ldapClient.GetUserDN(cfg.ConfigEntry, c, userBindDN, username)
	if err != nil {
		return "", nil, logical.ErrorResponse(err.Error()), nil, nil
	}

	if cfg.AnonymousGroupSearch {
		c, err = ldapClient.DialLDAP(cfg.ConfigEntry)
		if err != nil {
			return "", nil, logical.ErrorResponse("ldap operation failed: failed to connect to LDAP server"), nil, nil
		}
		defer c.Close() // Defer closing of this connection as the deferal above closes the other defined connection
	}

	ldapGroups, err := ldapClient.GetLdapGroups(cfg.ConfigEntry, c, userDN, username)
	if err != nil {
		return "", nil, logical.ErrorResponse(err.Error()), nil, nil
	}
	if b.Logger().IsDebug() {
		b.Logger().Debug("groups fetched from server", "num_server_groups", len(ldapGroups), "server_groups", ldapGroups)
	}

	ldapResponse := &logical.Response{
		Data: map[string]interface{}{},
	}
	if len(ldapGroups) == 0 {
		errString := fmt.Sprintf(
			"no LDAP groups found in groupDN %q; only policies from locally-defined groups available",
			cfg.GroupDN)
		ldapResponse.AddWarning(errString)
	}

	var allGroups []string
	canonicalUsername := username
	cs := *cfg.CaseSensitiveNames
	if !cs {
		canonicalUsername = strings.ToLower(username)
	}
	// Import the custom added groups from ldap backend
	user, err := b.User(ctx, req.Storage, canonicalUsername)
	if err == nil && user != nil && user.Groups != nil {
		if b.Logger().IsDebug() {
			b.Logger().Debug("adding local groups", "num_local_groups", len(user.Groups), "local_groups", user.Groups)
		}
		allGroups = append(allGroups, user.Groups...)
	}
	// Merge local and LDAP groups
	allGroups = append(allGroups, ldapGroups...)

	canonicalGroups := allGroups
	// If not case sensitive, lowercase all
	if !cs {
		canonicalGroups = make([]string, len(allGroups))
		for i, v := range allGroups {
			canonicalGroups[i] = strings.ToLower(v)
		}
	}

	// Retrieve policies
	var policies []string
	for _, groupName := range canonicalGroups {
		group, err := b.Group(ctx, req.Storage, groupName)
		if err == nil && group != nil {
			policies = append(policies, group.Policies...)
		}
	}
	if user != nil && user.Policies != nil {
		policies = append(policies, user.Policies...)
	}
	// Policies from each group may overlap
	policies = strutil.RemoveDuplicates(policies, true)

	if usernameAsAlias {
		return username, policies, ldapResponse, allGroups, nil
	}

	entityAliasAttribute, err := ldapClient.GetUserAliasAttributeValue(cfg.ConfigEntry, c, username)
	if err != nil {
		return "", nil, logical.ErrorResponse(err.Error()), nil, nil
	}
	if entityAliasAttribute == "" {
		return "", nil, logical.ErrorResponse("missing entity alias attribute value"), nil, nil
	}

	if err := logical.EndTxStorage(ctx, req); err != nil {
		return "", nil, nil, nil, err
	}

	return entityAliasAttribute, policies, ldapResponse, allGroups, nil
}

const backendHelp = `
The "ldap" credential provider allows authentication querying
a LDAP server, checking username and password, and associating groups
to set of policies.

Configuration of the server is done through the "config" and "groups"
endpoints by a user with root access. Authentication is then done
by supplying the two fields for "login".
`
