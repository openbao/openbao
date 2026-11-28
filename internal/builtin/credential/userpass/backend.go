// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package userpass

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const operationPrefixUserpass = "userpass"

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
		},

		Paths: []*framework.Path{
			pathUsers(&b),
			pathUsersList(&b),
			pathUserPolicies(&b),
			pathUserPassword(&b),
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

// Enforce username rules
var validUsername = regexp.MustCompile("^" + framework.GenericNameWithAtRegex("username") + "$")

// During routing, anything except "/" is acceptable in a username. Routing only checks for endpoint matches. Username rules are checked separately.
const usernamePathRegex = `(?P<username>[^/]+)`

// Read username and reinforce rules
func getUsername(d *framework.FieldData) (string, error) {
	username := d.Get("username").(string)
	if username == "" {
		return "", errors.New("missing username")
	}

	if !validUsername.MatchString(username) {
		return "", fmt.Errorf("invalid username: %q", username)
	}
	return strings.ToLower(username), nil
}

const backendHelp = `
The "userpass" credential provider allows authentication using
a combination of a username and password. No additional factors
are supported.

The username/password combination is configured using the "users/"
endpoints by a user with root access. Authentication is then done
by supplying the two fields for "login".
`
