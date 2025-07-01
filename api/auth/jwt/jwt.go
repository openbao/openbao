// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package jwt

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/openbao/openbao/api/v2"
)

// DefaultMountPath specifies the default mount path for the JWT
// Authentication Method.
const DefaultMountPath = "jwt"

// ErrNoToken is an error, which is returned when [JWTAuth] is configured
// with an empty token.
var ErrNoToken = errors.New("no token specified")

// ErrInvalidMountPath is an error, which is returned when configuring [JWTAuth]
// to use an invalid mount path for an Authentication Method.
var ErrInvalidMountPath = errors.New("invalid auth method mount path specified")

// ErrNoRoleName is an error, which is returned when no role name was specified
// when creating a [JWTAuth].
var ErrNoRoleName = errors.New("no role name specified")

// JWTAuth implements support for the [JWT Authentication Method].
//
// [JWT Authentication Method]: https://openbao.org/docs/auth/jwt/
type JWTAuth struct {
	// roleName specifies the name of the role to use.
	roleName string

	// mountPath specifies the mount path for the JWT Authentication Method.
	mountPath string

	// token specifies the JWT token which will be used for authenticating
	// against the OpenBao Authentication Method endpoint.
	token string

	// tokenPath specifies a path from which to read the JWT token.
	tokenPath string
}

var _ api.AuthMethod = &JWTAuth{}

// Option is a function which configures [JWTAuth].
type Option func(a *JWTAuth) error

// New creates a new [JWTAuth] and configures it with the given options.
//
// The default mount path for the JWT Authentication Method is
// [DefaultMountPath]. In order to configure a different mount path for the
// Authentication Method you can use the [WithMountPath] option.
//
// The JWT token which will be used for authentication against the OpenBao
// Authentication Method login endpoint may be specified either as a string,
// from path, or via an environment variable. In order to configure the token
// for authentication use the [WithToken], [WithTokenFromPath] or
// [WithTokenFromEnv] options.
func New(roleName string, opts ...Option) (*JWTAuth, error) {
	if roleName == "" {
		return nil, ErrNoRoleName
	}

	jwtAuth := &JWTAuth{
		roleName:  roleName,
		mountPath: DefaultMountPath,
	}

	for _, opt := range opts {
		if err := opt(jwtAuth); err != nil {
			return nil, err
		}
	}

	if jwtAuth.token == "" && jwtAuth.tokenPath == "" {
		return nil, ErrNoToken
	}

	if jwtAuth.mountPath == "" {
		return nil, ErrInvalidMountPath
	}

	return jwtAuth, nil
}

// Login implements the [api.AuthMethod] interface.
func (a *JWTAuth) Login(ctx context.Context, client *api.Client) (*api.Secret, error) {
	var token string

	switch {
	case a.token != "":
		token = a.token
	case a.tokenPath != "":
		data, err := os.ReadFile(filepath.Clean(a.tokenPath))
		if err != nil {
			return nil, err
		}
		token = string(data)
		if token == "" {
			return nil, fmt.Errorf("%w: got empty token from %s", ErrNoToken, a.tokenPath)
		}
	}

	path := fmt.Sprintf("auth/%s/login", a.mountPath)
	data := map[string]any{
		"jwt":  strings.TrimSpace(token),
		"role": a.roleName,
	}

	return client.Logical().WriteWithContext(ctx, path, data)
}

// WithToken is an [Option], which configures [JWTAuth] to use the given token
// when authenticating against the OpenBao JWT Authentication Method.
func WithToken(token string) Option {
	opt := func(a *JWTAuth) error {
		a.token = token

		return nil
	}

	return opt
}

// WithTokenFromPath is an [Option], which configures [JWTAuth] to read the
// token from the given path.
func WithTokenFromPath(path string) Option {
	opt := func(a *JWTAuth) error {
		a.tokenPath = path

		return nil
	}

	return opt
}

// WithTokenFromEnv is an [Option], which configures [JWTAuth] to read the token
// from the given environment variable.
func WithTokenFromEnv(env string) Option {
	opt := func(a *JWTAuth) error {
		value := os.Getenv(env)
		a.token = value

		return nil
	}

	return opt
}

// WithMountPath is an [Option], which configures [JWTAuth] to use the given
// mount path for the OpenBao Authentication Method.
func WithMountPath(mountPath string) Option {
	opt := func(a *JWTAuth) error {
		a.mountPath = mountPath

		return nil
	}

	return opt
}
