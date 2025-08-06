// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package jwtauth

import (
	"context"
	"errors"
	"fmt"
	"reflect"

	"github.com/google/cel-go/common/types/ref"
	"github.com/hashicorp/cap/jwt"
	"github.com/hashicorp/go-sockaddr"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/sdk/v2/plugin/pb"
)

func pathCelLogin(b *jwtAuthBackend) *framework.Path {
	return &framework.Path{
		Pattern: `cel/login$`,

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixJWT,
			OperationVerb:   "login",
		},

		Fields: map[string]*framework.FieldSchema{
			"role": {
				Type:        framework.TypeLowerCaseString,
				Description: "The CEL role to log in against.",
			},
			"jwt": {
				Type:        framework.TypeString,
				Description: "The signed JWT to validate.",
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathCelLogin,
				Summary:  pathCelLoginHelpSyn,
			},
			logical.AliasLookaheadOperation: &framework.PathOperation{
				Callback: b.pathCelLogin,
			},
			logical.ResolveRoleOperation: &framework.PathOperation{
				Callback: b.pathResolveCelRole,
			},
		},

		HelpSynopsis:    pathCelLoginHelpSyn,
		HelpDescription: pathCelLoginHelpDesc,
	}
}

func (b *jwtAuthBackend) pathResolveCelRole(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	txRollback, err := logical.StartTxStorage(ctx, req)
	if err != nil {
		return nil, err
	}
	defer txRollback()

	config, err := b.config(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return logical.ErrorResponse("could not load configuration"), nil
	}
	celRole, resp, err := b.getCelRoleFromLoginRequest(config, ctx, req, d)
	if resp != nil || err != nil {
		return resp, err
	}

	if err := logical.EndTxStorage(ctx, req); err != nil {
		return nil, err
	}

	return logical.ResolveRoleResponse(celRole.Name)
}

func (b *jwtAuthBackend) getCelRoleFromLoginRequest(config *jwtConfig, ctx context.Context, req *logical.Request, d *framework.FieldData) (*celRoleEntry, *logical.Response, error) {
	roleName := d.Get("role").(string)
	if roleName == "" {
		roleName = config.DefaultRole
	}
	if roleName == "" {
		return nil, logical.ErrorResponse("missing role"), nil
	}

	role, err := b.getCelRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, nil, err
	}
	if role == nil {
		return nil, logical.ErrorResponse("role %q could not be found", roleName), nil
	}

	return role, nil, nil
}

func (b *jwtAuthBackend) pathCelLogin(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	txRollback, err := logical.StartTxStorage(ctx, req)
	if err != nil {
		return nil, err
	}
	defer txRollback()

	config, err := b.config(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return logical.ErrorResponse("could not load configuration"), nil
	}

	celRoleEntry, resp, err := b.getCelRoleFromLoginRequest(config, ctx, req, d)
	if resp != nil || err != nil {
		return resp, err
	}

	token := d.Get("jwt").(string)
	if len(token) == 0 {
		return logical.ErrorResponse("missing token"), nil
	}

	// Get the JWT validator based on the configured auth type
	validator, err := b.jwtValidator(config)
	if err != nil {
		return logical.ErrorResponse("error configuring token validator: %s", err.Error()), nil
	}

	// Validate JWT supported algorithms if they've been provided. Otherwise,
	// ensure that the signing algorithm is a member of the supported set.
	signingAlgorithms := toAlg(config.JWTSupportedAlgs)
	if len(signingAlgorithms) == 0 {
		signingAlgorithms = []jwt.Alg{
			jwt.RS256, jwt.RS384, jwt.RS512, jwt.ES256, jwt.ES384,
			jwt.ES512, jwt.PS256, jwt.PS384, jwt.PS512, jwt.EdDSA,
		}
	}

	// Set expected claims values to assert on the JWT
	expected := jwt.Expected{
		Issuer:            config.BoundIssuer,
		SigningAlgorithms: signingAlgorithms,
		Audiences:         celRoleEntry.BoundAudiences,
		NotBeforeLeeway:   celRoleEntry.NotBeforeLeeway,
		ExpirationLeeway:  celRoleEntry.ExpirationLeeway,
		ClockSkewLeeway:   celRoleEntry.ClockSkewLeeway,
	}

	// Validate the JWT by verifying its signature and asserting expected claims values
	allClaims, err := validator.Validate(ctx, token, expected)
	if err != nil {
		return logical.ErrorResponse("error validating token: %s", err.Error()), nil
	}

	// execute celRoleEntry.AuthProgram
	pbAuth, err := b.runCelProgram(ctx, req.Operation, celRoleEntry, allClaims)
	if err != nil {
		return logical.ErrorResponse("error executing cel program: %s", err.Error()), nil
	}

	auth, err := pb.ProtoAuthToLogicalAuth(pbAuth)
	if err != nil {
		return logical.ErrorResponse("error converting proto auth: %s", err.Error()), nil
	}

	if err := logical.EndTxStorage(ctx, req); err != nil {
		return nil, err
	}

	return &logical.Response{
		Auth: auth,
	}, nil
}

// runCelProgram executes the CelProgram for the celRoleEntry and returns a pb.Auth or error
func (b *jwtAuthBackend) runCelProgram(ctx context.Context, operation logical.Operation, celRoleEntry *celRoleEntry, allClaims map[string]any) (*pb.Auth, error) {
	result, err := b.celEvalProgram(celRoleEntry.CelProgram, operation, allClaims)
	if err != nil {
		return nil, fmt.Errorf("Cel role auth program failed: %w", err)
	}

	refVal := result.(ref.Val)

	// process result from CEL program
	switch v := refVal.Value().(type) {
	// if boolean false return auth failed
	case bool:
		if !v {
			return nil, fmt.Errorf("Cel role '%s' blocked authorization with boolean false return", celRoleEntry.Name)
		}
	// if string, return this as auth failed message
	case string:
		return nil, fmt.Errorf("Cel role '%s' blocked authorization with message: %s", celRoleEntry.Name, v)

	}

	// handle protobuf Auth return type
	if msg, err := refVal.ConvertToNative(reflect.TypeOf(&pb.Auth{})); err == nil {
		pbAuth, ok := msg.(*pb.Auth)
		if ok {
			return pbAuth, nil
		}
	}

	return nil, fmt.Errorf("Cel program '%s' returned unexpected type: %T", celRoleEntry.Name, result)
}

func (b *jwtAuthBackend) pathCelLoginRenew(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := req.Auth.InternalData["role"].(string)
	if roleName == "" {
		return nil, errors.New("failed to fetch cel role_name during renewal")
	}

	// Ensure that the Role still exists.
	role, err := b.getCelRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, fmt.Errorf("failed to validate cel role %s during renewal: %v", roleName, err)
	}
	if role == nil {
		return nil, fmt.Errorf("cel role %s does not exist during renewal", roleName)
	}

	resp := &logical.Response{Auth: req.Auth}
	// on renew, keep the previous TTLs -- not available without running against JWT
	return resp, nil
}

const (
	pathCelLoginHelpSyn = `
	Authenticates to OpenBao using a JWT (or OIDC) token against a CEL role.
	`
	pathCelLoginHelpDesc = `
Authenticates JWTs against a CEL role.
`
)

func marshalCIDRs(cidrs []string) []*sockaddr.SockAddrMarshaler {
	sockaddrs := []*sockaddr.SockAddrMarshaler{}
	for _, cidr := range cidrs {
		sockaddr := sockaddr.SockAddrMarshaler{}
		sockaddr.UnmarshalJSON([]byte(cidr))
		sockaddrs = append(sockaddrs, &sockaddr)
	}
	return sockaddrs
}
