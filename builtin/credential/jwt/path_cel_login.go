// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package jwtauth

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
	"github.com/hashicorp/cap/jwt"
	"github.com/hashicorp/errwrap"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/helper/cidrutil"
	"github.com/openbao/openbao/sdk/v2/logical"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	CelResultAuthorizedKey     = "authorized"
	CelResultAddPoliciesKey    = "add_policies"
	CelResultRemovePoliciesKey = "remove_policies"
)

func pathCelLogin(b *jwtAuthBackend) *framework.Path {
	return &framework.Path{
		Pattern: `cel/login/?`,

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

	// virtual role produced by the CEL program
	role := &jwtRole{}

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
	}

	// Validate the JWT by verifying its signature and asserting expected claims values
	allClaims, err := validator.Validate(ctx, token, expected)
	if err != nil {
		return logical.ErrorResponse("error validating token: %s", err.Error()), nil
	}

	// execute celRoleEntry.AuthProgram
	role, err = b.runCelProgram(ctx, celRoleEntry, allClaims)
	if err != nil {
		return logical.ErrorResponse("error executing cel program: %s", err.Error()), nil
	}

	if len(role.TokenBoundCIDRs) > 0 {
		if req.Connection == nil {
			b.Logger().Warn("token bound CIDRs found but no connection information available for validation")
			return nil, logical.ErrPermissionDenied
		}
		if !cidrutil.RemoteAddrIsOk(req.Connection.RemoteAddr, role.TokenBoundCIDRs) {
			return nil, logical.ErrPermissionDenied
		}
	}

	// If there are no bound audiences for the role, then the existence of any audience
	// in the audience claim should result in an error.
	aud, ok := getClaim(b.Logger(), allClaims, "aud").([]interface{})
	if ok && len(aud) > 0 && len(role.BoundAudiences) == 0 {
		return logical.ErrorResponse("audience claim found in JWT but no audiences bound to the role"), nil
	}

	alias, groupAliases, err := b.createIdentity(ctx, allClaims, celRoleEntry.Name, role, nil)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	if err := validateBoundClaims(b.Logger(), role.BoundClaimsType, role.BoundClaims, allClaims); err != nil {
		return logical.ErrorResponse("error validating claims: %s", err.Error()), nil
	}

	tokenMetadata := make(map[string]string)
	for k, v := range alias.Metadata {
		tokenMetadata[k] = v
	}

	auth := &logical.Auth{
		DisplayName:  alias.Name,
		Alias:        alias,
		GroupAliases: groupAliases,
		InternalData: map[string]interface{}{
			"role": celRoleEntry.Name,
		},
		Metadata: tokenMetadata,
	}

	if err := role.PopulateTokenAuth(auth, req); err != nil {
		return nil, fmt.Errorf("failed to populate auth information: %w", err)
	}

	if err := role.maybeTemplatePolicies(auth, allClaims); err != nil {
		return nil, err
	}

	return &logical.Response{
		Auth: auth,
	}, nil
}

func (b *jwtAuthBackend) runCelProgram(ctx context.Context, celRoleEntry *celRoleEntry, allClaims map[string]any) (*jwtRole, error) {
	role := jwtRole{}
	env, err := cel.NewEnv(
		cel.Variable("claims", cel.MapType(cel.StringType, cel.DynType)),
		cel.Function("SetPolicies",
			cel.Overload("SetPolicies",
				[]*cel.Type{cel.ListType(types.StringType)},
				cel.NullType,
				cel.UnaryBinding(func(arg ref.Val) ref.Val {
					list, ok := arg.(traits.Lister)
					if !ok {
						return types.NewErr("expected a list of strings")
					}

					// Iterate over the list
					for i := int64(0); i < int64(list.Size().(types.Int)); i++ {
						elem := fmt.Sprintf("%v", list.Get(types.Int(i)))
						role.TokenPolicies = append(role.TokenPolicies, elem)
					}

					// Return nil
					return types.NullValue
				}),
			),
		),
	)
	if err != nil {
		return nil, err
	}
	ast, iss := env.Compile(celRoleEntry.AuthProgram)
	if iss.Err() != nil {
		return nil, fmt.Errorf("Cel role auth program failed to compile: %w", iss.Err())
	}
	prog, err := env.Program(ast)
	if err != nil {
		return nil, fmt.Errorf("Cel role auth program failed: %w", err)
	}
	result, _, err := prog.Eval(map[string]any{
		"claims": allClaims,
	})
	if err != nil {
		return nil, fmt.Errorf("Cel role auth program failed to evaluate: %w", err)
	}

	// process result from CEL program
	switch v := result.Value().(type) {
	// if boolean return value
	case bool:
		if !v {
			return nil, fmt.Errorf("Cel role '%s' blocked authorization with boolean false return", celRoleEntry.Name)
		}
	case structpb.NullValue:
		// okay, just continue
	default:
		return nil, fmt.Errorf("Cel role '%s' returned unexpected type: %T", celRoleEntry.Name, result.Value())
	}

	return &role, nil
}

func (b *jwtAuthBackend) pathCelLoginRenew(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := req.Auth.InternalData["role"].(string)
	if roleName == "" {
		return nil, errors.New("failed to fetch role_name during renewal")
	}

	// Ensure that the Role still exists.
	role, err := b.role(ctx, req.Storage, roleName)
	if err != nil {
		return nil, errwrap.Wrapf(fmt.Sprintf("failed to validate role %s during renewal: {{err}}", roleName), err)
	}
	if role == nil {
		return nil, fmt.Errorf("role %s does not exist during renewal", roleName)
	}

	resp := &logical.Response{Auth: req.Auth}
	resp.Auth.TTL = role.TokenTTL
	resp.Auth.MaxTTL = role.TokenMaxTTL
	resp.Auth.Period = role.TokenPeriod
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
