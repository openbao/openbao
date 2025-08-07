// Copyright (c) 2024 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package jwtauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	"github.com/openbao/openbao/sdk/v2/framework"
	celhelper "github.com/openbao/openbao/sdk/v2/helper/cel"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/sdk/v2/plugin/pb"
)

type celRoleEntry struct {
	Name       string               `json:"name"`        // Required
	CelProgram celhelper.CelProgram `json:"cel_program"` // Required
	Message    string               `json:"message,omitempty"`

	// The following attributes are used for validating a JWT prior to CEL evaluation
	// Duration of leeway for expiration to account for clock skew
	ExpirationLeeway time.Duration `json:"expiration_leeway"`
	// Duration of leeway for not before to account for clock skew
	NotBeforeLeeway time.Duration `json:"not_before_leeway"`
	// Duration of leeway for all claims to account for clock skew
	ClockSkewLeeway time.Duration `json:"clock_skew_leeway"`
	// Role binding properties
	BoundAudiences []string `json:"bound_audiences"`
}

func pathCelRoleList(b *jwtAuthBackend) *framework.Path {
	return &framework.Path{
		Pattern: "cel/role/?",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixJWT,
			OperationSuffix: "cel",
			OperationVerb:   "list",
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
				Callback: b.pathCelRoleList,
				Responses: map[int][]framework.Response{
					http.StatusOK: {{
						Description: "OK",
						Fields: map[string]*framework.FieldSchema{
							"keys": {
								Type:        framework.TypeStringSlice,
								Description: "List of CEL roles",
								Required:    true,
							},
						},
					}},
				},
			},
		},

		HelpSynopsis:    pathListCelHelpSyn,
		HelpDescription: pathListCelHelpDesc,
	}
}

func pathCelRole(b *jwtAuthBackend) *framework.Path {
	pathCelRolesResponseFields := map[string]*framework.FieldSchema{
		"name": {
			Type:        framework.TypeString,
			Description: "Name of the cel role",
		},
		"cel_program": {
			Type:        framework.TypeMap,
			Description: "CEL variables and expression defining the program for the role",
		},
		"failure_policy": {
			Type:        framework.TypeString,
			Description: "Failure policy if CEL expressions are not validated",
		},
		"message": {
			Type:        framework.TypeString,
			Description: "Static error message if validation fails",
		},
		"expiration_leeway": {
			Type: framework.TypeSignedDurationSecond,
			Description: `Duration in seconds of leeway when validating expiration of a token to account for clock skew.
 Defaults to 150 (2.5 minutes) if set to 0 and can be disabled if set to -1.`,
			Default: claimDefaultLeeway,
		},
		"not_before_leeway": {
			Type: framework.TypeSignedDurationSecond,
			Description: `Duration in seconds of leeway when validating not before values of a token to account for clock skew.
 Defaults to 150 (2.5 minutes) if set to 0 and can be disabled if set to -1.`,
			Default: claimDefaultLeeway,
		},
		"clock_skew_leeway": {
			Type: framework.TypeSignedDurationSecond,
			Description: `Duration in seconds of leeway when validating all claims to account for clock skew.
 Defaults to 60 (1 minute) if set to 0 and can be disabled if set to -1.`,
			Default: jwt.DefaultLeeway,
		},
		"bound_audiences": {
			Type:        framework.TypeCommaStringSlice,
			Description: `Comma-separated list of 'aud' claims that are valid for login; any match is sufficient`,
		},
	}

	return &framework.Path{
		Pattern: "cel/role/" + framework.GenericNameRegex("name"),

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixJWT,
			OperationSuffix: "role",
		},

		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the cel role",
			},
			"cel_program": {
				Type:        framework.TypeMap,
				Description: "CEL variables and expression defining the program for the role",
			},
			"failure_policy": {
				Type:        framework.TypeString,
				Description: "Failure policy if CEL expressions are not validated",
			},
			"message": {
				Type:        framework.TypeString,
				Description: "Static error message if validation fails",
			},
			"expiration_leeway": {
				Type: framework.TypeSignedDurationSecond,
				Description: `Duration in seconds of leeway when validating expiration of a token to account for clock skew.
 Defaults to 150 (2.5 minutes) if set to 0 and can be disabled if set to -1.`,
				Default: claimDefaultLeeway,
			},
			"not_before_leeway": {
				Type: framework.TypeSignedDurationSecond,
				Description: `Duration in seconds of leeway when validating not before values of a token to account for clock skew.
 Defaults to 150 (2.5 minutes) if set to 0 and can be disabled if set to -1.`,
				Default: claimDefaultLeeway,
			},
			"clock_skew_leeway": {
				Type: framework.TypeSignedDurationSecond,
				Description: `Duration in seconds of leeway when validating all claims to account for clock skew.
 Defaults to 60 (1 minute) if set to 0 and can be disabled if set to -1.`,
				Default: jwt.DefaultLeeway,
			},
			"bound_audiences": {
				Type:        framework.TypeCommaStringSlice,
				Description: `Comma-separated list of 'aud' claims that are valid for login; any match is sufficient`,
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathCelRoleRead,
				Responses: map[int][]framework.Response{
					http.StatusOK: {{
						Description: "OK",
						Fields:      pathCelRolesResponseFields,
					}},
				},
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathCelRoleCreate,
				Responses: map[int][]framework.Response{
					http.StatusOK: {{
						Description: "OK",
						Fields:      pathCelRolesResponseFields,
					}},
				},
				// Read more about why these flags are set in backend.go.
				ForwardPerformanceStandby:   true,
				ForwardPerformanceSecondary: true,
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathCelRoleDelete,
				Responses: map[int][]framework.Response{
					http.StatusNoContent: {{
						Description: "No Content",
					}},
				},
				// Read more about why these flags are set in backend.go.
				ForwardPerformanceStandby:   true,
				ForwardPerformanceSecondary: true,
			},
			logical.PatchOperation: &framework.PathOperation{
				Callback: b.pathCelRolePatch,
				Responses: map[int][]framework.Response{
					http.StatusOK: {{
						Description: "OK",
						Fields:      pathCelRolesResponseFields,
					}},
				},
				// Read more about why these flags are set in backend.go.
				ForwardPerformanceStandby:   true,
				ForwardPerformanceSecondary: true,
			},
		},

		HelpSynopsis:    pathCelRoleHelpSyn,
		HelpDescription: pathCelRoleHelpDesc,
	}
}

func (b *jwtAuthBackend) pathCelRoleCreate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	var err error
	nameRaw, ok := data.GetOk("name")
	if !ok {
		return logical.ErrorResponse("missing required field 'name'"), nil
	}
	name := nameRaw.(string)

	celProgram := celhelper.CelProgram{}
	if celProgramRaw, ok := data.GetOk("cel_program"); !ok {
		return logical.ErrorResponse("missing required field 'cel_program'"), nil
	} else {
		jsonString, err := json.Marshal(celProgramRaw)
		if err != nil {
			return logical.ErrorResponse("failed to parse cel_program: %s", err), nil
		}
		if err := json.Unmarshal(jsonString, &celProgram); err != nil {
			return logical.ErrorResponse("failed to parse cel_program: %s", err), nil
		}
	}

	failurePolicy := "Deny" // Default value
	if failurePolicyRaw, ok := data.GetOk("failure_policy"); ok {
		failurePolicy = failurePolicyRaw.(string)
		if failurePolicy != "Deny" && failurePolicy != "Modify" {
			return logical.ErrorResponse("failure_policy must be 'Deny' or 'Modify'"), nil
		}
	}

	expirationLeeway := time.Duration(claimDefaultLeeway) * time.Second
	if tokenExpLeewayRaw, ok := data.GetOk("expiration_leeway"); ok {
		expirationLeeway = time.Duration(tokenExpLeewayRaw.(int)) * time.Second
	}

	notBeforeLeeway := time.Duration(claimDefaultLeeway) * time.Second
	if tokenNotBeforeLeewayRaw, ok := data.GetOk("not_before_leeway"); ok {
		notBeforeLeeway = time.Duration(tokenNotBeforeLeewayRaw.(int)) * time.Second
	}

	clockSkewLeeway := jwt.DefaultLeeway
	if tokenClockSkewLeeway, ok := data.GetOk("clock_skew_leeway"); ok {
		clockSkewLeeway = time.Duration(tokenClockSkewLeeway.(int)) * time.Second
	}

	boundAudiences := []string{}
	if tokenBoundAudiences, ok := data.GetOk("bound_audiences"); ok {
		boundAudiences = tokenBoundAudiences.([]string)
	}

	entry := &celRoleEntry{
		Name:             name,
		CelProgram:       celProgram,
		Message:          data.Get("message").(string),
		BoundAudiences:   boundAudiences,
		ExpirationLeeway: expirationLeeway,
		NotBeforeLeeway:  notBeforeLeeway,
		ClockSkewLeeway:  clockSkewLeeway,
	}

	resp, err := validateCelRoleCreation(b, entry, ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	if resp.IsError() {
		return resp, nil
	}

	// Store it
	jsonEntry, err := logical.StorageEntryJSON("cel/role/"+name, entry)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, jsonEntry); err != nil {
		return nil, err
	}

	return resp, nil
}

func (b *jwtAuthBackend) pathCelRoleList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	after := data.Get("after").(string)
	limit := data.Get("limit").(int)

	entries, err := req.Storage.ListPage(ctx, "cel/role/", after, limit)
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}

func (b *jwtAuthBackend) pathCelRoleRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("name").(string)
	if roleName == "" {
		return logical.ErrorResponse("missing CEL role name"), nil
	}

	role, err := b.getCelRole(ctx, req.Storage, roleName)
	if err != nil || role == nil {
		return nil, err
	}

	resp := &logical.Response{
		Data: role.ToResponseData(),
	}
	return resp, nil
}

func (b *jwtAuthBackend) pathCelRolePatch(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	txRollback, err := logical.StartTxStorage(ctx, req)
	if err != nil {
		return nil, err
	}
	defer txRollback()

	roleName := data.Get("name").(string)

	oldEntry, err := b.getCelRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if oldEntry == nil {
		return logical.ErrorResponse("Unable to fetch cel role entry to patch"), nil
	}

	entry := &celRoleEntry{
		Name:       roleName,
		CelProgram: data.GetWithExplicitDefault("cel_program", oldEntry.CelProgram).(celhelper.CelProgram),
		Message:    data.GetWithExplicitDefault("message", oldEntry.Message).(string),
	}

	resp, err := validateCelRoleCreation(b, entry, ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if resp.IsError() {
		return resp, nil
	}

	// Store it
	jsonEntry, err := logical.StorageEntryJSON("cel/role/"+roleName, entry)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, jsonEntry); err != nil {
		return nil, err
	}

	if err := logical.EndTxStorage(ctx, req); err != nil {
		return nil, err
	}

	return resp, nil
}

func (b *jwtAuthBackend) pathCelRoleDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := req.Storage.Delete(ctx, "cel/role/"+data.Get("name").(string))
	return nil, err
}

func (b *jwtAuthBackend) getCelRole(ctx context.Context, s logical.Storage, roleName string) (*celRoleEntry, error) {
	entry, err := s.Get(ctx, "cel/role/"+roleName)
	if err != nil || entry == nil {
		return nil, err
	}

	var result celRoleEntry
	if err := entry.DecodeJSON(&result); err != nil {
		return nil, err
	}

	result.Name = roleName

	return &result, nil
}

func validateCelRoleCreation(b *jwtAuthBackend, entry *celRoleEntry, ctx context.Context, s logical.Storage) (*logical.Response, error) {
	resp := &logical.Response{}

	_, err := b.validateCelProgram(entry.CelProgram)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	resp.Data = entry.ToResponseData()
	return resp, nil
}

func (b *jwtAuthBackend) validateCelProgram(program celhelper.CelProgram) (bool, error) {
	// adding a minimal jwtClaims collection here, for validating usages in CEL expression
	_, err := b.celEvalProgram(program, logical.UpdateOperation, map[string]any{"sub": "email@example.com", "aud": "audience", "iss": "issuer"})
	if err != nil {
		return false, fmt.Errorf("failed to validate CEL program: %w", err)
	}
	return true, nil
}

func (b *jwtAuthBackend) celEvalProgram(program celhelper.CelProgram, operation logical.Operation, jwtClaims map[string]any) (any, error) {
	env, err := b.celEnv(program)
	if err != nil {
		return nil, err
	}
	// Initialize the evaluation context for CEL expressions with the raw request data.
	// The "request" key allows CEL expressions to access and evaluate against input fields.
	// Additional variables and evaluated results will be added dynamically during processing.
	evaluationData := map[string]interface{}{
		"claims":    jwtClaims,
		"now":       time.Now(),
		"operation": string(operation),
	}

	// Evaluate all variables
	for _, variable := range program.Variables {
		result, err := celhelper.ParseCompileAndEvaluateVariable(env, variable, evaluationData)
		if err != nil {
			return nil, fmt.Errorf("%w", err)
		}

		// Add the evaluated result for subsequent CEL evaluations.
		// This ensures variables can reference each other and build a cumulative evaluation context.
		evaluationData[variable.Name] = result.Value()
	}

	// Evaluate the CEL Role success expression
	return celhelper.ParseCompileAndEvaluateExpression(env, program.Expression, evaluationData)
}

func (b *jwtAuthBackend) celEnv(program celhelper.CelProgram) (*cel.Env, error) {
	envOptions := []cel.EnvOption{}

	// Add all variable declarations to the CEL environment.
	for _, variable := range program.Variables {
		envOptions = append(envOptions, cel.Declarations(decls.NewVar(variable.Name, decls.Dyn)))
	}

	// Add "pb.Auth" return type to environment
	envOptions = append(envOptions, cel.Types(&pb.Auth{}))
	return cel.NewEnv(envOptions...)
}

const (
	pathListCelHelpSyn  = `List the existing CEL roles in this backend`
	pathListCelHelpDesc = `CEL roles will be listed by the role name.`
	pathCelRoleHelpSyn  = `Manage the CEL roles that can be created with this backend.`
	pathCelRoleHelpDesc = `This path lets you manage the CEL roles that can be created with this backend.`
)

func (r *celRoleEntry) ToResponseData() map[string]interface{} {
	return map[string]interface{}{
		"name":              r.Name,
		"cel_program":       r.CelProgram,
		"message":           r.Message,
		"expiration_leeway": int64(r.ExpirationLeeway.Seconds()),
		"not_before_leeway": int64(r.NotBeforeLeeway.Seconds()),
		"clock_skew_leeway": int64(r.ClockSkewLeeway.Seconds()),
		"bound_audiences":   r.BoundAudiences,
	}
}
