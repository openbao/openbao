// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package pki

import (
	"context"
	"fmt"
	"net/http"

	celgo "github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/common/types/ref"
	"github.com/mitchellh/mapstructure"
	"github.com/openbao/openbao/sdk/v2/framework"
	celhelper "github.com/openbao/openbao/sdk/v2/helper/cel"
	"github.com/openbao/openbao/sdk/v2/logical"
)

type CELRoleEntry struct {
	// Required, the name of the role
	Name string `json:"name"`
	// Required, defines validation logic
	CelProgram celhelper.CelProgram `json:"validation_program"`
	// Warnings about the request or adjustments made by the CEL policy engine.
	// E.g., "common_name was empty so added example.com"
	Warnings string

	// Specifies if certificates issued/signed against this role will have OpenBao leases attached to them.
	GenerateLease string
	// If set, certificates issued/signed against this role will not be stored in the storage backend.
	NoStore string
	// The issuer used to sign the certificate.
	Issuer string
	// CSR ignored if certificate is being issued.
	CSR string
}

func pathListCelRoles(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "cel/roles/?$",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixPKI,
			OperationSuffix: "cel-roles",
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
				Callback: b.pathCelList,
				Responses: map[int][]framework.Response{
					http.StatusOK: {{
						Description: "OK",
						Fields: map[string]*framework.FieldSchema{
							"keys": {
								Type:        framework.TypeStringSlice,
								Description: "List of cel roles",
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

func pathCelRoles(b *backend) *framework.Path {
	pathCelRolesResponseFields := map[string]*framework.FieldSchema{
		"name": {
			Type:        framework.TypeString,
			Description: "Name of the cel role",
		},
		"cel_program": {
			Type:        framework.TypeMap,
			Description: "CEL variables and expression defining the program for the role",
		},
		"warnings": {
			Type:        framework.TypeString,
			Description: "Warnings about the request or adjustments made by the CEL policy engine.",
		},
		"generate_lease": {
			Type:        framework.TypeString,
			Description: "Specifies if certificates issued/signed against this role will have OpenBao leases attached to them.",
		},
		"no_store": {
			Type:        framework.TypeString,
			Description: "If set, certificates issued/signed against this role will not be stored in the storage backend.",
		},
		"issuer": {
			Type:        framework.TypeString,
			Description: "The issuer used to sign the certificate.",
		},
		"csr": {
			Type:        framework.TypeString,
			Description: "Certificate Signing Request.",
		},
	}

	return &framework.Path{
		Pattern: "cel/roles/" + framework.GenericNameRegex("name"),

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixPKI,
			OperationSuffix: "cel-role",
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
			"warnings": {
				Type:        framework.TypeString,
				Description: "Warnings about the request or adjustments made by the CEL policy engine.",
			},
			"generate_lease": {
				Type:        framework.TypeString,
				Description: "Specifies if certificates issued/signed against this role will have OpenBao leases attached to them.",
			},
			"no_store": {
				Type:        framework.TypeString,
				Description: "If set, certificates issued/signed against this role will not be stored in the storage backend.",
			},
			"issuer": {
				Type:        framework.TypeString,
				Description: "The issuer used to sign the certificate.",
			},
			"csr": {
				Type:        framework.TypeString,
				Description: "Certificate Signing Request.",
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

func (b *backend) pathCelRoleCreate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	var err error
	nameRaw, ok := data.GetOk("name")
	if !ok {
		return logical.ErrorResponse("missing required field 'name'"), nil
	}
	name := nameRaw.(string)

	celProgram, err := celhelper.GetCELProgram(data)

	entry := &CELRoleEntry{
		Name:          name,
		CelProgram:    *celProgram,
		Warnings:      data.Get("warnings").(string),
		GenerateLease: data.Get("generate_lease").(string),
		NoStore:       data.Get("no_store").(string),
		Issuer:        data.Get("issuer").(string),
		CSR:           data.Get("csr").(string),
	}

	resp, err := validateCelRoleCreation(entry)
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

func (b *backend) pathCelList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	after := data.Get("after").(string)
	limit := data.Get("limit").(int)

	entries, err := req.Storage.ListPage(ctx, "cel/role/", after, limit)
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}

func (b *backend) pathCelRoleRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
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

func (b *backend) pathCelRolePatch(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	txRollback, err := logical.StartTxStorage(ctx, req)
	if err != nil {
		return nil, err
	}
	defer txRollback()

	roleName := data.Get("name").(string)

	// Retrieve the existing entry
	oldEntry, err := b.getCelRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if oldEntry == nil {
		return logical.ErrorResponse("Unable to fetch cel role entry to patch"), nil
	}

	// Initialize the new entry with existing values
	entry := &CELRoleEntry{
		Name:       roleName,
		CelProgram: oldEntry.CelProgram,
	}

	// Update the fields only if provided
	if celProgramRaw, ok := data.GetOk("cel_program"); ok {
		celProgramMap, ok := celProgramRaw.(map[string]interface{})
		if !ok {
			return logical.ErrorResponse("'cel_program' must be a valid map"), nil
		}
		if err := mapstructure.Decode(celProgramMap, &entry.CelProgram); err != nil {
			return logical.ErrorResponse("failed to decode 'cel_program': %v", err), nil
		}
	}

	// Validate the patched entry
	resp, err := validateCelRoleCreation(entry)
	if err != nil {
		return nil, err
	}
	if resp.IsError() {
		return resp, nil
	}

	// Store the updated entry
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

func (b *backend) pathCelRoleDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := req.Storage.Delete(ctx, "cel/role/"+data.Get("name").(string))
	if err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) getCelRole(ctx context.Context, s logical.Storage, roleName string) (*CELRoleEntry, error) {
	entry, err := s.Get(ctx, "cel/role/"+roleName)
	if err != nil || entry == nil {
		return nil, err
	}

	var result CELRoleEntry
	if err := entry.DecodeJSON(&result); err != nil {
		return nil, err
	}

	result.Name = roleName

	return &result, nil
}

func validateCelRoleCreation(entry *CELRoleEntry) (*logical.Response, error) {
	resp := &logical.Response{}

	_, err := validateCelExpressions(entry.CelProgram)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	resp.Data = entry.ToResponseData()
	return resp, nil
}

const (
	pathListCelHelpSyn  = `List the existing CEL roles in this backend`
	pathListCelHelpDesc = `CEL policies will be listed by the role name.`
	pathCelRoleHelpSyn  = `Manage the cel roles that can be created with this backend.`
	pathCelRoleHelpDesc = `This path lets you manage the cel roles that can be created with this backend.`
)

func (r *CELRoleEntry) ToResponseData() map[string]interface{} {
	return map[string]interface{}{
		"name":        r.Name,
		"cel_program": r.CelProgram,
	}
}

func validateCelExpressions(celProgram celhelper.CelProgram) (bool, error) {
	// Create a CEL environment and include the "request" object
	envOptions := []celgo.EnvOption{
		celgo.Declarations(
			decls.NewVar("request", decls.NewMapType(decls.String, decls.Dyn)), // Define `request` as a map
		),
	}

	// Add variables to the CEL environment
	for _, variable := range celProgram.Variables {
		envOptions = append(envOptions, celgo.Declarations(decls.NewVar(variable.Name, decls.Dyn)))
	}

	env, err := celgo.NewEnv(envOptions...)
	if err != nil {
		return false, fmt.Errorf("failed to create CEL environment: %w", err)
	}

	// Validate each variable's CEL syntax
	for _, variable := range celProgram.Variables {
		_, issues := env.Parse(variable.Expression)
		if issues != nil && issues.Err() != nil {
			return false, fmt.Errorf("invalid CEL syntax for variable '%s': %v", variable.Name, issues.Err())
		}
	}

	// Validate the main CEL expression
	ast, issues := env.Parse(celProgram.Expression)
	if issues != nil && issues.Err() != nil {
		return false, fmt.Errorf("invalid CEL syntax for main expression: %v", issues.Err())
	}

	// Ensure the AST is non-nil
	if ast == nil {
		return false, fmt.Errorf("failed to compile CEL main expression: AST is nil")
	}

	// Create a CEL program to validate runtime behavior
	_, err = env.Program(ast)
	if err != nil {
		return false, fmt.Errorf("failed to create CEL program for main expression: %w", err)
	}

	checked, issues := env.Check(ast) // semantic analysis

	if issues != nil && issues.Err() != nil {
		return false, fmt.Errorf("error type-checking CEL MainProgram: %v", issues.Err())
	}
	if checked == nil {
		return false, fmt.Errorf("failed to type-check CEL MainProgram")
	}

	return true, nil
}

func createEnvWithVariables(variables map[string]string) (*celgo.Env, error) {
	var decls []celgo.EnvOption
	for name := range variables {
		decls = append(decls, celgo.Variable(name, celgo.StringType))
	}
	return celgo.NewEnv(decls...)
}

func compileExpression(env *celgo.Env, expression string) (celgo.Program, error) {
	ast, issues := env.Parse(expression)
	if issues.Err() != nil {
		return nil, fmt.Errorf("%v for expression: %v", issues.Err(), expression)
	}
	prog, err := env.Program(ast)
	if err != nil {
		return nil, fmt.Errorf("failed to compile expression: %v", err)
	}
	return prog, nil
}

func evaluateExpression(prog celgo.Program, variables map[string]interface{}) (bool, error) {
	evalResult, _, err := prog.Eval(variables)
	if err != nil {
		return false, fmt.Errorf("failed to evaluate expression: %v", err)
	}
	return evalResult.Value().(bool), nil
}

// Helper function to parse, compile, and evaluate a CEL variable's expression
func parseCompileAndEvaluateVariable(env *celgo.Env, variable celhelper.CelVariable, evaluationData map[string]interface{}) (ref.Val, error) {
	// Parse the expression
	ast, issues := env.Parse(variable.Expression)
	if issues != nil && issues.Err() != nil {
		return nil, fmt.Errorf("invalid CEL syntax for variable '%s': %w", variable.Name, issues.Err())
	}

	// Compile the expression
	prog, err := env.Program(ast)
	if err != nil {
		return nil, fmt.Errorf("failed to compile variable '%s': %w", variable.Name, err)
	}

	// Evaluate the expression
	result, _, err := prog.Eval(evaluationData)
	if err != nil {
		return nil, fmt.Errorf("failed to evaluate variable '%s': %w", variable.Name, err)
	}

	// Return the evaluated result
	return result, nil
}
