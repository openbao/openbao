// Copyright (c) 2024 OpenBao a Series of LF Projects, LLC
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
	"github.com/openbao/openbao/sdk/v2/logical"

	"k8s.io/apiextensions-apiserver/pkg/apiserver/schema"
	"k8s.io/apiextensions-apiserver/pkg/apiserver/schema/cel"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

type celRoleEntry struct {
	// Required, the name of the role
	Name string `json:"name"`
	// Required, defines validation logic
	ValidationProgram ValidationProgram `json:"validation_program"`
	// Defaults to "deny"
	FailurePolicy string `json:"failure_policy,omitempty"`
	// Optional, error message on validation failure
	Message string `json:"message,omitempty"`
}

type ValidationProgram struct {
	// List of variables with explicit order
	Variables []Variable `json:"variables,omitempty"`
	// Required, the main CEL expression
	Expressions string `json:"expressions"`
	// Optional, custom error message logic
	MessageExpression string `json:"message_expressions,omitempty"`
}

type Variable struct {
	// Name of the variable.
	Name string
	// CEL expression for the variable
	Expression string
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
		"validation_program": {
			Type:        framework.TypeMap,
			Description: "CEL rules defining the validation program for the role",
		},
		"failure_policy": {
			Type:        framework.TypeString,
			Description: "Failure policy if CEL expressions are not validated",
		},
		"message": {
			Type:        framework.TypeString,
			Description: "Static error message if validation fails",
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
			"validation_program": {
				Type:        framework.TypeMap,
				Description: "CEL rules defining the validation program for the role",
			},
			"failure_policy": {
				Type:        framework.TypeString,
				Description: "Failure policy if CEL expressions are not validated",
			},
			"message": {
				Type:        framework.TypeString,
				Description: "Static error message if validation fails",
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

	validationProgram := ValidationProgram{}
	if validationProgramRaw, ok := data.GetOk("validation_program"); !ok {
		return logical.ErrorResponse("missing required field 'validation_program'"), nil

		// Ensure "validation_program" is a map
	} else if validationProgramMap, ok := validationProgramRaw.(map[string]interface{}); !ok {
		return logical.ErrorResponse("'validation_program' must be a valid map"), nil

		// Decode "validation_program" into the ValidationProgram struct
	} else if err := mapstructure.Decode(validationProgramMap, &validationProgram); err != nil {
		return logical.ErrorResponse("failed to decode 'validation_program': %v", err), nil
	}

	failurePolicy := "deny" // Default value
	if failurePolicyRaw, ok := data.GetOk("failure_policy"); ok {
		failurePolicy = failurePolicyRaw.(string)
		if failurePolicy != "deny" && failurePolicy != "modify" {
			return logical.ErrorResponse("failure_policy must be 'deny' or 'modify'"), nil
		}
	}

	entry := &celRoleEntry{
		Name:              name,
		ValidationProgram: validationProgram,
		FailurePolicy:     failurePolicy,
		Message:           data.Get("message").(string),
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
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}

	resp := &logical.Response{
		Data: role.ToResponseData(),
	}
	return resp, nil
}

func (b *backend) pathCelRolePatch(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
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
	entry := &celRoleEntry{
		Name:              oldEntry.Name,
		ValidationProgram: oldEntry.ValidationProgram,
		FailurePolicy:     oldEntry.FailurePolicy,
		Message:           oldEntry.Message,
	}

	// Update the fields only if provided
	if validationProgramRaw, ok := data.GetOk("validation_program"); ok {
		validationProgramMap, ok := validationProgramRaw.(map[string]interface{})
		if !ok {
			return logical.ErrorResponse("'validation_program' must be a valid map"), nil
		}
		if err := mapstructure.Decode(validationProgramMap, &entry.ValidationProgram); err != nil {
			return logical.ErrorResponse("failed to decode 'validation_program': %v", err), nil
		}
	}

	if failurePolicyRaw, ok := data.GetOk("failure_policy"); ok {
		entry.FailurePolicy = failurePolicyRaw.(string)
	}

	if messageRaw, ok := data.GetOk("message"); ok {
		entry.Message = messageRaw.(string)
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

	return resp, nil
}

func (b *backend) pathCelRoleDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := req.Storage.Delete(ctx, "cel/role/"+data.Get("name").(string))
	if err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) getCelRole(ctx context.Context, s logical.Storage, roleName string) (*celRoleEntry, error) {
	entry, err := s.Get(ctx, "cel/role/"+roleName)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var result celRoleEntry
	if err := entry.DecodeJSON(&result); err != nil {
		return nil, err
	}

	result.Name = roleName

	return &result, nil
}

func validateCelRoleCreation(entry *celRoleEntry) (*logical.Response, error) {
	resp := &logical.Response{}

	_, err := validateCelExpressions(entry.ValidationProgram)
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

func (r *celRoleEntry) ToResponseData() map[string]interface{} {
	return map[string]interface{}{
		"name": r.Name,
		"validation_program": map[string]interface{}{
			"variables":          r.ValidationProgram.Variables,
			"expressions":        r.ValidationProgram.Expressions,
			"message_expression": r.ValidationProgram.MessageExpression,
		},
		"failure_policy": r.FailurePolicy,
		"message":        r.Message,
	}
}

func validateCelExpressions(validationProgram ValidationProgram) (bool, error) {
	// Create a CEL environment and include the "request" object
	envOptions := []celgo.EnvOption{
		celgo.Declarations(
			decls.NewVar("request", decls.NewMapType(decls.String, decls.Dyn)), // Define `request` as a map
		),
	}

	// Add variables to the CEL environment
	for _, variable := range validationProgram.Variables {
		envOptions = append(envOptions, celgo.Declarations(decls.NewVar(variable.Name, decls.Dyn)))
	}

	env, err := celgo.NewEnv(envOptions...)
	if err != nil {
		return false, fmt.Errorf("failed to create CEL environment: %w", err)
	}

	// Validate each variable's CEL syntax
	for _, variable := range validationProgram.Variables {
		_, issues := env.Parse(variable.Expression)
		if issues != nil && issues.Err() != nil {
			return false, fmt.Errorf("invalid CEL syntax for variable '%s': %v", variable.Name, issues.Err())
		}
	}

	// Validate the main CEL expression
	ast, issues := env.Parse(validationProgram.Expressions)
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

	return true, nil
}

func validateWithK8sValidator(ctx context.Context, validationProgram ValidationProgram, schema *schema.Structural) error {
	// Replace `config.DefaultPerCallLimit` with an actual limit, e.g., 1000
	const perCallLimit = 1000

	validator := cel.NewValidator(schema, true, perCallLimit)
	if validator == nil {
		return fmt.Errorf("failed to create CEL validator")
	}

	// Object to validate - replace with actual data
	obj := map[string]interface{}{}

	// Validate the object
	errs, _ := validator.Validate(ctx, field.NewPath("root"), schema, obj, nil, perCallLimit)
	if len(errs) > 0 {
		return fmt.Errorf("validation errors: %v", errs)
	}

	return nil
}

func (b *backend) storeCelRole(ctx context.Context, storage logical.Storage, entry *celRoleEntry) error {
	jsonEntry, err := logical.StorageEntryJSON("cel/role/"+entry.Name, entry)
	if err != nil {
		return err
	}
	return storage.Put(ctx, jsonEntry)
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
		return nil, fmt.Errorf("invalid CEL syntax for expression: %v", issues.Err())
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

// Helper function to parse, compile, and evaluate a CEL expression
func parseCompileAndEvaluateVariable(env *celgo.Env, variable Variable, evaluationData map[string]interface{}) (ref.Val, error) {
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
