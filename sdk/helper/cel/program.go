// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package cel

import (
	"context"
	"fmt"

	"github.com/go-viper/mapstructure/v2"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/decls"
	celenv "github.com/google/cel-go/common/env"
	"github.com/google/cel-go/common/operators"
	"github.com/google/cel-go/common/overloads"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"

	"github.com/openbao/openbao/sdk/v2/framework"
)

const DefaultCtxCheckFreq uint = 100

// Program represents a CEL program as standardized by OpenBao: the user
// can build a repository of variables, culminating in a final expression.
//
// This structure can be directly unmarshalled with JSON.
type Program struct {
	// List of variables with explicit order (optional)
	Variables []Variable `json:"variables,omitempty"`

	// Required, the main CEL expression
	Expression string `json:"expression"`
}

// Variable represents a single CEL program variable: an identifying name
// and an expression to assign to that name.
type Variable struct {
	// Name of the variable.
	Name string `json:"name"`

	// CEL expression for the variable
	Expression string `json:"expression"`
}

// EvalConfig is the subsystem's context during validation and evaluation.
//
// There is a strict ordering of dependencies here:
// 1. External standard library, when imported.
// 2. Identity subsystem definitions.
// 3. Other subsystem definitions.
// 4. User's variables
// 5. User's final expression
//
// Elements which appear in the evaluation data should also be described with
// declarations in custom options.
type EvalConfig struct {
	Container     string
	WithExtLib    bool
	WithEmail     bool
	WithIdentity  bool
	WithJSON      bool
	CustomOptions []cel.EnvOption
}

// ToOptions resolves an evaluation configuration to final set of options.
func (e *EvalConfig) ToOptions() []cel.EnvOption {
	var options []cel.EnvOption

	if e.Container != "" {
		options = append(options, cel.Container(e.Container))
	}

	if e.WithExtLib {
		options = append(options, CelGoExtFunctions()...)
	}

	if e.WithEmail {
		options = append(options, CheckValidEmailFunction())
	}

	if e.WithIdentity {
		options = append(options, IdentityDeclarations()...)
	}

	if e.WithJSON {
		options = append(options, EncodeJSONFunction())
		options = append(options, DecodeJSONFunction())
	}

	if len(e.CustomOptions) > 0 {
		options = append(options, e.CustomOptions...)
	}

	return options
}

func (e *EvalConfig) ToEnv() (*cel.Env, error) {
	// See https://github.com/google/cel-go/issues/1221
	//
	// We wish to build an environment that behaves like the standard library
	// but looses the type checking requirements around ternaries as we
	// frequently wish to return different types (object or error message
	// string).
	//
	// Notably, CEL allows subsetting the standard library without having to
	// provide an alternative for built-in operators. Even the ternary
	// conditional operator can be removed from type definitions (preventing
	// its use if you ever call .Check(...) but still allowing its standard
	// usage during .Program(...).Eval(...)). This lets us redefine it with
	// a wholly custom definition.
	env, err := cel.NewCustomEnv()
	if err != nil {
		return nil, fmt.Errorf("failed building new custom environment: %w", err)
	}

	paramA := types.NewTypeParamType("A")
	paramB := types.NewTypeParamType("B")

	// See definition in google/cel-go/common/stdlib/standard.go.
	conditionalFunction, err := decls.NewFunction(operators.Conditional,
		decls.FunctionDocs(
			`The ternary operator tests a boolean predicate and returns the left-hand side `+
				`(truthy) expression if true, or the right-hand side (falsy) expression if false`),
		decls.Overload(overloads.Conditional,
			[]*types.Type{types.BoolType, paramA, paramB}, // This signature is different
			types.DynType, // This return type is different
			decls.OverloadIsNonStrict(),
			decls.OverloadExamples(
				`'hello'.contains('lo') ? 'hi' : false // 'hi'`,
				`'hello'.contains('lo') ? 'hi' : 'bye' // 'hi'`,
				`32 % 3 == 0 ? 'divisible' : -1 // -1`)),
		decls.SingletonFunctionBinding(func(args ...ref.Val) ref.Val {
			return types.NoSuchOverloadErr()
		}))
	if err != nil {
		return nil, fmt.Errorf("failed redefining ternary conditional operator: %w", err)
	}

	// See definition of NewEnv(...).
	env, err = env.Extend(
		cel.StdLib(
			cel.StdLibSubset(&celenv.LibrarySubset{
				ExcludeFunctions: []*celenv.Function{
					celenv.NewFunction(operators.Conditional), // remove existing definition
				},
			}),
		),
		cel.EagerlyValidateDeclarations(false), // to maintain compatibility with NewEnv(...)
		cel.FunctionDecls(conditionalFunction), // to add our alternative ternary operator
	)
	if err != nil {
		return nil, fmt.Errorf("failed expanding env to include adjusted standard library: %w", err)
	}

	// Now add in our custom environment.
	return env.Extend(e.ToOptions()...)
}

// Support directly assigning a CEL program from the request.
func JSONProgramFromRequest(data *framework.FieldData) (*Program, error) {
	var celProgram Program
	raw, ok := data.GetOk("cel_program")
	if !ok {
		return nil, fmt.Errorf("missing required field 'cel_program'")
	}

	if err := mapstructure.Decode(raw, &celProgram); err != nil {
		return nil, fmt.Errorf("failed to decode 'cel_program': %w", err)
	}

	if celProgram.Expression == "" {
		return nil, fmt.Errorf("cel_program.expression cannot be empty")
	}

	return &celProgram, nil
}

// parseCompileAndEvaluateExpression parses, compiles, and evaluates a CEL expression
func parseCompileAndEvaluateExpression(ctx context.Context, env *cel.Env, expression string, evaluationData map[string]interface{}) (ref.Val, error) {
	// Parse the expression
	ast, issues := env.Parse(expression)
	if issues != nil && issues.Err() != nil {
		return nil, fmt.Errorf("invalid CEL syntax for expression %q: %w", expression, issues.Err())
	}

	// Compile the expression
	prog, err := env.Program(ast, cel.InterruptCheckFrequency(DefaultCtxCheckFreq))
	if err != nil {
		return nil, fmt.Errorf("failed to compile expression %q: %w", expression, err)
	}

	// Evaluate the expression
	result, _, err := prog.ContextEval(ctx, evaluationData)
	if err != nil {
		return nil, fmt.Errorf("failed to evaluate expression %q: %w", expression, err)
	}

	// Return the evaluated result
	return result, nil
}

func (v *Variable) Evaluate(ctx context.Context, env *cel.Env, evalData map[string]interface{}) (*cel.Env, error) {
	result, err := parseCompileAndEvaluateExpression(ctx, env, v.Expression, evalData)
	if err != nil {
		return nil, err
	}

	evalData[v.Name] = result.Value()

	// During evaluation, we know the final result type of this variable but
	// we can't easily convert it to a declaration type.
	return env.Extend(
		cel.Variable(v.Name, types.DynType),
	)
}

func (p *Program) EvaluateVars(ctx context.Context, env *cel.Env, evalData map[string]interface{}) (*cel.Env, error) {
	var err error
	for index, variable := range p.Variables {
		env, err = variable.Evaluate(ctx, env, evalData)
		if err != nil {
			return nil, fmt.Errorf("variable[%d].%v: %w", index, variable.Name, err)
		}
	}

	return env, nil
}

func (p *Program) Evaluate(ctx context.Context, config *EvalConfig, evalData map[string]interface{}) (ref.Val, error) {
	env, err := config.ToEnv()
	if err != nil {
		return nil, fmt.Errorf("failed to render config to CEL environment: %w", err)
	}

	env, err = p.EvaluateVars(ctx, env, evalData)
	if err != nil {
		return nil, fmt.Errorf("failed to evaluate variables: %w", err)
	}

	result, err := parseCompileAndEvaluateExpression(ctx, env, p.Expression, evalData)
	if err != nil {
		return nil, fmt.Errorf("failed to evaluate expression: %w", err)
	}

	return result, nil
}

// Validate ensures a single variable is valid and then adds its declaration
// to the environment.
func (v *Variable) Validate(env *cel.Env) (*cel.Env, error) {
	_, issues := env.Parse(v.Expression)
	if issues != nil && issues.Err() != nil {
		return nil, fmt.Errorf("invalid CEL syntax for variable '%s': %v", v.Name, issues.Err())
	}

	// During type checking, we haven't executed this expression and so we
	// do not know the final result type of this variable. Mark it dynamic
	// as such.
	return env.Extend(cel.Variable(v.Name, types.DynType))
}

// validateVars validates all variables and updates the environment to add
// their declarations.
func (p *Program) ValidateVars(env *cel.Env) (*cel.Env, error) {
	var err error

	for index, variable := range p.Variables {
		env, err = variable.Validate(env)
		if err != nil {
			return nil, fmt.Errorf("variable[%d].%v: failed to validate: %w", index, variable.Name, err)
		}
	}

	return env, nil
}

func (p *Program) Validate(config *EvalConfig) error {
	env, err := config.ToEnv()
	if err != nil {
		return fmt.Errorf("failed to render config to CEL environment: %w", err)
	}

	// 1. Validate variables; these adjust the environment.
	env, err = p.ValidateVars(env)
	if err != nil {
		return fmt.Errorf("failed to validate variables: %w", err)
	}

	// 2. Validate the main CEL expression
	ast, issues := env.Parse(p.Expression)
	if issues != nil && issues.Err() != nil {
		return fmt.Errorf("invalid CEL syntax for main expression: %v", issues.Err())
	}

	// 3. Perform semantic analysis on the AST.
	checked, issues := env.Check(ast)
	if issues != nil && issues.Err() != nil {
		return fmt.Errorf("error type-checking CEL MainProgram: %v", issues.Err())
	}
	if checked == nil {
		return fmt.Errorf("failed to type-check CEL MainProgram")
	}

	// 4. Finally create a CEL program to validate runtime behavior
	_, err = env.Program(ast)
	if err != nil {
		return fmt.Errorf("failed to create CEL program for main expression: %w", err)
	}

	// All good!
	return nil
}

func FrameworkFieldSchema() *framework.FieldSchema {
	return &framework.FieldSchema{
		Type: framework.TypeMap,
		Description: `CEL variables and expression defining the program for the role.
This is a map with two fields:

1. 'variables', a list of objects with two fields ('name' and 'expression')
   defining each variable and the exact execution order.
2. 'expression', the final statement to execute and whose result is returned.

For example:

cel_program = {
	"variables": [
		{
			"name": "condition",
			"expression": "len(claims.groups) > 0"
		},
		{
			"name": "result",
			"expression": "pb.Auth{Alias: claims.aud, Groups: claims.groups}"
		}
	],
	"expression": "condition ? result : false"
}
`,
	}
}
