// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package cel

import (
	"encoding/json"
	"fmt"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types/ref"
	"github.com/openbao/openbao/sdk/v2/framework"
)

type CelProgram struct {
	// List of variables with explicit order (optional)
	Variables []CelVariable `json:"variables,omitempty"`
	// Required, the main CEL expression
	Expression string `json:"expression"`
}

type CelVariable struct {
	// Name of the variable.
	Name string `json:"name"`
	// CEL expression for the variable
	Expression string `json:"expression"`
}

func CelVarsToEvalData(env *cel.Env, program CelProgram) (map[string]any, error) {
	evaluationData := map[string]any{}
	// Evaluate all variables
	for _, variable := range program.Variables {
		result, err := ParseCompileAndEvaluateVariable(env, variable, evaluationData)
		if err != nil {
			return nil, fmt.Errorf("%w", err)
		}

		// Add the evaluated result for subsequent CEL evaluations.
		// This ensures variables can reference each other and build a cumulative evaluation context.
		evaluationData[variable.Name] = result.Value()
	}
	return evaluationData, nil
}

// ParseCompileAndEvaluateVariable evaluates a variable expression
func ParseCompileAndEvaluateVariable(env *cel.Env, variable CelVariable, evaluationData map[string]interface{}) (ref.Val, error) {
	val, err := ParseCompileAndEvaluateExpression(env, variable.Expression, evaluationData)
	if err != nil {
		return nil, fmt.Errorf("Error processing variable '%s': %w", variable.Name, err)
	}
	return val, nil
}

// ParseCompileAndEvaluateExpression parses, compiles, and evaluates a CEL expression
func ParseCompileAndEvaluateExpression(env *cel.Env, expression string, evaluationData map[string]interface{}) (ref.Val, error) {
	// Parse the expression
	ast, issues := env.Parse(expression)
	if issues != nil && issues.Err() != nil {
		return nil, fmt.Errorf("invalid CEL syntax for expression '%s': %w", expression, issues.Err())
	}

	// Compile the expression
	prog, err := env.Program(ast)
	if err != nil {
		return nil, fmt.Errorf("failed to compile expression '%s': %w", expression, err)
	}

	// Evaluate the expression
	result, _, err := prog.Eval(evaluationData)
	if err != nil {
		return nil, fmt.Errorf("failed to evaluate expression '%s': %w", expression, err)
	}

	// Return the evaluated result
	return result, nil
}

func GetCELProgram(data *framework.FieldData) (*CelProgram, error) {
	var celProgram CelProgram

	raw, ok := data.GetOk("cel_program")
	if !ok {
		return nil, fmt.Errorf("missing required field 'cel_program'")
	}

	bytes, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("failed to parse cel_program: %s", err)
	}
	if err := json.Unmarshal(bytes, &celProgram); err != nil {
		return nil, fmt.Errorf("failed to parse cel_program: %s", err)
	}
	if celProgram.Expression == "" {
		return nil, fmt.Errorf("cel_program.expression cannot be empty")
	}

	return &celProgram, nil
}
