// Copyright (c) 2024 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package pki

import (
	"context"
	"slices"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
)

// Test creating, reading, updating and deleting CEL roles
func TestCRUDCelRoles(t *testing.T) {
	t.Parallel()
	var resp *logical.Response
	var err error
	b, storage := CreateBackendWithStorage(t)

	// Create a CEL role
	roleData := map[string]interface{}{
		"validation_program": map[string]interface{}{
			"variables": []map[string]interface{}{
				{
					"name":       "require_ip_sans",
					"expression": "size(request.ip_sans) > 0",
				},
			},
			"expressions": map[string]interface{}{
				"success": "request.common_name == 'example.com' && require_ip_sans",
				"error":   "error!",
			},
		},
		"message": "Error",
	}

	roleReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "cel/roles/testrole",
		Storage:   storage,
		Data:      roleData,
	}

	// Validate CEL role creation
	resp, err = b.HandleRequest(context.Background(), roleReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: err: %v resp: %#v", err, resp)
	}

	// Read the created CEL role
	roleReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(context.Background(), roleReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: err: %v resp: %#v", err, resp)
	}

	// Patch (update) the CEL role
	newMessage := "Common name must be 'example.com'."
	patchData := map[string]interface{}{
		"message": newMessage,
	}
	patchReq := &logical.Request{
		Operation: logical.PatchOperation,
		Path:      "cel/roles/testrole",
		Storage:   storage,
		Data:      patchData,
	}

	resp, err = b.HandleRequest(context.Background(), patchReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("Failed to patch role: err: %v resp: %#v", err, resp)
	}

	// Verify the patch by reading the updated CEL role
	readReq := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "cel/roles/testrole",
		Storage:   storage,
	}
	resp, err = b.HandleRequest(context.Background(), readReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("Failed to read role after patch: err: %v resp: %#v", err, resp)
	}

	// Assert the patched message is correct
	updatedMessage := resp.Data["message"].(string)
	if updatedMessage != newMessage {
		t.Fatalf("Expected message to be '%s', but got '%s'", newMessage, updatedMessage)
	}

	// Create a second CEL role
	roleData2 := map[string]interface{}{
		"validation_program": map[string]interface{}{
			"expressions": map[string]interface{}{
				"success": "request.common_name == 'example2.com'",
			},
		},
		"message": "Common name must be 'example2.com'.",
	}

	roleReq2 := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "cel/roles/testrole2",
		Storage:   storage,
		Data:      roleData2,
	}

	resp, err = b.HandleRequest(context.Background(), roleReq2)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: err: %v resp: %#v", err, resp)
	}

	// Validate the second CEL role creation by reading it
	roleReq2.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(context.Background(), roleReq2)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: err: %v resp: %#v", err, resp)
	}

	// list CEL roles
	listResp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ListOperation,
		Path:      "cel/roles",
		Storage:   storage,
	})
	if err != nil || (listResp != nil && listResp.IsError()) {
		t.Fatalf("bad: err: %v resp: %#v", err, listResp)
	}

	// check both CEL roles are in the list
	if roles, ok := listResp.Data["keys"].([]string); !ok || !slices.Contains(roles, "testrole") || !slices.Contains(roles, "testrole2") {
		t.Fatalf("Expected roles not found in the list: %v", listResp.Data["keys"].([]string))
	}
	if len(listResp.Data["keys"].([]string)) != 2 {
		t.Fatalf("Expected 2 roles in list.")
	}

	// Delete first CEL role
	roleReqDel := &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "cel/roles/testrole",
		Storage:   storage,
	}

	_, err = b.HandleRequest(context.Background(), roleReqDel)

	// Verify deletion by listing remaining CEL roles
	listResp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ListOperation,
		Path:      "cel/roles",
		Storage:   storage,
	})
	if err != nil || (listResp != nil && listResp.IsError()) {
		t.Fatalf("bad: err: %v resp: %#v", err, listResp)
	}

	// Check only second CEL role is in the list
	if roles, ok := listResp.Data["keys"].([]string); !ok || !slices.Contains(roles, "testrole2") {
		t.Fatalf("Expected second role to be in the list: %v", listResp.Data["keys"].([]string))
	}
	if len(listResp.Data["keys"].([]string)) != 1 {
		t.Fatalf("Expected only second role to be in list.")
	}
}

func TestVariableHandlingWithCELMany(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		variables      map[string]string
		mainExpression string
		expectedError  string
		expectedResult interface{}
	}{
		{
			name: "All variables valid, expression evaluates to true",
			variables: map[string]string{
				"var1": "1 == 1", // True condition
				"var2": "5 > 3",  // True condition
			},
			mainExpression: "var1 && var2",
			expectedError:  "",
			expectedResult: true,
		},
		{
			name: "Nested expression evaluates to false",
			variables: map[string]string{
				"var1": "1 == 1",       // True condition
				"var2": "10 < 5",       // False condition
				"var3": "var1 && var2", // Nested expression
			},
			mainExpression: "var3",
			expectedError:  "",
			expectedResult: false,
		},
		{
			name: "Undefined variable in main expression",
			variables: map[string]string{
				"var1": "1 == 1",
			},
			mainExpression: "var1 && var2", // var2 is undefined
			expectedError:  "failed to evaluate expression: no such attribute(s): var2",
			expectedResult: nil,
		},
		{
			name: "Expression with OR operator evaluates to true",
			variables: map[string]string{
				"var1": "false",
				"var2": "true",
			},
			mainExpression: "var1 || var2",
			expectedError:  "",
			expectedResult: true,
		},
		{
			name: "Expression with NOT operator evaluates to true",
			variables: map[string]string{
				"var1": "false",
			},
			mainExpression: "!var1",
			expectedError:  "",
			expectedResult: true,
		},
		{
			name: "Expression with a missing variable reference in a nested variable",
			variables: map[string]string{
				"var1": "var2 > 5", // var2 is undefined
			},
			mainExpression: "var1",
			expectedError:  "failed to evaluate expression: no such attribute(s): var2",
			expectedResult: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create the CEL environment with the declared variables
			env, err := createEnvWithVariables(tt.variables)
			if err != nil {
				t.Fatalf("Failed to create CEL environment: %v", err)
			}

			// Parse and validate each variable expression
			variableValues := make(map[string]interface{})
			for name, expr := range tt.variables {
				prog, err := compileExpression(env, expr)
				if err != nil {
					t.Fatalf("Failed to compile variable '%s': %v", name, err)
				}

				result, err := evaluateExpression(prog, nil)
				if err != nil {
					if tt.expectedError != "" && err.Error() != tt.expectedError {
						t.Fatalf("Expected error '%s', but got '%v'", tt.expectedError, err)
					}
					return
				}
				variableValues[name] = result
			}

			// Compile the main expression
			prog, err := compileExpression(env, tt.mainExpression)
			if err != nil {
				t.Fatalf("Failed to compile main expression: %v", err)
			}

			// Evaluate the main expression
			result, err := evaluateExpression(prog, variableValues)
			if err != nil {
				if tt.expectedError != "" && err.Error() != tt.expectedError {
					t.Fatalf("Expected error '%s', but got '%v'", tt.expectedError, err)
				}
				return
			}

			// Assert the result matches the expected result
			if result != tt.expectedResult {
				t.Fatalf("Expected result '%v', but got '%v'", tt.expectedResult, result)
			}
		})
	}
}
