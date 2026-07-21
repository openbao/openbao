// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package jwtauth

import (
	"fmt"
	"slices"
	"testing"

	celhelper "github.com/openbao/openbao/sdk/v2/helper/cel"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
)

// TestJwt_CelRoleCreate tests the path_cel_role create handler
func TestJwt_CelRoleCreate(t *testing.T) {
	t.Parallel()

	// Test case for creating CEL roles
	type TestCase struct {
		Name       string
		CelProgram map[string]any
		ExpectErr  bool
	}

	testCases := []TestCase{
		{
			Name: "testcelrole_valid",
			CelProgram: map[string]any{
				"expression": "1 == 1",
			},
			ExpectErr: false,
		},
		{
			Name: "testcelrole_invalid",
			CelProgram: map[string]any{
				"expression": "invalid_cel_syntax",
			},
			ExpectErr: true,
		},
	}

	// Create a backend with storage for testing
	b, storage := getBackend(t)

	for tcNum, tc := range testCases {
		t.Run(tc.Name, func(*testing.T) {
			var resp *logical.Response
			var roleDataResp *logical.Response
			var err error

			// Data for creating the role
			roleData := map[string]interface{}{
				"cel_program": tc.CelProgram,
			}

			// Create the CEL role
			roleReq := &logical.Request{
				Operation: logical.UpdateOperation,
				Path:      "cel/role/" + tc.Name,
				Storage:   storage,
				Data:      roleData,
			}

			resp, err = b.HandleRequest(t.Context(), roleReq)
			updateError := err != nil || (resp != nil && resp.IsError())
			if tc.ExpectErr {
				if !updateError {
					t.Fatalf("expected failure for [%s] but got none", tc.Name)
				}
			} else {
				if updateError {
					t.Fatalf("bad [%d/%s] read: err: %v resp: %#v", tcNum, tc.Name, err, resp)
				}
			}

			// Read back the role to verify
			roleReq.Operation = logical.ReadOperation
			roleDataResp, err = b.HandleRequest(t.Context(), roleReq)
			// if we expected an error above there should be no cel role to read
			found := err == nil && roleDataResp != nil
			if tc.ExpectErr {
				if found {
					t.Fatalf("expected failure for [%s] but got none", tc.Name)
				}
			} else {
				if !found {
					t.Fatalf("bad [%d/%s] read: not found", tcNum, tc.Name)
				}
				// Verify role data in read
				data := roleDataResp.Data
				if data == nil {
					t.Fatalf("bad [%d/%s] read: expected data, got nil", tcNum, tc.Name)
				}

				// Validate fields
				require.Equal(t, tc.Name, data["name"], fmt.Sprintf("bad [%d] name mismatch", tcNum))
				require.Equal(t, tc.CelProgram["expression"], data["cel_program"].(*celhelper.Program).Expression, fmt.Sprintf("bad [%d] cel_program mismatch", tcNum))
			}

			// List roles to verify
			roleReq.Path = "cel/role"
			roleReq.Operation = logical.ListOperation
			roleListResp, err := b.HandleRequest(t.Context(), roleReq)
			if err != nil {
				t.Fatalf("bad [%d/%s] unexpected error %v", tcNum, tc.Name, err)
			}
			foundRoleInList := roleListResp != nil && slices.Contains(roleListResp.Data["keys"].([]string), tc.Name)
			if tc.ExpectErr {
				if foundRoleInList {
					t.Fatalf("expected not to find [%s] in cel roles list", tc.Name)
				}
			} else {
				if !foundRoleInList {
					t.Fatalf("bad [%d/%s] read: cel role not found", tcNum, tc.Name)
				}
			}
		})
	}
}

func TestJwt_CelRoleCRUD(t *testing.T) {
	b, storage := getBackend(t)
	path := "cel/role/testrole"

	type TestCase struct {
		operation    logical.Operation
		data         map[string]any
		expectedRole map[string]any
	}

	cases := []TestCase{{
		operation: logical.UpdateOperation,
		data: map[string]any{
			"cel_program": map[string]any{
				"expression": "1 == 1",
			},
			"clock_skew_leeway": 10,
			"expiration_leeway": 11,
			"not_before_leeway": 12,
		},
		expectedRole: map[string]any{
			"bound_audiences": []string{},
			"cel_program": &celhelper.Program{
				Expression: "1 == 1",
			},
			"clock_skew_leeway": int64(10),
			"expiration_leeway": int64(11),
			"message":           "",
			"name":              "testrole",
			"not_before_leeway": int64(12),
		},
	}, {
		operation: logical.PatchOperation,
		data: map[string]any{
			"message":         "my-message",
			"bound_audiences": "a,b,c",
			"cel_program": map[string]any{
				"variables": []map[string]any{{
					"name":       "x",
					"expression": "true",
				}},
			},
			"clock_skew_leeway": 120,
		},
		// should keep previous fields + updates
		expectedRole: map[string]any{
			"bound_audiences": []string{"a", "b", "c"},
			"cel_program": &celhelper.Program{
				Expression: "1 == 1",
				Variables:  []celhelper.Variable{{Name: "x", Expression: "true"}},
			},
			"clock_skew_leeway": int64(120),
			"expiration_leeway": int64(11),
			"message":           "my-message",
			"name":              "testrole",
			"not_before_leeway": int64(12),
		},
	}, {
		operation: logical.UpdateOperation,
		data: map[string]any{
			"cel_program": map[string]any{
				"expression": "2 == 2",
			},
		},
		// this time we expect the defaults to be restored
		expectedRole: map[string]any{
			"bound_audiences": []string{},
			"cel_program": &celhelper.Program{
				Expression: "2 == 2",
			},
			"clock_skew_leeway": int64(60),
			"expiration_leeway": int64(150),
			"message":           "",
			"name":              "testrole",
			"not_before_leeway": int64(150),
		},
	}, {
		operation:    logical.DeleteOperation,
		data:         nil,
		expectedRole: nil,
	}}

	for i, tc := range cases {
		t.Logf("executing case %d: %s", i, tc.operation)
		roleReq := &logical.Request{
			Operation: tc.operation,
			Path:      path,
			Storage:   storage,
			Data:      tc.data,
		}
		resp, err := b.HandleRequest(t.Context(), roleReq)
		require.NoError(t, err)
		if tc.expectedRole == nil {
			require.Nil(t, resp)
			continue
		}
		require.NotNil(t, resp)
		require.NoError(t, resp.Error())

		resp, err = b.HandleRequest(t.Context(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      path,
			Storage:   storage,
		})
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.NoError(t, resp.Error())

		require.Equal(t, resp.Data, tc.expectedRole)
	}
}
