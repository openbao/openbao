// Copyright (c) 2024 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package pki

import (
	"context"
	"fmt"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
)

func TestPki_CelRoleCreate(t *testing.T) {
	t.Parallel()

	// Test case for creating CEL roles
	type TestCase struct {
		Name              string
		ValidationProgram string
	}

	testCases := []TestCase{
		{
			Name:              "testrole_valid",
			ValidationProgram: "1 == 1",
		},
		{
			Name:              "testrole_invalid",
			ValidationProgram: "invalid_cel_syntax", // Should fail validation
		},
	}

	// Create a backend with storage for testing
	b, storage := CreateBackendWithStorage(t)

	for index, testCase := range testCases {
		var resp *logical.Response
		var roleDataResp *logical.Response
		var err error

		// Data for creating the role
		roleData := map[string]interface{}{
			"validation_program": testCase.ValidationProgram,
		}

		// Create the CEL role
		roleReq := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "cel/roles/" + testCase.Name,
			Storage:   storage,
			Data:      roleData,
		}

		resp, err = b.HandleRequest(context.Background(), roleReq)
		if err != nil || (resp != nil && resp.IsError()) {
			if testCase.Name == "testrole_invalid" {
				require.Error(t, err, fmt.Sprintf("expected failure for [%s] but got none", testCase.Name))
				continue
			}
		}

		// Read back the role to verify
		roleReq.Operation = logical.ReadOperation
		roleReq.Path = "cel/roles/" + testCase.Name
		roleDataResp, err = b.HandleRequest(context.Background(), roleReq)

		if err != nil || (roleDataResp != nil && roleDataResp.IsError()) {
			t.Fatalf("bad [%d/%s] read: err: %v resp: %#v", index, testCase.Name, err, resp)
		}

		// Verify role data
		data := roleDataResp.Data
		if data == nil {
			t.Fatalf("bad [%d/%s] read: expected data, got nil", index, testCase.Name)
		}

		// Validate fields
		require.Equal(t, testCase.Name, data["name"], fmt.Sprintf("bad [%d] name mismatch", index))
		require.Equal(t, testCase.ValidationProgram, data["validation_program"], fmt.Sprintf("bad [%d] validation_program mismatch", index))
	}
}
