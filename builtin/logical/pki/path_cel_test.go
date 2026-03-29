// Copyright (c) 2024 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package pki

import (
	"context"
	"slices"
	"testing"

	celhelper "github.com/openbao/openbao/sdk/v2/helper/cel"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
)

// TestCRUDCelRoles creating, reading, updating and deleting CEL roles
func TestCRUDCelRoles(t *testing.T) {
	t.Parallel()
	var resp *logical.Response
	var err error
	b, storage := CreateBackendWithStorage(t)

	// Create a CEL role
	roleData := map[string]any{
		"cel_program": map[string]any{
			"variables": []map[string]any{
				{
					"name":       "require_ip_sans",
					"expression": "size(request.ip_sans) > 0",
				},
				{
					"name":       "success",
					"expression": "request.common_name == 'example.com' && require_ip_sans",
				},
				{
					"name": "cert",
					"expression": `CertTemplate{
						Subject: PKIX.Name{
							CommonName: request.common_name,
							Country:    ["ZW", "US"],
						},						
					}`,
				},
				{
					"name": "output",
					"expression": `ValidationOutput{
						template: cert,
					}`,
				},
				{
					"name":       "err",
					"expression": "'Request should have atleast 1 IP SAN.'",
				},
			},
			"expression": "success ? output : err",
		},
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
	patchData := map[string]any{
		"cel_program": map[string]any{
			"variables": []map[string]any{
				{
					"name":       "require_ip_sans",
					"expression": "size(request.ip_sans) >= 2", // new rule
				},
				{
					"name":       "success",
					"expression": "request.common_name == 'example.com' && require_ip_sans",
				},
				{
					"name": "cert",
					"expression": `CertTemplate{
						Subject: PKIX.Name{
							CommonName: request.common_name,
							Country:    ["ZW", "US"],
						},						
					}`,
				},
				{
					"name": "output",
					"expression": `ValidationOutput{
						template: cert,
					}`,
				},
				{
					"name":       "err",
					"expression": "'Request should have atleast 2 IP SANs.'",
				},
			},
		},
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

	// Assert the patch is correct
	vars := resp.Data["cel_program"].(celhelper.Program).Variables
	require.Equal(t, 5, len(vars))

	found := false
	for _, v := range vars {
		if v.Name == "require_ip_sans" {
			found = true
			require.Equal(t,
				"size(request.ip_sans) >= 2",
				v.Expression,
				"`require_ip_sans` expression not updated",
			)
			break
		}
	}
	require.True(t, found, "`require_ip_sans` variable not present after patch")

	// Create a second CEL role
	roleData2 := map[string]interface{}{
		"cel_program": map[string]interface{}{
			"variables": []map[string]any{
				{
					"name":       "require_cn",
					"expression": "has(request.common_name)",
				},
				{
					"name": "output",
					"expression": `ValidationOutput{
						template: cert,
					}`,
				},
				{
					"name": "cert",
					"expression": `CertTemplate{
						Subject: PKIX.Name{
							CommonName: request.common_name,
						},
					}`,
				},
			},
			"expression": "require_cn ? output : 'Role requires CN.'",
		},
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
	if err != nil {
		t.Fatalf("bad: err: %v", err)
	}

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
