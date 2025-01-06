// Copyright (c) 2024 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package pki

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"reflect"
	"slices"
	"testing"
	"time"

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
			"expressions": "request.common_name == 'example.com'",
		},
		"failure_policy": "deny",
		"message":        "Error",
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
			"expressions": "request.common_name == 'example2.com'",
		},
		"failure_policy": "deny",
		"message":        "Common name must be 'example2.com'.",
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

// Test issuing a certificate against a CEL role
func TestCelRoleIssue(t *testing.T) {
	t.Parallel()

	b, storage := CreateBackendWithStorage(t)

	// Create a root CA
	caData := map[string]interface{}{
		"common_name": "root.com",
		"ttl":         "30h",
		"ip_sans":     "127.0.0.1",
		"locality":    "MiltonPark",
	}
	caReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "root/generate/internal",
		Storage:   storage,
		Data:      caData,
	}
	caResp, err := b.HandleRequest(context.Background(), caReq)
	if err != nil || (caResp != nil && caResp.IsError()) {
		t.Fatalf("Failed to initialize CA: err: %v, resp: %#v", err, caResp)
	}

	// Create a CEL role
	roleData := map[string]interface{}{
		"name": "testrole",
		"validation_program": map[string]interface{}{
			"expressions": "request.common_name == 'example.com' && size(request.ip_sans) > 0",
		},
		"failure_policy": "deny",
		"message":        "Common name must be 'example.com' and atleast 1 ip_san should be present.",
	}

	roleReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "cel/roles/testrole",
		Storage:   storage,
		Data:      roleData,
	}

	resp, err := b.HandleRequest(context.Background(), roleReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("Failed to create CEL role: err: %v, resp: %v", err, resp)
	}

	// Issue a certificate using the CEL role
	issueData := map[string]interface{}{
		"format":      "pem",
		"common_name": "example.com",
		"ttl":         "1h",
		"ip_sans":     "192.168.1.1,10.0.0.1",
	}

	issueReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "cel/issue/testrole",
		Storage:   storage,
		Data:      issueData,
	}

	resp, err = b.HandleRequest(context.Background(), issueReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("Failed to issue certificate: err: %v, \nresp: %v", err, resp)
	}

	// Validate the response
	certPEM, ok := resp.Data["certificate"].(string)
	if !ok || certPEM == "" {
		t.Fatalf("Certificate not found in response: %v", resp.Data)
	}

	block, _ := pem.Decode([]byte(certPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("Failed to decode certificate PEM: %v", certPEM)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	// Validate the TTL
	expectedTTL := 1 * time.Hour
	actualTTL := cert.NotAfter.Sub(cert.NotBefore)
	if diff := actualTTL - expectedTTL; diff < -1*time.Minute || diff > 1*time.Minute {
		t.Fatalf("Expected TTL: %v ± 1m, but got: %v", expectedTTL, actualTTL)
	}

	// Validate the IP SANs
	expectedIPSANs := []string{"192.168.1.1", "10.0.0.1"}
	var actualIPSANs []string
	for _, ip := range cert.IPAddresses {
		actualIPSANs = append(actualIPSANs, ip.String())
	}
	if !reflect.DeepEqual(expectedIPSANs, actualIPSANs) {
		t.Fatalf("Expected IP SANs: %v, but got: %v", expectedIPSANs, actualIPSANs)
	}
}
