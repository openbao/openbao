// Copyright (c) 2024 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package pki

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
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
			"variables": []map[string]interface{}{
				{
					"name":       "require_ip_sans",
					"expression": "size(request.ip_sans) > 0",
				},
			},
			"expressions": "request.common_name == 'example.com' && require_ip_sans",
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

	// Validate the response
	CAcertPEM, ok := caResp.Data["certificate"].(string)
	if !ok || CAcertPEM == "" {
		t.Fatalf("Certificate not found in response: %v", caResp.Data)
	}

	CAblock, _ := pem.Decode([]byte(CAcertPEM))
	if CAblock == nil || CAblock.Type != "CERTIFICATE" {
		t.Fatalf("Failed to decode certificate PEM: %v", CAcertPEM)
	}

	CAcert, err := x509.ParseCertificate(CAblock.Bytes)
	if err != nil && CAcert != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
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
		"key_type":    "ec",
		"key_bits":    "256",
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

	if checkKeyDetails(cert, "ECDSA", 256) == false {
		t.Fatal("Key details of issued certificate are not as expected")
	}
}

func checkKeyDetails(cert *x509.Certificate, expectedKey string, expectedBits int) bool {
	// Check public key type is as expected
	if cert.PublicKeyAlgorithm.String() != expectedKey {
		return false
	}

	// Check key length is as expected
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return pub.Size()*8 == expectedBits
	case *ecdsa.PublicKey:
		return pub.Params().BitSize == expectedBits
	default:
		return false
	}
}

func TestVariableHandlingWithCEL(t *testing.T) {
	t.Parallel()

	// Define the variables and their values
	variables := map[string]string{
		"var1": "1 == 1", // True condition
		"var2": "5 < 1",  // False condition
	}

	// Create the CEL environment with the declared variables
	env, err := createEnvWithVariables(variables)
	if err != nil {
		t.Fatalf("Failed to create CEL environment: %v", err)
	}

	// Parse and validate each variable expression
	variableValues := make(map[string]interface{})
	for name, expr := range variables {
		prog, err := compileExpression(env, expr)
		if err != nil {
			t.Fatalf("Failed to compile variable '%s': %v", name, err)
		}
		result, err := evaluateExpression(prog, nil)
		if err != nil {
			t.Fatalf("Failed to evaluate variable '%s': %v", name, err)
		}
		variableValues[name] = result
	}

	// Define the main expression using the declared variables
	expression := "var1 && var2"

	// Compile the main expression
	prog, err := compileExpression(env, expression)
	if err != nil {
		t.Fatalf("Failed to compile expression: %v", err)
	}

	// Evaluate the compiled program with the evaluated variable values
	result, err := evaluateExpression(prog, variableValues)
	if err != nil {
		t.Fatalf("Failed to evaluate expression: %v", err)
	}

	// Assert the result of the evaluation
	if result {
		t.Fatalf("Expected expression to evaluate to false, but got true")
	}
}

// Test issuing a certificate against a CEL role with Variables
func TestCelRoleIssueWithVariables(t *testing.T) {
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

	// Validate the response
	CAcertPEM, ok := caResp.Data["certificate"].(string)
	if !ok || CAcertPEM == "" {
		t.Fatalf("Certificate not found in response: %v", caResp.Data)
	}

	CAblock, _ := pem.Decode([]byte(CAcertPEM))
	if CAblock == nil || CAblock.Type != "CERTIFICATE" {
		t.Fatalf("Failed to decode certificate PEM: %v", CAcertPEM)
	}

	CAcert, err := x509.ParseCertificate(CAblock.Bytes)
	if err != nil && CAcert != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	// Create a CEL role
	roleData := map[string]interface{}{
		"validation_program": map[string]interface{}{
			"variables": []map[string]interface{}{
				{
					"name":       "var1",
					"expression": "request.common_name == 'example.com'",
				},
				{
					"name":       "var2",
					"expression": "size(request.ip_sans) > 0",
				},
			},
			"expressions": "var1 && var2",
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

// Test issuing a certificate against a CEL role with Variables
func TestCelRoleIssueModifyRequest(t *testing.T) {
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

	// Validate the response
	CAcertPEM, ok := caResp.Data["certificate"].(string)
	if !ok || CAcertPEM == "" {
		t.Fatalf("Certificate not found in response: %v", caResp.Data)
	}

	CAblock, _ := pem.Decode([]byte(CAcertPEM))
	if CAblock == nil || CAblock.Type != "CERTIFICATE" {
		t.Fatalf("Failed to decode certificate PEM: %v", CAcertPEM)
	}

	CAcert, err := x509.ParseCertificate(CAblock.Bytes)
	if err != nil && CAcert != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	// Create a CEL role
	roleData := map[string]interface{}{
		"name": "testrole",
		"validation_program": map[string]interface{}{
			"variables": []map[string]string{
				{
					"name":       "ip_sans",
					"expression": `!has(request.ip_sans) ? "10.0.0.1" : (request.ip_sans == "" ? "10.0.0.1" : true)`,
				},
			},
			"expressions": "ip_sans",
		},
		"failure_policy": "deny",
		"message":        "ip_sans 10.0.0.1 should be present.",
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
	expectedIPSANs := []string{"10.0.0.1"}
	var actualIPSANs []string
	for _, ip := range cert.IPAddresses {
		actualIPSANs = append(actualIPSANs, ip.String())
	}
	if !reflect.DeepEqual(expectedIPSANs, actualIPSANs) {
		t.Fatalf("Expected IP SANs: %v, but got: %v", expectedIPSANs, actualIPSANs)
	}
}

func TestCelRoleIssue3(t *testing.T) {
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

	// Validate the response
	CAcertPEM, ok := caResp.Data["certificate"].(string)
	if !ok || CAcertPEM == "" {
		t.Fatalf("Certificate not found in response: %v", caResp.Data)
	}

	CAblock, _ := pem.Decode([]byte(CAcertPEM))
	if CAblock == nil || CAblock.Type != "CERTIFICATE" {
		t.Fatalf("Failed to decode certificate PEM: %v", CAcertPEM)
	}

	CAcert, err := x509.ParseCertificate(CAblock.Bytes)
	if err != nil && CAcert != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	// Create a CEL role
	roleData := map[string]interface{}{
		"name": "testrole",
		"validation_program": map[string]interface{}{
			"variables": []map[string]interface{}{
				{
					"name":       "b",
					"expression": "request.common_name == 'example.com'",
				},
				{
					"name":       "a",
					"expression": "b && size(request.ip_sans) >  0",
				},
			},
			"expressions": "a",
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
