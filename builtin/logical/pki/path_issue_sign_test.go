// Copyright (c) 2024 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package pki

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"
)

// Test issuing a certificate against a CEL role
func TestCelRoleIssueMany(t *testing.T) {
	tests := []struct {
		name          string
		issueData     map[string]interface{}
		expectedError string
	}{
		{
			name: "Valid Request",
			issueData: map[string]interface{}{
				"format":      "pem",
				"common_name": "example.com",
				"ttl":         "1h",
				"ip_sans":     "192.168.1.1,10.0.0.1",
			},
			expectedError: "",
		},
		{
			name: "Missing Common Name",
			issueData: map[string]interface{}{
				"format":  "pem",
				"ttl":     "1h",
				"ip_sans": "192.168.1.1,10.0.0.1",
			},
			expectedError: "Common name must be 'example.com' and at least 1 ip_san should be present.",
		},
		{
			name: "Invalid IP SANs",
			issueData: map[string]interface{}{
				"format":      "pem",
				"common_name": "example.com",
				"ttl":         "1h",
			},
			expectedError: "Common name must be 'example.com' and at least 1 ip_san should be present.",
		},
	}

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
			"variables": []map[string]interface{}{
				{
					"name":       "b",
					"expression": "has(request.common_name) && request.common_name == 'example.com'",
				},
				{
					"name":       "a",
					"expression": "b && has(request.ip_sans) && size(request.ip_sans) > 0",
				},
			},
			"expressions": "a",
		},
		"message": "Common name must be 'example.com' and at least 1 ip_san should be present.",
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

	// Run test cases
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			issueReq := &logical.Request{
				Operation: logical.UpdateOperation,
				Path:      "cel/issue/testrole",
				Storage:   storage,
				Data:      tc.issueData,
			}

			resp, err := b.HandleRequest(context.Background(), issueReq)

			if tc.expectedError == "" {
				if err != nil || (resp != nil && resp.IsError()) {
					t.Fatalf("Test '%s' failed unexpectedly: %v", tc.name, err)
				}
			} else {
				// Test expects an error
				if err == nil {
					t.Fatalf("Test '%s' expected error '%s', but got none", tc.name, tc.expectedError)
				}

				// Check if the error message matches the expected error
				if !strings.Contains(err.Error(), tc.expectedError) {
					t.Fatalf("Test '%s' expected error '%s', but got '%s'", tc.name, tc.expectedError, err.Error())
				}
			}
		})
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

// Test issuing a certificate against a CEL role that specifies generate_lease
func TestCelRoleIssueWithGenerateLease(t *testing.T) {
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
					"name":       "generate_lease",
					"expression": "request.ttl < '2h'",
				},
				{
					"name":       "var1",
					"expression": "request.common_name == 'example.com'",
				},
			},
			"expressions": "var1",
		},
		"failure_policy": "deny",
		"message":        "common_name should be 'example.com'",
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
}

// Test issuing a certificate against a CEL Role which modifies a cel/issue field which is a bool value
func TestCelRoleIssueModifyBoolField(t *testing.T) {
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
					"name":       "use_pss",
					"expression": `!has(request.use_pss) ? true : true`,
				},
			},
			"expressions": "use_pss",
		},
		"failure_policy": "modify",
		"message":        "use_pss should be set to true.",
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
}

func TestCelRoleValidateAndModifyIPSans(t *testing.T) {
	tests := []struct {
		name          string
		issueData     map[string]interface{}
		expectedError string
	}{
		{
			name: "Valid Request",
			issueData: map[string]interface{}{
				"format":      "pem",
				"common_name": "example.com",
				"ttl":         "1h",
				"ip_sans":     "10.0.0.1",
			},
			expectedError: "",
		},
		{
			name: "2 IP Sans",
			issueData: map[string]interface{}{
				"format":  "pem",
				"ttl":     "1h",
				"ip_sans": "192.168.1.1,10.0.0.1",
			},
			expectedError: "",
		},
		{
			name: "No IP SANs",
			issueData: map[string]interface{}{
				"format":      "pem",
				"common_name": "example.com",
				"ttl":         "1h",
			},
			expectedError: "",
		},
	}

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
			"variables": []map[string]string{
				{
					"name":       "ip_sans",
					"expression": `!has(request.ip_sans) ? "10.0.0.1" : (request.ip_sans == "" ? "10.0.0.1" : true)`,
				},
			},
			"expressions": "ip_sans",
		},
		"failure_policy": "modify",
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

	// Run test cases
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			issueReq := &logical.Request{
				Operation: logical.UpdateOperation,
				Path:      "cel/issue/testrole",
				Storage:   storage,
				Data:      tc.issueData,
			}

			resp, err := b.HandleRequest(context.Background(), issueReq)

			if tc.expectedError == "" {
				if err != nil || (resp != nil && resp.IsError()) {
					t.Fatalf("Test '%s' failed unexpectedly: %v", tc.name, err)
				}
			} else {
				// Test expects an error
				if err == nil {
					t.Fatalf("Test '%s' expected error '%s', but got none", tc.name, tc.expectedError)
				}

				// Check if the error message matches the expected error
				if !strings.Contains(err.Error(), tc.expectedError) {
					t.Fatalf("Test '%s' expected error '%s', but got '%s'", tc.name, tc.expectedError, err.Error())
				}
			}
		})
	}
}
