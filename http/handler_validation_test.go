// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package http

import (
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
)

// Tests for validateAuthResponse

func TestEstValidateAuthResponse_Valid(t *testing.T) {
	resp := &logical.Response{
		Auth: &logical.Auth{
			ClientToken: "test-token-123",
		},
	}

	err := validateAuthResponse(resp, "test-auth")
	if err != nil {
		t.Errorf("Expected no error for valid response, got: %v", err)
	}
}

func TestEstValidateAuthResponse_NilResponse(t *testing.T) {
	err := validateAuthResponse(nil, "basic-auth")
	if err == nil {
		t.Fatal("Expected error for nil response, got nil")
	}

	expectedMsg := "basic-auth login failed: no response"
	if err.Error() != expectedMsg {
		t.Errorf("Expected error '%s', got '%s'", expectedMsg, err.Error())
	}
}

func TestEstValidateAuthResponse_ResponseWithError(t *testing.T) {
	// IsError() requires Data to have only "error" or "error" + "data"
	resp := &logical.Response{
		Data: map[string]interface{}{
			"error": "invalid credentials",
		},
	}

	err := validateAuthResponse(resp, "client-cert")
	if err == nil {
		t.Fatal("Expected error for error response, got nil")
	}

	// Check that error message contains auth type and error details
	if err.Error() != "client-cert login failed: invalid credentials" {
		t.Errorf("Unexpected error message: %v", err)
	}
}

func TestEstValidateAuthResponse_NilAuth(t *testing.T) {
	resp := &logical.Response{
		Auth: nil,
	}

	err := validateAuthResponse(resp, "bearer-token")
	if err == nil {
		t.Fatal("Expected error for nil Auth, got nil")
	}

	expectedMsg := "bearer-token login failed: no token returned"
	if err.Error() != expectedMsg {
		t.Errorf("Expected error '%s', got '%s'", expectedMsg, err.Error())
	}
}

func TestEstValidateAuthResponse_EmptyToken(t *testing.T) {
	resp := &logical.Response{
		Auth: &logical.Auth{
			ClientToken: "",
		},
	}

	err := validateAuthResponse(resp, "userpass")
	if err == nil {
		t.Fatal("Expected error for empty token, got nil")
	}

	expectedMsg := "userpass login failed: no token returned"
	if err.Error() != expectedMsg {
		t.Errorf("Expected error '%s', got '%s'", expectedMsg, err.Error())
	}
}

func TestEstValidateAuthResponse_WithMetadata(t *testing.T) {
	// Test that validation succeeds even with additional metadata
	resp := &logical.Response{
		Auth: &logical.Auth{
			ClientToken: "test-token-456",
			Metadata: map[string]string{
				"username": "testuser",
				"role":     "admin",
			},
			Policies: []string{"default", "admin"},
		},
		Data: map[string]interface{}{
			"extra": "data",
		},
	}

	err := validateAuthResponse(resp, "ldap")
	if err != nil {
		t.Errorf("Expected no error for valid response with metadata, got: %v", err)
	}
}

func TestEstValidateAuthResponse_WithErrorString(t *testing.T) {
	// Test response with error as string
	resp := &logical.Response{
		Data: map[string]interface{}{
			"error": "authentication failed",
		},
	}

	err := validateAuthResponse(resp, "oidc")
	if err == nil {
		t.Fatal("Expected error for response with errors, got nil")
	}

	// Should contain the error message
	if err.Error() != "oidc login failed: authentication failed" {
		t.Errorf("Expected error message, got: %s", err.Error())
	}
}

func TestEstValidateAuthResponse_DifferentAuthTypes(t *testing.T) {
	// Test that authType parameter is properly used in error messages
	tests := []struct {
		authType string
	}{
		{"basic-auth"},
		{"client-cert"},
		{"bearer-token"},
		{"userpass"},
		{"ldap"},
		{"oidc"},
		{"kubernetes"},
	}

	for _, tt := range tests {
		t.Run(tt.authType, func(t *testing.T) {
			err := validateAuthResponse(nil, tt.authType)
			if err == nil {
				t.Fatal("Expected error, got nil")
			}

			expectedPrefix := tt.authType + " login failed:"
			if len(err.Error()) < len(expectedPrefix) || err.Error()[:len(expectedPrefix)] != expectedPrefix {
				t.Errorf("Expected error to start with '%s', got: %s", expectedPrefix, err.Error())
			}
		})
	}
}

func TestEstValidateAuthResponse_AuthWithNoTokenButWithPolicies(t *testing.T) {
	// Edge case: Auth object exists with policies but no token
	resp := &logical.Response{
		Auth: &logical.Auth{
			ClientToken: "",
			Policies:    []string{"default"},
		},
	}

	err := validateAuthResponse(resp, "test")
	if err == nil {
		t.Fatal("Expected error for auth without token, got nil")
	}

	if err.Error() != "test login failed: no token returned" {
		t.Errorf("Unexpected error: %v", err)
	}
}
