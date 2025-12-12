// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package pki

import (
	"context"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
)

// TestEstConfig tests the EST configuration endpoint
func TestEstConfig(t *testing.T) {
	t.Parallel()

	b, s := CreateBackendWithStorage(t)

	// Test reading default config
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config/est",
		Storage:   s,
	})
	if err != nil {
		t.Fatalf("failed to read default config: %v", err)
	}

	if resp == nil {
		t.Fatal("expected non-nil response")
	}

	// Verify default values
	if enabled := resp.Data["enabled"].(bool); enabled {
		t.Errorf("expected enabled=false by default, got %v", enabled)
	}

	if defaultMount := resp.Data["default_mount"].(bool); defaultMount {
		t.Errorf("expected default_mount=false by default, got %v", defaultMount)
	}

	// Test writing config
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/est",
		Storage:   s,
		Data: map[string]interface{}{
			"enabled":             true,
			"default_mount":       true,
			"default_path_policy": "sign-verbatim",
			"authenticators": map[string]interface{}{
				"userpass": map[string]interface{}{
					"accessor": "auth_userpass_test123",
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	if resp == nil {
		t.Fatal("expected non-nil response")
	}

	// Verify updated values
	if enabled := resp.Data["enabled"].(bool); !enabled {
		t.Errorf("expected enabled=true, got %v", enabled)
	}

	if defaultMount := resp.Data["default_mount"].(bool); !defaultMount {
		t.Errorf("expected default_mount=true, got %v", defaultMount)
	}

	if policy := resp.Data["default_path_policy"].(string); policy != "sign-verbatim" {
		t.Errorf("expected default_path_policy=sign-verbatim, got %v", policy)
	}

	// Test reading after write
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config/est",
		Storage:   s,
	})
	if err != nil {
		t.Fatalf("failed to read config after write: %v", err)
	}

	if resp == nil {
		t.Fatal("expected non-nil response")
	}

	if enabled := resp.Data["enabled"].(bool); !enabled {
		t.Errorf("expected enabled=true after write, got %v", enabled)
	}
}

// TestEstConfigValidation tests validation of EST configuration
func TestEstConfigValidation(t *testing.T) {
	t.Parallel()

	b, s := CreateBackendWithStorage(t)

	// Test that default_mount requires default_path_policy
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/est",
		Storage:   s,
		Data: map[string]interface{}{
			"enabled":       true,
			"default_mount": true,
			// Missing default_path_policy
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp == nil || !resp.IsError() {
		t.Fatal("expected error response when default_mount=true without default_path_policy")
	}

	// Test invalid path policy
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/est",
		Storage:   s,
		Data: map[string]interface{}{
			"enabled":             true,
			"default_mount":       true,
			"default_path_policy": "invalid-policy",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp == nil || !resp.IsError() {
		t.Fatal("expected error response for invalid path policy")
	}

	// Test valid role-based policy
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/est",
		Storage:   s,
		Data: map[string]interface{}{
			"enabled":             true,
			"default_mount":       true,
			"default_path_policy": "role:test-role",
		},
	})
	if err != nil {
		t.Fatalf("failed to set valid role-based policy: %v", err)
	}

	if resp == nil {
		t.Fatal("expected non-nil response")
	}

	if resp.IsError() {
		t.Fatalf("unexpected error: %v", resp.Error())
	}
}

// TestEstConfigAuthenticators tests EST authenticator configuration
func TestEstConfigAuthenticators(t *testing.T) {
	t.Parallel()

	b, s := CreateBackendWithStorage(t)

	// Test cert authenticator with cert_role
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/est",
		Storage:   s,
		Data: map[string]interface{}{
			"enabled": true,
			"authenticators": map[string]interface{}{
				"cert": map[string]interface{}{
					"accessor":  "auth_cert_test123",
					"cert_role": "est-ca",
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to configure cert authenticator: %v", err)
	}

	if resp == nil || resp.IsError() {
		t.Fatalf("unexpected error configuring cert authenticator: %v", resp)
	}

	// Test userpass authenticator (should not allow cert_role)
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/est",
		Storage:   s,
		Data: map[string]interface{}{
			"enabled": true,
			"authenticators": map[string]interface{}{
				"userpass": map[string]interface{}{
					"accessor":  "auth_userpass_test123",
					"cert_role": "should-fail", // cert_role only valid for cert
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp == nil || !resp.IsError() {
		t.Fatal("expected error when setting cert_role on userpass authenticator")
	}

	// Test invalid authenticator type
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/est",
		Storage:   s,
		Data: map[string]interface{}{
			"enabled": true,
			"authenticators": map[string]interface{}{
				"invalid": map[string]interface{}{
					"accessor": "auth_invalid_test123",
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp == nil || !resp.IsError() {
		t.Fatal("expected error for invalid authenticator type")
	}
}

// TestEstConfigAuditFields tests EST audit field configuration
func TestEstConfigAuditFields(t *testing.T) {
	t.Parallel()

	b, s := CreateBackendWithStorage(t)

	// Test valid audit fields
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/est",
		Storage:   s,
		Data: map[string]interface{}{
			"enabled":      true,
			"audit_fields": []string{"common_name", "alt_names", "ip_sans"},
		},
	})
	if err != nil {
		t.Fatalf("failed to set audit fields: %v", err)
	}

	if resp == nil || resp.IsError() {
		t.Fatalf("unexpected error setting audit fields: %v", resp)
	}

	// Test invalid audit field
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/est",
		Storage:   s,
		Data: map[string]interface{}{
			"enabled":      true,
			"audit_fields": []string{"invalid_field"},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp == nil || !resp.IsError() {
		t.Fatal("expected error for invalid audit field")
	}
}
