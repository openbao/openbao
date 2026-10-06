// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package approle

import (
	"strings"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"
)

func TestAppRole_BoundCIDRLogin(t *testing.T) {
	var resp *logical.Response
	var err error
	b, s := createBackendWithStorage(t)

	// Create a role with secret ID binding disabled and only bound cidr list
	// enabled
	b.requestNoErr(t, &logical.Request{
		Path:      "role/testrole",
		Operation: logical.CreateOperation,
		Data: map[string]any{
			"bind_secret_id":    false,
			"bound_cidr_list":   []string{"127.0.0.1/8"},
			"token_bound_cidrs": []string{"10.0.0.0/8"},
		},
		Storage: s,
	})

	// Read the role ID
	resp = b.requestNoErr(t, &logical.Request{
		Path:      "role/testrole/role-id",
		Operation: logical.ReadOperation,
		Storage:   s,
	})

	roleID := resp.Data["role_id"]

	// Fill in the connection information and login with just the role ID
	resp = b.requestNoErr(t, &logical.Request{
		Path:      "login",
		Operation: logical.UpdateOperation,
		Data: map[string]any{
			"role_id": roleID,
		},
		Storage:    s,
		Connection: &logical.Connection{RemoteAddr: "127.0.0.1"},
	})

	if resp.Auth == nil {
		t.Fatal("expected login to succeed")
	}
	if len(resp.Auth.BoundCIDRs) != 1 {
		t.Fatal("bad token bound cidrs")
	}
	if resp.Auth.BoundCIDRs[0].String() != "10.0.0.0/8" {
		t.Fatalf("bad: %s", resp.Auth.BoundCIDRs[0].String())
	}

	// Override with a secret-id value, verify it doesn't pass
	_ = b.requestNoErr(t, &logical.Request{
		Path:      "role/testrole",
		Operation: logical.UpdateOperation,
		Data: map[string]any{
			"bind_secret_id": true,
		},
		Storage: s,
	})

	roleSecretIDReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "role/testrole/secret-id",
		Storage:   s,
		Data: map[string]any{
			"token_bound_cidrs": []string{"11.0.0.0/24"},
		},
	}
	_, err = b.HandleRequest(t.Context(), roleSecretIDReq)
	if err == nil {
		t.Fatal("expected error due to mismatching subnet relationship")
	}

	roleSecretIDReq.Data["token_bound_cidrs"] = "10.0.0.0/24"
	resp = b.requestNoErr(t, roleSecretIDReq)

	secretID := resp.Data["secret_id"]

	resp = b.requestNoErr(t, &logical.Request{
		Path:      "login",
		Operation: logical.UpdateOperation,
		Data: map[string]any{
			"role_id":   roleID,
			"secret_id": secretID,
		},
		Storage:    s,
		Connection: &logical.Connection{RemoteAddr: "127.0.0.1"},
	})

	if resp.Auth == nil {
		t.Fatal("expected login to succeed")
	}
	if len(resp.Auth.BoundCIDRs) != 1 {
		t.Fatal("bad token bound cidrs")
	}
	if resp.Auth.BoundCIDRs[0].String() != "10.0.0.0/24" {
		t.Fatalf("bad: %s", resp.Auth.BoundCIDRs[0].String())
	}
}

func TestAppRole_RoleLogin(t *testing.T) {
	var resp *logical.Response
	var err error
	b, storage := createBackendWithStorage(t)

	createRole(t, b, storage, "role1", "a,b,c")
	roleRoleIDReq := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "role/role1/role-id",
		Storage:   storage,
	}
	resp = b.requestNoErr(t, roleRoleIDReq)

	roleID := resp.Data["role_id"]

	roleSecretIDReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "role/role1/secret-id",
		Storage:   storage,
	}
	resp = b.requestNoErr(t, roleSecretIDReq)

	secretID := resp.Data["secret_id"]

	loginData := map[string]any{
		"role_id":   roleID,
		"secret_id": secretID,
	}
	loginReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Storage:   storage,
		Data:      loginData,
		Connection: &logical.Connection{
			RemoteAddr: "127.0.0.1",
		},
	}
	loginResp, err := b.HandleRequest(t.Context(), loginReq)
	if err != nil || (loginResp != nil && loginResp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, loginResp)
	}

	if loginResp.Auth == nil {
		t.Fatal("expected a non-nil auth object in the response")
	}

	if loginResp.Auth.Metadata == nil {
		t.Fatal("expected a non-nil metadata object in the response")
	}

	if val := loginResp.Auth.Metadata["role_name"]; val != "role1" {
		t.Fatalf("expected metadata.role_name to equal 'role1', got: %v", val)
	}

	if loginResp.Auth.Alias.Metadata == nil {
		t.Fatal("expected a non-nil alias metadata object in the response")
	}

	if val := loginResp.Auth.Alias.Metadata["role_name"]; val != "role1" {
		t.Fatalf("expected metadata.alias.role_name to equal 'role1', got: %v", val)
	}

	// Test renewal
	renewReq := generateRenewRequest(storage, loginResp.Auth)

	resp, err = b.HandleRequest(t.Context(), renewReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	if resp.Auth.TTL != 400*time.Second {
		t.Fatalf("expected period value from response to be 400s, got: %s", resp.Auth.TTL)
	}

	///
	// Test renewal with period
	///

	// Create role
	period := 600 * time.Second
	roleData := map[string]any{
		"policies": "a,b,c",
		"period":   period.String(),
	}
	roleReq := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/" + "role-period",
		Storage:   storage,
		Data:      roleData,
	}
	_ = b.requestNoErr(t, roleReq)

	roleRoleIDReq = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "role/role-period/role-id",
		Storage:   storage,
	}
	resp = b.requestNoErr(t, roleRoleIDReq)

	roleID = resp.Data["role_id"]

	roleSecretIDReq = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "role/role-period/secret-id",
		Storage:   storage,
	}
	resp = b.requestNoErr(t, roleSecretIDReq)

	secretID = resp.Data["secret_id"]

	loginData["role_id"] = roleID
	loginData["secret_id"] = secretID

	loginResp, err = b.HandleRequest(t.Context(), loginReq)
	if err != nil || (loginResp != nil && loginResp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, loginResp)
	}

	if loginResp.Auth == nil {
		t.Fatal("expected a non-nil auth object in the response")
	}

	renewReq = generateRenewRequest(storage, loginResp.Auth)

	resp, err = b.HandleRequest(t.Context(), renewReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	if resp.Auth.Period != period {
		t.Fatalf("expected period value of %d in the response, got: %s", period, resp.Auth.Period)
	}

	// Test input validation with secret_id that exceeds max length
	loginData["secret_id"] = strings.Repeat("a", maxHmacInputLength+1)

	loginReq = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Storage:   storage,
		Data:      loginData,
		Connection: &logical.Connection{
			RemoteAddr: "127.0.0.1",
		},
	}

	loginResp, err = b.HandleRequest(t.Context(), loginReq)

	expectedErr := "failed to create HMAC of secret_id"
	if loginResp != nil || err == nil || !strings.Contains(err.Error(), expectedErr) {
		t.Fatalf("expected login test to fail with error %q, resp: %#v, err: %v", expectedErr, loginResp, err)
	}
}

func generateRenewRequest(s logical.Storage, auth *logical.Auth) *logical.Request {
	renewReq := &logical.Request{
		Operation: logical.RenewOperation,
		Storage:   s,
		Auth:      &logical.Auth{},
	}
	renewReq.Auth.InternalData = auth.InternalData
	renewReq.Auth.Metadata = auth.Metadata
	renewReq.Auth.LeaseOptions = auth.LeaseOptions
	renewReq.Auth.Policies = auth.Policies
	renewReq.Auth.Period = auth.Period

	return renewReq
}

func TestAppRole_RoleResolve(t *testing.T) {
	b, storage := createBackendWithStorage(t)

	role := "role1"
	createRole(t, b, storage, role, "a,b,c")
	roleRoleIDReq := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "role/role1/role-id",
		Storage:   storage,
	}
	resp := b.requestNoErr(t, roleRoleIDReq)

	roleID := resp.Data["role_id"]

	roleSecretIDReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "role/role1/secret-id",
		Storage:   storage,
	}
	resp = b.requestNoErr(t, roleSecretIDReq)

	secretID := resp.Data["secret_id"]

	loginData := map[string]any{
		"role_id":   roleID,
		"secret_id": secretID,
	}
	loginReq := &logical.Request{
		Operation: logical.ResolveRoleOperation,
		Path:      "login",
		Storage:   storage,
		Data:      loginData,
		Connection: &logical.Connection{
			RemoteAddr: "127.0.0.1",
		},
	}

	resp = b.requestNoErr(t, loginReq)

	if resp.Data["role"] != role {
		t.Fatalf("Role was not as expected. Expected %s, received %s", role, resp.Data["role"])
	}
}

func TestAppRole_RoleDoesNotExist(t *testing.T) {
	var resp *logical.Response
	var err error
	b, storage := createBackendWithStorage(t)

	roleID := "roleDoesNotExist"

	loginData := map[string]any{
		"role_id":   roleID,
		"secret_id": "secret",
	}
	loginReq := &logical.Request{
		Operation: logical.ResolveRoleOperation,
		Path:      "login",
		Storage:   storage,
		Data:      loginData,
		Connection: &logical.Connection{
			RemoteAddr: "127.0.0.1",
		},
	}

	resp, err = b.HandleRequest(t.Context(), loginReq)
	if resp == nil && !resp.IsError() {
		t.Fatalf("Response was not an error: err:%v resp:%#v", err, resp)
	}

	errString, ok := resp.Data["error"].(string)
	if !ok {
		t.Fatal("Error not part of response.")
	}

	if !strings.Contains(errString, "invalid role or secret ID") {
		t.Fatalf("Error was not due to invalid role ID. Error: %s", errString)
	}
}

func TestAppRole_ExpiredSecretID(t *testing.T) {
	b, storage := createBackendWithStorage(t)

	b.requestNoErr(t, &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/role1",
		Storage:   storage,
		Data:      map[string]any{"policies": "a", "secret_id_ttl": "1s"},
	})
	roleID := b.requestNoErr(t, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "role/role1/role-id",
		Storage:   storage,
	}).Data["role_id"]
	resp := b.requestNoErr(t, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "role/role1/secret-id",
		Storage:   storage,
	})
	secretID := resp.Data["secret_id"]

	time.Sleep(1500 * time.Millisecond)

	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation:  logical.UpdateOperation,
		Path:       "login",
		Storage:    storage,
		Data:       map[string]any{"role_id": roleID, "secret_id": secretID},
		Connection: &logical.Connection{RemoteAddr: "127.0.0.1"},
	})
	if err != logical.ErrInvalidCredentials || resp == nil || !resp.IsError() {
		t.Fatalf("expected login with expired secret ID to fail, err:%v resp:%#v", err, resp)
	}
}

// TestAppRole_CIDRLoginRefusalMessages verifies that CIDR refusals return a
// clean error message instead of a raw `%!w(<nil>)`, and that a genuine CIDR
// lookup error (invalid IP address) is surfaced separately.
func TestAppRole_CIDRLoginRefusalMessages(t *testing.T) {
	b, storage := createBackendWithStorage(t)

	// Role CIDR refusal (role-level secret_id_bound_cidrs).
	b.requestNoErr(t, &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/cidrrole",
		Storage:   storage,
		Data: map[string]any{
			"secret_id_bound_cidrs": []string{"10.0.0.0/8"},
		},
	})
	roleID := b.requestNoErr(t, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "role/cidrrole/role-id",
		Storage:   storage,
	}).Data["role_id"]
	roleSecretID := b.requestNoErr(t, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "role/cidrrole/secret-id",
		Storage:   storage,
	}).Data["secret_id"]

	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Storage:   storage,
		Data:      map[string]any{"role_id": roleID, "secret_id": roleSecretID},
		Connection: &logical.Connection{
			RemoteAddr: "192.168.1.1",
		},
	})
	if err != nil || resp == nil || !resp.IsError() {
		t.Fatalf("expected CIDR refusal as error response, err:%v resp:%#v", err, resp)
	}
	errString, ok := resp.Data["error"].(string)
	if !ok {
		t.Fatal("error message not part of response")
	}
	if strings.Contains(errString, "%!w") {
		t.Fatalf("error message contains raw %%!w placeholder: %q", errString)
	}
	if !strings.Contains(errString, "unauthorized by CIDR restrictions on the role") {
		t.Fatalf("unexpected error message: %q", errString)
	}

	// Secret-ID CIDR refusal (role with a use-count limit so the
	// SecretIDNumUses != 0 branch is exercised).
	b.requestNoErr(t, &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/cidrsecret",
		Storage:   storage,
		Data: map[string]any{
			"secret_id_num_uses":    5,
			"secret_id_bound_cidrs": []string{"10.0.0.0/8"},
		},
	})
	secretRoleID := b.requestNoErr(t, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "role/cidrsecret/role-id",
		Storage:   storage,
	}).Data["role_id"]
	secretIDWithCIDR := b.requestNoErr(t, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "role/cidrsecret/secret-id",
		Storage:   storage,
		Data: map[string]any{
			"cidr_list": []string{"10.0.0.0/8"},
		},
	}).Data["secret_id"]

	resp, err = b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Storage:   storage,
		Data:      map[string]any{"role_id": secretRoleID, "secret_id": secretIDWithCIDR},
		Connection: &logical.Connection{
			RemoteAddr: "192.168.1.1",
		},
	})
	if err != nil || resp == nil || !resp.IsError() {
		t.Fatalf("expected secret-ID CIDR refusal as error response, err:%v resp:%#v", err, resp)
	}
	errString, ok = resp.Data["error"].(string)
	if !ok {
		t.Fatal("error message not part of response")
	}
	if strings.Contains(errString, "%!w") {
		t.Fatalf("error message contains raw %%!w placeholder: %q", errString)
	}
	if !strings.Contains(errString, "unauthorized by CIDR restrictions on the secret ID") {
		t.Fatalf("unexpected error message: %q", errString)
	}

	// A malformed source address is a genuine lookup error: it must be
	// surfaced as a separate error (ErrInvalidRequest) rather than being
	// folded into the refusal message.
	resp, err = b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Storage:   storage,
		Data:      map[string]any{"role_id": secretRoleID, "secret_id": secretIDWithCIDR},
		Connection: &logical.Connection{
			RemoteAddr: "not-an-ip",
		},
	})
	if err != logical.ErrInvalidRequest || resp == nil || !resp.IsError() {
		t.Fatalf("expected invalid-address lookup error, err:%v resp:%#v", err, resp)
	}
	errString, ok = resp.Data["error"].(string)
	if !ok {
		t.Fatal("error message not part of response")
	}
	if !strings.Contains(errString, "invalid IP address") {
		t.Fatalf("unexpected error message: %q", errString)
	}
}
