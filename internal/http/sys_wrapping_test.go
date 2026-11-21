// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package http

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/sdk/v2/helper/jsonutil"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/v2/internal/builtin/credential/userpass"
	"github.com/openbao/openbao/v2/internal/vault"
	"github.com/stretchr/testify/require"
)

// Test wrapping functionality
func TestHTTP_Wrapping(t *testing.T) {
	cluster := vault.NewTestCluster(t, &vault.CoreConfig{}, &vault.TestClusterOptions{
		HandlerFunc: Handler,
	})
	cluster.Start()
	defer cluster.Cleanup()

	cores := cluster.Cores

	// make it easy to get access to the active
	core := cores[0].Core
	vault.TestWaitActive(t, core)

	client := cores[0].Client
	client.SetToken(cluster.RootToken)

	// Write a value that we will use with wrapping for lookup
	_, err := client.Logical().Write("secret/foo", map[string]any{
		"zip": "zap",
	})
	require.NoError(t, err)

	// Set a wrapping lookup function for reads on that path
	client.SetWrappingLookupFunc(func(operation, path string) string {
		if operation == "GET" && path == "secret/foo" {
			return "5m"
		}

		return api.DefaultWrappingLookupFunc(operation, path)
	})

	// First test: basic things that should fail, lookup edition
	// Root token isn't a wrapping token
	_, err = client.Logical().Write("sys/wrapping/lookup", nil)
	if err == nil {
		t.Fatal("expected error")
	}
	// Not supplied
	_, err = client.Logical().Write("sys/wrapping/lookup", map[string]any{
		"foo": "bar",
	})
	if err == nil {
		t.Fatal("expected error")
	}
	// Nonexistent token isn't a wrapping token
	_, err = client.Logical().Write("sys/wrapping/lookup", map[string]any{
		"token": "bar",
	})
	if err == nil {
		t.Fatal("expected error")
	}

	// Second: basic things that should fail, unwrap edition
	// Root token isn't a wrapping token
	_, err = client.Logical().Unwrap(cluster.RootToken)
	if err == nil {
		t.Fatal("expected error")
	}
	// Root token isn't a wrapping token
	_, err = client.Logical().Write("sys/wrapping/unwrap", nil)
	if err == nil {
		t.Fatal("expected error")
	}
	// Not supplied
	_, err = client.Logical().Write("sys/wrapping/unwrap", map[string]any{
		"foo": "bar",
	})
	if err == nil {
		t.Fatal("expected error")
	}
	// Nonexistent token isn't a wrapping token
	_, err = client.Logical().Write("sys/wrapping/unwrap", map[string]any{
		"token": "bar",
	})
	if err == nil {
		t.Fatal("expected error")
	}

	//
	// Test lookup
	//

	// Create a wrapping token
	secret, err := client.Logical().Read("secret/foo")
	require.NoError(t, err)
	if secret == nil || secret.WrapInfo == nil {
		t.Fatal("secret or wrap info is nil")
	}
	wrapInfo := secret.WrapInfo

	// Test this twice to ensure no ill effect to the wrapping token as a result of the lookup
	for range 2 {
		secret, err = client.Logical().Write("sys/wrapping/lookup", map[string]any{
			"token": wrapInfo.Token,
		})
		require.NoError(t, err)
		if secret == nil || secret.Data == nil {
			t.Fatal("secret or secret data is nil")
		}
		creationTTL, _ := secret.Data["creation_ttl"].(json.Number).Int64()
		if int(creationTTL) != wrapInfo.TTL {
			t.Fatalf("mismatched ttls: %d vs %d", creationTTL, wrapInfo.TTL)
		}
		if secret.Data["creation_time"].(string) != wrapInfo.CreationTime.Format(time.RFC3339Nano) {
			t.Fatalf("mismatched creation times: %q vs %q", secret.Data["creation_time"].(string), wrapInfo.CreationTime.Format(time.RFC3339Nano))
		}
	}

	//
	// Test unwrap
	//

	// Create a wrapping token
	secret, err = client.Logical().Read("secret/foo")
	require.NoError(t, err)
	if secret == nil || secret.WrapInfo == nil {
		t.Fatal("secret or wrap info is nil")
	}
	wrapInfo = secret.WrapInfo

	// Test unwrap via the client token
	client.SetToken(wrapInfo.Token)
	secret, err = client.Logical().Write("sys/wrapping/unwrap", nil)
	require.NoError(t, err)
	if secret.Warnings != nil {
		t.Fatalf("Warnings found: %v", secret.Warnings)
	}
	if secret == nil || secret.Data == nil {
		t.Fatal("secret or secret data is nil")
	}
	ret1 := secret
	// Should be expired and fail
	_, err = client.Logical().Write("sys/wrapping/unwrap", nil)
	if err == nil {
		t.Fatal("expected err")
	}

	// Create a wrapping token
	client.SetToken(cluster.RootToken)
	secret, err = client.Logical().Read("secret/foo")
	require.NoError(t, err)
	if secret == nil || secret.WrapInfo == nil {
		t.Fatal("secret or wrap info is nil")
	}
	wrapInfo = secret.WrapInfo

	// Test as a separate token
	secret, err = client.Logical().Write("sys/wrapping/unwrap", map[string]any{
		"token": wrapInfo.Token,
	})
	require.NoError(t, err)
	ret2 := secret
	// Should be expired and fail
	_, err = client.Logical().Write("sys/wrapping/unwrap", map[string]any{
		"token": wrapInfo.Token,
	})
	if err == nil {
		t.Fatal("expected err")
	}

	// Create a wrapping token
	secret, err = client.Logical().Read("secret/foo")
	require.NoError(t, err)
	if secret == nil || secret.WrapInfo == nil {
		t.Fatal("secret or wrap info is nil")
	}
	wrapInfo = secret.WrapInfo

	// Read response directly
	client.SetToken(wrapInfo.Token)
	secret, err = client.Logical().Read("cubbyhole/response")
	require.NoError(t, err)
	ret3 := secret
	// Should be expired and fail
	_, err = client.Logical().Write("cubbyhole/response", nil)
	if err == nil {
		t.Fatal("expected err")
	}

	// Create a wrapping token
	client.SetToken(cluster.RootToken)
	secret, err = client.Logical().Read("secret/foo")
	require.NoError(t, err)
	if secret == nil || secret.WrapInfo == nil {
		t.Fatal("secret or wrap info is nil")
	}
	wrapInfo = secret.WrapInfo

	// Read via Unwrap method
	secret, err = client.Logical().Unwrap(wrapInfo.Token)
	require.NoError(t, err)
	if secret.Warnings != nil {
		t.Fatalf("Warnings found: %v", secret.Warnings)
	}
	ret4 := secret
	// Should be expired and fail
	_, err = client.Logical().Unwrap(wrapInfo.Token)
	if err == nil {
		t.Fatal("expected err")
	}

	if !reflect.DeepEqual(ret1.Data, map[string]any{
		"zip": "zap",
	}) {
		t.Fatalf("ret1 data did not match expected: %#v", ret1.Data)
	}
	if !reflect.DeepEqual(ret2.Data, map[string]any{
		"zip": "zap",
	}) {
		t.Fatalf("ret2 data did not match expected: %#v", ret2.Data)
	}
	var ret3Secret api.Secret
	err = jsonutil.DecodeJSON([]byte(ret3.Data["response"].(string)), &ret3Secret)
	require.NoError(t, err)
	if !reflect.DeepEqual(ret3Secret.Data, map[string]any{
		"zip": "zap",
	}) {
		t.Fatalf("ret3 data did not match expected: %#v", ret3Secret.Data)
	}
	if !reflect.DeepEqual(ret4.Data, map[string]any{
		"zip": "zap",
	}) {
		t.Fatalf("ret4 data did not match expected: %#v", ret4.Data)
	}

	//
	// Custom wrapping
	//

	client.SetToken(cluster.RootToken)
	data := map[string]any{
		"zip":   "zap",
		"three": json.Number("2"),
	}

	// Don't set a request TTL on that path, should fail
	client.SetWrappingLookupFunc(func(operation, path string) string {
		return ""
	})
	_, err = client.Logical().Write("sys/wrapping/wrap", data)
	if err == nil {
		t.Fatal("expected error")
	}

	// Re-set the lookup function
	client.SetWrappingLookupFunc(func(operation, path string) string {
		if operation == "GET" && path == "secret/foo" {
			return "5m"
		}

		return api.DefaultWrappingLookupFunc(operation, path)
	})
	secret, err = client.Logical().Write("sys/wrapping/wrap", data)
	require.NoError(t, err)
	if secret.Warnings != nil {
		t.Fatalf("Warnings found: %v", secret.Warnings)
	}
	secret, err = client.Logical().Unwrap(secret.WrapInfo.Token)
	require.NoError(t, err)
	if secret.Warnings != nil {
		t.Fatalf("Warnings found: %v", secret.Warnings)
	}
	if !reflect.DeepEqual(data, secret.Data) {
		t.Fatalf("custom wrap did not match expected: %#v", secret.Data)
	}

	//
	// Test rewrap
	//

	// Create a wrapping token
	secret, err = client.Logical().Read("secret/foo")
	require.NoError(t, err)
	if secret == nil || secret.WrapInfo == nil {
		t.Fatal("secret or wrap info is nil")
	}
	wrapInfo = secret.WrapInfo

	// Check for correct CreationPath before rewrap
	if wrapInfo.CreationPath != "secret/foo" {
		t.Fatalf("error on wrapInfo.CreationPath: expected: secret/foo, got: %s", wrapInfo.CreationPath)
	}

	// Test rewrapping
	secret, err = client.Logical().Write("sys/wrapping/rewrap", map[string]any{
		"token": wrapInfo.Token,
	})
	require.NoError(t, err)
	if secret.Warnings != nil {
		t.Fatalf("Warnings found: %v", secret.Warnings)
	}

	// Check for correct Creation path after rewrap
	if wrapInfo.CreationPath != "secret/foo" {
		t.Fatalf("error on wrapInfo.CreationPath: expected: secret/foo, got: %s", wrapInfo.CreationPath)
	}

	// Should be expired and fail
	_, err = client.Logical().Write("sys/wrapping/unwrap", map[string]any{
		"token": wrapInfo.Token,
	})
	if err == nil {
		t.Fatal("expected err")
	}

	// Attempt unwrapping the rewrapped token
	wrapToken := secret.WrapInfo.Token
	secret, err = client.Logical().Unwrap(wrapToken)
	require.NoError(t, err)
	// Should be expired and fail
	_, err = client.Logical().Unwrap(wrapToken)
	if err == nil {
		t.Fatal("expected err")
	}

	if !reflect.DeepEqual(secret.Data, map[string]any{
		"zip": "zap",
	}) {
		t.Fatalf("secret data did not match expected: %#v", secret.Data)
	}

	// Ensure that wrapping lookup without a client token responds correctly
	client.ClearToken()
	secret, err = client.Logical().Read("sys/wrapping/lookup")
	if secret != nil {
		t.Fatalf("expected no response: %#v", secret)
	}

	if err == nil {
		t.Fatal("expected error")
	}

	var respError *api.ResponseError
	if errors.As(err, &respError); respError.StatusCode != 403 {
		t.Fatalf("expected 403 response, actual: %d", respError.StatusCode)
	}
}

// Test wrapping functionality with Control Group
func TestHTTP_ControlGroupWrapping(t *testing.T) {
	secetPolicy := `
path "secret/foo" {
  capabilities = ["read", "update"]
  control_group = {
    ttl = "5m"
    factor "security-approval" {
      controlled_capabilities = ["update"]
      identity = {
	group_names = ["security-approvers"]
	approvals   = 1
      }
    }
  }
}
`

	approverPolicy := `
path "sys/control-group/authorize" { capabilities = ["update"] }
path "sys/control-group/request"   { capabilities = ["update"] }
`

	coreConfig := &vault.CoreConfig{
		CredentialBackends: map[string]logical.Factory{
			"userpass": userpass.Factory,
		},
	}

	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		HandlerFunc: Handler,
	})
	cluster.Start()
	defer cluster.Cleanup()

	cores := cluster.Cores

	// make it easy to get access to the active
	core := cores[0].Core
	vault.TestWaitActive(t, core)

	client := cores[0].Client
	client.SetToken(cluster.RootToken)

	resp, err := client.Logical().Write("identity/entity", map[string]any{
		"name": "alice",
		"policies": []string{
			"secretPolicy",
		},
		"metadata": map[string]string{
			"key": "metadata",
		},
	})
	require.NoError(t, err)
	aliceID := resp.Data["id"].(string)

	resp, err = client.Logical().Write("identity/entity", map[string]any{
		"name":     "bob",
		"policies": []string{},
		"metadata": map[string]string{
			"key": "metadata",
		},
	})
	require.NoError(t, err)
	bobID := resp.Data["id"].(string)

	resp, err = client.Logical().Write("identity/group", map[string]any{
		"policies": []string{
			"approverPolicy",
		},
		"member_entity_ids": []string{
			bobID,
		},
		"name": "security-approvers",
	})
	require.NoError(t, err)
	if resp.Data["id"] == nil {
		t.Fatal("new group should have id")
	}

	// Enable userpass auth
	err = client.Sys().EnableAuthWithOptions("userpass", &api.EnableAuthOptions{
		Type: "userpass",
	})
	require.NoError(t, err)
	auths, err := client.Sys().ListAuth()
	require.NoError(t, err)
	userpassAccessor := auths["userpass/"].Accessor

	// Create aliases
	_, err = client.Logical().Write("identity/entity-alias", map[string]any{
		"name":           "alice",
		"mount_accessor": userpassAccessor,
		"canonical_id":   aliceID,
	})
	require.NoError(t, err)

	_, err = client.Logical().Write("identity/entity-alias", map[string]any{
		"name":           "bob",
		"mount_accessor": userpassAccessor,
		"canonical_id":   bobID,
	})
	require.NoError(t, err)

	// Add users to userpass backend
	_, err = client.Logical().Write("auth/userpass/users/alice", map[string]any{
		"password": "alicepw",
	})
	require.NoError(t, err)

	_, err = client.Logical().Write("auth/userpass/users/bob", map[string]any{
		"password": "bobpw",
	})
	require.NoError(t, err)

	// Write policies
	err = client.Sys().PutPolicy("secretPolicy", secetPolicy)
	require.NoError(t, err)

	err = client.Sys().PutPolicy("approverPolicy", approverPolicy)
	require.NoError(t, err)

	// Authenticate
	authResponse, err := client.Logical().Write("auth/userpass/login/alice", map[string]any{
		"password": "alicepw",
	})
	require.NoError(t, err)
	aliceToken := authResponse.Auth.ClientToken

	authResponse, err = client.Logical().Write("auth/userpass/login/bob", map[string]any{
		"password": "bobpw",
	})
	require.NoError(t, err)
	bobToken := authResponse.Auth.ClientToken

	// Create a secret protected by control group policy by path
	_, err = client.Logical().Write("secret/foo", map[string]any{
		"foo": "bar",
	})
	require.NoError(t, err)

	//
	// Test lookup
	//

	// Get the wrapped response with wrapping token and accessor
	client.SetToken(aliceToken)
	secretResponse, err := client.Logical().Write("secret/foo", map[string]any{
		"foo": "baz",
	})
	require.NoError(t, err)
	if secretResponse == nil || secretResponse.WrapInfo == nil {
		t.Fatal("wrap info is nil")
	}
	wrapInfo := secretResponse.WrapInfo

	// Attempt unwrap via the client token (should be error now)
	client.SetToken(wrapInfo.Token)
	_, err = client.Logical().Write("sys/wrapping/unwrap", nil)
	require.Error(t, err)

	// Validate the update is deferred
	client.SetToken(aliceToken)
	secretResponse, err = client.Logical().Read("secret/foo")
	require.NoError(t, err)
	if secretResponse.Data["foo"] != "bar" {
		t.Fatal("secret updated but should not have")
	}

	// Authorize it
	client.SetToken(bobToken)
	approverResponse, err := client.Logical().Write("sys/control-group/request", map[string]any{
		"accessor": wrapInfo.Accessor,
	})
	require.NoError(t, err)
	if approverResponse.Data["approved"] == nil {
		t.Fatal("unexpected request data")
	}

	approverResponse, err = client.Logical().Write("sys/control-group/authorize", map[string]any{
		"accessor": wrapInfo.Accessor,
	})
	require.NoError(t, err)
	if approverResponse.Data["approved"] == nil {
		t.Fatal("unexpected request data")
	}

	// Unwrap via the wrapping token (should execute the secret update)
	client.SetToken(wrapInfo.Token)
	_, err = client.Logical().Write("sys/wrapping/unwrap", nil)
	require.NoError(t, err)

	// Validate the update has executed
	client.SetToken(aliceToken)
	secretResponse, err = client.Logical().Read("secret/foo")
	require.NoError(t, err)
	if secretResponse.Data["foo"] != "baz" {
		t.Fatal("secret did not update")
	}

	// Make sure the token is single-use.
	client.SetToken(wrapInfo.Token)
	_, err = client.Logical().Write("sys/wrapping/unwrap", nil)
	require.Error(t, err)
}

func TestHTTP_Wrapping_RewrapCrossNamespace(t *testing.T) {
	cluster := vault.NewTestCluster(t, &vault.CoreConfig{}, &vault.TestClusterOptions{
		HandlerFunc: Handler,
	})
	cluster.Start()
	defer cluster.Cleanup()

	core := cluster.Cores[0].Core
	vault.TestWaitActive(t, core)

	rootClient := cluster.Cores[0].Client
	rootClient.SetToken(cluster.RootToken)

	_, err := rootClient.Logical().Write("sys/namespaces/ns1", nil)
	require.NoError(t, err)

	ns1RootClient, err := rootClient.Clone()
	require.NoError(t, err)
	ns1RootClient.SetNamespace("ns1")
	ns1RootClient.SetToken(cluster.RootToken)

	err = ns1RootClient.Sys().PutPolicy("wrapping", `path "sys/wrapping/*" { capabilities = ["update"] }`)
	require.NoError(t, err)

	tokResp, err := ns1RootClient.Logical().Write("auth/token/create", map[string]any{
		"policies": []string{"wrapping"},
	})
	require.NoError(t, err)
	ns1Token := tokResp.Auth.ClientToken

	ns1Client, err := ns1RootClient.Clone()
	require.NoError(t, err)
	ns1Client.SetNamespace("ns1")
	ns1Client.SetToken(ns1Token)

	wrapOnce := func() string {
		ns1Client.SetWrappingLookupFunc(func(operation, path string) string {
			if path == "sys/wrapping/wrap" {
				return "5m"
			}
			return ""
		})
		defer ns1Client.SetWrappingLookupFunc(nil)
		w, err := ns1Client.Logical().Write("sys/wrapping/wrap", map[string]any{
			"value": "ns1-secret",
		})
		require.NoError(t, err)
		require.NotNil(t, w)
		require.NotNil(t, w.WrapInfo)
		return w.WrapInfo.Token
	}

	// Root token rewraps ns1 wrapping token with namespace=ns1, and the rewrapped token remains in ns1.
	orig1 := wrapOnce()
	rewrapped1, err := ns1RootClient.Logical().Write("sys/wrapping/rewrap", map[string]any{
		"token": orig1,
	})
	require.NoError(t, err)
	require.NotNil(t, rewrapped1)
	require.NotNil(t, rewrapped1.WrapInfo)

	_, err = rootClient.Logical().Unwrap(orig1)
	require.Error(t, err)

	rewrapped1b, err := ns1Client.Logical().Write("sys/wrapping/rewrap", map[string]any{
		"token": rewrapped1.WrapInfo.Token,
	})
	require.NoError(t, err)
	require.NotNil(t, rewrapped1b)
	require.NotNil(t, rewrapped1b.WrapInfo)

	unwrapped1, err := rootClient.Logical().Unwrap(rewrapped1b.WrapInfo.Token)
	require.NoError(t, err)
	require.Equal(t, "ns1-secret", unwrapped1.Data["value"])

	// Root token rewraps ns1 wrapping token without a namespace header.
	orig2 := wrapOnce()
	rewrapped2, err := rootClient.Logical().Write("sys/wrapping/rewrap", map[string]any{
		"token": orig2,
	})
	require.NoError(t, err)
	require.NotNil(t, rewrapped2)
	require.NotNil(t, rewrapped2.WrapInfo)

	unwrapped2, err := ns1Client.Logical().Unwrap(rewrapped2.WrapInfo.Token)
	require.NoError(t, err)
	require.Equal(t, "ns1-secret", unwrapped2.Data["value"])
}
