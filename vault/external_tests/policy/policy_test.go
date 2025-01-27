// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package policy

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/go-test/deep"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-secure-stdlib/strutil"
	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/builtin/credential/ldap"
	credUserpass "github.com/openbao/openbao/builtin/credential/userpass"
	logicalKv "github.com/openbao/openbao/builtin/logical/kv"
	ldaphelper "github.com/openbao/openbao/helper/testhelpers/ldap"
	vaulthttp "github.com/openbao/openbao/http"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/vault"
	"github.com/stretchr/testify/require"
)

func TestPolicy_NoDefaultPolicy(t *testing.T) {
	var err error
	coreConfig := &vault.CoreConfig{
		DisableCache: true,
		Logger:       hclog.NewNullLogger(),
		CredentialBackends: map[string]logical.Factory{
			"ldap": ldap.Factory,
		},
	}

	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
	})

	cluster.Start()
	defer cluster.Cleanup()

	cores := cluster.Cores

	vault.TestWaitActive(t, cores[0].Core)

	client := cores[0].Client

	err = client.Sys().EnableAuthWithOptions("ldap", &api.EnableAuthOptions{
		Type: "ldap",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Configure LDAP auth backend
	cleanup, cfg := ldaphelper.PrepareTestContainer(t, "latest")
	defer cleanup()

	_, err = client.Logical().Write("auth/ldap/config", map[string]interface{}{
		"url":                     cfg.Url,
		"userattr":                cfg.UserAttr,
		"userdn":                  cfg.UserDN,
		"groupdn":                 cfg.GroupDN,
		"groupattr":               cfg.GroupAttr,
		"binddn":                  cfg.BindDN,
		"bindpass":                cfg.BindPassword,
		"token_no_default_policy": true,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Create a local user in LDAP
	secret, err := client.Logical().Write("auth/ldap/users/hermes conrad", map[string]interface{}{
		"policies": "foo",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Login with LDAP and create a token
	secret, err = client.Logical().Write("auth/ldap/login/hermes conrad", map[string]interface{}{
		"password": "hermes",
	})
	if err != nil {
		t.Fatal(err)
	}
	token := secret.Auth.ClientToken

	// Lookup the token to get the entity ID
	secret, err = client.Auth().Token().Lookup(token)
	if err != nil {
		t.Fatal(err)
	}

	if diff := deep.Equal(secret.Data["policies"], []interface{}{"foo"}); diff != nil {
		t.Fatal(diff)
	}
}

func TestPolicy_NoConfiguredPolicy(t *testing.T) {
	var err error
	coreConfig := &vault.CoreConfig{
		DisableCache: true,
		Logger:       hclog.NewNullLogger(),
		CredentialBackends: map[string]logical.Factory{
			"ldap": ldap.Factory,
		},
	}

	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
	})

	cluster.Start()
	defer cluster.Cleanup()

	cores := cluster.Cores

	vault.TestWaitActive(t, cores[0].Core)

	client := cores[0].Client

	err = client.Sys().EnableAuthWithOptions("ldap", &api.EnableAuthOptions{
		Type: "ldap",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Configure LDAP auth backend
	cleanup, cfg := ldaphelper.PrepareTestContainer(t, "latest")
	defer cleanup()

	_, err = client.Logical().Write("auth/ldap/config", map[string]interface{}{
		"url":       cfg.Url,
		"userattr":  cfg.UserAttr,
		"userdn":    cfg.UserDN,
		"groupdn":   cfg.GroupDN,
		"groupattr": cfg.GroupAttr,
		"binddn":    cfg.BindDN,
		"bindpass":  cfg.BindPassword,
		"token_ttl": "24h",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Create a local user in LDAP without any policies configured
	secret, err := client.Logical().Write("auth/ldap/users/hermes conrad", map[string]interface{}{})
	if err != nil {
		t.Fatal(err)
	}

	// Login with LDAP and create a token
	secret, err = client.Logical().Write("auth/ldap/login/hermes conrad", map[string]interface{}{
		"password": "hermes",
	})
	if err != nil {
		t.Fatal(err)
	}
	token := secret.Auth.ClientToken

	// Lookup the token to get the entity ID
	secret, err = client.Auth().Token().Lookup(token)
	if err != nil {
		t.Fatal(err)
	}

	if diff := deep.Equal(secret.Data["policies"], []interface{}{"default"}); diff != nil {
		t.Fatal(diff)
	}

	// Renew the token with an increment of 2 hours to ensure that lease renewal
	// occurred and can be checked against the default lease duration with a
	// big enough delta.
	secret, err = client.Logical().Write("auth/token/renew", map[string]interface{}{
		"token":     token,
		"increment": "2h",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Verify that the lease renewal extended the duration properly.
	if float64(secret.Auth.LeaseDuration) < (1 * time.Hour).Seconds() {
		t.Fatalf("failed to renew lease, got: %v", secret.Auth.LeaseDuration)
	}
}

func TestPolicy_TokenRenewal(t *testing.T) {
	cases := []struct {
		name             string
		tokenPolicies    []string
		identityPolicies []string
	}{
		{
			"default only",
			nil,
			nil,
		},
		{
			"with token policies",
			[]string{"token-policy"},
			nil,
		},
		{
			"with identity policies",
			nil,
			[]string{"identity-policy"},
		},
		{
			"with token and identity policies",
			[]string{"token-policy"},
			[]string{"identity-policy"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			coreConfig := &vault.CoreConfig{
				CredentialBackends: map[string]logical.Factory{
					"userpass": credUserpass.Factory,
				},
			}
			cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
				HandlerFunc: vaulthttp.Handler,
			})
			cluster.Start()
			defer cluster.Cleanup()

			core := cluster.Cores[0].Core
			vault.TestWaitActive(t, core)
			client := cluster.Cores[0].Client

			// Enable userpass auth
			err := client.Sys().EnableAuthWithOptions("userpass", &api.EnableAuthOptions{
				Type: "userpass",
			})
			if err != nil {
				t.Fatal(err)
			}

			// Add a user to userpass backend
			data := map[string]interface{}{
				"password": "testpassword",
			}
			if len(tc.tokenPolicies) > 0 {
				data["token_policies"] = tc.tokenPolicies
			}
			_, err = client.Logical().Write("auth/userpass/users/testuser", data)
			if err != nil {
				t.Fatal(err)
			}

			// Set up entity if we're testing against an identity_policies
			if len(tc.identityPolicies) > 0 {
				auths, err := client.Sys().ListAuth()
				if err != nil {
					t.Fatal(err)
				}
				userpassAccessor := auths["userpass/"].Accessor

				resp, err := client.Logical().Write("identity/entity", map[string]interface{}{
					"name":     "test-entity",
					"policies": tc.identityPolicies,
				})
				if err != nil {
					t.Fatal(err)
				}
				entityID := resp.Data["id"].(string)

				// Create an alias
				resp, err = client.Logical().Write("identity/entity-alias", map[string]interface{}{
					"name":           "testuser",
					"mount_accessor": userpassAccessor,
					"canonical_id":   entityID,
				})
				if err != nil {
					t.Fatal(err)
				}
			}

			// Authenticate
			secret, err := client.Logical().Write("auth/userpass/login/testuser", map[string]interface{}{
				"password": "testpassword",
			})
			if err != nil {
				t.Fatal(err)
			}
			clientToken := secret.Auth.ClientToken

			// Verify the policies exist in the login response
			expectedTokenPolicies := append([]string{"default"}, tc.tokenPolicies...)
			if !strutil.EquivalentSlices(secret.Auth.TokenPolicies, expectedTokenPolicies) {
				t.Fatalf("token policy mismatch:\nexpected: %v\ngot: %v", expectedTokenPolicies, secret.Auth.TokenPolicies)
			}

			if !strutil.EquivalentSlices(secret.Auth.IdentityPolicies, tc.identityPolicies) {
				t.Fatalf("identity policy mismatch:\nexpected: %v\ngot: %v", tc.identityPolicies, secret.Auth.IdentityPolicies)
			}

			expectedPolicies := append(expectedTokenPolicies, tc.identityPolicies...)
			if !strutil.EquivalentSlices(secret.Auth.Policies, expectedPolicies) {
				t.Fatalf("policy mismatch:\nexpected: %v\ngot: %v", expectedPolicies, secret.Auth.Policies)
			}

			// Renew token
			secret, err = client.Logical().Write("auth/token/renew", map[string]interface{}{
				"token": clientToken,
			})
			if err != nil {
				t.Fatal(err)
			}

			// Verify the policies exist in the renewal response
			if !strutil.EquivalentSlices(secret.Auth.TokenPolicies, expectedTokenPolicies) {
				t.Fatalf("policy mismatch:\nexpected: %v\ngot: %v", expectedTokenPolicies, secret.Auth.TokenPolicies)
			}

			if !strutil.EquivalentSlices(secret.Auth.IdentityPolicies, tc.identityPolicies) {
				t.Fatalf("identity policy mismatch:\nexpected: %v\ngot: %v", tc.identityPolicies, secret.Auth.IdentityPolicies)
			}

			if !strutil.EquivalentSlices(secret.Auth.Policies, expectedPolicies) {
				t.Fatalf("policy mismatch:\nexpected: %v\ngot: %v", expectedPolicies, secret.Auth.Policies)
			}
		})
	}
}

func TestPolicy_PaginationLimit(t *testing.T) {
	coreConfig := &vault.CoreConfig{
		CredentialBackends: map[string]logical.Factory{
			"userpass": credUserpass.Factory,
		},
		LogicalBackends: map[string]logical.Factory{
			"kv": logicalKv.VersionedKVFactory,
		},
	}
	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
	})
	cluster.Start()
	defer cluster.Cleanup()

	core := cluster.Cores[0].Core
	vault.TestWaitActive(t, core)
	client := cluster.Cores[0].Client

	// Enable userpass auth
	err := client.Sys().EnableAuthWithOptions("userpass", &api.EnableAuthOptions{
		Type: "userpass",
	})
	require.NoError(t, err, "failed to enable userpass auth")

	// Add a user to userpass backend
	data := map[string]interface{}{
		"password":       "testpassword",
		"token_policies": "testpolicy",
	}
	_, err = client.Logical().Write("auth/userpass/users/testuser", data)
	require.NoError(t, err, "failed to set ")

	// Mount K/V and add some secrets.
	err = client.Sys().Mount("kv", &api.MountInput{
		Type: "kv",
		Options: map[string]string{
			"version": "2",
		},
	})
	require.NoError(t, err, "failed to mount kv")

	for i := 1; i <= 100; i++ {
		_, err = client.KVv2("kv").Put(context.Background(), fmt.Sprintf("a/key-%v", i), map[string]interface{}{
			"value": i,
		})
		require.NoError(t, err, "failed writing k/v key")

		_, err = client.KVv2("kv").Put(context.Background(), fmt.Sprintf("b/key-%v", i), map[string]interface{}{
			"value": i,
		})
		require.NoError(t, err, "failed writing k/v key")

		_, err = client.KVv2("kv").Put(context.Background(), fmt.Sprintf("c/key-%v", i), map[string]interface{}{
			"value": i,
		})
		require.NoError(t, err, "failed writing k/v key")

		_, err = client.KVv2("kv").Put(context.Background(), fmt.Sprintf("d/key-%v", i), map[string]interface{}{
			"value": i,
		})
		require.NoError(t, err, "failed writing k/v key")
	}

	// Write policy and create a client token.
	//
	// a/ is a raw list
	// b/ is an optionally limited list (when specified)
	// c/ has a required parameter of limit but no pagination limit,
	//    meaning it will be ignored
	// d/ requires pagination.
	err = client.Sys().PutPolicy("testpolicy", `path "kv/metadata/a" {
	capabilities = ["list"]
}

path "kv/metadata/b" {
	capabilities = ["list"]
	pagination_limit = 10
}

path "kv/metadata/c" {
	capabilities = ["list"]
	required_parameters = ["limit"]
}

path "kv/metadata/d" {
	capabilities = ["list"]
	pagination_limit = 10
	required_parameters = ["limit"]
}

path "kv/metadata/" {
	capabilities = ["scan", "list"]
	pagination_limit = 10
	required_parameters = ["limit"]
}
`)
	require.NoError(t, err, "failed to write policy")

	resp, err := client.Logical().Write("auth/userpass/login/testuser", map[string]interface{}{
		"password": "testpassword",
	})
	require.NoError(t, err, "failed to auth")
	require.NotNil(t, resp)
	require.NotNil(t, resp.Auth)

	// root := client.Token()
	user := resp.Auth.ClientToken
	client.SetToken(user)

	// Paths should behave ok.
	testPagination(t, client, "a/", true, false)
	testPagination(t, client, "b/", true, true)
	testPagination(t, client, "c/", true, false)
	testPagination(t, client, "d/", false, true)
	testPagination(t, client, "", false, true)

	// Test scan limits.
	resp, err = client.Logical().Scan("kv/metadata")
	require.Error(t, err, "expected error scanning without limits")

	resp, err = client.Logical().ScanPage("kv/metadata", "", 10)
	require.NoError(t, err, "failed to scan")
	require.NotNil(t, resp)
	require.NotNil(t, resp.Data)
	// TODO - kv metadata scanning doesn't accept pagination
	require.Equal(t, 400, len(resp.Data["keys"].([]interface{})))

	// Test 'max' value.
	resp, err = client.Logical().ReadWithData("kv/metadata/d", map[string][]string{
		"list":  {"true"},
		"limit": {"max"},
	})
	require.NoError(t, err, "failed to list with max value")
	require.NotNil(t, resp)
	require.NotNil(t, resp.Data)
	require.Equal(t, 10, len(resp.Data["keys"].([]interface{})))

	// This endpoint has no limit.
	resp, err = client.Logical().ReadWithData("kv/metadata/a", map[string][]string{
		"list":  {"true"},
		"limit": {"max"},
	})
	require.NoError(t, err, "failed to list with max value")
	require.NotNil(t, resp)
	require.NotNil(t, resp.Data)
	require.Equal(t, 100, len(resp.Data["keys"].([]interface{})))
}

func testPagination(t *testing.T, client *api.Client, path string, raw bool, limited bool) {
	resp, err := client.Logical().List("kv/metadata/" + path)
	if raw {
		require.NoError(t, err, "failed to raw list on "+path)
		require.NotNil(t, resp)
		require.NotNil(t, resp.Data)
		if limited {
			require.LessOrEqual(t, len(resp.Data["keys"].([]interface{})), 10)
		} else {
			require.Equal(t, 100, len(resp.Data["keys"].([]interface{})))
		}
	} else {
		require.Error(t, err, "expected failure to raw list on "+path)
	}

	resp, err = client.Logical().ListPage("kv/metadata/"+path, "", 75)
	if limited {
		require.Error(t, err, "expected failure to list (over limit) on "+path)
	} else {
		require.NoError(t, err, "failed to raw list on "+path)
		require.NotNil(t, resp)
		require.NotNil(t, resp.Data)
		require.Equal(t, 75, len(resp.Data["keys"].([]interface{})))
	}

	resp, err = client.Logical().ListPage("kv/metadata/"+path, "", 10)
	require.NoError(t, err, "failed to raw list on "+path)
	require.NotNil(t, resp)
	require.NotNil(t, resp.Data)
	require.LessOrEqual(t, len(resp.Data["keys"].([]interface{})), 10)
}
