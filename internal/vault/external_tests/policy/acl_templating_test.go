// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package policy

import (
	"fmt"
	"testing"

	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/sdk/v2/logical"
	credUserpass "github.com/openbao/openbao/v2/internal/builtin/credential/userpass"
	vaulthttp "github.com/openbao/openbao/v2/internal/http"
	"github.com/openbao/openbao/v2/internal/vault"
	"github.com/stretchr/testify/require"
)

func TestPolicyTemplating(t *testing.T) {
	goodPolicy1 := `
path "secret/{{ identity.entity.name}}/*" {
	capabilities = ["read", "create", "update"]
}

path "secret/{{ identity.entity.aliases.%s.name}}/*" {
	capabilities = ["read", "create", "update"]
}

path "secret/{{ identity.entity.metadata.key}}/*" {
	capabilities = ["read", "create", "update"]
}
`

	goodPolicy2 := `
path "secret/{{ identity.groups.ids.%s.name}}/*" {
	capabilities = ["read", "create", "update"]

}

path "secret/{{ identity.groups.names.group_name.id}}/*" {
	capabilities = ["read", "create", "update"]

}
`

	badPolicy1 := `
path "secret/{{ identity.groups.names.foobar.name}}/*" {
	capabilities = ["read", "create", "update"]

}
`

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

	resp, err := client.Logical().Write("identity/entity", map[string]any{
		"name": "entity_name",
		"policies": []string{
			"goodPolicy1",
			"badPolicy1",
		},
		"metadata": map[string]string{
			"key": "metadata",
		},
	})
	require.NoError(t, err)
	entityID := resp.Data["id"].(string)

	resp, err = client.Logical().Write("identity/group", map[string]any{
		"policies": []string{
			"goodPolicy2",
		},
		"member_entity_ids": []string{
			entityID,
		},
		"name": "group_name",
	})
	require.NoError(t, err)
	groupID := resp.Data["id"]

	resp, err = client.Logical().Write("identity/group", map[string]any{
		"name": "foobar",
	})
	require.NoError(t, err)
	foobarGroupID := resp.Data["id"]

	// Enable userpass auth
	err = client.Sys().EnableAuthWithOptions("userpass", &api.EnableAuthOptions{
		Type: "userpass",
	})
	require.NoError(t, err)

	// Create an external group and renew the token. This should add external
	// group policies to the token.
	auths, err := client.Sys().ListAuth()
	require.NoError(t, err)
	userpassAccessor := auths["userpass/"].Accessor

	// Create an alias
	resp, err = client.Logical().Write("identity/entity-alias", map[string]any{
		"name":           "testuser",
		"mount_accessor": userpassAccessor,
		"canonical_id":   entityID,
	})
	require.NoErrorf(t, err, "err:%v resp:%#v", err, resp)

	// Add a user to userpass backend
	_, err = client.Logical().Write("auth/userpass/users/testuser", map[string]any{
		"password": "testpassword",
	})
	require.NoError(t, err)

	// Write in policies
	goodPolicy1 = fmt.Sprintf(goodPolicy1, userpassAccessor)
	goodPolicy2 = fmt.Sprintf(goodPolicy2, groupID)
	err = client.Sys().PutPolicy("goodPolicy1", goodPolicy1)
	require.NoError(t, err)
	err = client.Sys().PutPolicy("goodPolicy2", goodPolicy2)
	require.NoError(t, err)

	// Authenticate
	secret, err := client.Logical().Write("auth/userpass/login/testuser", map[string]any{
		"password": "testpassword",
	})
	require.NoError(t, err)
	clientToken := secret.Auth.ClientToken

	tests := []struct {
		name string
		path string
		fail bool
	}{
		{
			name: "entity name",
			path: "secret/entity_name/foo",
		},
		{
			name: "bad entity name",
			path: "secret/entityname/foo",
			fail: true,
		},
		{
			name: "group name",
			path: "secret/group_name/foo",
		},
		{
			name: "group id",
			path: fmt.Sprintf("secret/%s/foo", groupID),
		},
		{
			name: "alias name",
			path: "secret/testuser/foo",
		},
		{
			name: "bad group name",
			path: "secret/foobar/foo",
		},
		{
			name: "entity metadata",
			path: "secret/metadata/test/foo",
		},
	}

	runTests := func(failGroupName, failBadTemplating bool) {
		for _, test := range tests {
			resp, err := client.Logical().Write(test.path, map[string]any{"zip": "zap"})
			fail := test.fail
			if test.name == "bad group name" {
				fail = failGroupName
			}
			if failBadTemplating {
				fail = true
			}
			if err != nil && !fail {
				if resp != nil && resp.Data["error"].(string) != "permission denied" {
					t.Fatalf("%s: unexpected status %v", test.name, resp.Data["error"])
				}
				t.Fatalf("%s: got unexpected error: %v", test.name, err)
			}
			if err == nil && fail {
				t.Fatalf("%s: expected error", test.name)
			}
		}
	}

	rootToken := client.Token()
	client.SetToken(clientToken)
	runTests(true, false)

	client.SetToken(rootToken)
	// Test that a policy with bad group membership doesn't kill the other paths
	err = client.Sys().PutPolicy("badPolicy1", badPolicy1)
	require.NoError(t, err)
	client.SetToken(clientToken)
	runTests(true, false)

	// Test that adding group membership now allows access
	client.SetToken(rootToken)
	_, err = client.Logical().Write("identity/group", map[string]any{
		"id": foobarGroupID,
		"member_entity_ids": []string{
			entityID,
		},
	})
	require.NoError(t, err)
	client.SetToken(clientToken)
	runTests(false, false)

	// Test invalid metadata is rejected (wildcard characters and slashes)
	client.SetToken(rootToken)
	_, err = client.Logical().WriteWithContext(t.Context(), "identity/entity", map[string]any{
		"name": "entity_name",
		"metadata": map[string]string{
			"key": "metadata/+",
		},
	})
	require.NoError(t, err)

	client.SetToken(clientToken)
	runTests(false, true)

	// Test with explicitly allowed wildcards and slashes
	client.SetToken(rootToken)
	_, err = client.Logical().WriteWithContext(t.Context(), "sys/policy/goodPolicy1", map[string]any{
		"policy":                                goodPolicy1,
		"allow_wildcards_in_identity_templates": true,
		"allow_slashes_in_identity_templates":   true,
	})
	require.NoError(t, err)

	client.SetToken(clientToken)
	runTests(false, false)
}
