// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package identity

import (
	"testing"

	"github.com/openbao/openbao/api/v2"
	vaulthttp "github.com/openbao/openbao/http"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/vault"

	credLdap "github.com/openbao/openbao/builtin/credential/ldap"
)

func TestIdentityStore_GroupAliasLocalMount(t *testing.T) {
	coreConfig := &vault.CoreConfig{
		CredentialBackends: map[string]logical.Factory{
			"ldap": credLdap.Factory,
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

	// Create a local auth mount
	err := client.Sys().EnableAuthWithOptions("ldap", &api.EnableAuthOptions{
		Type:  "ldap",
		Local: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Extract out the mount accessor for LDAP auth
	auths, err := client.Sys().ListAuth()
	if err != nil {
		t.Fatal(err)
	}
	ldapMountAccessor := auths["ldap/"].Accessor

	// Create an external group
	secret, err := client.Logical().Write("identity/group", map[string]interface{}{
		"type": "external",
	})
	if err != nil {
		t.Fatal(err)
	}
	groupID := secret.Data["id"].(string)

	// Attempt to create a group alias against a local mount should fail
	_, err = client.Logical().Write("identity/group-alias", map[string]interface{}{
		"name":           "testuser",
		"mount_accessor": ldapMountAccessor,
		"canonical_id":   groupID,
	})
	if err == nil {
		t.Fatal("expected error since mount is local")
	}
}
