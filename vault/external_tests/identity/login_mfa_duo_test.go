// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package identity

import (
	"context"
	"fmt"
	"testing"

	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/builtin/credential/userpass"
	vaulthttp "github.com/openbao/openbao/http"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/vault"
)

var identityMFACoreConfigDUO = &vault.CoreConfig{
	CredentialBackends: map[string]logical.Factory{
		"userpass": userpass.Factory,
	},
}

var (
	secret_key      = "<secret key for DUO>"
	integration_key = "<integration key>"
	api_hostname    = "<api hostname>"
)

func TestInteg_LoginMFADUO(t *testing.T) {
	t.Skip("This test requires manual intervention and DUO verify on cellphone is needed")
	cluster := vault.NewTestCluster(t, identityMFACoreConfigDUO, &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
	})
	cluster.Start()
	defer cluster.Cleanup()

	client := cluster.Cores[0].Client

	// Enable Userpass authentication
	err := client.Sys().EnableAuthWithOptions("userpass", &api.EnableAuthOptions{
		Type: "userpass",
	})
	if err != nil {
		t.Fatalf("failed to enable userpass auth: %v", err)
	}

	err = mfaGenerateLoginDUOTest(client)
	if err != nil {
		t.Fatalf("DUO verification failed. error: %s", err)
	}
}

func mfaGenerateLoginDUOTest(client *api.Client) error {
	var err error

	auths, err := client.Sys().ListAuth()
	if err != nil {
		return fmt.Errorf("failed to list auth mount")
	}
	mountAccessor := auths["userpass/"].Accessor

	_, err = client.Logical().Write("auth/userpass/users/vaultmfa", map[string]interface{}{
		"password": "testpassword",
	})
	if err != nil {
		return fmt.Errorf("failed to configure userpass backend: %v", err)
	}
	secret, err := client.Logical().Write("identity/entity", map[string]interface{}{
		"name": "test",
	})
	if err != nil {
		return fmt.Errorf("failed to create an entity")
	}
	entityID := secret.Data["id"].(string)

	_, err = client.Logical().Write("identity/entity-alias", map[string]interface{}{
		"name":           "vaultmfa",
		"canonical_id":   entityID,
		"mount_accessor": mountAccessor,
	})
	if err != nil {
		return fmt.Errorf("failed to create an entity alias")
	}

	var methodID string
	// login MFA
	{
		// create a config
		mfaConfigData := map[string]interface{}{
			"username_format": fmt.Sprintf("{{identity.entity.aliases.%s.name}}", mountAccessor),
			"secret_key":      secret_key,
			"integration_key": integration_key,
			"api_hostname":    api_hostname,
		}
		resp, err := client.Logical().Write("identity/mfa/method/duo", mfaConfigData)

		if err != nil || (resp == nil) {
			return fmt.Errorf("bad: resp: %#v\n err: %v", resp, err)
		}

		methodID = resp.Data["method_id"].(string)
		if methodID == "" {
			return fmt.Errorf("method ID is empty")
		}

		// creating MFAEnforcementConfig
		_, err = client.Logical().Write("identity/mfa/login-enforcement/randomName", map[string]interface{}{
			"auth_method_accessors": []string{mountAccessor},
			"auth_method_types":     []string{"userpass"},
			"identity_entity_ids":   []string{entityID},
			"name":                  "randomName",
			"mfa_method_ids":        []string{methodID},
		})
		if err != nil {
			return fmt.Errorf("failed to configure MFAEnforcementConfig: %v", err)
		}
	}
	secret, err = client.Logical().Write("auth/userpass/login/vaultmfa", map[string]interface{}{
		"password": "testpassword",
	})
	if err != nil {
		return fmt.Errorf("failed to login using userpass auth: %v", err)
	}

	if secret.Auth == nil || secret.Auth.MFARequirement == nil {
		return fmt.Errorf("two phase login returned nil MFARequirement")
	}
	if secret.Auth.MFARequirement.MFARequestID == "" {
		return fmt.Errorf("MFARequirement contains empty MFARequestID")
	}
	if secret.Auth.MFARequirement.MFAConstraints == nil || len(secret.Auth.MFARequirement.MFAConstraints) == 0 {
		return fmt.Errorf("MFAConstraints is nil or empty")
	}
	mfaConstraints, ok := secret.Auth.MFARequirement.MFAConstraints["randomName"]
	if !ok {
		return fmt.Errorf("failed to find the mfaConstrains")
	}
	if mfaConstraints.Any == nil || len(mfaConstraints.Any) == 0 {
		return fmt.Errorf("")
	}
	for _, mfaAny := range mfaConstraints.Any {
		if mfaAny.ID != methodID || mfaAny.Type != "duo" {
			return fmt.Errorf("invalid mfa constraints")
		}
	}

	// validation
	secret, err = client.Sys().MFAValidateWithContext(context.Background(),
		secret.Auth.MFARequirement.MFARequestID,
		map[string]interface{}{
			methodID: []string{},
		})
	if err != nil {
		return fmt.Errorf("MFA failed: %v", err)
	}

	if secret.Auth.ClientToken == "" {
		return fmt.Errorf("MFA was not enforced")
	}

	return nil
}
