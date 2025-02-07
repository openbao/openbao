// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package identity

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/builtin/credential/userpass"
	"github.com/openbao/openbao/helper/testhelpers"
	logicaltest "github.com/openbao/openbao/helper/testhelpers/logical"
	vaulthttp "github.com/openbao/openbao/http"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/vault"
)

// To run these tests, set the following env variables:
// VAULT_ACC=1
// OKTA_ORG=dev-219337
// OKTA_API_TOKEN=<generate via web UI, see Confluence for login details>
// OKTA_USERNAME=<an MFA-enabled user account>
//
// You will need to install the Okta client app on your mobile device and
// setup MFA (Okta push verify and TOTP) for the okta user account.
// Make sure that your Okta Application is configured with an
// Authentication Policy that requires MFA, or that the Global Session Policy requires MFA.
//
// To test with Okta TOTP (instead of Okta push verify), set:
// OKTA_USE_TOTP=1

var identityOktaMFACoreConfig = &vault.CoreConfig{
	CredentialBackends: map[string]logical.Factory{
		"userpass": userpass.Factory,
	},
}

func TestInteg_LoginMFAOkta(t *testing.T) {
	if os.Getenv(logicaltest.TestEnvVar) == "" {
		t.Skip("This test requires manual intervention and OKTA verify on cellphone is needed")
	}

	// Ensure each cred is populated.
	credNames := []string{
		"OKTA_ORG",
		"OKTA_API_TOKEN",
		"OKTA_USERNAME",
	}
	testhelpers.SkipUnlessEnvVarsSet(t, credNames)

	cluster := vault.NewTestCluster(t, identityOktaMFACoreConfig, &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
	})
	cluster.Start()
	defer cluster.Cleanup()

	client := cluster.Cores[0].Client

	// Enable Userpass authentication
	mountAccessor := testhelpers.SetupUserpassMountAccessor(t, client)

	// Create testuser entity and alias
	entityClient, entityID, _ := testhelpers.CreateCustomEntityAndAliasWithinMount(t,
		client, mountAccessor, "userpass", "testuser",
		map[string]interface{}{
			"name": "test-entity",
			"metadata": map[string]string{
				"email": os.Getenv("OKTA_USERNAME"),
			},
		})

	err := mfaGenerateOktaLoginMFATest(t, entityClient, mountAccessor, entityID)
	if err != nil {
		t.Fatalf("Okta failed: %s", err)
	}
}

func mfaGenerateOktaLoginMFATest(t *testing.T, client *api.Client, mountAccessor, entityID string) error {
	t.Helper()

	var methodID string
	var userpassToken string

	// OKTA_USE_TOTP allows the test runner to decide whether to use TOTP or Push verification.
	useTOTP := os.Getenv("OKTA_USE_TOTP") != ""

	// login MFA
	{
		// create a config
		mfaConfigData := map[string]interface{}{
			"mount_accessor":  mountAccessor,
			"org_name":        os.Getenv("OKTA_ORG"),
			"api_token":       os.Getenv("OKTA_API_TOKEN"),
			"primary_email":   true,
			"username_format": "{{identity.entity.metadata.email}}",
		}
		if useTOTP {
			mfaConfigData["use_passcode"] = true
		}
		resp, err := client.Logical().Write("identity/mfa/method/okta", mfaConfigData)

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

	secret, err := client.Logical().Write("auth/userpass/login/testuser", map[string]interface{}{
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
		return fmt.Errorf("failed to find the mfaConstraints")
	}
	if mfaConstraints.Any == nil || len(mfaConstraints.Any) == 0 {
		return fmt.Errorf("")
	}
	for _, mfaAny := range mfaConstraints.Any {
		if mfaAny.ID != methodID || mfaAny.Type != "okta" || (mfaAny.UsesPasscode != useTOTP) {
			return fmt.Errorf("invalid mfa constraints")
		}
	}

	// get totp from file if requested by test runner
	var passcodes []string
	if useTOTP {
		// generate tmp file path
		tempDir := t.TempDir()
		totpFile := tempDir + string(os.PathSeparator) + "totp.txt"

		t.Logf("Please save your totp to: %s", totpFile)

		// Try to read the file 10x per second or until 5 minutes have passed.
		timer := time.NewTimer(5 * time.Minute)
		defer timer.Stop()
		for {
			totpFileContents, err := os.ReadFile(totpFile)
			if err != nil {
				select {
				case <-timer.C:
					break
				default:
					time.Sleep(100 * time.Millisecond)
					continue
				}
				return fmt.Errorf("the TOTP file did not exist after 5 min: %s", totpFile)
			}

			totp := strings.TrimSpace(string(totpFileContents))
			passcodes = []string{totp}
			break
		}
	} else {
		// passcodes must not be nil (must be [] instead of none) for the MFAValidate endpoint.
		passcodes = []string{}
	}

	// validation
	secret, err = client.Sys().MFAValidateWithContext(context.Background(),
		secret.Auth.MFARequirement.MFARequestID,
		map[string]interface{}{
			methodID: passcodes,
		},
	)
	if err != nil {
		return fmt.Errorf("MFA failed: %v", err)
	}

	userpassToken = secret.Auth.ClientToken
	if secret.Auth.ClientToken == "" {
		return fmt.Errorf("MFA was not enforced")
	}

	client.SetToken(client.Token())
	secret, err = client.Logical().Write("auth/token/lookup", map[string]interface{}{
		"token": userpassToken,
	})
	if err != nil {
		return fmt.Errorf("failed to lookup userpass authenticated token: %v", err)
	}

	entityIDCheck := secret.Data["entity_id"].(string)
	if entityIDCheck != entityID {
		return fmt.Errorf("different entityID assigned")
	}

	return nil
}
