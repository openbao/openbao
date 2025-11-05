// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package identity

import (
	"os"
	"testing"

	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/builtin/credential/userpass"
	vaulthttp "github.com/openbao/openbao/http"
	"github.com/openbao/openbao/sdk/v2/helper/pointerutil"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/vault"
	"github.com/stretchr/testify/require"
)

const (
	UserLockoutThresholdDefault = 5
)

// TestIdentityStore_DisableUserLockoutTest tests that user login will
// fail when supplied with wrong credentials. If the user is locked,
// it returns permission denied. Otherwise, it returns invalid user
// credentials error if the user lockout feature is disabled.
// It tests disabling the feature using env variable VAULT_DISABLE_USER_LOCKOUT
// and also using auth tune. Also, tests that env var has more precedence over
// settings in auth tune.
func TestIdentityStore_DisableUserLockoutTest(t *testing.T) {
	// reset to false before exiting
	defer os.Unsetenv("VAULT_DISABLE_USER_LOCKOUT")

	coreConfig := &vault.CoreConfig{
		CredentialBackends: map[string]logical.Factory{
			"userpass": userpass.Factory,
		},
	}
	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
	})
	cluster.Start()
	defer cluster.Cleanup()

	// standby client
	client := cluster.Cores[1].Client

	// enable userpass
	err := client.Sys().EnableAuthWithOptions("userpass", &api.EnableAuthOptions{
		Type: "userpass",
	})
	require.NoError(t, err)

	// create a userpass user
	_, err = client.Logical().Write("auth/userpass/users/bsmith", map[string]any{
		"password": "training",
	})
	require.NoError(t, err)

	// get mount accessor for userpass mount
	secret, err := client.Logical().Read("sys/auth/userpass")
	require.NoError(t, err)
	require.NotNil(t, secret)

	mountAccessor := secret.Data["accessor"].(string)

	tests := []struct {
		name                        string
		setDisableUserLockoutEnvVar string
		// default is false
		setDisableLockoutAuthTune bool
		expectedUserLocked        bool
	}{
		{
			name:                        "Both unset, uses default behaviour i.e; user lockout feature enabled",
			setDisableUserLockoutEnvVar: "",
			setDisableLockoutAuthTune:   false,
			expectedUserLocked:          true,
		},
		{
			name:                        "User lockout feature is disabled using auth tune",
			setDisableUserLockoutEnvVar: "",
			setDisableLockoutAuthTune:   true,
			expectedUserLocked:          false,
		},
		{
			name:                        "User Lockout feature is disabled using env var VAULT_DISABLE_USER_LOCKOUT",
			setDisableUserLockoutEnvVar: "true",
			setDisableLockoutAuthTune:   false,
			expectedUserLocked:          false,
		},
		{
			name:                        "User lockout feature is enabled using env variable, disabled using auth tune",
			setDisableUserLockoutEnvVar: "false",
			setDisableLockoutAuthTune:   true,
			expectedUserLocked:          true,
		},
		{
			name:                        "User lockout feature is disabled using auth tune and env variable",
			setDisableUserLockoutEnvVar: "true",
			setDisableLockoutAuthTune:   true,
			expectedUserLocked:          false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setDisableUserLockoutEnvVar != "" {
				os.Setenv("VAULT_DISABLE_USER_LOCKOUT", tt.setDisableUserLockoutEnvVar)
			} else {
				os.Unsetenv("VAULT_DISABLE_USER_LOCKOUT")
			}

			// tune auth mount
			userLockoutConfig := &api.UserLockoutConfigInput{
				DisableLockout: &tt.setDisableLockoutAuthTune,
			}
			err := client.Sys().TuneMount("auth/userpass", api.MountConfigInput{
				UserLockoutConfig: userLockoutConfig,
			})
			require.NoError(t, err)

			// login for default lockout threshold times with wrong credentials
			for i := range UserLockoutThresholdDefault {
				_, err = client.Logical().Write("auth/userpass/login/bsmith", map[string]any{
					"password": "wrongPassword",
				})
				require.ErrorContains(t, err, "invalid username or password", "expected login attempt %d to fail due to wrong credentials", i+1)
			}

			// login to check if user locked
			_, err = client.Logical().Write("auth/userpass/login/bsmith", map[string]any{
				"password": "wrongPassword",
			})

			if tt.expectedUserLocked {
				require.ErrorContains(t, err, logical.ErrPermissionDenied.Error(), "expected login to fail due to wrong credentials")

				// user locked, unlock user to perform next test iteration
				_, err = client.Logical().Write("sys/locked-users/"+mountAccessor+"/unlock/bsmith", nil)
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, "invalid username or password", "expected login to fail due to wrong credentials")
			}
		})
	}

	require.NoError(t, client.Sys().TuneMount("auth/userpass", api.MountConfigInput{
		UserLockoutConfig: &api.UserLockoutConfigInput{
			DisableLockout: pointerutil.BoolPtr(false),
		},
	}))
	os.Unsetenv("VAULT_DISABLE_USER_LOCKOUT")

	t.Run("successful login resets counter", func(t *testing.T) {
		// almost lock the user
		for i := range UserLockoutThresholdDefault - 1 {
			_, err = client.Logical().Write("auth/userpass/login/bsmith", map[string]any{
				"password": "wrongPassword",
			})
			require.ErrorContains(t, err, "invalid username or password", "expected login attempt %d to fail due to wrong credentials", i+1)
		}

		// successful login should reset the counter
		_, err = client.Logical().Write("auth/userpass/login/bsmith", map[string]any{
			"password": "training",
		})
		require.NoError(t, err)

		// almost lock the user again
		for i := range UserLockoutThresholdDefault - 1 {
			_, err = client.Logical().Write("auth/userpass/login/bsmith", map[string]any{
				"password": "wrongPassword",
			})
			require.ErrorContains(t, err, "invalid username or password", "expected login attempt %d to fail due to wrong credentials", i+1)
		}

		// successful inline-auth login should reset the counter
		inlineAuthClient, err := client.WithInlineAuth("auth/userpass/login/bsmith", map[string]any{
			"password": "training",
		})
		require.NoError(t, err)

		_, err = inlineAuthClient.Logical().Read("cubbyhole/hello")
		require.NoError(t, err)

		// almost lock the user again
		for i := range UserLockoutThresholdDefault - 1 {
			_, err = client.Logical().Write("auth/userpass/login/bsmith", map[string]any{
				"password": "wrongPassword",
			})
			require.ErrorContains(t, err, "invalid username or password", "expected login attempt %d to fail due to wrong credentials", i+1)
		}
	})
}
