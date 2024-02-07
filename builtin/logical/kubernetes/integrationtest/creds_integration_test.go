// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package integrationtest

import (
	"fmt"
	"testing"

	"github.com/openbao/openbao/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test token ttl handling and defaults
func TestCreds_ttl(t *testing.T) {
	// Pick up VAULT_ADDR and VAULT_TOKEN from env vars
	client, err := api.NewClient(nil)
	if err != nil {
		t.Fatal(err)
	}

	path, umount := mountHelper(t, client)
	defer umount()
	client, delNamespace := namespaceHelper(t, client)
	defer delNamespace()

	// create default config
	_, err = client.Logical().Write(path+"/config", map[string]interface{}{})
	require.NoError(t, err)

	type testCase struct {
		roleConfig     map[string]interface{}
		credsConfig    map[string]interface{}
		expectedTTLSec int
	}

	tests := map[string]testCase{
		"both set": {
			roleConfig: map[string]interface{}{
				"allowed_kubernetes_namespaces": []string{"*"},
				"service_account_name":          "sample-app",
				"token_default_ttl":             "4h",
				"token_max_ttl":                 "24h",
			},
			credsConfig: map[string]interface{}{
				"kubernetes_namespace": "test",
				"ttl":                  "2h",
			},
			expectedTTLSec: 7200,
		},
		"default to token_default_ttl": {
			roleConfig: map[string]interface{}{
				"allowed_kubernetes_namespaces": []string{"*"},
				"service_account_name":          "sample-app",
				"token_default_ttl":             "4h",
				"token_max_ttl":                 "24h",
			},
			credsConfig: map[string]interface{}{
				"kubernetes_namespace": "test",
			},
			expectedTTLSec: 14400,
		},
		"capped to token_max_ttl from system default": {
			roleConfig: map[string]interface{}{
				"allowed_kubernetes_namespaces": []string{"*"},
				"service_account_name":          "sample-app",
				"token_max_ttl":                 "24h",
			},
			credsConfig: map[string]interface{}{
				"kubernetes_namespace": "test",
			},
			expectedTTLSec: 86400,
		},
		"default to system ttl": {
			roleConfig: map[string]interface{}{
				"allowed_kubernetes_namespaces": []string{"*"},
				"service_account_name":          "sample-app",
			},
			credsConfig: map[string]interface{}{
				"kubernetes_namespace": "test",
			},
			expectedTTLSec: 2764800,
		},
		"token_default_ttl higher than the system max ttl": {
			roleConfig: map[string]interface{}{
				"allowed_kubernetes_namespaces": []string{"*"},
				"service_account_name":          "sample-app",
				"token_default_ttl":             "2764801",
			},
			credsConfig: map[string]interface{}{
				"kubernetes_namespace": "test",
			},
			expectedTTLSec: 2764800,
		},
		"token_max_ttl higher than the system max ttl": {
			roleConfig: map[string]interface{}{
				"allowed_kubernetes_namespaces": []string{"*"},
				"service_account_name":          "sample-app",
				"token_max_ttl":                 "3700000",
			},
			credsConfig: map[string]interface{}{
				"kubernetes_namespace": "test",
				"ttl":                  "2764801",
			},
			expectedTTLSec: 2764800,
		},
	}
	i := 0
	for n, tc := range tests {
		t.Run(n, func(t *testing.T) {
			roleName := fmt.Sprintf("testrole-%d", i)
			_, err = client.Logical().Write(path+"/roles/"+roleName, tc.roleConfig)
			assert.NoError(t, err)

			creds, err := client.Logical().Write(path+"/creds/"+roleName, tc.credsConfig)
			assert.NoError(t, err)
			require.NotNil(t, creds)
			assert.Equal(t, tc.expectedTTLSec, creds.LeaseDuration)

			// check k8s token expiry
			testK8sTokenTTL(t, tc.expectedTTLSec, creds.Data["service_account_token"].(string))
		})
		i = i + 1
	}
}

// Test token audiences handling and defaults
func TestCreds_audiences(t *testing.T) {
	// Pick up VAULT_ADDR and VAULT_TOKEN from env vars
	client, err := api.NewClient(nil)
	if err != nil {
		t.Fatal(err)
	}

	path, umount := mountHelper(t, client)
	defer umount()
	client, delNamespace := namespaceHelper(t, client)
	defer delNamespace()

	// create default config
	_, err = client.Logical().Write(path+"/config", map[string]interface{}{})
	require.NoError(t, err)

	type testCase struct {
		roleConfig        map[string]interface{}
		credsConfig       map[string]interface{}
		expectedAudiences []interface{}
	}

	tests := map[string]testCase{
		"both set": {
			roleConfig: map[string]interface{}{
				"allowed_kubernetes_namespaces": []string{"*"},
				"service_account_name":          "sample-app",
				"token_default_audiences":       []string{"foo", "bar"},
			},
			credsConfig: map[string]interface{}{
				"kubernetes_namespace": "test",
				"audiences":            "baz,qux",
			},
			expectedAudiences: []interface{}{"baz", "qux"},
		},
		"default to token_default_audiences": {
			roleConfig: map[string]interface{}{
				"allowed_kubernetes_namespaces": []string{"*"},
				"service_account_name":          "sample-app",
				"token_default_audiences":       []string{"foo", "bar"},
			},
			credsConfig: map[string]interface{}{
				"kubernetes_namespace": "test",
			},
			expectedAudiences: []interface{}{"foo", "bar"},
		},
		"default to audiences of k8s cluster default if both not set": {
			roleConfig: map[string]interface{}{
				"allowed_kubernetes_namespaces": []string{"*"},
				"service_account_name":          "sample-app",
			},
			credsConfig: map[string]interface{}{
				"kubernetes_namespace": "test",
			},
			expectedAudiences: []interface{}{"https://kubernetes.default.svc.cluster.local"},
		},
	}
	i := 0
	for n, tc := range tests {
		t.Run(n, func(t *testing.T) {
			roleName := fmt.Sprintf("testrole-%d", i)
			_, err = client.Logical().Write(path+"/roles/"+roleName, tc.roleConfig)
			assert.NoError(t, err)

			creds, err := client.Logical().Write(path+"/creds/"+roleName, tc.credsConfig)
			assert.NoError(t, err)
			require.NotNil(t, creds)

			testK8sTokenAudiences(t, tc.expectedAudiences, creds.Data["service_account_token"].(string))
		})
		i = i + 1
	}
}

func TestCreds_service_account_name(t *testing.T) {
	// Pick up VAULT_ADDR and VAULT_TOKEN from env vars
	client, err := api.NewClient(nil)
	if err != nil {
		t.Fatal(err)
	}

	path, umount := mountHelper(t, client)
	defer umount()
	client, delNamespace := namespaceHelper(t, client)
	defer delNamespace()

	// create default config
	_, err = client.Logical().Write(path+"/config", map[string]interface{}{})
	require.NoError(t, err)

	_, err = client.Logical().Write(path+"/roles/testrole", map[string]interface{}{
		"allowed_kubernetes_namespaces": []string{"*"},
		"service_account_name":          "sample-app",
		"token_default_ttl":             "1h",
		"token_max_ttl":                 "24h",
	})
	assert.NoError(t, err)

	roleResponse, err := client.Logical().Read(path + "/roles/testrole")
	assert.NoError(t, err)
	assert.Equal(t, map[string]interface{}{
		"allowed_kubernetes_namespaces":         []interface{}{"*"},
		"allowed_kubernetes_namespace_selector": "",
		"extra_labels":                          nil,
		"extra_annotations":                     nil,
		"generated_role_rules":                  "",
		"kubernetes_role_name":                  "",
		"kubernetes_role_type":                  "Role",
		"name":                                  "testrole",
		"name_template":                         "",
		"service_account_name":                  "sample-app",
		"token_max_ttl":                         oneDay,
		"token_default_ttl":                     oneHour,
		"token_default_audiences":               nil,
	}, roleResponse.Data)

	result1, err := client.Logical().Write(path+"/creds/testrole", map[string]interface{}{
		"kubernetes_namespace": "test",
		"ttl":                  "2h",
	})
	assert.NoError(t, err)
	verifyCredsResponse(t, result1, "test", "sample-app", 7200)

	testRoleBindingToken(t, result1)

	// Clean up lease and delete role
	leases, err := client.Logical().List("sys/leases/lookup/" + path + "/creds/testrole/")
	assert.NoError(t, err)
	assert.Len(t, leases.Data["keys"], 1)

	err = client.Sys().RevokePrefix(path + "/creds/testrole")
	assert.NoError(t, err)

	noLeases, err := client.Logical().List("sys/leases/lookup/" + path + "/creds/testrole/")
	assert.NoError(t, err)
	assert.Empty(t, noLeases)

	_, err = client.Logical().Delete(path + "/roles/testrole")
	assert.NoError(t, err)

	result, err := client.Logical().Read(path + "/roles/testrole")
	assert.NoError(t, err)
	assert.Nil(t, result)
}

func TestCreds_kubernetes_role_name(t *testing.T) {
	// Pick up VAULT_ADDR and VAULT_TOKEN from env vars
	client, err := api.NewClient(nil)
	if err != nil {
		t.Fatal(err)
	}

	path, umount := mountHelper(t, client)
	defer umount()
	client, delNamespace := namespaceHelper(t, client)
	defer delNamespace()

	// create default config
	_, err = client.Logical().Write(path+"/config", map[string]interface{}{})
	require.NoError(t, err)

	t.Run("Role type", func(t *testing.T) {
		extraLabels := map[string]string{
			"environment": "testing",
		}
		extraAnnotations := map[string]string{
			"tested": "today",
		}
		roleConfig := map[string]interface{}{
			"allowed_kubernetes_namespaces": []string{"test"},
			"extra_annotations":             extraAnnotations,
			"extra_labels":                  extraLabels,
			"kubernetes_role_name":          "test-role-list-pods",
			"kubernetes_role_type":          "role",
			"token_default_ttl":             "1h",
			"token_max_ttl":                 "24h",
			"name_template":                 `{{ printf "v-custom-name-%s" (random 24) | truncate 62 | lowercase }}`,
		}
		expectedRoleResponse := map[string]interface{}{
			"allowed_kubernetes_namespaces":         []interface{}{"test"},
			"allowed_kubernetes_namespace_selector": "",
			"extra_annotations":                     asMapInterface(extraAnnotations),
			"extra_labels":                          asMapInterface(extraLabels),
			"generated_role_rules":                  "",
			"kubernetes_role_name":                  "test-role-list-pods",
			"kubernetes_role_type":                  "Role",
			"name":                                  "testrole",
			"name_template":                         `{{ printf "v-custom-name-%s" (random 24) | truncate 62 | lowercase }}`,
			"service_account_name":                  "",
			"token_max_ttl":                         oneDay,
			"token_default_ttl":                     oneHour,
			"token_default_audiences":               nil,
		}
		testRoleType(t, client, path, roleConfig, expectedRoleResponse)
	})

	t.Run("ClusterRole type", func(t *testing.T) {
		extraLabels := map[string]string{
			"environment": "staging",
		}
		extraAnnotations := map[string]string{
			"tested": "tomorrow",
		}
		roleConfig := map[string]interface{}{
			"allowed_kubernetes_namespaces":         []string{"random"},
			"allowed_kubernetes_namespace_selector": `{"matchExpressions": [{"key": "target", "operator": "In", "values": ["integration-test"]}, {"key": "nonexistantlabel", "operator": "DoesNotExist", "values": []}]}`,
			"extra_annotations":                     extraAnnotations,
			"extra_labels":                          extraLabels,
			"kubernetes_role_name":                  "test-cluster-role-list-pods",
			"kubernetes_role_type":                  "Clusterrole",
			"token_default_ttl":                     "1h",
			"token_max_ttl":                         "24h",
		}
		expectedRoleResponse := map[string]interface{}{
			"allowed_kubernetes_namespaces":         []interface{}{"random"},
			"allowed_kubernetes_namespace_selector": `{"matchExpressions": [{"key": "target", "operator": "In", "values": ["integration-test"]}, {"key": "nonexistantlabel", "operator": "DoesNotExist", "values": []}]}`,
			"extra_annotations":                     asMapInterface(extraAnnotations),
			"extra_labels":                          asMapInterface(extraLabels),
			"generated_role_rules":                  "",
			"kubernetes_role_name":                  "test-cluster-role-list-pods",
			"kubernetes_role_type":                  "ClusterRole",
			"name":                                  "clusterrole",
			"name_template":                         "",
			"service_account_name":                  "",
			"token_max_ttl":                         oneDay,
			"token_default_ttl":                     oneHour,
			"token_default_audiences":               nil,
		}
		testClusterRoleType(t, client, path, roleConfig, expectedRoleResponse)
	})
}

func TestCreds_generated_role_rules(t *testing.T) {
	// Pick up VAULT_ADDR and VAULT_TOKEN from env vars
	client, err := api.NewClient(nil)
	if err != nil {
		t.Fatal(err)
	}

	path, umount := mountHelper(t, client)
	defer umount()
	client, delNamespace := namespaceHelper(t, client)
	defer delNamespace()

	// create default config
	_, err = client.Logical().Write(path+"/config", map[string]interface{}{})
	require.NoError(t, err)

	roleRulesYAML := `rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["list"]`

	roleRulesJSON := `"rules": [
	{
		"apiGroups": [
			""
		],
		"resources": [
			"pods"
		],
		"verbs": [
			"list"
		]
	}
]`

	t.Run("Role type", func(t *testing.T) {
		extraLabels := map[string]string{
			"environment": "testing",
		}
		extraAnnotations := map[string]string{
			"tested": "today",
		}
		roleConfig := map[string]interface{}{
			"allowed_kubernetes_namespaces": []string{"test"},
			"extra_annotations":             extraAnnotations,
			"extra_labels":                  extraLabels,
			"generated_role_rules":          roleRulesYAML,
			"kubernetes_role_type":          "RolE",
			"token_default_ttl":             "1h",
			"token_max_ttl":                 "24h",
		}
		expectedRoleResponse := map[string]interface{}{
			"allowed_kubernetes_namespaces":         []interface{}{"test"},
			"allowed_kubernetes_namespace_selector": "",
			"extra_annotations":                     asMapInterface(extraAnnotations),
			"extra_labels":                          asMapInterface(extraLabels),
			"generated_role_rules":                  roleRulesYAML,
			"kubernetes_role_name":                  "",
			"kubernetes_role_type":                  "Role",
			"name":                                  "testrole",
			"name_template":                         "",
			"service_account_name":                  "",
			"token_max_ttl":                         oneDay,
			"token_default_ttl":                     oneHour,
			"token_default_audiences":               nil,
		}
		testRoleType(t, client, path, roleConfig, expectedRoleResponse)
	})

	t.Run("ClusterRole type", func(t *testing.T) {
		extraLabels := map[string]string{
			"environment": "staging",
			"asdf":        "123",
		}
		extraAnnotations := map[string]string{
			"tested":  "tomorrow",
			"checked": "again",
		}
		roleConfig := map[string]interface{}{
			"allowed_kubernetes_namespaces": []string{"test"},
			"extra_annotations":             extraAnnotations,
			"extra_labels":                  extraLabels,
			"generated_role_rules":          roleRulesJSON,
			"kubernetes_role_type":          "clusterRole",
			"token_default_ttl":             "1h",
			"token_max_ttl":                 "24h",
		}
		expectedRoleResponse := map[string]interface{}{
			"allowed_kubernetes_namespaces":         []interface{}{"test"},
			"allowed_kubernetes_namespace_selector": "",
			"extra_annotations":                     asMapInterface(extraAnnotations),
			"extra_labels":                          asMapInterface(extraLabels),
			"generated_role_rules":                  roleRulesJSON,
			"kubernetes_role_name":                  "",
			"kubernetes_role_type":                  "ClusterRole",
			"name":                                  "clusterrole",
			"name_template":                         "",
			"service_account_name":                  "",
			"token_max_ttl":                         oneDay,
			"token_default_ttl":                     oneHour,
			"token_default_audiences":               nil,
		}
		testClusterRoleType(t, client, path, roleConfig, expectedRoleResponse)
	})
}

// Test kubernetes_namespace handling
func TestCreds_kubernetes_namespace(t *testing.T) {
	// Pick up VAULT_ADDR and VAULT_TOKEN from env vars
	client, err := api.NewClient(nil)
	if err != nil {
		t.Fatal(err)
	}

	path, umount := mountHelper(t, client)
	defer umount()
	client, delNamespace := namespaceHelper(t, client)
	defer delNamespace()

	// create default config
	_, err = client.Logical().Write(path+"/config", map[string]interface{}{})
	require.NoError(t, err)

	type testCase struct {
		roleConfig                  map[string]interface{}
		credsConfig                 map[string]interface{}
		expectedCredsCreateErrIsNil bool
	}

	tests := map[string]testCase{
		"allowed_kubernetes_namespaces to * and kubernetes_namespace to test": {
			roleConfig: map[string]interface{}{
				"allowed_kubernetes_namespaces": []string{"*"},
				"service_account_name":          "sample-app",
			},
			credsConfig: map[string]interface{}{
				"kubernetes_namespace": "test",
			},
			expectedCredsCreateErrIsNil: true,
		},
		"allowed_kubernetes_namespaces to a single namespace, allowed_kubernetes_namespace_selector to empty," +
			" and kubernetes_namespace omitted": {
			roleConfig: map[string]interface{}{
				"allowed_kubernetes_namespaces": []string{"test"},
				"service_account_name":          "sample-app",
			},
			credsConfig:                 nil,
			expectedCredsCreateErrIsNil: true,
		},
		"allowed_kubernetes_namespaces to * and kubernetes_namespace omitted": {
			roleConfig: map[string]interface{}{
				"allowed_kubernetes_namespaces": []string{"*"},
				"service_account_name":          "sample-app",
			},
			credsConfig:                 nil,
			expectedCredsCreateErrIsNil: false,
		},
		"allowed_kubernetes_namespaces to a single namespace, allowed_kubernetes_namespace_selector to nonempty," +
			" and kubernetes_namespace omitted": {
			roleConfig: map[string]interface{}{
				"allowed_kubernetes_namespaces":         []string{"test"},
				"allowed_kubernetes_namespace_selector": `{"matchExpressions": [{"key": "target", "operator": "In", "values": ["integration-test"]}, {"key": "nonexistantlabel", "operator": "DoesNotExist", "values": []}]}`,
				"service_account_name":                  "sample-app",
			},
			credsConfig:                 nil,
			expectedCredsCreateErrIsNil: false,
		},
		"allowed_kubernetes_namespaces to empty, allowed_kubernetes_namespace_selector to nonempty," +
			"kubernetes_namespace omitted": {
			roleConfig: map[string]interface{}{
				"allowed_kubernetes_namespace_selector": `{"matchExpressions": [{"key": "target", "operator": "In", "values": ["integration-test"]}, {"key": "nonexistantlabel", "operator": "DoesNotExist", "values": []}]}`,
				"service_account_name":                  "sample-app",
			},
			credsConfig:                 nil,
			expectedCredsCreateErrIsNil: false,
		},
		"allowed_kubernetes_namespaces to more than one specified, kubernetes_namespace omitted": {
			roleConfig: map[string]interface{}{
				"allowed_kubernetes_namespaces": []string{"test", "foo"},
				"service_account_name":          "sample-app",
			},
			credsConfig:                 nil,
			expectedCredsCreateErrIsNil: false,
		},
	}
	i := 0
	for n, tc := range tests {
		t.Run(n, func(t *testing.T) {
			roleName := fmt.Sprintf("testrole-%d", i)
			_, err = client.Logical().Write(path+"/roles/"+roleName, tc.roleConfig)
			require.NoError(t, err)

			creds, err := client.Logical().Write(path+"/creds/"+roleName, tc.credsConfig)
			assert.Equal(t, tc.expectedCredsCreateErrIsNil, err == nil)
			if tc.expectedCredsCreateErrIsNil {
				require.NotNil(t, creds)
			}
		})
		i = i + 1
	}
}
