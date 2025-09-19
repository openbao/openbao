// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package integrationtest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/hashicorp/go-version"
	"github.com/openbao/openbao/api/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Set the environment variable INTEGRATION_TESTS to any non-empty value to run
// the tests in this package. The test assumes it has available:
// - kubectl
//   - A Kubernetes cluster in which:
//   - it can use the `test` namespace
//   - Vault is deployed and accessible
//
// See `make setup-integration-test` for manual testing.
func TestMain(m *testing.M) {
	if os.Getenv("INTEGRATION_TESTS") != "" {
		checkKubectlVersion()
		os.Setenv("BAO_ADDR", "http://127.0.0.1:38300")
		os.Setenv("BAO_TOKEN", "root")
		os.Setenv("KUBERNETES_CA", getK8sCA())
		os.Setenv("KUBE_HOST", getKubeHost(os.Getenv("KIND_CLUSTER_NAME")))
		os.Setenv("SUPER_JWT", getSuperJWT())
		os.Setenv("BROKEN_JWT", getBrokenJWT())
		os.Exit(m.Run())
	}
}

type kubectlVersion struct {
	ClientVersion struct {
		GitVersion string `json:"gitVersion"`
	} `json:"clientVersion"`
}

// kubectl create token requires kubectl >= v1.24.0
func checkKubectlVersion() {
	versionJSON := runCmd("kubectl version --client --output=json")
	var versionInfo kubectlVersion

	if err := json.Unmarshal([]byte(versionJSON), &versionInfo); err != nil {
		panic(err)
	}

	v := version.Must(version.NewSemver(versionInfo.ClientVersion.GitVersion))
	if v.LessThan(version.Must(version.NewSemver("v1.24.0"))) {
		panic("integration tests require kubectl version >= v1.24.0, but found: " + versionInfo.ClientVersion.GitVersion)
	}
}

func TestMount(t *testing.T) {
	// Pick up VAULT_ADDR and VAULT_TOKEN from env vars
	client, err := api.NewClient(nil)
	if err != nil {
		t.Fatal(err)
	}

	_, umount := mountHelper(t, client)
	defer umount()
}

func TestCheckViability(t *testing.T) {
	client, err := api.NewClient(nil)
	if err != nil {
		t.Fatal(err)
	}

	path, umount := mountHelper(t, client)
	defer umount()
	client, delNamespace := namespaceHelper(t, client)
	defer delNamespace()

	// check
	resp, err := client.Logical().ReadRaw(path + "/check")
	assert.NoError(t, err)
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
}

func TestConfig(t *testing.T) {
	// Pick up VAULT_ADDR and VAULT_TOKEN from env vars
	client, err := api.NewClient(nil)
	if err != nil {
		t.Fatal(err)
	}

	path, umount := mountHelper(t, client)
	defer umount()
	client, delNamespace := namespaceHelper(t, client)
	defer delNamespace()

	// create
	_, err = client.Logical().Write(path+"/config", map[string]interface{}{
		"disable_local_ca_jwt": true,
		"kubernetes_ca_cert":   "cert",
		"kubernetes_host":      "host",
		"service_account_jwt":  "jwt",
	})
	assert.NoError(t, err)

	result, err := client.Logical().Read(path + "/config")
	assert.NoError(t, err)
	assert.Equal(t, map[string]interface{}{
		"disable_local_ca_jwt": true,
		"kubernetes_ca_cert":   "cert",
		"kubernetes_host":      "host",
	}, result.Data)

	// update
	_, err = client.Logical().Write(path+"/config", map[string]interface{}{
		"kubernetes_host": "another-host",
	})
	assert.NoError(t, err)

	result, err = client.Logical().Read(path + "/config")
	assert.NoError(t, err)
	assert.Equal(t, map[string]interface{}{
		"disable_local_ca_jwt": true,
		"kubernetes_ca_cert":   "cert",
		"kubernetes_host":      "another-host",
	}, result.Data)

	// delete
	_, err = client.Logical().Delete(path + "/config")
	assert.NoError(t, err)

	result, err = client.Logical().Read(path + "/config")
	assert.NoError(t, err)
	assert.Nil(t, result)
}

func TestRole(t *testing.T) {
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
		"generated_role_rules":          sampleRules,
		"token_default_ttl":             "1h",
		"token_max_ttl":                 "24h",
		"token_default_audiences":       []string{"foobar"},
	})
	assert.NoError(t, err)

	result, err := client.Logical().Read(path + "/roles/testrole")
	assert.NoError(t, err)
	assert.Equal(t, map[string]interface{}{
		"allowed_kubernetes_namespaces":         []interface{}{"*"},
		"allowed_kubernetes_namespace_selector": "",
		"extra_annotations":                     nil,
		"extra_labels":                          nil,
		"generated_role_rules":                  sampleRules,
		"kubernetes_role_name":                  "",
		"kubernetes_role_type":                  "Role",
		"name":                                  "testrole",
		"name_template":                         "",
		"service_account_name":                  "",
		"token_max_ttl":                         oneDay,
		"token_default_ttl":                     oneHour,
		"token_default_audiences":               []interface{}{"foobar"},
	}, result.Data)

	// update
	result, err = client.Logical().Write(path+"/roles/testrole", map[string]interface{}{
		"allowed_kubernetes_namespaces": []string{"app1", "app2"},
		"extra_annotations":             sampleExtraAnnotations,
		"extra_labels":                  sampleExtraLabels,
		"token_default_ttl":             "30m",
		"token_default_audiences":       []string{"bar"},
	})
	assert.NoError(t, err)
	assert.Nil(t, result)

	result, err = client.Logical().Read(path + "/roles/testrole")
	assert.NoError(t, err)
	assert.Equal(t, map[string]interface{}{
		"allowed_kubernetes_namespaces":         []interface{}{"app1", "app2"},
		"allowed_kubernetes_namespace_selector": "",
		"extra_annotations":                     asMapInterface(sampleExtraAnnotations),
		"extra_labels":                          asMapInterface(sampleExtraLabels),
		"generated_role_rules":                  sampleRules,
		"kubernetes_role_name":                  "",
		"kubernetes_role_type":                  "Role",
		"name":                                  "testrole",
		"name_template":                         "",
		"service_account_name":                  "",
		"token_max_ttl":                         oneDay,
		"token_default_ttl":                     thirtyMinutes,
		"token_default_audiences":               []interface{}{"bar"},
	}, result.Data)

	// update again
	_, err = client.Logical().Write(path+"/roles/testrole", map[string]interface{}{
		"allowed_kubernetes_namespaces":         []string{},
		"allowed_kubernetes_namespace_selector": sampleSelector,
	})
	assert.NoError(t, err)

	result, err = client.Logical().Read(path + "/roles/testrole")
	assert.NoError(t, err)
	assert.Equal(t, map[string]interface{}{
		"allowed_kubernetes_namespaces":         []interface{}{},
		"allowed_kubernetes_namespace_selector": sampleSelector,
		"extra_annotations":                     asMapInterface(sampleExtraAnnotations),
		"extra_labels":                          asMapInterface(sampleExtraLabels),
		"generated_role_rules":                  sampleRules,
		"kubernetes_role_name":                  "",
		"kubernetes_role_type":                  "Role",
		"name":                                  "testrole",
		"name_template":                         "",
		"service_account_name":                  "",
		"token_max_ttl":                         oneDay,
		"token_default_ttl":                     thirtyMinutes,
		"token_default_audiences":               []interface{}{"bar"},
	}, result.Data)

	result, err = client.Logical().List(path + "/roles")
	assert.NoError(t, err)
	assert.Equal(t, map[string]interface{}{"keys": []interface{}{"testrole"}}, result.Data)

	_, err = client.Logical().Delete(path + "/roles/testrole")
	assert.NoError(t, err)

	result, err = client.Logical().Read(path + "/roles/testrole")
	assert.NoError(t, err)
	assert.Nil(t, result)
}

func isEnterprise(client *api.Client) bool {
	req := client.NewRequest("GET", "/v1/sys/license/status")
	resp, err := client.RawRequest(req)
	if err != nil {
		return false
	}
	return resp.StatusCode == 200
}

func createNamespace(client *api.Client, namespace string) error {
	req := client.NewRequest("PUT", "/v1/sys/namespaces/"+namespace)
	resp, err := client.RawRequest(req)
	if err != nil {
		return err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("error creating namespace. Server returned status %d %s", resp.StatusCode, resp.Status)
	}
	return nil
}

func deleteNamespace(client *api.Client, namespace string) error {
	req := client.NewRequest("DELETE", "/v1/sys/namespaces/"+namespace)
	resp, err := client.RawRequest(req)
	if err != nil {
		return err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("error creating namespace. Server returned status %d %s", resp.StatusCode, resp.Status)
	}
	return nil
}

// mountHelper creates the kubernetes mount.
func mountHelper(t *testing.T, client *api.Client) (string, func()) {
	t.Helper()

	path := randomWithPrefix("kubernetes")
	fullPath := fmt.Sprintf("sys/mounts/%s", path)
	_, err := client.Logical().Write(fullPath, map[string]interface{}{
		"type": "kubernetes-dev",
	})
	if err != nil {
		t.Fatal(err)
	}

	return path, func() {
		_, err = client.Logical().Delete(fullPath)
		if err != nil {
			t.Fatal(err)
		}
	}
}

// namespaceHelper creates a Vault Enterprise namespace and returns a client with the namespace changed to it.
func namespaceHelper(t *testing.T, client *api.Client) (*api.Client, func()) {
	t.Helper()

	var err error
	namespace := ""
	newClient := client

	if isEnterprise(client) {
		namespace := randomWithPrefix("somenamespace")
		if err != nil {
			t.Fatal(err)
		}
		err = createNamespace(client, namespace)
		if err != nil {
			t.Fatal(err)
		}
		newClient, err := client.Clone()
		if err != nil {
			t.Fatal(err)
		}
		newClient.SetNamespace(namespace)
	}

	return newClient, func() {
		if namespace != "" {
			err = deleteNamespace(client, namespace)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
}

const (
	sampleRules = `rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "watch", "list"]
`

	sampleSelector = `matchLabels:
  target: integration-test
`
)

var (
	sampleExtraLabels = map[string]string{
		"key1": "value1",
		"key2": "value2",
	}
	sampleExtraAnnotations = map[string]string{
		"key3": "value3",
		"key4": "value4",
	}
)

const (
	thirtyMinutes json.Number = "1800"
	oneHour       json.Number = "3600"
	oneDay        json.Number = "86400"
)

func runCmd(command string) string {
	parts := strings.Split(command, " ")
	fmt.Println(parts)
	cmd := exec.Command(parts[0], parts[1:]...)
	out := &bytes.Buffer{}
	cmd.Stdout = out
	cmd.Stderr = out
	if err := cmd.Run(); err != nil {
		panic(fmt.Sprintf("Got unexpected output: %s, err = %s", out.String(), err))
	}
	return out.String()
}

func getSuperJWT() string {
	return runCmd("kubectl --namespace=test create token super-jwt")
}

func getBrokenJWT() string {
	return runCmd("kubectl --namespace=test create token broken-jwt")
}

func getK8sCA() string {
	return runCmd("kubectl exec --namespace=test vault-0 -- cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
}

func getKubeHost(clusterName string) string {
	cmd := fmt.Sprintf(`kubectl config view --raw --minify --flatten --output=jsonpath={.clusters[?(@.name=="kind-%s")].cluster.server}`, clusterName)
	return runCmd(cmd)
}
