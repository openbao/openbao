package integrationtest

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"testing"

	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
)

// Set the environment variable INTEGRATION_TESTS to any non-empty value to run
// the tests in this package. The test assumes it has available:
//   - kubectl
//   - A Kubernetes cluster in which:
//       - it can use the `test` namespace
//       - Vault is deployed and accessible
// See `make setup-integration-test` for manual testing.
func TestMain(m *testing.M) {
	if os.Getenv("INTEGRATION_TESTS") != "" {
		cmd := exec.Command("kubectl", "exec", "--namespace=test", "vault-0", "--", "cat", "/var/run/secrets/kubernetes.io/serviceaccount/token")
		out := &bytes.Buffer{}
		cmd.Stdout = out
		cmd.Stderr = out
		if err := cmd.Run(); err != nil {
			fmt.Println(out.String())
			fmt.Println(err)
			os.Exit(1)
		}
		os.Setenv("VAULT_ADDR", "http://127.0.0.1:38300")
		os.Setenv("VAULT_TOKEN", "root")
		os.Setenv("KUBERNETES_JWT", out.String())
		os.Exit(m.Run())
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

func TestConfig(t *testing.T) {
	// Pick up VAULT_ADDR and VAULT_TOKEN from env vars
	client, err := api.NewClient(nil)
	if err != nil {
		t.Fatal(err)
	}

	path, umount := mountHelper(t, client)
	defer umount()

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
