package integrationtest

import (
	"bytes"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"reflect"
	"testing"

	"github.com/hashicorp/vault/api"
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
		os.Setenv("VAULT_ADDR", "http://127.0.0.1:38200")
		os.Setenv("VAULT_TOKEN", "root")
		os.Setenv("KUBERNETES_JWT", out.String())
		os.Exit(m.Run())
	}
}

func TestUnauthorizedServiceAccountErrorCode(t *testing.T) {
	// Pick up VAULT_ADDR and VAULT_TOKEN from env vars
	client, err := api.NewClient(nil)
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.Logical().Write("sys/auth/kubernetes", map[string]interface{}{
		"type": "kubernetes-dev",
	})
	if err != nil {
		t.Fatal(err)
	}

	defer func() {
		_, err = client.Logical().Delete("sys/auth/kubernetes")
		if err != nil {
			t.Fatal(err)
		}
	}()

	_, err = client.Logical().Write("auth/kubernetes/config", map[string]interface{}{
		"kubernetes_host": "https://kubernetes.default.svc.cluster.local",
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.Logical().Write("auth/kubernetes/role/test-role", map[string]interface{}{
		"bound_service_account_names":      "test",
		"bound_service_account_namespaces": "test",
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.Logical().Write("auth/kubernetes/login", map[string]interface{}{
		"role": "test-role",
		"jwt":  os.Getenv("KUBERNETES_JWT"),
	})
	respErr, ok := err.(*api.ResponseError)
	if !ok {
		t.Fatalf("Expected api.ResponseError but was: %s", reflect.TypeOf(err).Name())
	}
	if respErr.StatusCode != http.StatusForbidden {
		t.Fatalf("Expected 403 but was %d", respErr.StatusCode)
	}
}
