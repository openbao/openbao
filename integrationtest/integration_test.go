// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package integrationtest

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"testing"

	"github.com/hashicorp/vault-plugin-auth-kubernetes/integrationtest/k8s"
	"github.com/hashicorp/vault/api"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	matchLabelsKeyValue = `{
	"matchLabels": {
		"target": "integration-test"
	}
}`
	mismatchLabelsKeyValue = `{
	"matchLabels": {
		"target": "not-integration-test"
	}
}`
)

// Set the environment variable INTEGRATION_TESTS to any non-empty value to run
// the tests in this package. The test assumes it has available:
// - A Kubernetes cluster in which:
//   - it can use the `test` namespace
//   - Vault is deployed and accessible
//   - There is a serviceaccount called test-token-reviewer-account with access to the TokenReview API
//
// See `make setup-integration-test` for manual testing.
func TestMain(m *testing.M) {
	if os.Getenv("INTEGRATION_TESTS") != "" {
		os.Exit(run(m))
	}
}

func run(m *testing.M) int {
	localPort, close, err := k8s.SetupPortForwarding(os.Getenv("KUBE_CONTEXT"), "test", "vault-0")
	if err != nil {
		fmt.Println(err)
		return 1
	}
	defer close()

	os.Setenv("VAULT_ADDR", fmt.Sprintf("http://127.0.0.1:%d", localPort))
	os.Setenv("VAULT_TOKEN", "root")

	return m.Run()
}

func createToken(t *testing.T, sa string, audiences []string) string {
	t.Helper()

	k8sClient, err := k8s.ClientFromKubeConfig(os.Getenv("KUBE_CONTEXT"))
	if err != nil {
		t.Fatal(err)
	}

	resp, err := k8sClient.CoreV1().ServiceAccounts("test").CreateToken(context.Background(), sa, &authenticationv1.TokenRequest{
		Spec: authenticationv1.TokenRequestSpec{
			Audiences: audiences,
		},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	return resp.Status.Token
}

func setupKubernetesAuth(t *testing.T, boundServiceAccountName string, mountConfigOverride map[string]interface{}, roleConfigOverride map[string]interface{}) (*api.Client, func()) {
	t.Helper()
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

	cleanup := func() {
		_, err = client.Logical().Delete("sys/auth/kubernetes")
		if err != nil {
			t.Fatal(err)
		}
	}

	defer func() {
		if t.Failed() {
			cleanup()
		}
	}()

	mountConfig := map[string]interface{}{
		"kubernetes_host": "https://kubernetes.default.svc.cluster.local",
	}
	if len(mountConfigOverride) != 0 {
		mountConfig = mountConfigOverride
	}

	_, err = client.Logical().Write("auth/kubernetes/config", mountConfig)
	if err != nil {
		t.Fatal(err)
	}

	roleConfig := map[string]interface{}{
		"bound_service_account_names":      boundServiceAccountName,
		"bound_service_account_namespaces": "test",
	}
	if len(roleConfigOverride) != 0 {
		roleConfig = roleConfigOverride
	}

	_, err = client.Logical().Write("auth/kubernetes/role/test-role", roleConfig)
	if err != nil {
		t.Fatal(err)
	}

	return client, cleanup
}

func TestSuccess(t *testing.T) {
	client, cleanup := setupKubernetesAuth(t, "vault", nil, nil)
	defer cleanup()

	_, err := client.Logical().Write("auth/kubernetes/login", map[string]interface{}{
		"role": "test-role",
		"jwt":  createToken(t, "vault", nil),
	})
	if err != nil {
		t.Fatalf("Expected successful login but got: %v", err)
	}
}

func TestSuccessWithTokenReviewerJwt(t *testing.T) {
	client, cleanup := setupKubernetesAuth(t, "vault", map[string]interface{}{
		"kubernetes_host":    "https://kubernetes.default.svc.cluster.local",
		"token_reviewer_jwt": createToken(t, "test-token-reviewer-account", nil),
	}, nil)
	defer cleanup()

	_, err := client.Logical().Write("auth/kubernetes/login", map[string]interface{}{
		"role": "test-role",
		"jwt":  createToken(t, "vault", nil),
	})
	if err != nil {
		t.Fatalf("Expected successful login but got: %v", err)
	}
}

func TestSuccessWithNamespaceLabels(t *testing.T) {
	roleConfigOverride := map[string]interface{}{
		"bound_service_account_names":              "vault",
		"bound_service_account_namespace_selector": matchLabelsKeyValue,
	}
	client, cleanup := setupKubernetesAuth(t, "vault", nil, roleConfigOverride)
	defer cleanup()

	_, err := client.Logical().Write("auth/kubernetes/login", map[string]interface{}{
		"role": "test-role",
		"jwt":  createToken(t, "vault", nil),
	})
	if err != nil {
		t.Fatalf("Expected successful login but got: %v", err)
	}
}

func TestFailWithMismatchNamespaceLabels(t *testing.T) {
	roleConfigOverride := map[string]interface{}{
		"bound_service_account_names":              "vault",
		"bound_service_account_namespace_selector": mismatchLabelsKeyValue,
	}
	client, cleanup := setupKubernetesAuth(t, "vault", nil, roleConfigOverride)
	defer cleanup()

	_, err := client.Logical().Write("auth/kubernetes/login", map[string]interface{}{
		"role": "test-role",
		"jwt":  createToken(t, "vault", nil),
	})
	respErr, ok := err.(*api.ResponseError)
	if !ok {
		t.Fatalf("Expected api.ResponseError but was: %T", err)
	}
	if respErr.StatusCode != http.StatusForbidden {
		t.Fatalf("Expected 403 but was %d: %s", respErr.StatusCode, respErr.Error())
	}
}

func TestFailWithBadTokenReviewerJwt(t *testing.T) {
	client, cleanup := setupKubernetesAuth(t, "vault", map[string]interface{}{
		"kubernetes_host":    "https://kubernetes.default.svc.cluster.local",
		"token_reviewer_jwt": badTokenReviewerJwt,
	}, nil)
	defer cleanup()

	_, err := client.Logical().Write("auth/kubernetes/login", map[string]interface{}{
		"role": "test-role",
		"jwt":  createToken(t, "vault", nil),
	})
	respErr, ok := err.(*api.ResponseError)
	if !ok {
		t.Fatalf("Expected api.ResponseError but was: %T", err)
	}
	if respErr.StatusCode != http.StatusForbidden {
		t.Fatalf("Expected 403 but was %d: %s", respErr.StatusCode, respErr.Error())
	}
}

func TestUnauthorizedServiceAccountErrorCode(t *testing.T) {
	client, cleanup := setupKubernetesAuth(t, "badServiceAccount", nil, nil)
	defer cleanup()

	_, err := client.Logical().Write("auth/kubernetes/login", map[string]interface{}{
		"role": "test-role",
		"jwt":  createToken(t, "vault", nil),
	})
	respErr, ok := err.(*api.ResponseError)
	if !ok {
		t.Fatalf("Expected api.ResponseError but was: %T", err)
	}
	if respErr.StatusCode != http.StatusForbidden {
		t.Fatalf("Expected 403 but was %d: %s", respErr.StatusCode, respErr.Error())
	}
}

const badTokenReviewerJwt = "eyJhbGciOiJSUzI1NiIsImtpZCI6IkZza1ViNWREek8tQ05uaVk3TU5mRWZ2dEx5bzFuU0tsV3JhUU5nekhVQ28ifQ.eyJhdWQiOlsiaHR0cHM6Ly9rdWJlcm5ldGVzLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWwiXSwiZXhwIjoxNjgwODg5NjQ4LCJpYXQiOjE2NDkzNTM2NDgsImlzcyI6Imh0dHBzOi8va3ViZXJuZXRlcy5kZWZhdWx0LnN2Yy5jbHVzdGVyLmxvY2FsIiwia3ViZXJuZXRlcy5pbyI6eyJuYW1lc3BhY2UiOiJ0ZXN0IiwicG9kIjp7Im5hbWUiOiJ2YXVsdC0wIiwidWlkIjoiYTQwNGZiMTktNWQ4MC00OTBlLTkwYjktMGJjNWE3NzA5ODdkIn0sInNlcnZpY2VhY2NvdW50Ijp7Im5hbWUiOiJ2YXVsdCIsInVpZCI6ImI2ZTM2ZDMxLTA2MDQtNDE5MS04Y2JjLTAwYzg4ZWViZDlmOSJ9LCJ3YXJuYWZ0ZXIiOjE2NDkzNTcyNTV9LCJuYmYiOjE2NDkzNTM2NDgsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDp0ZXN0OnZhdWx0In0.hxzMpKx38rKvaWUBNEg49TioRXt_JT1Z5st4A9NeBWO2xiC8hCDgVJRWqPzejz-sYoQGhZyZcrTa0cbNRIevcR7XH4DnHd27OOzSoj198I2DAdLfw_pntzOjq35-tZhxSYXsfKH69DSpHACpu5HHUAf1aiY3B6cq5Z3gXbtaoHBocfNwvtOirGL8pTYXo1kNCkcahDPfpf3faztyUQ77v0viBKIAqwxDuGks4crqIG5jT_tOnXbb7PahwtE5cS3bMLjQb1j5oEcgq6HF4NMV46Ly479QRoXtYWWsI9OSwl4H7G9Rel3fr9q4IMdCCI5A-FLxL2Fpep9TDwrNQ3mhBQ"

func TestAudienceValidation(t *testing.T) {
	jwtWithDefaultAud := createToken(t, "vault", nil)
	jwtWithAudA := createToken(t, "vault", []string{"a"})
	jwtWithAudB := createToken(t, "vault", []string{"b"})

	for name, tc := range map[string]struct {
		audienceConfig string
		jwt            string
		expectSuccess  bool
	}{
		"config: default, JWT: default": {"https://kubernetes.default.svc.cluster.local", jwtWithDefaultAud, true},
		"config: default, JWT: a":       {"https://kubernetes.default.svc.cluster.local", jwtWithAudA, false},
		"config: a, JWT: a":             {"a", jwtWithAudA, true},
		"config: a, JWT: b":             {"a", jwtWithAudB, false},
		"config: unset, JWT: default":   {"", jwtWithDefaultAud, true},
		"config: unset, JWT: a":         {"", jwtWithAudA, true},
	} {
		t.Run(name, func(t *testing.T) {
			roleConfig := map[string]interface{}{
				"bound_service_account_names":      "vault",
				"bound_service_account_namespaces": "test",
			}
			if tc.audienceConfig != "" {
				roleConfig["audience"] = tc.audienceConfig
			}
			client, cleanup := setupKubernetesAuth(t, "vault", nil, roleConfig)
			defer cleanup()

			login := func(jwt string) error {
				_, err := client.Logical().Write("auth/kubernetes/login", map[string]interface{}{
					"role": "test-role",
					"jwt":  jwt,
				})
				return err
			}

			err := login(tc.jwt)
			if err != nil {
				if tc.expectSuccess {
					t.Fatal("Expected successful login", err)
				} else {
					respErr, ok := err.(*api.ResponseError)
					if !ok {
						t.Fatalf("Expected api.ResponseError but was: %T", err)
					}
					if respErr.StatusCode != http.StatusForbidden {
						t.Fatalf("Expected 403 but was %d: %s", respErr.StatusCode, respErr.Error())
					}
				}
			} else if !tc.expectSuccess {
				t.Fatal("Expected error but successfully logged in")
			}
		})
	}
}
