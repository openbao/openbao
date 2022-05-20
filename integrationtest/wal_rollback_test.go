package integrationtest

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v3"
	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
)

func TestCreds_wal_rollback(t *testing.T) {
	if _, ok := os.LookupEnv("SKIP_WAL_TEST"); ok {
		t.Skip("Skipping WAL rollback test")
	}

	// Pick up VAULT_ADDR and VAULT_TOKEN from env vars
	client, err := api.NewClient(nil)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("generated_role_rules (takes 10 minutes)", func(t *testing.T) {
		t.Parallel()
		mountPath, umount := mountHelper(t, client)
		defer umount()

		// create default config
		_, err = client.Logical().Write(mountPath+"/config", map[string]interface{}{
			"service_account_jwt": os.Getenv("BROKEN_JWT"),
		})
		require.NoError(t, err)

		roleRulesYAML := `rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["list"]`

		metadata := map[string]interface{}{
			"labels": map[string]interface{}{
				"environment": "testing",
				"test":        "wal_rollback",
				"type":        "role",
			},
			"annotations": map[string]interface{}{
				"tested": "today",
			},
		}
		roleConfig := map[string]interface{}{
			"additional_metadata":           metadata,
			"allowed_kubernetes_namespaces": []string{"test"},
			"generated_role_rules":          roleRulesYAML,
			"kubernetes_role_type":          "RolE",
			"token_default_ttl":             "1h",
			"token_max_ttl":                 "24h",
		}
		expectedRoleResponse := map[string]interface{}{
			"additional_metadata":           metadata,
			"allowed_kubernetes_namespaces": []interface{}{"test"},
			"generated_role_rules":          roleRulesYAML,
			"kubernetes_role_name":          "",
			"kubernetes_role_type":          "Role",
			"name":                          "walrole",
			"name_template":                 "",
			"service_account_name":          "",
			"token_max_ttl":                 oneDay,
			"token_default_ttl":             oneHour,
		}

		_, err := client.Logical().Write(mountPath+"/roles/walrole", roleConfig)
		require.NoError(t, err)

		roleResult, err := client.Logical().Read(mountPath + "/roles/walrole")
		assert.NoError(t, err)
		assert.Equal(t, expectedRoleResponse, roleResult.Data)

		// This will fail because it can't create a ServiceAccount. Wait for the
		// WALRollbackMinAge, then verify that the objects aren't around by
		// using the additional metadata.labels that were passed in.
		credsResponse, err := client.Logical().Write(mountPath+"/creds/walrole", map[string]interface{}{
			"kubernetes_namespace": "test",
			"cluster_role_binding": false,
			"ttl":                  "2h",
		})
		assert.Error(t, err)
		assert.Nil(t, credsResponse)
		assert.Contains(t, err.Error(), `User "system:serviceaccount:test:broken-jwt" cannot create resource "serviceaccounts" in API group "" in the namespace "test"`)

		checkObjects(t, roleConfig, false, true, 30*time.Second)

		// The backend's WAL min age is 10 minutes. After that the k8s objects
		// should be cleaned up.
		checkObjects(t, roleConfig, false, false, 15*time.Minute)
	})

	t.Run("kubernetes_role_name (takes 10 minutes)", func(t *testing.T) {
		t.Parallel()
		mountPath, umount := mountHelper(t, client)
		defer umount()

		// create default config
		_, err = client.Logical().Write(mountPath+"/config", map[string]interface{}{
			"service_account_jwt": os.Getenv("BROKEN_JWT"),
		})
		require.NoError(t, err)

		metadata := map[string]interface{}{
			"labels": map[string]interface{}{
				"environment": "staging",
				"test":        "wal_rollback",
				"type":        "clusterrolebinding",
			},
			"annotations": map[string]interface{}{
				"tested":  "tomorrow",
				"checked": "again",
			},
		}
		roleConfig := map[string]interface{}{
			"additional_metadata":           metadata,
			"allowed_kubernetes_namespaces": []string{"test"},
			"kubernetes_role_name":          "test-cluster-role-list-pods",
			"kubernetes_role_type":          "ClusterRole",
			"token_default_ttl":             "1h",
			"token_max_ttl":                 "24h",
		}
		expectedRoleResponse := map[string]interface{}{
			"additional_metadata":           metadata,
			"allowed_kubernetes_namespaces": []interface{}{"test"},
			"generated_role_rules":          "",
			"kubernetes_role_name":          "test-cluster-role-list-pods",
			"kubernetes_role_type":          "ClusterRole",
			"name":                          "walrolebinding",
			"name_template":                 "",
			"service_account_name":          "",
			"token_max_ttl":                 oneDay,
			"token_default_ttl":             oneHour,
		}

		_, err := client.Logical().Write(mountPath+"/roles/walrolebinding", roleConfig)
		require.NoError(t, err)

		roleResult, err := client.Logical().Read(mountPath + "/roles/walrolebinding")
		assert.NoError(t, err)
		assert.Equal(t, expectedRoleResponse, roleResult.Data)

		// This will fail because it can't create a ServiceAccount. Wait for the
		// WALRollbackMinAge, then verify that the objects aren't around by
		// using the additional metadata.labels that were passed in.
		credsResponse, err := client.Logical().Write(mountPath+"/creds/walrolebinding", map[string]interface{}{
			"kubernetes_namespace": "test",
			"cluster_role_binding": true,
			"ttl":                  "2h",
		})
		assert.Error(t, err)
		assert.Nil(t, credsResponse)
		assert.Contains(t, err.Error(), `User "system:serviceaccount:test:broken-jwt" cannot create resource "serviceaccounts" in API group "" in the namespace "test"`)

		checkObjects(t, roleConfig, true, true, 30*time.Second)

		// The backend's WAL min age is 10 minutes. After that the k8s objects
		// should be cleaned up.
		checkObjects(t, roleConfig, true, false, 15*time.Minute)
	})
}

func checkObjects(t *testing.T, roleConfig map[string]interface{}, isClusterBinding bool, shouldExist bool, maxWaitTime time.Duration) {
	t.Helper()

	k8sClient := newK8sClient(t, os.Getenv("SUPER_JWT"))
	roleType := strings.ToLower(roleConfig["kubernetes_role_type"].(string))
	existingRole := ""
	if value, ok := roleConfig["kubernetes_role_name"]; ok {
		existingRole = value.(string)
	}

	// Query by labels since we may not know the name
	l := makeExpectedLabels(t, roleConfig["additional_metadata"].(map[string]interface{}))
	validatedSelector, err := labels.ValidatedSelectorFromSet(l)
	require.NoError(t, err)
	listOptions := metav1.ListOptions{
		LabelSelector: validatedSelector.String(),
	}

	// Check the k8s objects that should have been created (all but the ServiceAccount)
	operation := func() error {
		if existingRole == "" {
			exists, err := checkRoleExists(k8sClient, listOptions, roleType)
			require.NoError(t, err)
			if exists != shouldExist {
				return fmt.Errorf("%s exists (%v) but should be (%v)", roleType, exists, shouldExist)
			}
		}

		exists, err := checkRoleBindingExists(k8sClient, listOptions, isClusterBinding)
		require.NoError(t, err)
		if exists != shouldExist {
			return fmt.Errorf("binding (cluster %v) exists (%v) but should be (%v)", isClusterBinding, exists, shouldExist)
		}
		return nil
	}
	bo := backoff.NewExponentialBackOff()
	bo.MaxElapsedTime = maxWaitTime

	err = backoff.Retry(operation, bo)
	assert.NoError(t, err, "timed out waiting for objects to exist=%v", shouldExist)
}

func verifyObjectsDeleted(t *testing.T, roleConfig map[string]interface{}, isClusterBinding bool) {
	t.Helper()

	k8sClient := newK8sClient(t, os.Getenv("SUPER_JWT"))
	roleType := strings.ToLower(roleConfig["kubernetes_role_type"].(string))

	// Query by labels since we may not know the name
	l := makeExpectedLabels(t, roleConfig["additional_metadata"].(map[string]interface{}))
	validatedSelector, err := labels.ValidatedSelectorFromSet(l)
	require.NoError(t, err)
	listOptions := metav1.ListOptions{
		LabelSelector: validatedSelector.String(),
	}

	// Check the k8s objects that should be cleaned up

	exists, err := checkRoleExists(k8sClient, listOptions, roleType)
	require.NoError(t, err)
	assert.False(t, exists)
	exists, err = checkRoleBindingExists(k8sClient, listOptions, isClusterBinding)
	require.NoError(t, err)
	assert.False(t, exists)
	exists, err = checkServiceAccountExists(k8sClient, listOptions)
	require.NoError(t, err)
	assert.False(t, exists)
}

func checkRoleExists(k8sClient kubernetes.Interface, listOptions metav1.ListOptions, roleType string) (bool, error) {
	switch roleType {
	case "role":
		roles, err := k8sClient.RbacV1().Roles("test").List(context.Background(), listOptions)
		if err != nil {
			return false, err
		}
		if roles == nil {
			return false, fmt.Errorf("roles list response was nil")
		}
		return len(roles.Items) > 0, nil
	case "clusterrole":
		roles, err := k8sClient.RbacV1().ClusterRoles().List(context.Background(), listOptions)
		if err != nil {
			return false, err
		}
		if roles == nil {
			return false, fmt.Errorf("cluster roles list response was nil")
		}
		return len(roles.Items) > 0, nil
	}

	return false, fmt.Errorf("unknown roleType: %s", roleType)
}

func checkRoleBindingExists(k8sClient kubernetes.Interface, listOptions metav1.ListOptions, isClusterBinding bool) (bool, error) {
	if isClusterBinding {
		clusterBindings, err := k8sClient.RbacV1().ClusterRoleBindings().List(context.Background(), listOptions)
		if err != nil {
			return false, err
		}
		if clusterBindings == nil {
			return false, fmt.Errorf("cluster role bindings list response was nil")
		}
		return len(clusterBindings.Items) > 0, nil
	} else {
		bindings, err := k8sClient.RbacV1().RoleBindings("test").List(context.Background(), listOptions)
		if err != nil {
			return false, err
		}
		if bindings == nil {
			return false, fmt.Errorf("role bindings list response was nil")
		}
		return len(bindings.Items) > 0, nil
	}
}

func checkServiceAccountExists(k8sClient kubernetes.Interface, listOptions metav1.ListOptions) (bool, error) {
	acct, err := k8sClient.CoreV1().ServiceAccounts("test").List(context.Background(), listOptions)
	if err != nil {
		return false, err
	}
	if acct == nil {
		return false, fmt.Errorf("service account list response was nil")
	}
	return len(acct.Items) > 0, nil
}
