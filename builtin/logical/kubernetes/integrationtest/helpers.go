// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package integrationtest

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"testing"
	"time"

	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8s_yaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

var standardLabels = map[string]string{
	"app.kubernetes.io/managed-by": "HashiCorp-Vault",
	"app.kubernetes.io/created-by": "vault-plugin-secrets-kubernetes",
}

func randomWithPrefix(name string) string {
	return fmt.Sprintf("%s-%d", name, rand.New(rand.NewSource(time.Now().UnixNano())).Int())
}

func newK8sClient(t *testing.T, token string) kubernetes.Interface {
	t.Helper()
	config := rest.Config{
		Host:        os.Getenv("KUBE_HOST"),
		BearerToken: token,
	}
	config.TLSClientConfig.CAData = append(config.TLSClientConfig.CAData, []byte(os.Getenv("KUBERNETES_CA"))...)

	client, err := kubernetes.NewForConfig(&config)
	if err != nil {
		t.Fatalf("error creating k8s client: %s", err)
	}
	return client
}

// Verify a creds response with a generated service account
func verifyCredsResponseGenerated(t *testing.T, result *api.Secret, namespace string, leaseDuration int, name string) {
	t.Helper()
	assert.Equal(t, leaseDuration, result.LeaseDuration)
	assert.Equal(t, false, result.Renewable)
	assert.Contains(t, result.Data["service_account_name"], name)
	assert.Equal(t, namespace, result.Data["service_account_namespace"])
}

// Verify a creds response with an existing service account
func verifyCredsResponse(t *testing.T, result *api.Secret, namespace, serviceAccount string, leaseDuration int) {
	t.Helper()
	assert.Equal(t, leaseDuration, result.LeaseDuration)
	assert.Equal(t, false, result.Renewable)
	assert.Equal(t, serviceAccount, result.Data["service_account_name"])
	assert.Equal(t, namespace, result.Data["service_account_namespace"])
}

// If it's a token that's bound to a Role, test listing pods in the response's
// namespace, and other namespaces should be denied
func testRoleBindingToken(t *testing.T, credsResponse *api.Secret) {
	t.Helper()
	token := credsResponse.Data["service_account_token"].(string)
	namespace := credsResponse.Data["service_account_namespace"].(string)
	serviceAccountName := credsResponse.Data["service_account_name"].(string)
	canListPods, err := tryListPods(t, namespace, token, 1)
	assert.NoError(t, err)
	assert.True(t, canListPods)

	canListPods, err = tryListPods(t, "default", token, 0)
	assert.Errorf(t, err, `pods is forbidden: User "system:serviceaccount:test:%s" cannot list resource "pods" in API group "" in the namespace "default"`, serviceAccountName)
	assert.False(t, canListPods)
}

func testTokenRevoked(t *testing.T, credsResponse *api.Secret) {
	t.Helper()
	token := credsResponse.Data["service_account_token"].(string)
	namespace := credsResponse.Data["service_account_namespace"].(string)
	serviceAccountName := credsResponse.Data["service_account_name"].(string)

	listPods, err := tryListPods(t, namespace, token, 1)
	assert.Errorf(t, err, `pods is forbidden: User "system:serviceaccount:test:%s" cannot list resource "pods" in API group "" in the namespace "%s"`, serviceAccountName, namespace)
	assert.False(t, listPods)
}

// For a token bound to a ClusterRole, test listing pods in the response's
// namespace, and other resource types should be denied
func testClusterRoleBindingToken(t *testing.T, credsResponse *api.Secret) {
	t.Helper()
	token := credsResponse.Data["service_account_token"].(string)
	namespace := credsResponse.Data["service_account_namespace"].(string)
	serviceAccountName := credsResponse.Data["service_account_name"].(string)
	canListPods, err := tryListPods(t, namespace, token, 1)
	assert.NoError(t, err)
	assert.True(t, canListPods)

	canListPods, err = tryListPods(t, "default", token, 0)
	assert.NoError(t, err)
	assert.True(t, canListPods)

	canListDeployments, err := tryListDeployments(t, "default", token)
	assert.Errorf(t, err, `pods is forbidden: User "system:serviceaccount:test:%s" cannot list resource "pods" in API group "" in the namespace "default"`, serviceAccountName)
	assert.False(t, canListDeployments)
}

func verifyRole(t *testing.T, roleConfig map[string]interface{}, credsResponse *api.Secret) {
	t.Helper()

	// All the created kubernetes objects have the same name, so the
	// service_account_name that is return from creds/ is the same as the Role
	// or ClusterRole
	roleName := credsResponse.Data["service_account_name"].(string)
	roleType := strings.ToLower(roleConfig["kubernetes_role_type"].(string))

	expectedLabels := makeExpectedLabels(t, roleConfig["extra_labels"].(map[string]interface{}))
	expectedAnnotations := asMapString(roleConfig["extra_annotations"].(map[string]interface{}))
	expectedRules := makeRules(t, roleConfig["generated_role_rules"].(string))

	var returnedLabels map[string]string
	var returnedAnnotations map[string]string
	var returnedRules []rbacv1.PolicyRule

	k8sClient := newK8sClient(t, os.Getenv("SUPER_JWT"))
	if roleType == "role" {
		role, err := k8sClient.RbacV1().Roles("test").Get(context.Background(), roleName, metav1.
			GetOptions{})
		require.NoError(t, err)
		returnedLabels = role.Labels
		returnedAnnotations = role.Annotations
		returnedRules = role.Rules
	} else {
		clusterRole, err := k8sClient.RbacV1().ClusterRoles().Get(context.Background(), roleName, metav1.GetOptions{})
		require.NoError(t, err)
		returnedLabels = clusterRole.Labels
		returnedAnnotations = clusterRole.Annotations
		returnedRules = clusterRole.Rules
	}
	assert.Equal(t, expectedLabels, returnedLabels)
	assert.Equal(t, expectedAnnotations, returnedAnnotations)
	assert.Equal(t, expectedRules, returnedRules)
}

func verifyBinding(t *testing.T, roleConfig map[string]interface{}, credsResponse *api.Secret, isClusterBinding bool) {
	t.Helper()

	// All the created kubernetes objects have the same name, so the
	// service_account_name that is return from creds/ is the same as the Role
	// or ClusterRole
	objName := credsResponse.Data["service_account_name"].(string)

	expectedLabels := makeExpectedLabels(t, roleConfig["extra_labels"].(map[string]interface{}))
	expectedAnnotations := asMapString(roleConfig["extra_annotations"].(map[string]interface{}))
	expectedSubjects := []rbacv1.Subject{
		{
			Kind:      "ServiceAccount",
			Name:      objName,
			Namespace: "test",
		},
	}

	var returnedLabels map[string]string
	var returnedAnnotations map[string]string
	var returnedSubjects []rbacv1.Subject

	k8sClient := newK8sClient(t, os.Getenv("SUPER_JWT"))
	if isClusterBinding {
		clusterBinding, err := k8sClient.RbacV1().ClusterRoleBindings().Get(context.Background(), objName, metav1.GetOptions{})
		require.NoError(t, err)
		returnedLabels = clusterBinding.Labels
		returnedAnnotations = clusterBinding.Annotations
		returnedSubjects = clusterBinding.Subjects
	} else {
		binding, err := k8sClient.RbacV1().RoleBindings("test").Get(context.Background(), objName, metav1.GetOptions{})
		require.NoError(t, err)
		returnedLabels = binding.Labels
		returnedAnnotations = binding.Annotations
		returnedSubjects = binding.Subjects
	}
	assert.Equal(t, expectedLabels, returnedLabels)
	assert.Equal(t, expectedAnnotations, returnedAnnotations)
	assert.Equal(t, expectedSubjects, returnedSubjects)
}

func verifyServiceAccount(t *testing.T, roleConfig map[string]interface{}, credsResponse *api.Secret) {
	t.Helper()

	// All the created kubernetes objects have the same name, so the
	// service_account_name that is return from creds/ is the same as the Role
	// or ClusterRole
	objName := credsResponse.Data["service_account_name"].(string)

	expectedLabels := makeExpectedLabels(t, roleConfig["extra_labels"].(map[string]interface{}))
	expectedAnnotations := asMapString(roleConfig["extra_annotations"].(map[string]interface{}))

	k8sClient := newK8sClient(t, os.Getenv("SUPER_JWT"))
	acct, err := k8sClient.CoreV1().ServiceAccounts("test").Get(context.Background(), objName, metav1.GetOptions{})
	require.NoError(t, err)
	returnedLabels := acct.Labels
	returnedAnnotations := acct.Annotations

	assert.Equal(t, expectedLabels, returnedLabels)
	assert.Equal(t, expectedAnnotations, returnedAnnotations)
}

func tryListPods(t *testing.T, namespace, token string, count int) (bool, error) {
	k8sClient := newK8sClient(t, token)
	podsList, err := k8sClient.CoreV1().
		Pods(namespace).
		List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return false, err
	}
	if len(podsList.Items) != count {
		return false, fmt.Errorf("expected %d pod(s) in list, not %d", count, len(podsList.Items))
	}

	return true, nil
}

func tryListDeployments(t *testing.T, namespace, token string) (bool, error) {
	k8sClient := newK8sClient(t, token)
	podsList, err := k8sClient.AppsV1().
		Deployments(namespace).
		List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return false, err
	}
	if len(podsList.Items) != 1 {
		return false, fmt.Errorf("expected one pod in list, not %d", len(podsList.Items))
	}

	return true, nil
}

func testRoleType(t *testing.T, client *api.Client, mountPath string, roleConfig, expectedRoleResponse map[string]interface{}) {
	t.Helper()

	_, err := client.Logical().Write(mountPath+"/roles/testrole", roleConfig)
	require.NoError(t, err)

	roleResult, err := client.Logical().Read(mountPath + "/roles/testrole")
	assert.NoError(t, err)
	assert.Equal(t, expectedRoleResponse, roleResult.Data)

	result1, err := client.Logical().Write(mountPath+"/creds/testrole", map[string]interface{}{
		"kubernetes_namespace": "test",
		"cluster_role_binding": false,
		"ttl":                  "2h",
	})
	require.NoError(t, err)
	require.NotNil(t, result1)

	expectedName := "v-token-"
	if nt, ok := roleConfig["name_template"]; ok && nt != "" {
		expectedName = "v-custom-name-"
	}
	verifyCredsResponseGenerated(t, result1, "test", 7200, expectedName)

	// Check the k8s objects that should've been created
	if grr, ok := roleConfig["generated_role_rules"]; ok && grr.(string) != "" {
		verifyRole(t, expectedRoleResponse, result1)
	}
	verifyBinding(t, expectedRoleResponse, result1, false)
	verifyServiceAccount(t, expectedRoleResponse, result1)

	// Try using the generated token. Listing pods should be allowed in the
	// 'test' namespace, but nowhere else.
	testRoleBindingToken(t, result1)

	leases, err := client.Logical().List("sys/leases/lookup/" + mountPath + "/creds/testrole/")
	assert.NoError(t, err)
	assert.Len(t, leases.Data["keys"], 1)

	// Clean up the lease
	err = client.Sys().RevokePrefix(mountPath + "/creds/testrole")
	assert.NoError(t, err)

	noLeases, err := client.Logical().List("sys/leases/lookup/" + mountPath + "/creds/testrole/")
	assert.NoError(t, err)
	assert.Empty(t, noLeases)

	testTokenRevoked(t, result1)

	// Test ClusterRoleBinding
	// This should fail since k8s doesn't allow a ClusterRoleBinding with a Role
	result2, err := client.Logical().Write(mountPath+"/creds/testrole", map[string]interface{}{
		"kubernetes_namespace": "test",
		"cluster_role_binding": true,
		"ttl":                  "2h",
	})
	assert.Error(t, err, "a ClusterRoleBinding cannot ref a Role")
	assert.Nil(t, result2)

	// Finally, delete the role
	_, err = client.Logical().Delete(mountPath + "/roles/testrole")
	assert.NoError(t, err)

	result, err := client.Logical().Read(mountPath + "/roles/testrole")
	assert.NoError(t, err)
	assert.Nil(t, result)
}

func testClusterRoleType(t *testing.T, client *api.Client, mountPath string, roleConfig, expectedRoleResponse map[string]interface{}) {
	t.Helper()

	_, err := client.Logical().Write(mountPath+"/roles/clusterrole", roleConfig)
	require.NoError(t, err)

	roleResult, err := client.Logical().Read(mountPath + "/roles/clusterrole")
	assert.NoError(t, err)
	assert.Equal(t, expectedRoleResponse, roleResult.Data)

	// Generate creds with a RoleBinding
	result1, err := client.Logical().Write(mountPath+"/creds/clusterrole", map[string]interface{}{
		"kubernetes_namespace": "test",
		"cluster_role_binding": false,
		"ttl":                  "2h",
	})
	assert.NoError(t, err)
	verifyCredsResponseGenerated(t, result1, "test", 7200, "v-token-")

	if grr, ok := roleConfig["generated_role_rules"]; ok && grr.(string) != "" {
		verifyRole(t, expectedRoleResponse, result1)
	}
	verifyBinding(t, expectedRoleResponse, result1, false)
	verifyServiceAccount(t, expectedRoleResponse, result1)

	// Try using the generated token. Listing pods should be allowed in the
	// 'test' namespace, but nowhere else.
	testRoleBindingToken(t, result1)

	// Generate creds with a ClusterRoleBinding
	result2, err := client.Logical().Write(mountPath+"/creds/clusterrole", map[string]interface{}{
		"kubernetes_namespace": "test",
		"cluster_role_binding": true,
		"ttl":                  "2h",
	})
	assert.NoError(t, err)
	verifyCredsResponseGenerated(t, result2, "test", 7200, "v-token-")

	if grr, ok := roleConfig["generated_role_rules"]; ok && grr.(string) != "" {
		verifyRole(t, expectedRoleResponse, result2)
	}
	verifyBinding(t, expectedRoleResponse, result2, true)
	verifyServiceAccount(t, expectedRoleResponse, result2)

	// Try the generated token, listing pods should work in any namespace,
	// but listing deployments should be denied
	testClusterRoleBindingToken(t, result2)

	leases, err := client.Logical().List("sys/leases/lookup/" + mountPath + "/creds/clusterrole/")
	assert.NoError(t, err)
	assert.Len(t, leases.Data["keys"], 2)

	// Clean up leases and delete the role
	err = client.Sys().RevokePrefix(mountPath + "/creds/clusterrole")
	assert.NoError(t, err)

	noLeases, err := client.Logical().List("sys/leases/lookup/" + mountPath + "/creds/clusterrole/")
	assert.NoError(t, err)
	assert.Empty(t, noLeases)

	testTokenRevoked(t, result1)
	testTokenRevoked(t, result2)

	_, err = client.Logical().Delete(mountPath + "/roles/clusterrole")
	assert.NoError(t, err)

	result, err := client.Logical().Read(mountPath + "/roles/clusterrole")
	assert.NoError(t, err)
	assert.Nil(t, result)
}

func testK8sTokenTTL(t *testing.T, expectedSec int, token string) {
	parsed, err := josejwt.ParseSigned(token, consts.AllowedJWTSignatureAlgorithmsK8s)
	require.NoError(t, err)
	claims := map[string]interface{}{}
	err = parsed.UnsafeClaimsWithoutVerification(&claims)
	require.NoError(t, err)
	iat := claims["iat"].(float64)
	exp := claims["exp"].(float64)
	assert.Equal(t, expectedSec, int(exp-iat))
}

func testK8sTokenAudiences(t *testing.T, expectedAudiences []interface{}, token string) {
	parsed, err := josejwt.ParseSigned(token, consts.AllowedJWTSignatureAlgorithmsK8s)
	require.NoError(t, err)
	claims := map[string]interface{}{}
	err = parsed.UnsafeClaimsWithoutVerification(&claims)
	require.NoError(t, err)
	aud := claims["aud"].([]interface{})
	assert.ElementsMatch(t, expectedAudiences, aud)
}

func combineMaps(maps ...map[string]string) map[string]string {
	newMap := make(map[string]string)
	for _, m := range maps {
		for k, v := range m {
			newMap[k] = v
		}
	}
	return newMap
}

func makeRules(t *testing.T, rules string) []rbacv1.PolicyRule {
	t.Helper()

	policyRules := struct {
		Rules []rbacv1.PolicyRule `json:"rules"`
	}{}
	decoder := k8s_yaml.NewYAMLOrJSONDecoder(strings.NewReader(rules), len(rules))
	err := decoder.Decode(&policyRules)
	require.NoError(t, err)
	return policyRules.Rules
}

func makeExpectedLabels(t *testing.T, extraLabels map[string]interface{}) map[string]string {
	t.Helper()

	var expectedLabels map[string]string
	if extraLabels != nil {
		expectedLabels = combineMaps(asMapString(extraLabels), standardLabels)
	} else {
		expectedLabels = standardLabels
	}
	return expectedLabels
}

func asMapInterface(m map[string]string) map[string]interface{} {
	result := map[string]interface{}{}
	for k, v := range m {
		result[k] = v
	}

	return result
}

func asMapString(m map[string]interface{}) map[string]string {
	result := map[string]string{}
	for k, v := range m {
		result[k] = v.(string)
	}

	return result
}
