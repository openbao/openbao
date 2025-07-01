// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mockPolicyWithCore(t *testing.T, disableCache bool) (*Core, [][]byte, string, *PolicyStore) {
	conf := &CoreConfig{
		DisableCache: disableCache,
	}
	core, shares, token := TestCoreUnsealedWithConfig(t, conf)
	ps := core.policyStore

	return core, shares, token, ps
}

func TestPolicyStore_Root(t *testing.T) {
	t.Run("root", func(t *testing.T) {
		t.Parallel()

		core, _, _ := TestCoreUnsealed(t)
		ps := core.policyStore
		testPolicyRoot(t, ps, namespace.RootNamespace, true)
	})
}

func testPolicyRoot(t *testing.T, ps *PolicyStore, ns *namespace.Namespace, expectFound bool) {
	// Get should return a special policy
	ctx := namespace.ContextWithNamespace(context.Background(), ns)
	p, err := ps.GetPolicy(ctx, "root", PolicyTypeToken)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// Handle whether a root token is expected
	if expectFound {
		if p == nil {
			t.Fatalf("bad: %v", p)
		}
		if p.Name != "root" {
			t.Fatalf("bad: %v", p)
		}
	} else {
		if p != nil {
			t.Fatal("expected nil root policy")
		}
		// Create root policy for subsequent modification and deletion failure
		// tests
		p = &Policy{
			Name: "root",
		}
	}

	// Set should fail
	ctx = namespace.ContextWithNamespace(context.Background(), ns)
	err = ps.SetPolicy(ctx, p, nil)
	if err.Error() != `cannot update "root" policy` {
		t.Fatalf("err: %v", err)
	}

	// Delete should fail
	ctx = namespace.ContextWithNamespace(context.Background(), ns)
	err = ps.DeletePolicy(ctx, "root", PolicyTypeACL)
	if err.Error() != `cannot delete "root" policy` {
		t.Fatalf("err: %v", err)
	}
}

func TestPolicyStore_CRUD(t *testing.T) {
	t.Run("root-ns", func(t *testing.T) {
		t.Run("cached", func(t *testing.T) {
			core, shares, token, ps := mockPolicyWithCore(t, false)
			testPolicyStoreCRUD(t, core, shares, token, ps, namespace.RootNamespace)
		})

		t.Run("no-cache", func(t *testing.T) {
			core, shares, token, ps := mockPolicyWithCore(t, true)
			testPolicyStoreCRUD(t, core, shares, token, ps, namespace.RootNamespace)
		})
	})
}

func testPolicyStoreCRUD(t *testing.T, core *Core, shares [][]byte, token string, ps *PolicyStore, ns *namespace.Namespace) {
	testPolicyStoreCRUDOneShot(t, ps, ns)

	// Seal, unseal, and try again.
	require.NoError(t, core.Seal(token), "failed to seal")
	for _, share := range shares {
		finished, err := TestCoreUnseal(core, share)
		if finished {
			break
		}

		require.NoError(t, err)
	}

	testPolicyStoreCRUDOneShot(t, ps, ns)
}

func testPolicyStoreCRUDOneShot(t *testing.T, ps *PolicyStore, ns *namespace.Namespace) {
	// Get should return nothing
	ctx := namespace.ContextWithNamespace(context.Background(), ns)
	p, err := ps.GetPolicy(ctx, "Dev", PolicyTypeToken)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if p != nil {
		t.Fatalf("bad: %v", p)
	}

	// Delete should be no-op
	ctx = namespace.ContextWithNamespace(context.Background(), ns)
	err = ps.DeletePolicy(ctx, "deV", PolicyTypeACL)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// List should be blank
	ctx = namespace.ContextWithNamespace(context.Background(), ns)
	out, err := ps.ListPolicies(ctx, PolicyTypeACL, true)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("bad: %v", out)
	}

	// Set should work
	ctx = namespace.ContextWithNamespace(context.Background(), ns)
	policy, _ := ParseACLPolicy(ns, aclPolicy)
	err = ps.SetPolicy(ctx, policy, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// Get should work
	ctx = namespace.ContextWithNamespace(context.Background(), ns)
	p, err = ps.GetPolicy(ctx, "dEv", PolicyTypeToken)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !reflect.DeepEqual(p, policy) {
		t.Fatalf("bad: %v", p)
	}

	// List should contain two elements
	ctx = namespace.ContextWithNamespace(context.Background(), ns)
	out, err = ps.ListPolicies(ctx, PolicyTypeACL, true)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("bad: %v", out)
	}

	expected := []string{"default", "dev"}
	if !reflect.DeepEqual(expected, out) {
		t.Fatalf("expected: %v\ngot: %v", expected, out)
	}

	// Delete should be clear the entry
	ctx = namespace.ContextWithNamespace(context.Background(), ns)
	err = ps.DeletePolicy(ctx, "Dev", PolicyTypeACL)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// List should contain one element
	ctx = namespace.ContextWithNamespace(context.Background(), ns)
	out, err = ps.ListPolicies(ctx, PolicyTypeACL, true)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(out) != 1 || out[0] != "default" {
		t.Fatalf("bad: %v", out)
	}

	// Get should fail
	ctx = namespace.ContextWithNamespace(context.Background(), ns)
	p, err = ps.GetPolicy(ctx, "deV", PolicyTypeToken)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if p != nil {
		t.Fatalf("bad: %v", p)
	}
}

func TestPolicyStore_Predefined(t *testing.T) {
	t.Run("root-ns", func(t *testing.T) {
		_, _, _, ps := mockPolicyWithCore(t, false)
		testPolicyStorePredefined(t, ps, namespace.RootNamespace)
	})
}

// Test predefined policy handling
func testPolicyStorePredefined(t *testing.T, ps *PolicyStore, ns *namespace.Namespace) {
	// List should be two elements
	ctx := namespace.ContextWithNamespace(context.Background(), ns)
	out, err := ps.ListPolicies(ctx, PolicyTypeACL, true)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	// This shouldn't contain response-wrapping since it's non-assignable
	if len(out) != 1 || out[0] != "default" {
		t.Fatalf("bad: %v", out)
	}

	// Response-wrapping policy checks
	ctx = namespace.ContextWithNamespace(context.Background(), ns)
	pCubby, err := ps.GetPolicy(ctx, "response-wrapping", PolicyTypeToken)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if pCubby == nil {
		t.Fatal("nil cubby policy")
	}
	if pCubby.Raw != responseWrappingPolicy {
		t.Fatalf("bad: expected\n%s\ngot\n%s\n", responseWrappingPolicy, pCubby.Raw)
	}
	ctx = namespace.ContextWithNamespace(context.Background(), ns)
	err = ps.SetPolicy(ctx, pCubby, nil)
	if err == nil {
		t.Fatalf("expected err setting %s", pCubby.Name)
	}
	ctx = namespace.ContextWithNamespace(context.Background(), ns)
	err = ps.DeletePolicy(ctx, pCubby.Name, PolicyTypeACL)
	if err == nil {
		t.Fatalf("expected err deleting %s", pCubby.Name)
	}

	// Root policy checks, behavior depending on namespace
	ctx = namespace.ContextWithNamespace(context.Background(), ns)
	pRoot, err := ps.GetPolicy(ctx, "root", PolicyTypeToken)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if ns.ID == namespace.RootNamespaceID {
		if pRoot == nil {
			t.Fatal("nil root policy")
		}
	} else {
		if pRoot != nil {
			t.Fatal("expected nil root policy")
		}
		pRoot = &Policy{
			Name: "root",
		}
	}
	ctx = namespace.ContextWithNamespace(context.Background(), ns)
	err = ps.SetPolicy(ctx, pRoot, nil)
	if err == nil {
		t.Fatalf("expected err setting %s", pRoot.Name)
	}
	ctx = namespace.ContextWithNamespace(context.Background(), ns)
	err = ps.DeletePolicy(ctx, pRoot.Name, PolicyTypeACL)
	if err == nil {
		t.Fatalf("expected err deleting %s", pRoot.Name)
	}
}

func TestPolicyStore_ACL(t *testing.T) {
	t.Run("root-ns", func(t *testing.T) {
		_, _, _, ps := mockPolicyWithCore(t, false)
		testPolicyStoreACL(t, ps, namespace.RootNamespace)
	})
}

func testPolicyStoreACL(t *testing.T, ps *PolicyStore, ns *namespace.Namespace) {
	ctx := namespace.ContextWithNamespace(context.Background(), ns)
	policy, _ := ParseACLPolicy(ns, aclPolicy)
	err := ps.SetPolicy(ctx, policy, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	ctx = namespace.ContextWithNamespace(context.Background(), ns)
	policy, _ = ParseACLPolicy(ns, aclPolicy2)
	err = ps.SetPolicy(ctx, policy, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	ctx = namespace.ContextWithNamespace(context.Background(), ns)
	acl, err := ps.ACL(ctx, nil, map[string][]string{ns.ID: {"dev", "ops"}})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	testLayeredACL(t, acl, ns)
}

func TestDefaultPolicy(t *testing.T) {
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	policy, err := ParseACLPolicy(namespace.RootNamespace, defaultPolicy)
	if err != nil {
		t.Fatal(err)
	}
	acl, err := NewACL(ctx, []*Policy{policy})
	if err != nil {
		t.Fatal(err)
	}

	for name, tc := range map[string]struct {
		op            logical.Operation
		path          string
		expectAllowed bool
	}{
		"lookup self":            {logical.ReadOperation, "auth/token/lookup-self", true},
		"renew self":             {logical.UpdateOperation, "auth/token/renew-self", true},
		"revoke self":            {logical.UpdateOperation, "auth/token/revoke-self", true},
		"check own capabilities": {logical.UpdateOperation, "sys/capabilities-self", true},

		"read arbitrary path":     {logical.ReadOperation, "foo/bar", false},
		"login at arbitrary path": {logical.UpdateOperation, "auth/foo", false},
	} {
		t.Run(name, func(t *testing.T) {
			request := new(logical.Request)
			request.Operation = tc.op
			request.Path = tc.path

			result := acl.AllowOperation(ctx, request, false)
			if result.RootPrivs {
				t.Fatal("unexpected root")
			}
			if tc.expectAllowed != result.Allowed {
				t.Fatalf("Expected %v, got %v", tc.expectAllowed, result.Allowed)
			}
		})
	}
}

// TestPolicyStore_GetNonEGPPolicyType has two test cases:
//   - happy-acl: we store a policy in the policy type map and
//     then look up its type successfully.
//   - not-in-map-acl: ensure that GetNonEGPPolicyType fails
//     returning a nil and an error when the policy doesn't exist in the map.
func TestPolicyStore_GetNonEGPPolicyType(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		policyStoreKey       string
		policyStoreValue     any
		paramNamespace       string
		paramPolicyName      string
		paramPolicyType      PolicyType
		isErrorExpected      bool
		expectedErrorMessage string
	}{
		"happy-acl": {
			policyStoreKey:   "root/default",
			policyStoreValue: PolicyTypeACL,
			paramNamespace:   "root",
			paramPolicyName:  "default",
			paramPolicyType:  PolicyTypeACL,
		},
		"not-in-map-acl": {
			policyStoreKey:       "root/policy2",
			policyStoreValue:     PolicyTypeACL,
			paramNamespace:       "root",
			paramPolicyName:      "policy2",
			isErrorExpected:      true,
			expectedErrorMessage: "policy does not exist",
		},
	}

	for name, tc := range tests {
		name := name
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, _, _, ps := mockPolicyWithCore(t, false)
			ctx := namespace.RootContext(context.Background())
			got, err := ps.GetNonEGPPolicyType(ctx, tc.paramPolicyName)
			if tc.isErrorExpected {
				require.Error(t, err)
				require.Nil(t, got)
				require.EqualError(t, err, tc.expectedErrorMessage)

			}
			if !tc.isErrorExpected {
				require.NoError(t, err)
				require.NotNil(t, got)
				require.Equal(t, tc.paramPolicyType, *got)
			}
		})
	}
}

// TestPolicyStore_LoadACLPolicyNamespaces verifies that loadACLPolicyNamespaces
// correctly loads policies into the current namespace.
func TestPolicyStore_LoadACLPolicyNamespaces(t *testing.T) {
	core, _, token := TestCoreUnsealed(t)
	ctx := namespace.RootContext(context.Background())
	ps := core.policyStore

	// Create a namespace
	nsPath := "test-ns-load"
	resp, err := core.HandleRequest(ctx, &logical.Request{
		Operation:   logical.UpdateOperation,
		Path:        "sys/namespaces/" + nsPath,
		ClientToken: token,
	})
	require.NoError(t, err)
	require.False(t, resp.IsError())

	// Lookup the namespace
	ns, err := core.namespaceStore.GetNamespaceByPath(ctx, nsPath)
	require.NoError(t, err)
	require.NotNil(t, ns, "namespace not found: %s", nsPath)

	// Create namespace context
	nsCtx := namespace.ContextWithNamespace(ctx, ns)

	testPolicy := `
path "secret/*" {
	capabilities = ["read"]
}
`

	// Load the policy through loadACLPolicyNamespaces from the namespace context
	err = ps.loadACLPolicy(nsCtx, "test-load-policy", testPolicy)
	require.NoError(t, err)

	// Verify the policy exists in the namespace
	nsPolicy, err := ps.GetPolicy(nsCtx, "test-load-policy", PolicyTypeToken)
	require.NoError(t, err)
	require.NotNil(t, nsPolicy, "expected policy to exist in namespace")

	// Verify policy content is the same
	assert.Equal(t, testPolicy, nsPolicy.Raw)

	modifiedPolicy := `
path "secret/*" {
	capabilities = ["read", "list"]
}
`

	// Create a new policy in the namespace
	policy, _ := ParseACLPolicy(ns, modifiedPolicy)
	policy.Name = "test-load-policy"
	err = ps.SetPolicy(nsCtx, policy, nil)
	require.NoError(t, err)

	// Verify the policies are now different
	nsPolicy, _ = ps.GetPolicy(nsCtx, "test-load-policy", PolicyTypeToken)
	assert.Equal(t, modifiedPolicy, nsPolicy.Raw)
}

// TestPolicyStore_NamespaceStorage verifies that policies are stored under their
// respective namespace's storage prefix and not in the root namespace.
func TestPolicyStore_NamespaceStorage(t *testing.T) {
	core, _, token := TestCoreUnsealed(t)
	ctx := namespace.RootContext(context.Background())
	ps := core.policyStore

	// Create a namespace
	nsPath := "test-ns"
	resp, err := core.HandleRequest(ctx, &logical.Request{
		Operation:   logical.UpdateOperation,
		Path:        "sys/namespaces/" + nsPath,
		Data:        nil,
		ClientToken: token,
	})
	require.NoError(t, err)
	require.False(t, resp.IsError())

	// Lookup the namespace
	ns, err := core.namespaceStore.GetNamespaceByPath(ctx, nsPath)
	require.NoError(t, err)
	require.NotNil(t, ns, "namespace not found: %s", nsPath)

	// Create policy in namespace
	nsCtx := namespace.ContextWithNamespace(ctx, ns)
	policy, _ := ParseACLPolicy(ns, aclPolicy)
	policy.Name = "test-policy"
	require.NoError(t, ps.SetPolicy(nsCtx, policy, nil))

	// Verify the policy exists in the namespace
	p, err := ps.GetPolicy(nsCtx, "test-policy", PolicyTypeToken)
	require.NoError(t, err)
	require.NotNil(t, p, "expected policy to exist in namespace")

	// Verify the policy is not retrievable from the root namespace
	rootP, err := ps.GetPolicy(ctx, "test-policy", PolicyTypeToken)
	require.NoError(t, err)
	assert.Nil(t, rootP, "unexpected policy found in root namespace")

	// Check storage locations
	nsBarrierView := ps.getACLView(ns)
	require.NotNil(t, nsBarrierView, "expected namespace storage")

	out, err := nsBarrierView.Get(nsCtx, "test-policy")
	require.NoError(t, err)
	require.NotNil(t, out, "expected policy in namespace storage")

	rootBarrierView := ps.getACLView(namespace.RootNamespace)
	require.NotNil(t, rootBarrierView, "expected root namespace storage")

	rootOut, err := rootBarrierView.Get(ctx, "test-policy")
	require.NoError(t, err)
	assert.Nil(t, rootOut, "policy should not exist in root storage")

	// Check policy listings
	policies, err := ps.ListPolicies(nsCtx, PolicyTypeACL, true)
	require.NoError(t, err)
	assert.Contains(t, policies, "test-policy", "policy not found in namespace listing")

	rootPolicies, err := ps.ListPolicies(ctx, PolicyTypeACL, true)
	require.NoError(t, err)
	assert.NotContains(t, rootPolicies, "test-policy", "namespace policy found in root listing")

	// Delete and verify
	require.NoError(t, ps.DeletePolicy(nsCtx, "test-policy", PolicyTypeACL))
	p, err = ps.GetPolicy(nsCtx, "test-policy", PolicyTypeToken)
	require.NoError(t, err)
	assert.Nil(t, p, "policy should be deleted")
}

// TestPolicyStore_NamespaceAPI tests namespace policy operations through the API
func TestPolicyStore_NamespaceAPI(t *testing.T) {
	core, _, token := TestCoreUnsealed(t)
	ctx := namespace.RootContext(context.Background())

	// Create a namespace
	nsPath := "test-ns-api"
	resp, err := core.HandleRequest(ctx, &logical.Request{
		Operation:   logical.UpdateOperation,
		Path:        "sys/namespaces/" + nsPath,
		Data:        nil,
		ClientToken: token,
	})
	require.NoError(t, err)
	require.False(t, resp.IsError())

	// Create and verify root policy
	policyPath := "sys/policies/acl/test-api-policy"
	policyData := map[string]interface{}{
		"policy": `path "secret/data/*" { capabilities = ["read"] }`,
	}
	rootResp, err := core.HandleRequest(ctx, &logical.Request{
		Operation:   logical.UpdateOperation,
		Path:        policyPath,
		Data:        policyData,
		ClientToken: token,
	})
	require.NoError(t, err)
	require.False(t, rootResp.IsError())

	// Get namespace and create context
	ns, err := core.namespaceStore.GetNamespaceByPath(ctx, nsPath)
	require.NoError(t, err)
	require.NotNil(t, ns, "namespace not found: %s", nsPath)
	nsCtx := namespace.ContextWithNamespace(ctx, ns)

	// Create and verify namespace policy
	nsPolicyData := map[string]interface{}{
		"policy": `path "secret/data/*" { capabilities = ["read", "list"] }`,
	}
	nsResp, err := core.HandleRequest(nsCtx, &logical.Request{
		Operation:   logical.UpdateOperation,
		Path:        policyPath,
		Data:        nsPolicyData,
		ClientToken: token,
	})
	require.NoError(t, err)
	require.False(t, nsResp.IsError())

	// Compare policies
	rootReadResp, err := core.HandleRequest(ctx, &logical.Request{
		Operation:   logical.ReadOperation,
		Path:        policyPath,
		ClientToken: token,
	})
	require.NoError(t, err)
	require.False(t, rootReadResp.IsError())

	nsReadResp, err := core.HandleRequest(nsCtx, &logical.Request{
		Operation:   logical.ReadOperation,
		Path:        policyPath,
		ClientToken: token,
	})
	require.NoError(t, err)
	require.False(t, nsReadResp.IsError())

	rootPolicy := rootReadResp.Data["policy"].(string)
	nsPolicy := nsReadResp.Data["policy"].(string)
	assert.NotEqual(t, rootPolicy, nsPolicy, "policies should be different")
	assert.Contains(t, nsPolicy, "list", "namespace policy missing list capability")
	assert.NotContains(t, rootPolicy, "list", "root policy contains unexpected list capability")

	// Delete and verify
	_, err = core.HandleRequest(nsCtx, &logical.Request{
		Operation:   logical.DeleteOperation,
		Path:        policyPath,
		ClientToken: token,
	})
	require.NoError(t, err)

	nsReadRespAfterDelete, err := core.HandleRequest(nsCtx, &logical.Request{
		Operation:   logical.ReadOperation,
		Path:        policyPath,
		ClientToken: token,
	})
	require.NoError(t, err)
	assert.Nil(t, nsReadRespAfterDelete, "expected nil response for deleted policy")

	rootReadRespAfterDelete, err := core.HandleRequest(ctx, &logical.Request{
		Operation:   logical.ReadOperation,
		Path:        policyPath,
		ClientToken: token,
	})
	require.NoError(t, err)
	require.NotNil(t, rootReadRespAfterDelete, "root policy read response is nil")
	require.NotNil(t, rootReadRespAfterDelete.Data, "root policy should still exist")
}

// TestPolicyStore_NestedNamespaces tests that policies are correctly stored
// and isolated in a hierarchy of namespaces, including proper inheritance
// and cross-namespace access control.
func TestPolicyStore_ListPoliciesByNamespace(t *testing.T) {
	core, _, token := TestCoreUnsealed(t)
	rootCtx := namespace.RootContext(context.Background())
	ps := core.policyStore

	// Create parent namespace
	parentResp, err := core.HandleRequest(rootCtx, &logical.Request{
		Operation:   logical.UpdateOperation,
		Path:        "sys/namespaces/parent",
		ClientToken: token,
	})
	require.NoError(t, err)
	require.False(t, parentResp.IsError())

	// Get parent namespace context
	parentNS, err := core.namespaceStore.GetNamespaceByPath(rootCtx, "parent")
	require.NoError(t, err)
	parentCtx := namespace.ContextWithNamespace(rootCtx, parentNS)

	// Create child namespace
	childResp, err := core.HandleRequest(parentCtx, &logical.Request{
		Operation:   logical.UpdateOperation,
		Path:        "sys/namespaces/child",
		ClientToken: token,
	})
	require.NoError(t, err)
	require.False(t, childResp.IsError())

	// Get child namespace context
	childNS, err := core.namespaceStore.GetNamespaceByPath(parentCtx, "child")
	require.NoError(t, err)
	// Create child context from root context to avoid inheriting parent context
	childCtx := namespace.ContextWithNamespace(parentCtx, childNS)

	// Add distinct policies to each namespace
	policyTemplates := []struct {
		ns      *namespace.Namespace
		ctx     context.Context
		name    string
		content string
	}{
		{namespace.RootNamespace, rootCtx, "root-policy", `path "sys/*" { capabilities = ["read"] }`},
		{parentNS, parentCtx, "parent-policy", `path "secret/*" { capabilities = ["list"] }`},
		{childNS, childCtx, "child-policy", `path "auth/*" { capabilities = ["create"] }`},
	}

	for _, tmpl := range policyTemplates {
		policy, _ := ParseACLPolicy(tmpl.ns, tmpl.content)
		policy.Name = tmpl.name
		require.NoError(t, ps.SetPolicy(tmpl.ctx, policy, nil))
	}

	// Verify policy listings in each namespace context
	tests := []struct {
		name        string
		ctx         context.Context
		expected    []string
		requireRoot bool
	}{
		{
			"root-namespace",
			rootCtx,
			[]string{"default", "root-policy", "root"},
			true, // Should include root policy
		},
		{
			"parent-namespace",
			parentCtx,
			[]string{"default", "parent-policy"},
			false,
		},
		{
			"child-namespace",
			childCtx,
			[]string{"default", "child-policy"},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policiesRes, err := core.HandleRequest(tt.ctx, &logical.Request{
				Operation:   logical.ListOperation,
				Path:        "sys/policies/acl",
				ClientToken: token,
			})
			require.NoError(t, err)
			require.False(t, childResp.IsError())

			policies := policiesRes.Data["keys"].([]string)

			// Verify expected policies exist
			require.ElementsMatch(t, tt.expected, policies)

			// Verify namespace isolation
			switch tt.name {
			case "root-namespace":
				assert.NotContains(t, policies, "parent-policy", "parent policy should not appear in root namespace")
				assert.NotContains(t, policies, "child-policy", "child policy should not appear in root namespace")
			case "parent-namespace":
				assert.NotContains(t, policies, "child-policy", "child policy should not appear in parent namespace")
			case "child-namespace":
				assert.NotContains(t, policies, "parent-policy", "parent policy should not appear in child namespace")
			}
		})
	}

	// Verify child namespace only sees its own policy
	childPolicies, err := ps.ListPolicies(childCtx, PolicyTypeACL, true)
	assert.NoError(t, err)
	assert.ElementsMatch(t, []string{"default", "child-policy"}, childPolicies,
		"child namespace should only contain its own policy and default")

	// Verify parent namespace listing
	parentPolicies, err := ps.ListPolicies(parentCtx, PolicyTypeACL, true)
	assert.NoError(t, err)
	assert.ElementsMatch(t, []string{"default", "parent-policy"}, parentPolicies,
		"parent namespace should contain its own policy and default")

	// Verify root namespace listing
	rootPolicies, err := ps.ListPolicies(rootCtx, PolicyTypeACL, true)
	assert.NoError(t, err)
	assert.ElementsMatch(t, []string{"default", "root-policy"}, rootPolicies,
		"root namespace should contain its own policy and default")
}

func TestPolicyStore_NestedNamespaces(t *testing.T) {
	core, _, token := TestCoreUnsealed(t)
	ctx := namespace.RootContext(context.Background())
	ps := core.policyStore

	// Create a parent namespace
	parentPath := "parent"
	resp, err := core.HandleRequest(ctx, &logical.Request{
		Operation:   logical.UpdateOperation,
		Path:        "sys/namespaces/" + parentPath,
		ClientToken: token,
	})
	require.NoError(t, err)
	require.False(t, resp.IsError(), "response error: %#v", resp)

	// Get the parent namespace
	parentNS, err := core.namespaceStore.GetNamespaceByPath(ctx, parentPath)
	require.NoError(t, err)
	require.NotNil(t, parentNS, "parent namespace not found")
	parentCtx := namespace.ContextWithNamespace(ctx, parentNS)

	// Create a child namespace
	childPath := "child"
	resp, err = core.HandleRequest(parentCtx, &logical.Request{
		Operation:   logical.UpdateOperation,
		Path:        "sys/namespaces/" + childPath,
		ClientToken: token,
	})
	require.NoError(t, err)
	require.False(t, resp.IsError(), "response error: %#v", resp)

	// Get the child namespace
	childNS, err := core.namespaceStore.GetNamespaceByPath(parentCtx, childPath)
	require.NoError(t, err)
	require.NotNil(t, childNS, "child namespace not found")
	childCtx := namespace.ContextWithNamespace(parentCtx, childNS)

	// Create policies in each namespace
	rootPolicy := `path "secret/*" { capabilities = ["read"] }`
	parentPolicy := `path "secret/*" { capabilities = ["read", "list"] }`
	childPolicy := `path "secret/*" { capabilities = ["read", "list", "create"] }`

	// Create in root namespace
	policy, _ := ParseACLPolicy(namespace.RootNamespace, rootPolicy)
	policy.Name = "test-nested-policy"
	require.NoError(t, ps.SetPolicy(ctx, policy, nil))

	// Create in parent namespace
	policy, _ = ParseACLPolicy(parentNS, parentPolicy)
	policy.Name = "test-nested-policy"
	require.NoError(t, ps.SetPolicy(parentCtx, policy, nil))

	// Create in child namespace
	policy, _ = ParseACLPolicy(childNS, childPolicy)
	policy.Name = "test-nested-policy"
	require.NoError(t, ps.SetPolicy(childCtx, policy, nil))

	// Verify policies were stored in correct locations
	rootP, err := ps.GetPolicy(ctx, "test-nested-policy", PolicyTypeToken)
	require.NoError(t, err)
	require.NotNil(t, rootP, "expected policy in root namespace")
	assert.Contains(t, rootP.Raw, `capabilities = ["read"]`)

	parentP, err := ps.GetPolicy(parentCtx, "test-nested-policy", PolicyTypeToken)
	require.NoError(t, err)
	require.NotNil(t, parentP, "expected policy in parent namespace")
	assert.Contains(t, parentP.Raw, `capabilities = ["read", "list"]`)

	childP, err := ps.GetPolicy(childCtx, "test-nested-policy", PolicyTypeToken)
	require.NoError(t, err)
	require.NotNil(t, childP, "expected policy in child namespace")
	assert.Contains(t, childP.Raw, `capabilities = ["read", "list", "create"]`)

	// Verify storage locations by directly accessing the barrier views
	rootView := ps.getACLView(namespace.RootNamespace)
	parentView := ps.getACLView(parentNS)
	childView := ps.getACLView(childNS)

	rootEntry, err := rootView.Get(ctx, "test-nested-policy")
	require.NoError(t, err)
	require.NotNil(t, rootEntry, "policy not found in root storage")

	parentViewEntry, err := parentView.Get(parentCtx, "test-nested-policy")
	require.NoError(t, err)
	require.NotNil(t, parentViewEntry, "policy not found in parent storage")

	childViewEntry, err := childView.Get(childCtx, "test-nested-policy")
	require.NoError(t, err)
	require.NotNil(t, childViewEntry, "policy not found in child storage")

	// Verify namespace visibility
	rootList, err := ps.ListPolicies(ctx, PolicyTypeACL, true)
	require.NoError(t, err)
	assert.Contains(t, rootList, "test-nested-policy", "policy missing in root listing")

	parentList, err := ps.ListPolicies(parentCtx, PolicyTypeACL, true)
	require.NoError(t, err)
	assert.Contains(t, parentList, "test-nested-policy", "policy missing in parent listing")

	childList, err := ps.ListPolicies(childCtx, PolicyTypeACL, true)
	require.NoError(t, err)
	assert.Contains(t, childList, "test-nested-policy", "policy missing in child listing")

	// Verify cross-namespace visibility
	assert.NotContains(t, rootList, parentNS.ID+"/test-nested-policy", "parent policy visible in root")
	assert.NotContains(t, rootList, childNS.ID+"/test-nested-policy", "child policy visible in root")

	// Test policy inheritance
	// Child namespace should not see root policy when using its own context
	rootPolicyInChild, err := ps.GetPolicy(childCtx, "test-nested-policy", PolicyTypeToken)
	require.NoError(t, err)
	assert.NotEqual(t, rootP.Raw, rootPolicyInChild.Raw, "child namespace should not inherit root policy")

	// Test parent namespace policy access from child namespace
	// We error here due to the relative path; in the past this
	// was treated like a not-found policy, which is technically
	// correct but less informative.
	parentPolicyInChild, err := ps.GetPolicy(childCtx, "../test-nested-policy", PolicyTypeToken)
	require.Error(t, err)
	assert.Nil(t, parentPolicyInChild, "child namespace should not access parent policy via relative path")

	// Test cross-namespace policy access
	// Root namespace should not see child's policy
	childPolicyInRoot, err := ps.GetPolicy(ctx, childNS.ID+"/test-nested-policy", PolicyTypeToken)
	require.NoError(t, err)
	assert.Nil(t, childPolicyInRoot, "root namespace should not see child policy")

	// Test policy deletion isolation
	// Delete policy in child namespace
	require.NoError(t, ps.DeletePolicy(childCtx, "test-nested-policy", PolicyTypeACL))

	// Verify policy was deleted only in child namespace
	deletedChildPolicy, err := ps.GetPolicy(childCtx, "test-nested-policy", PolicyTypeToken)
	require.NoError(t, err)
	assert.Nil(t, deletedChildPolicy, "policy should be deleted in child namespace")

	// Verify parent and root policies still exist
	parentPolicyAfterDelete, err := ps.GetPolicy(parentCtx, "test-nested-policy", PolicyTypeToken)
	require.NoError(t, err)
	assert.NotNil(t, parentPolicyAfterDelete, "parent policy should still exist")

	rootPolicyAfterDelete, err := ps.GetPolicy(ctx, "test-nested-policy", PolicyTypeToken)
	require.NoError(t, err)
	assert.NotNil(t, rootPolicyAfterDelete, "root policy should still exist")
}

// TestPolicyStore_Expiration validates that expiration works as expected.
func TestPolicyStore_Expiration(t *testing.T) {
	t.Parallel()
	_, _, _, ps := mockPolicyWithCore(t, false)

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	p, err := ParseACLPolicy(namespace.RootNamespace, `path "*" { capabilities = ["read"] }`)
	require.NoError(t, err)
	require.NotNil(t, p)

	p.Name = "testing"
	p.Expiration = time.Now().Add(15 * time.Second)

	err = ps.SetPolicy(ctx, p, nil)
	require.NoError(t, err)

	p1, err := ps.GetPolicy(ctx, p.Name, p.Type)
	require.NoError(t, err)
	require.NotNil(t, p1)
	require.Equal(t, p, p1)

	time.Sleep(time.Until(p.Expiration) + 10*time.Millisecond)

	p2, err := ps.GetPolicy(ctx, p.Name, p.Type)
	require.NoError(t, err)
	require.Nil(t, p2)
}

// Validate that check-and-set logic works.
func TestPolicyStore_CAS(t *testing.T) {
	t.Parallel()
	_, _, _, ps := mockPolicyWithCore(t, false)

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	p, err := ParseACLPolicy(namespace.RootNamespace, `path "*" { capabilities = ["read"] }`)
	require.NoError(t, err)
	require.NotNil(t, p)

	p.Name = "testing"

	// Create a policy with high explicit cas fails.
	cas := 3
	err = ps.SetPolicy(ctx, p, &cas)
	require.Error(t, err)

	// Create a policy with -1 works.
	cas = -1
	err = ps.SetPolicy(ctx, p, &cas)
	require.NoError(t, err)

	require.Equal(t, 1, p.DataVersion)

	p1, err := ps.GetPolicy(ctx, p.Name, p.Type)
	require.NoError(t, err)
	require.NotNil(t, p1)
	require.Equal(t, p, p1)
}
