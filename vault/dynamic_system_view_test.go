// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"encoding/base64"
	"fmt"
	"reflect"
	"sort"
	"testing"
	"time"

	log "github.com/hashicorp/go-hclog"
	ldapcred "github.com/openbao/openbao/builtin/credential/ldap"
	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
)

var (
	testPolicyName        = "testpolicy"
	rawTestPasswordPolicy = `
length = 20
rule "charset" {
	charset = "abcdefghijklmnopqrstuvwxyz"
	min_chars = 1
}
rule "charset" {
	charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	min_chars = 1
}
rule "charset" {
	charset = "0123456789"
	min_chars = 1
}`
	rawTestPasswordPolicy2 = `
length = 10
rule "charset" {
	charset = "abcdefghijklmnopqrstuvwxyz"
	min_chars = 1
}`
)

func TestIdentity_BackendTemplating(t *testing.T) {
	var err error
	coreConfig := &CoreConfig{
		DisableCache: true,
		Logger:       log.NewNullLogger(),
		CredentialBackends: map[string]logical.Factory{
			"ldap": ldapcred.Factory,
		},
	}

	cluster := NewTestCluster(t, coreConfig, &TestClusterOptions{})

	cluster.Start()
	defer cluster.Cleanup()

	core := cluster.Cores[0].Core

	TestWaitActive(t, core)

	req := logical.TestRequest(t, logical.UpdateOperation, "sys/auth/ldap")
	req.ClientToken = cluster.RootToken
	req.Data["type"] = "ldap"
	resp, err := core.HandleRequest(namespace.RootContext(nil), req)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if resp != nil {
		t.Fatalf("bad: %v", resp)
	}

	req = logical.TestRequest(t, logical.ReadOperation, "sys/auth")
	req.ClientToken = cluster.RootToken
	resp, err = core.HandleRequest(namespace.RootContext(nil), req)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	accessor := resp.Data["ldap/"].(map[string]interface{})["accessor"].(string)

	// Create an entity
	req = logical.TestRequest(t, logical.UpdateOperation, "identity/entity")
	req.ClientToken = cluster.RootToken
	req.Data["name"] = "entity1"
	req.Data["metadata"] = map[string]string{
		"organization": "hashicorp",
		"team":         "vault",
	}
	resp, err = core.HandleRequest(namespace.RootContext(nil), req)
	if err != nil {
		t.Fatal(err)
	}

	entityID := resp.Data["id"].(string)

	// Create an alias
	req = logical.TestRequest(t, logical.UpdateOperation, "identity/entity-alias")
	req.ClientToken = cluster.RootToken
	req.Data["name"] = "alias1"
	req.Data["canonical_id"] = entityID
	req.Data["mount_accessor"] = accessor
	resp, err = core.HandleRequest(namespace.RootContext(nil), req)
	if err != nil {
		t.Fatal(err)
	}

	aliasID := resp.Data["id"].(string)

	// Create a group
	req = logical.TestRequest(t, logical.UpdateOperation, "identity/group")
	req.ClientToken = cluster.RootToken
	req.Data["name"] = "group1"
	req.Data["member_entity_ids"] = []string{entityID}
	req.Data["metadata"] = map[string]string{
		"group": "vault",
	}
	resp, err = core.HandleRequest(namespace.RootContext(nil), req)
	if err != nil {
		t.Fatal(err)
	}

	groupID := resp.Data["id"].(string)

	// Get the ldap mount
	sysView := core.router.MatchingSystemView(namespace.RootContext(nil), "auth/ldap/")

	tCases := []struct {
		tpl      string
		expected string
	}{
		{
			tpl:      "{{identity.entity.id}}",
			expected: entityID,
		},
		{
			tpl:      "{{identity.entity.name}}",
			expected: "entity1",
		},
		{
			tpl:      "{{identity.entity.metadata.organization}}",
			expected: "hashicorp",
		},
		{
			tpl:      "{{identity.entity.aliases." + accessor + ".id}}",
			expected: aliasID,
		},
		{
			tpl:      "{{identity.entity.aliases." + accessor + ".name}}",
			expected: "alias1",
		},
		{
			tpl:      "{{identity.groups.ids." + groupID + ".name}}",
			expected: "group1",
		},
		{
			tpl:      "{{identity.groups.names.group1.id}}",
			expected: groupID,
		},
		{
			tpl:      "{{identity.groups.names.group1.metadata.group}}",
			expected: "vault",
		},
		{
			tpl:      "{{identity.groups.ids." + groupID + ".metadata.group}}",
			expected: "vault",
		},
	}

	for _, tCase := range tCases {
		out, err := framework.PopulateIdentityTemplate(tCase.tpl, entityID, sysView)
		if err != nil {
			t.Fatal(err)
		}

		if out != tCase.expected {
			t.Fatalf("got %q, expected %q", out, tCase.expected)
		}
	}
}

func TestDynamicSystemView_GeneratePasswordFromPolicy_successful(t *testing.T) {
	var err error
	coreConfig := &CoreConfig{
		DisableCache:       true,
		Logger:             log.NewNullLogger(),
		CredentialBackends: map[string]logical.Factory{},
	}

	cluster := NewTestCluster(t, coreConfig, &TestClusterOptions{})

	cluster.Start()
	defer cluster.Cleanup()

	core := cluster.Cores[0].Core
	TestWaitActive(t, core)

	b64Policy := base64.StdEncoding.EncodeToString([]byte(rawTestPasswordPolicy))

	path := fmt.Sprintf("sys/policies/password/%s", testPolicyName)
	req := logical.TestRequest(t, logical.CreateOperation, path)
	req.ClientToken = cluster.RootToken
	req.Data["policy"] = b64Policy

	_, err = core.HandleRequest(namespace.RootContext(nil), req)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	ctx = namespace.RootContext(ctx)
	dsv := TestDynamicSystemView(cluster.Cores[0].Core, nil)

	runeset := map[rune]bool{}
	runesFound := []rune{}

	for i := 0; i < 100; i++ {
		actual, err := dsv.GeneratePasswordFromPolicy(ctx, testPolicyName)
		if err != nil {
			t.Fatalf("no error expected, but got: %s", err)
		}
		for _, r := range actual {
			if runeset[r] {
				continue
			}
			runeset[r] = true
			runesFound = append(runesFound, r)
		}
	}

	sort.Sort(runes(runesFound))

	expectedRunes := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	sort.Sort(runes(expectedRunes)) // Sort it so they can be compared

	if !reflect.DeepEqual(runesFound, expectedRunes) {
		t.Fatalf("Didn't find all characters from the charset\nActual  : [%s]\nExpected: [%s]", string(runesFound), string(expectedRunes))
	}
}

func TestDynamicSystemView_GeneratePasswordFromPolicy_failed(t *testing.T) {
	type testCase struct {
		policyName string
		entry      *logical.StorageEntry
	}

	tests := map[string]testCase{
		"no policy name": {
			policyName: "",
		},
		"no policy found": {
			policyName: "testpolicy",
		},
		"error retrieving policy": {
			policyName: "testpolicy",
		},
		"saved policy is malformed": {
			policyName: "testpolicy",
			entry: &logical.StorageEntry{
				Key:   getPasswordPolicyKey("testpolicy"),
				Value: []byte(`{"policy":"asdfahsdfasdf"}`),
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			core, _, _ := TestCoreUnsealed(t)

			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			defer cancel()

			if test.entry != nil {
				core.systemBarrierView.Put(ctx, test.entry)
			}

			dsv := TestDynamicSystemView(core, nil)

			actualPassword, err := dsv.GeneratePasswordFromPolicy(ctx, test.policyName)
			if err == nil {
				t.Fatal("err expected, got nil")
			}
			if actualPassword != "" {
				t.Fatalf("no password expected, got %s", actualPassword)
			}
		})
	}
}

func TestDynamicSystemView_GeneratePasswordFromPolicy_namespaces(t *testing.T) {
	core, _, token := TestCoreUnsealed(t)

	err := TestCoreCreateNamespaces(core,
		&namespace.Namespace{Path: "foo/"},
		&namespace.Namespace{Path: "foo/bar/"},
	)
	require.NoError(t, err)

	ctx := namespace.RootContext(nil)

	fooNs, err := core.namespaceStore.GetNamespaceByPath(ctx, "foo/")
	require.NoError(t, err)
	barNs, err := core.namespaceStore.GetNamespaceByPath(ctx, "foo/bar")
	require.NoError(t, err)

	// Create password policy in the 'foo/' namespace.
	path := fmt.Sprintf("sys/policies/password/%s", testPolicyName)
	req := logical.TestRequest(t, logical.CreateOperation, path)
	b64Policy := base64.StdEncoding.EncodeToString([]byte(rawTestPasswordPolicy))
	req.Data["policy"] = b64Policy
	req.ClientToken = token
	_, err = core.HandleRequest(namespace.ContextWithNamespace(ctx, fooNs), req)
	require.NoError(t, err)

	// Password policy should only work in the 'foo/' namespace,
	// not a child namespace, not the root namespace.
	pass, err := TestDynamicSystemView(core, fooNs).GeneratePasswordFromPolicy(ctx, testPolicyName)
	require.NoError(t, err)
	require.NotEmpty(t, pass)
	pass, err = TestDynamicSystemView(core, barNs).GeneratePasswordFromPolicy(ctx, testPolicyName)
	require.Error(t, err)
	require.Empty(t, pass)
	pass, err = TestDynamicSystemView(core, nil).GeneratePasswordFromPolicy(ctx, testPolicyName)
	require.Error(t, err)
	require.Empty(t, pass)

	// Create another password policy in the root namespace, with the same name.
	path = fmt.Sprintf("sys/policies/password/%s", testPolicyName)
	req = logical.TestRequest(t, logical.CreateOperation, path)
	b64Policy = base64.StdEncoding.EncodeToString([]byte(rawTestPasswordPolicy2))
	req.Data["policy"] = b64Policy
	req.ClientToken = token
	_, err = core.HandleRequest(ctx, req)
	require.NoError(t, err)

	// Password policy in 'foo/' should still act the same
	pass, err = TestDynamicSystemView(core, fooNs).GeneratePasswordFromPolicy(ctx, testPolicyName)
	require.NoError(t, err)
	require.NotEmpty(t, pass)
	require.Len(t, pass, 20)

	// Password policy in root namespace should now be available, but generate passwords
	// according to different constraints.
	pass, err = TestDynamicSystemView(core, nil).GeneratePasswordFromPolicy(ctx, testPolicyName)
	require.NoError(t, err)
	require.NotEmpty(t, pass)
	require.Len(t, pass, 10)
}

type runes []rune

func (r runes) Len() int           { return len(r) }
func (r runes) Less(i, j int) bool { return r[i] < r[j] }
func (r runes) Swap(i, j int)      { r[i], r[j] = r[j], r[i] }
