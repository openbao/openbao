// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/go-test/deep"
	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/vault/quotas"
	"github.com/stretchr/testify/require"
)

func testCore_Invalidate_sneakValueAroundCache(t *testing.T, c *Core, entry *logical.StorageEntry) {
	t.Helper()

	// we breifly disable the physical cache, this will put the value into the backing strorage, but not update the cache
	c.physicalCache.SetEnabled(false)
	defer c.physicalCache.SetEnabled(true)

	err := c.barrier.Put(t.Context(), entry)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
}

func TestCore_Invalidate_Namespaces(t *testing.T) {
	c, _, root := TestCoreUnsealed(t)

	// 1. Create some namespace to populate cache
	ns := &namespace.Namespace{
		ID:   "ns",
		Path: "ns",
		CustomMetadata: map[string]string{
			"testkey": "initial value",
		},
	}

	TestCoreCreateNamespaces(t, c, ns)

	// 2. Manipulate Storage
	clone := *ns
	clone.CustomMetadata["testkey"] = "updated value"

	storagePath := "core/namespaces/" + ns.UUID
	newEntry, err := logical.StorageEntryJSON(storagePath, clone)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	testCore_Invalidate_sneakValueAroundCache(t, c, newEntry)

	// 3. Invalidate Path
	c.Invalidate(storagePath)

	// 4. Check cache was properly invalidated
	req := logical.TestRequest(t, logical.ReadOperation, "sys/namespaces/ns")
	req.ClientToken = root
	resp, err := c.HandleRequest(namespace.RootContext(nil), req)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if diff := deep.Equal(resp.Data["custom_metadata"], map[string]string{
		"testkey": "updated value",
	}); diff != nil {
		t.Error(diff)
	}
}

func TestCore_Invalidate_Policy(t *testing.T) {
	testCases := map[string]func(t *testing.T, c *Core) (storagePath string, ctx context.Context){
		"global": func(t *testing.T, c *Core) (storagePath string, ctx context.Context) {
			return "sys/policy/test-policy", namespace.RootContext(t.Context())
		},

		"local": func(t *testing.T, c *Core) (storagePath string, ctx context.Context) {
			ns := &namespace.Namespace{
				ID:   "ns",
				Path: "ns",
			}
			TestCoreCreateNamespaces(t, c, ns)

			return fmt.Sprintf("namespaces/%s/sys/policy/test-policy", ns.UUID), namespace.ContextWithNamespace(t.Context(), ns)
		},
	}

	for name, init := range testCases {
		t.Run(name, func(t *testing.T) {
			c, _, root := TestCoreUnsealed(t)
			storagePath, ctx := init(t, c)

			// 1. Create some policy to populate cache
			req := logical.TestRequest(t, logical.CreateOperation, "sys/policy/test-policy")
			req.ClientToken = root
			req.Data = map[string]interface{}{
				"policy": `
					path "test/path/*" {
						capabilities = ["read"]
					}
			`,
			}
			resp, err := c.HandleRequest(ctx, req)
			if err != nil {
				t.Fatalf("err: %v", err)
			}

			if resp.IsError() {
				t.Fatalf("err: %v", resp.Error())
			}

			// 2. Manipulate Storage
			policy, err := c.policyStore.GetPolicy(ctx, "test-policy", PolicyTypeACL)
			if err != nil {
				t.Fatalf("err: %v", err)
			}

			clone := policy.ShallowClone()
			clone.Expiration = time.Date(2099, 1, 1, 12, 0, 0, 0, time.UTC)

			newEntry, err := logical.StorageEntryJSON(storagePath, clone)
			if err != nil {
				t.Fatalf("err: %v", err)
			}

			testCore_Invalidate_sneakValueAroundCache(t, c, newEntry)

			// 3. Invalidate Path
			c.Invalidate(storagePath)

			// 4. Check cache was properly invalidated
			updatedPolicy, err := c.policyStore.GetPolicy(ctx, "test-policy", PolicyTypeACL)
			if err != nil {
				t.Fatalf("err: %v", err)
			}

			if updatedPolicy.Expiration != clone.Expiration {
				t.Errorf("invalidation did not work: expected to see updated expiry time, got: %v", updatedPolicy.Expiration)
			}
		})
	}
}

func TestCore_Invalidate_Quota(t *testing.T) {
	c, _, root := TestCoreUnsealed(t)

	// 1. Create some qutoa to populate cache
	req := logical.TestRequest(t, logical.CreateOperation, "sys/quotas/rate-limit/test-quota")
	req.ClientToken = root
	req.Data = map[string]any{
		"rate":     3.141,
		"interval": "42s",
	}
	resp, err := c.HandleRequest(t.Context(), req)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if resp.IsError() {
		t.Fatalf("err: %v", resp.Error())
	}

	// 2. Manipulate Storage
	quota, err := c.quotaManager.QuotaByName("rate-limit", "test-quota")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	clone := quota.Clone().(*quotas.RateLimitQuota)
	clone.Interval = 1 * time.Second

	newEntry, err := logical.StorageEntryJSON("sys/quotas/rate-limit/test-quota", clone)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	testCore_Invalidate_sneakValueAroundCache(t, c, newEntry)

	// 3. Invalidate Path
	c.Invalidate("sys/quotas/rate-limit/test-quota")

	// 4. Check cache was properly invalidated
	req = logical.TestRequest(t, logical.ReadOperation, "sys/quotas/rate-limit/test-quota")
	req.ClientToken = root

	resp, err = c.HandleRequest(t.Context(), req)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if resp.IsError() {
		t.Fatalf("err: %v", resp.Error())
	}

	require.Equal(t, 1, resp.Data["interval"])
}
