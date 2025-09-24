// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"path"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-test/deep"
	"github.com/openbao/openbao/audit"
	"github.com/openbao/openbao/command/server"
	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/helper/testhelpers/corehelpers"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/helper/jsonutil"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/sdk/v2/physical/inmem"
	"github.com/openbao/openbao/vault/quotas"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testCore_Invalidate_sneakValueAroundCache(t *testing.T, c *Core, entry *logical.StorageEntry) {
	t.Helper()

	// we briefly disable the physical cache, this will put the value into the backing storage, but not update the cache
	c.physicalCache.SetEnabled(false)
	defer c.physicalCache.SetEnabled(true)

	require.NoError(t, c.barrier.Put(t.Context(), entry))
}

func testCore_Invalidate_sneakValueAroundCacheDelete(t *testing.T, c *Core, key string) {
	t.Helper()

	// we briefly disable the physical cache, this will put the value into the backing storage, but not update the cache
	c.physicalCache.SetEnabled(false)
	defer c.physicalCache.SetEnabled(true)

	require.NoError(t, logical.ClearView(t.Context(), logical.NewStorageView(c.barrier, key)))
}

func testCore_Invalidate_handleRequest(t require.TestingT, ctx context.Context, c *Core, req *logical.Request, expectedErrors ...string) *logical.Response {
	resp, err := c.HandleRequest(ctx, req)
	if len(expectedErrors) == 0 {
		require.NoError(t, err, "response: %#v", resp)
		require.NoError(t, resp.Error())
	} else {
		for _, expectedError := range expectedErrors {
			if err != nil {
				require.ErrorContains(t, err, expectedError)
			} else {
				require.ErrorContains(t, resp.Error(), expectedError)
			}
		}
	}

	return resp
}

func TestCore_Invalidate_Namespaces(t *testing.T) {
	t.Parallel()
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
	// 2.1 Inject custom metadata into namespace
	clone := *ns
	clone.CustomMetadata["testkey"] = "updated value"

	storagePath := "core/namespaces/" + ns.UUID
	newEntry, err := logical.StorageEntryJSON(storagePath, clone)
	require.NoError(t, err)

	testCore_Invalidate_sneakValueAroundCache(t, c, newEntry)

	// 2.2 add mount to namespace
	newEntry, err = logical.StorageEntryJSON("namespaces/"+ns.UUID+"/core/mounts/666666666-6666-6666-6666-6666666666666", MountEntry{
		Table:       "mounts",
		Type:        "kv",
		Path:        "my-path",
		UUID:        "666666666-6666-6666-6666-6666666666666",
		Accessor:    "mount_666",
		NamespaceID: ns.ID,
	})
	require.NoError(t, err)
	testCore_Invalidate_sneakValueAroundCache(t, c, newEntry)
	mountPath := "ns/my-path"

	// 3. Invalidate Path
	c.Invalidate(storagePath)

	// 4. Check cache was properly invalidated
	// 4.1 Validate custom metadata
	req := logical.TestRequest(t, logical.ReadOperation, "sys/namespaces/ns")
	req.ClientToken = root
	resp := testCore_Invalidate_handleRequest(t, namespace.RootContext(t.Context()), c, req)

	if diff := deep.Equal(resp.Data["custom_metadata"], map[string]string{
		"testkey": "updated value",
	}); diff != nil {
		t.Error(diff)
	}

	// 4.2 validate kv was mounted
	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		req = logical.TestRequest(t, logical.ListOperation, mountPath)
		req.ClientToken = root
		resp = testCore_Invalidate_handleRequest(collect, namespace.RootContext(t.Context()), c, req)
		require.NotNil(collect, resp)
	}, 10*time.Second, 10*time.Millisecond)

	// 5. Manipulate Storage: delete namespace
	testCore_Invalidate_sneakValueAroundCacheDelete(t, c, storagePath)
	testCore_Invalidate_sneakValueAroundCacheDelete(t, c, "namespaces/"+ns.UUID)

	// 6. Invalidate Path
	c.Invalidate(storagePath)

	// 7. Check cache was properly invalidated
	// 7.1 namespace should be gone
	req = logical.TestRequest(t, logical.ReadOperation, "sys/namespaces/ns")
	req.ClientToken = root
	resp = testCore_Invalidate_handleRequest(t, namespace.RootContext(t.Context()), c, req)

	require.Nil(t, resp)

	// 7.2 mount should be gone
	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		req = logical.TestRequest(t, logical.ListOperation, mountPath)
		req.ClientToken = root
		resp = testCore_Invalidate_handleRequest(collect, namespace.RootContext(t.Context()), c, req, "unsupported path")
	}, 10*time.Second, 10*time.Millisecond)
}

func TestCore_Invalidate_Namespaces_NonTransactional(t *testing.T) {
	t.Parallel()

	physical, err := inmem.NewInmem(map[string]string{
		"disable_transactions": "true",
	}, logger)
	require.NoError(t, err)
	c, _, root := TestCoreUnsealedWithConfig(t, &CoreConfig{
		Physical: physical,
	})

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
	// 2.1 Inject custom metadata into namespace
	clone := *ns
	clone.CustomMetadata["testkey"] = "updated value"

	storagePath := "core/namespaces/" + ns.UUID
	newEntry, err := logical.StorageEntryJSON(storagePath, clone)
	require.NoError(t, err)

	testCore_Invalidate_sneakValueAroundCache(t, c, newEntry)

	// 2.2 add mount to namespace
	storageEntry, err := c.barrier.Get(t.Context(), "core/mounts")
	require.NoError(t, err)
	require.NotNil(t, storageEntry, "expected mount table to be written at %s", storagePath)

	mountTable := new(MountTable)
	require.NoError(t, jsonutil.DecodeJSON(storageEntry.Value, mountTable))

	mountTable.Entries = append(mountTable.Entries, &MountEntry{
		Table:       "mounts",
		Type:        "kv",
		Path:        "my-path",
		UUID:        "666666666-6666-6666-6666-6666666666666",
		Accessor:    "mount_666",
		NamespaceID: ns.ID,
	})
	mountPath := "ns/my-path"

	updatedData, err := jsonutil.EncodeJSON(mountTable)
	require.NoError(t, err)

	testCore_Invalidate_sneakValueAroundCache(t, c, &logical.StorageEntry{
		Key:   "core/mounts",
		Value: updatedData,
	})

	// 3. Invalidate Path
	c.Invalidate(storagePath)

	// 4. Check cache was properly invalidated
	// 4.1 Validate custom metadata
	req := logical.TestRequest(t, logical.ReadOperation, "sys/namespaces/ns")
	req.ClientToken = root
	resp := testCore_Invalidate_handleRequest(t, namespace.RootContext(t.Context()), c, req)

	if diff := deep.Equal(resp.Data["custom_metadata"], map[string]string{
		"testkey": "updated value",
	}); diff != nil {
		t.Error(diff)
	}

	// 4.2 validate kv was mounted
	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		req = logical.TestRequest(t, logical.ListOperation, mountPath)
		req.ClientToken = root
		resp = testCore_Invalidate_handleRequest(collect, namespace.RootContext(t.Context()), c, req)
		require.NotNil(collect, resp)
	}, 10*time.Second, 10*time.Millisecond)
}

func TestCore_Invalidate_Policy(t *testing.T) {
	t.Parallel()
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
			testCore_Invalidate_handleRequest(t, ctx, c, req)

			// 2. Manipulate Storage
			policy, err := c.policyStore.GetPolicy(ctx, "test-policy", PolicyTypeACL)
			require.NoError(t, err)

			clone := policy.ShallowClone()
			clone.Expiration = time.Date(2099, 1, 1, 12, 0, 0, 0, time.UTC)

			newEntry, err := logical.StorageEntryJSON(storagePath, clone)
			require.NoError(t, err)

			testCore_Invalidate_sneakValueAroundCache(t, c, newEntry)

			// 3. Invalidate Path
			c.Invalidate(storagePath)

			// 4. Check cache was properly invalidated
			updatedPolicy, err := c.policyStore.GetPolicy(ctx, "test-policy", PolicyTypeACL)
			require.NoError(t, err)

			require.Equal(t, clone.Expiration, updatedPolicy.Expiration)
		})
	}
}

func TestCore_Invalidate_Quota(t *testing.T) {
	t.Parallel()
	c, _, root := TestCoreUnsealed(t)

	// 1. Create some qutoa to populate cache
	req := logical.TestRequest(t, logical.CreateOperation, "sys/quotas/rate-limit/test-quota")
	req.ClientToken = root
	req.Data = map[string]any{
		"rate":     3.141,
		"interval": "42s",
	}
	testCore_Invalidate_handleRequest(t, t.Context(), c, req)

	// 2. Manipulate Storage
	quota, err := c.quotaManager.QuotaByName("rate-limit", "test-quota")
	require.NoError(t, err)

	clone := quota.Clone().(*quotas.RateLimitQuota)
	clone.Interval = 1 * time.Second

	newEntry, err := logical.StorageEntryJSON("sys/quotas/rate-limit/test-quota", clone)
	require.NoError(t, err)

	testCore_Invalidate_sneakValueAroundCache(t, c, newEntry)

	// 3. Invalidate Path
	c.Invalidate("sys/quotas/rate-limit/test-quota")

	// 4. Check cache was properly invalidated
	req = logical.TestRequest(t, logical.ReadOperation, "sys/quotas/rate-limit/test-quota")
	req.ClientToken = root

	resp := testCore_Invalidate_handleRequest(t, t.Context(), c, req)

	require.Equal(t, 1, resp.Data["interval"])
}

func TestCore_Invalidate_Plugin(t *testing.T) {
	t.Parallel()
	testCases := map[string]func(t *testing.T, c *Core) (nsPrefix string, ctx context.Context){
		"global": func(t *testing.T, c *Core) (nsPrefix string, ctx context.Context) {
			return "", namespace.RootContext(t.Context())
		},

		"local": func(t *testing.T, c *Core) (nsPrefix string, ctx context.Context) {
			ns := &namespace.Namespace{
				ID:   "ns",
				Path: "ns",
			}
			TestCoreCreateNamespaces(t, c, ns)

			return fmt.Sprintf("namespaces/%s/", ns.UUID), namespace.ContextWithNamespace(t.Context(), ns)
		},
	}

	for name, init := range testCases {
		t.Run(name, func(t *testing.T) {
			c, _, root := TestCoreUnsealed(t)
			nsPrefix, ctx := init(t, c)

			// 1. Inject a dummy plugin
			var invalidatedKeyLock sync.Mutex
			invalidatedKey := []string{}

			c.logicalBackends["kv"] = func(ctx context.Context, config *logical.BackendConfig) (logical.Backend, error) {
				b := new(framework.Backend)
				b.BackendType = logical.TypeCredential
				b.Invalidate = func(ctx context.Context, key string) {
					invalidatedKeyLock.Lock()
					defer invalidatedKeyLock.Unlock()
					invalidatedKey = append(invalidatedKey, key)
				}
				return b, b.Setup(ctx, config)
			}

			// 2. Mount the plugin
			registerReq := &logical.Request{
				Operation:   logical.UpdateOperation,
				ClientToken: root,
				Path:        "sys/mounts/my-kv-mount",
				Data: map[string]any{
					"type": "kv",
				},
			}
			testCore_Invalidate_handleRequest(t, ctx, c, registerReq)

			// 3. Get the UUID
			readReq := &logical.Request{
				Operation:   logical.ReadOperation,
				ClientToken: root,
				Path:        "sys/mounts/my-kv-mount",
			}
			resp := testCore_Invalidate_handleRequest(t, ctx, c, readReq)

			uuid := resp.Data["uuid"].(string)

			// 4. Invalidate Paths
			c.Invalidate(nsPrefix + "logical/" + uuid + "/foo")
			c.Invalidate(nsPrefix + "logical/" + uuid + "/bar/bazz")

			// 5. Check callback was called
			assert.Equal(t, invalidatedKey, []string{"foo", "bar/bazz"})
		})
	}
}

func TestCore_Invalidate_Audit(t *testing.T) {
	t.Parallel()
	c, _, root := TestCoreUnsealedWithConfig(t, &CoreConfig{
		RawConfig: &server.Config{UnsafeAllowAPIAuditCreation: true, AllowAuditLogPrefixing: true},
	})

	// 1. Inject a dummy audit factory
	var callCount atomic.Int32
	var currentBackend *corehelpers.NoopAudit
	factory := corehelpers.NoopAuditFactory(nil)
	c.auditBackends["noop"] = func(ctx context.Context, config *audit.BackendConfig) (audit.Backend, error) {
		callCount.Add(1)
		backend, err := factory(ctx, config)
		currentBackend = backend.(*corehelpers.NoopAudit)
		return backend, err
	}

	// 2. Enable dummy audit
	registerReq := &logical.Request{
		Operation:   logical.CreateOperation,
		ClientToken: root,
		Path:        "sys/audit/my-noop-audit",
		Data: map[string]any{
			"type": "noop",
			"options": map[string]any{
				"prefix": "my-test-prefix",
			},
		},
	}

	testCore_Invalidate_handleRequest(t, t.Context(), c, registerReq)

	require.EqualValues(t, 1, callCount.Load(), "expected audit factory to be called exactly once")

	// 3. Trigger audit event
	triggerAuditEvent := func() {
		testCore_Invalidate_handleRequest(t, t.Context(), c, &logical.Request{
			Operation:   logical.ReadOperation,
			ClientToken: root,
			Path:        "secret/kv/dummy",
		})
	}
	triggerAuditEvent()

	require.Len(t, currentBackend.Req, 1, "expected 1 audit request event")

	// 4. Manipulate audit table in storage: delete audit
	entry, err := c.barrier.Get(t.Context(), "core/audit")
	require.NoError(t, err)
	require.NotNil(t, entry, "expected audit table to be written")

	auditTable := &MountTable{}
	require.NoError(t, jsonutil.DecodeJSON(entry.Value, auditTable), "failed to decode audit table")

	auditTable.Entries = make([]*MountEntry, 0)

	data, err := jsonutil.EncodeJSON(auditTable)
	require.NoError(t, err)

	testCore_Invalidate_sneakValueAroundCache(t, c, &logical.StorageEntry{
		Key:   "core/audit",
		Value: data,
	})

	// 5. call invalidate
	c.Invalidate("core/audit")

	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		require.Equal(collect, 0, c.auditBroker.Count())
	}, 10*time.Second, 10*time.Millisecond)

	require.EqualValues(t, 1, callCount.Load(), "expected audit factory to be called exactly once")

	// 6. Trigger audit event (but audit should be disabled)
	triggerAuditEvent()

	require.Len(t, currentBackend.Req, 1, "expected still 1 audit request event")

	// 7. Manipulate audit table in storage: restore audit
	testCore_Invalidate_sneakValueAroundCache(t, c, entry)

	// 8. call invalidate
	c.Invalidate("core/audit")

	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		require.EqualValues(collect, 2, callCount.Load(), "expected audit factory to be called exactly twice")
		require.Equal(collect, 1, c.auditBroker.Count())
	}, 10*time.Second, 10*time.Millisecond)

	require.Len(t, currentBackend.Req, 0, "expected 0 audit request event") // factory is called again, storage will be reset

	// 9. Trigger audit event
	triggerAuditEvent()

	require.Len(t, currentBackend.Req, 1, "expected 1 audit request event")
}

func TestCore_Invalidate_SecretMount(t *testing.T) {
	t.Parallel()
	testCases := map[string]func(t *testing.T, c *Core) (nsPrefix string, ctx context.Context){
		"global": func(t *testing.T, c *Core) (nsPrefix string, ctx context.Context) {
			return "", namespace.RootContext(t.Context())
		},

		"local": func(t *testing.T, c *Core) (nsPrefix string, ctx context.Context) {
			ns := &namespace.Namespace{
				ID:   "ns",
				Path: "ns",
			}
			TestCoreCreateNamespaces(t, c, ns)

			return fmt.Sprintf("namespaces/%s/", ns.UUID), namespace.ContextWithNamespace(t.Context(), ns)
		},
	}

	for name, init := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			c, _, root := TestCoreUnsealed(t)
			nsPrefix, ctx := init(t, c)

			// 1. Inject a dummy factory
			var factoryCallCount, cleanCallCount, readCallCount atomic.Int32
			c.logicalBackends["kv"] = func(ctx context.Context, config *logical.BackendConfig) (logical.Backend, error) {
				factoryCallCount.Add(1)
				b := new(framework.Backend)
				b.Clean = func(_ context.Context) {
					cleanCallCount.Add(1)
				}
				b.Paths = []*framework.Path{{
					Pattern: ".*",
					Callbacks: map[logical.Operation]framework.OperationFunc{
						logical.ReadOperation: func(context.Context, *logical.Request, *framework.FieldData) (*logical.Response, error) {
							readCallCount.Add(1)
							return &logical.Response{Headers: map[string][]string{
								"Test-Header": {"test-value"},
							}}, nil
						},
					},
				}}
				return b, b.Setup(ctx, config)
			}

			mountTableCount := len(c.mounts.Entries)

			// 2. Enable mount kv store
			registerReq := &logical.Request{
				Operation:   logical.UpdateOperation,
				ClientToken: root,
				Path:        "sys/mounts/my-kv-mount",
				Data: map[string]any{
					"type": "kv",
				},
			}
			testCore_Invalidate_handleRequest(t, ctx, c, registerReq)

			require.EqualValues(t, 1, factoryCallCount.Load(), "expected factory to be called exactly once")
			require.Equal(t, mountTableCount+1, len(c.mounts.Entries), "expected mount table to grew by one")

			// 3. Get the UUID
			readReq := &logical.Request{
				Operation:   logical.ReadOperation,
				ClientToken: root,
				Path:        "sys/mounts/my-kv-mount",
			}
			resp := testCore_Invalidate_handleRequest(t, ctx, c, readReq)

			uuid := resp.Data["uuid"].(string)
			storagePath := path.Join(nsPrefix, "core/mounts", uuid)

			triggerReadCall := func(collect require.TestingT, expectedErrors ...string) {
				testCore_Invalidate_handleRequest(collect, ctx, c, &logical.Request{
					Operation:   logical.ReadOperation,
					ClientToken: root,
					Path:        "my-kv-mount",
				}, expectedErrors...)
			}
			triggerReadCall(t)
			require.EqualValues(t, 1, readCallCount.Load(), "expected one read call")

			// 4. Manipulate mount table in storage: delete storageEntry
			storageEntry, err := c.barrier.Get(ctx, storagePath)
			require.NoError(t, err)
			require.NotNil(t, storageEntry, "expected mount entry to be written at %s", storagePath)

			testCore_Invalidate_sneakValueAroundCacheDelete(t, c, storagePath)

			// 5. call invalidate
			c.Invalidate(storagePath)

			require.EventuallyWithT(t, func(collect *assert.CollectT) {
				c.mountsLock.RLock()
				defer c.mountsLock.RUnlock()
				require.Equal(collect, mountTableCount, len(c.mounts.Entries), "expected mount table to be back at original size")
				require.EqualValues(t, 1, cleanCallCount.Load(), "expected one cleanup call")
			}, 10*time.Second, 10*time.Millisecond)

			require.EqualValues(t, 1, factoryCallCount.Load(), "expected factory to be called exactly once")

			// 6. verify 404
			triggerReadCall(t, "unsupported path")

			// 7. Manipulate mount table in storage: restore mount
			testCore_Invalidate_sneakValueAroundCache(t, c, storageEntry)

			// 8. call invalidate
			c.Invalidate(storagePath)

			require.EventuallyWithT(t, func(collect *assert.CollectT) {
				c.mountsLock.RLock()
				defer c.mountsLock.RUnlock()
				require.Equal(collect, mountTableCount+1, len(c.mounts.Entries), "expected mount table to grew by one")
				require.EqualValues(collect, 2, factoryCallCount.Load(), "expected factory to be called exactly twice")
				triggerReadCall(collect)
			}, 10*time.Second, 10*time.Millisecond)
			require.EqualValues(t, 2, readCallCount.Load(), "expected two read calls")

			// 9. Manipulate mount table in storage: taint mount
			mountEntry := new(MountEntry)
			require.NoError(t, jsonutil.DecodeJSON(storageEntry.Value, mountEntry))
			mountEntry.Tainted = true

			updatedData, err := jsonutil.EncodeJSON(mountEntry)
			require.NoError(t, err)

			testCore_Invalidate_sneakValueAroundCache(t, c, &logical.StorageEntry{
				Key:   storagePath,
				Value: updatedData,
			})

			// 10. call invalidate
			c.Invalidate(storagePath)

			require.EventuallyWithT(t, func(collect *assert.CollectT) {
				triggerReadCall(collect, "unsupported path")
			}, 10*time.Second, 10*time.Millisecond)

			// 11. Manipulate mount table in storage: untaint and allow header
			mountEntry.Tainted = false
			mountEntry.Config.AllowedResponseHeaders = []string{"Test-Header"}

			updatedData, err = jsonutil.EncodeJSON(mountEntry)
			require.NoError(t, err)

			testCore_Invalidate_sneakValueAroundCache(t, c, &logical.StorageEntry{
				Key:   storagePath,
				Value: updatedData,
			})

			// 12. call invalidate
			c.Invalidate(storagePath)

			require.EventuallyWithT(t, func(collect *assert.CollectT) {
				resp := testCore_Invalidate_handleRequest(collect, ctx, c, &logical.Request{
					Operation:   logical.ReadOperation,
					ClientToken: root,
					Path:        "my-kv-mount",
				})
				require.Equal(collect, map[string][]string{
					"Test-Header": {"test-value"},
				}, resp.Headers)
			}, 10*time.Second, 10*time.Millisecond)

			// 13. Manipulate mount table in storage: change kv version
			mountEntry.Options["version"] = "2"

			updatedData, err = jsonutil.EncodeJSON(mountEntry)
			require.NoError(t, err)

			testCore_Invalidate_sneakValueAroundCache(t, c, &logical.StorageEntry{
				Key:   storagePath,
				Value: updatedData,
			})

			// 14. call invalidate
			c.Invalidate(storagePath)

			require.EventuallyWithT(t, func(collect *assert.CollectT) {
				require.EqualValues(collect, 3, factoryCallCount.Load(), "expected factory to be called exactly thrice")
				triggerReadCall(collect)
			}, 10*time.Second, 10*time.Millisecond)
		})
	}
}

func TestCore_Invalidate_SecretMount_NonTransactional(t *testing.T) {
	t.Parallel()
	testCases := map[string]func(t *testing.T, c *Core) context.Context{
		"global": func(t *testing.T, c *Core) context.Context {
			return namespace.RootContext(t.Context())
		},

		"local": func(t *testing.T, c *Core) context.Context {
			ns := &namespace.Namespace{
				ID:   "ns",
				Path: "ns",
			}
			TestCoreCreateNamespaces(t, c, ns)

			return namespace.ContextWithNamespace(t.Context(), ns)
		},
	}

	for name, init := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			physical, err := inmem.NewInmem(map[string]string{
				"disable_transactions": "true",
			}, logger)
			require.NoError(t, err)
			c, _, root := TestCoreUnsealedWithConfig(t, &CoreConfig{
				Physical: physical,
			})

			ctx := init(t, c)

			// 1. Inject a dummy factory
			var factoryCallCount, cleanCallCount, readCallCount atomic.Int32
			c.logicalBackends["kv"] = func(ctx context.Context, config *logical.BackendConfig) (logical.Backend, error) {
				factoryCallCount.Add(1)
				b := new(framework.Backend)
				b.Clean = func(_ context.Context) {
					cleanCallCount.Add(1)
				}
				b.Paths = []*framework.Path{{
					Pattern: ".*",
					Callbacks: map[logical.Operation]framework.OperationFunc{
						logical.ReadOperation: func(context.Context, *logical.Request, *framework.FieldData) (*logical.Response, error) {
							readCallCount.Add(1)
							return &logical.Response{Headers: map[string][]string{
								"Test-Header": {"test-value"},
							}}, nil
						},
					},
				}}
				return b, b.Setup(ctx, config)
			}

			mountTableCount := len(c.mounts.Entries)

			// 2. Enable mount kv store
			registerReq := &logical.Request{
				Operation:   logical.UpdateOperation,
				ClientToken: root,
				Path:        "sys/mounts/my-kv-mount",
				Data: map[string]any{
					"type": "kv",
				},
			}
			testCore_Invalidate_handleRequest(t, ctx, c, registerReq)

			require.EqualValues(t, 1, factoryCallCount.Load(), "expected factory to be called exactly once")
			require.Equal(t, mountTableCount+1, len(c.mounts.Entries), "expected mount table to grew by one")

			storagePath := "core/mounts"

			triggerReadCall := func(collect require.TestingT, expectedErrors ...string) {
				testCore_Invalidate_handleRequest(collect, ctx, c, &logical.Request{
					Operation:   logical.ReadOperation,
					ClientToken: root,
					Path:        "my-kv-mount",
				}, expectedErrors...)
			}
			triggerReadCall(t)
			require.EqualValues(t, 1, readCallCount.Load(), "expected one read call")

			// 3. Manipulate mount table in storage: delete entry from mount table
			storageEntry, err := c.barrier.Get(ctx, storagePath)
			require.NoError(t, err)
			require.NotNil(t, storageEntry, "expected mount table to be written at %s", storagePath)

			mountTable := new(MountTable)
			require.NoError(t, jsonutil.DecodeJSON(storageEntry.Value, mountTable))

			require.Equal(t, "my-kv-mount/", mountTable.Entries[len(mountTable.Entries)-1].Path)
			mountTable.Entries = mountTable.Entries[:len(mountTable.Entries)-1]

			updatedData, err := jsonutil.EncodeJSON(mountTable)
			require.NoError(t, err)

			testCore_Invalidate_sneakValueAroundCache(t, c, &logical.StorageEntry{
				Key:   storagePath,
				Value: updatedData,
			})

			// 4. call invalidate
			c.Invalidate(storagePath)

			require.EventuallyWithT(t, func(collect *assert.CollectT) {
				c.mountsLock.RLock()
				defer c.mountsLock.RUnlock()
				require.Equal(collect, mountTableCount, len(c.mounts.Entries), "expected mount table to be back at original size")
				require.EqualValues(t, 1, cleanCallCount.Load(), "expected one cleanup call")
			}, 10*time.Second, 10*time.Millisecond)

			require.EqualValues(t, 1, factoryCallCount.Load(), "expected factory to be called exactly once")

			// 5. verify 404
			triggerReadCall(t, "unsupported path")

			// 6. Manipulate mount table in storage: restore mount
			testCore_Invalidate_sneakValueAroundCache(t, c, storageEntry)

			// 7. call invalidate
			c.Invalidate(storagePath)

			require.EventuallyWithT(t, func(collect *assert.CollectT) {
				c.mountsLock.RLock()
				defer c.mountsLock.RUnlock()
				require.Equal(collect, mountTableCount+1, len(c.mounts.Entries), "expected mount table to grew by one")
				require.EqualValues(collect, 2, factoryCallCount.Load(), "expected factory to be called exactly twice")
				triggerReadCall(collect)
			}, 10*time.Second, 10*time.Millisecond)
			require.EqualValues(t, 2, readCallCount.Load(), "expected two read calls")
		})
	}
}

func TestCore_Invalidate_AuthMount(t *testing.T) {
	t.Parallel()
	testCases := map[string]func(t *testing.T, c *Core) (nsPrefix string, ctx context.Context){
		"global": func(t *testing.T, c *Core) (nsPrefix string, ctx context.Context) {
			return "", namespace.RootContext(t.Context())
		},

		"local": func(t *testing.T, c *Core) (nsPrefix string, ctx context.Context) {
			ns := &namespace.Namespace{
				ID:   "ns",
				Path: "ns",
			}
			TestCoreCreateNamespaces(t, c, ns)

			return fmt.Sprintf("namespaces/%s/", ns.UUID), namespace.ContextWithNamespace(t.Context(), ns)
		},
	}

	for name, init := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			c, _, root := TestCoreUnsealed(t)
			nsPrefix, ctx := init(t, c)

			// 1. Inject a dummy factory
			var factoryCallCount, cleanCallCount, readCallCount atomic.Int32
			c.credentialBackends["dummy"] = func(ctx context.Context, config *logical.BackendConfig) (logical.Backend, error) {
				factoryCallCount.Add(1)
				b := new(framework.Backend)
				b.Clean = func(_ context.Context) {
					cleanCallCount.Add(1)
				}
				b.Paths = []*framework.Path{{
					Pattern: ".*",
					Callbacks: map[logical.Operation]framework.OperationFunc{
						logical.ReadOperation: func(context.Context, *logical.Request, *framework.FieldData) (*logical.Response, error) {
							t.Log("got a call")
							readCallCount.Add(1)
							return &logical.Response{}, nil
						},
					},
				}}
				b.BackendType = logical.TypeCredential
				return b, b.Setup(ctx, config)
			}

			mountTableCount := len(c.auth.Entries)

			// 2. Enable mount dummy auth
			registerReq := &logical.Request{
				Operation:   logical.UpdateOperation,
				ClientToken: root,
				Path:        "sys/auth/my-auth",
				Data: map[string]any{
					"type": "dummy",
				},
			}
			testCore_Invalidate_handleRequest(t, ctx, c, registerReq)

			require.EqualValues(t, 1, factoryCallCount.Load(), "expected factory to be called exactly once")
			require.Equal(t, mountTableCount+1, len(c.auth.Entries), "expected mount table to grew by one")

			// 3. Get the UUID
			readReq := &logical.Request{
				Operation:   logical.ReadOperation,
				ClientToken: root,
				Path:        "sys/auth/my-auth",
			}
			resp := testCore_Invalidate_handleRequest(t, ctx, c, readReq)

			uuid := resp.Data["uuid"].(string)
			storagePath := path.Join(nsPrefix, "core/auth", uuid)

			callLogin := func(collect require.TestingT, expectedErrors ...string) {
				testCore_Invalidate_handleRequest(collect, ctx, c, &logical.Request{
					Operation:   logical.ReadOperation,
					ClientToken: root,
					Path:        "auth/my-auth",
				}, expectedErrors...)
			}
			callLogin(t)
			require.EqualValues(t, 1, readCallCount.Load(), "expected one read call")

			// 4. Manipulate mount table in storage: delete storageEntry
			storageEntry, err := c.barrier.Get(ctx, storagePath)
			require.NoError(t, err)
			require.NotNil(t, storageEntry, "expected mount entry to be written at %s", storagePath)

			testCore_Invalidate_sneakValueAroundCacheDelete(t, c, storagePath)

			// 5. call invalidate
			c.Invalidate(storagePath)

			require.EventuallyWithT(t, func(collect *assert.CollectT) {
				c.authLock.RLock()
				defer c.authLock.RUnlock()
				require.Equal(collect, mountTableCount, len(c.auth.Entries), "expected mount table to be back at original size")
				require.EqualValues(t, 1, cleanCallCount.Load(), "expected one cleanup call")
			}, 10*time.Second, 10*time.Millisecond)

			require.EqualValues(t, 1, factoryCallCount.Load(), "expected factory to be called exactly once")

			// 6. verify 404
			callLogin(t, "unsupported path")

			// 7. Manipulate mount table in storage: restore mount
			testCore_Invalidate_sneakValueAroundCache(t, c, storageEntry)

			// 8. call invalidate
			c.Invalidate(storagePath)

			require.EventuallyWithT(t, func(collect *assert.CollectT) {
				c.authLock.RLock()
				defer c.authLock.RUnlock()
				require.Equal(collect, mountTableCount+1, len(c.auth.Entries), "expected mount table to grew by one")
				require.EqualValues(collect, 2, factoryCallCount.Load(), "expected factory to be called exactly twice")
				callLogin(collect)
			}, 10*time.Second, 10*time.Millisecond)
			require.EqualValues(t, 2, readCallCount.Load(), "expected two read calls")

			// 9. Manipulate mount table in storage: taint mount
			mountEntry := new(MountEntry)
			require.NoError(t, jsonutil.DecodeJSON(storageEntry.Value, mountEntry))
			mountEntry.Tainted = true

			updatedData, err := jsonutil.EncodeJSON(mountEntry)
			require.NoError(t, err)

			testCore_Invalidate_sneakValueAroundCache(t, c, &logical.StorageEntry{
				Key:   storagePath,
				Value: updatedData,
			})

			// 10. call invalidate
			c.Invalidate(storagePath)

			require.EventuallyWithT(t, func(collect *assert.CollectT) {
				callLogin(collect, "unsupported path")
			}, 10*time.Second, 10*time.Millisecond)
		})
	}
}

func TestCore_Invalidate_AuthMount_NonTransactional(t *testing.T) {
	t.Parallel()
	testCases := map[string]func(t *testing.T, c *Core) context.Context{
		"global": func(t *testing.T, c *Core) context.Context {
			return namespace.RootContext(t.Context())
		},

		"local": func(t *testing.T, c *Core) context.Context {
			ns := &namespace.Namespace{
				ID:   "ns",
				Path: "ns",
			}
			TestCoreCreateNamespaces(t, c, ns)

			return namespace.ContextWithNamespace(t.Context(), ns)
		},
	}

	for name, init := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			physical, err := inmem.NewInmem(map[string]string{
				"disable_transactions": "true",
			}, logger)
			require.NoError(t, err)
			c, _, root := TestCoreUnsealedWithConfig(t, &CoreConfig{
				Physical: physical,
			})
			ctx := init(t, c)

			// 1. Inject a dummy factory
			var factoryCallCount, cleanCallCount, readCallCount atomic.Int32
			c.credentialBackends["dummy"] = func(ctx context.Context, config *logical.BackendConfig) (logical.Backend, error) {
				factoryCallCount.Add(1)
				b := new(framework.Backend)
				b.Clean = func(_ context.Context) {
					cleanCallCount.Add(1)
				}
				b.Paths = []*framework.Path{{
					Pattern: ".*",
					Callbacks: map[logical.Operation]framework.OperationFunc{
						logical.ReadOperation: func(context.Context, *logical.Request, *framework.FieldData) (*logical.Response, error) {
							t.Log("got a call")
							readCallCount.Add(1)
							return &logical.Response{}, nil
						},
					},
				}}
				b.BackendType = logical.TypeCredential
				return b, b.Setup(ctx, config)
			}

			mountTableCount := len(c.auth.Entries)

			// 2. Enable mount dummy auth
			registerReq := &logical.Request{
				Operation:   logical.UpdateOperation,
				ClientToken: root,
				Path:        "sys/auth/my-auth",
				Data: map[string]any{
					"type": "dummy",
				},
			}
			testCore_Invalidate_handleRequest(t, ctx, c, registerReq)

			require.EqualValues(t, 1, factoryCallCount.Load(), "expected factory to be called exactly once")
			require.Equal(t, mountTableCount+1, len(c.auth.Entries), "expected mount table to grew by one")

			storagePath := "core/auth"

			callLogin := func(collect require.TestingT, expectedErrors ...string) {
				testCore_Invalidate_handleRequest(collect, ctx, c, &logical.Request{
					Operation:   logical.ReadOperation,
					ClientToken: root,
					Path:        "auth/my-auth",
				}, expectedErrors...)
			}
			callLogin(t)
			require.EqualValues(t, 1, readCallCount.Load(), "expected one read call")

			// 3. Manipulate mount table in storage: delete entry from mount table
			storageEntry, err := c.barrier.Get(ctx, storagePath)
			require.NoError(t, err)
			require.NotNil(t, storageEntry, "expected mount table to be written at %s", storagePath)

			mountTable := new(MountTable)
			require.NoError(t, jsonutil.DecodeJSON(storageEntry.Value, mountTable))

			require.Equal(t, "my-auth/", mountTable.Entries[len(mountTable.Entries)-1].Path)
			mountTable.Entries = mountTable.Entries[:len(mountTable.Entries)-1]

			updatedData, err := jsonutil.EncodeJSON(mountTable)
			require.NoError(t, err)

			testCore_Invalidate_sneakValueAroundCache(t, c, &logical.StorageEntry{
				Key:   storagePath,
				Value: updatedData,
			})

			// 4. call invalidate
			c.Invalidate(storagePath)

			require.EventuallyWithT(t, func(collect *assert.CollectT) {
				c.authLock.RLock()
				defer c.authLock.RUnlock()
				require.Equal(collect, mountTableCount, len(c.auth.Entries), "expected mount table to be back at original size")
				require.EqualValues(t, 1, cleanCallCount.Load(), "expected one cleanup call")
			}, 10*time.Second, 10*time.Millisecond)

			require.EqualValues(t, 1, factoryCallCount.Load(), "expected factory to be called exactly once")

			// 5. verify 404
			callLogin(t, "unsupported path")

			// 6. Manipulate mount table in storage: restore mount
			testCore_Invalidate_sneakValueAroundCache(t, c, storageEntry)

			// 7. call invalidate
			c.Invalidate(storagePath)

			require.EventuallyWithT(t, func(collect *assert.CollectT) {
				c.authLock.RLock()
				defer c.authLock.RUnlock()
				require.Equal(collect, mountTableCount+1, len(c.auth.Entries), "expected mount table to grew by one")
				require.EqualValues(collect, 2, factoryCallCount.Load(), "expected factory to be called exactly twice")
				callLogin(collect)
			}, 10*time.Second, 10*time.Millisecond)
			require.EqualValues(t, 2, readCallCount.Load(), "expected two read calls")

			// 8. Manipulate mount table in storage: taint mount
			require.NoError(t, jsonutil.DecodeJSON(storageEntry.Value, mountTable))
			mountTable.Entries[len(mountTable.Entries)-1].Tainted = true

			updatedData, err = jsonutil.EncodeJSON(mountTable)
			require.NoError(t, err)

			testCore_Invalidate_sneakValueAroundCache(t, c, &logical.StorageEntry{
				Key:   storagePath,
				Value: updatedData,
			})

			// 9. call invalidate
			c.Invalidate(storagePath)

			require.EventuallyWithT(t, func(collect *assert.CollectT) {
				callLogin(collect, "unsupported path")
			}, 10*time.Second, 10*time.Millisecond)
		})
	}
}
