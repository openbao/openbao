// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"path"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-test/deep"
	"github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/helper/jsonutil"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/sdk/v2/physical/inmem"
	"github.com/openbao/openbao/v2/internal/audit"
	"github.com/openbao/openbao/v2/internal/command/server"
	"github.com/openbao/openbao/v2/internal/helper/namespace"
	"github.com/openbao/openbao/v2/internal/helper/testhelpers/corehelpers"
	"github.com/openbao/openbao/v2/internal/vault/barrier"
	"github.com/openbao/openbao/v2/internal/vault/policy"
	"github.com/openbao/openbao/v2/internal/vault/quotas"
	"github.com/openbao/openbao/v2/internal/vault/routing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func testCore_Invalidate_TestCore(t *testing.T, config *CoreConfig) (*Core, string) {
	var c *Core
	var root string

	if config != nil {
		c, _, root = TestCoreUnsealedWithConfig(t, config)
	} else {
		c, _, root = TestCoreUnsealed(t)
	}

	// Fake being a standby for the purpose of testing invalidation; we ignore
	// events on the active node and directly modify storage, which is already
	// hooked.
	c.standby.Store(true)
	c.invalidations.Track()

	c.stateLock.RLock()
	c.invalidations.Start(t.Context())
	c.stateLock.RUnlock()

	return c, root
}

func testCore_Invalidate_sneakValueAroundCache(t *testing.T, ctx context.Context, c *Core, entry *logical.StorageEntry) {
	t.Helper()

	// we briefly disable the physical cache, this will put the value into the backing storage, but not update the cache
	c.physicalCache.SetEnabled(false)
	defer c.physicalCache.SetEnabled(true)

	ns, err := namespace.FromContext(ctx)
	require.NoError(t, err)

	view := c.NamespaceView(ns)
	require.NoError(t, view.Put(ctx, entry))
}

func testCore_Invalidate_sneakValueAroundCacheDelete(t *testing.T, ctx context.Context, c *Core, key string) {
	t.Helper()

	// we briefly disable the physical cache, this will put the value into the backing storage, but not update the cache
	c.physicalCache.SetEnabled(false)
	defer c.physicalCache.SetEnabled(true)

	ns, err := namespace.FromContext(ctx)
	require.NoError(t, err)

	view := c.NamespaceView(ns)
	require.NoError(t, logical.ClearView(ctx, view.SubView(key)))
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
	c, root := testCore_Invalidate_TestCore(t, nil)
	rootCtx := namespace.RootContext(t.Context())
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

	testCore_Invalidate_sneakValueAroundCache(t, rootCtx, c, newEntry)

	// 2.2 add mount to namespace
	newEntry, err = logical.StorageEntryJSON("namespaces/"+ns.UUID+"/core/mounts/666666666-6666-6666-6666-6666666666666", routing.MountEntry{
		Table:       "mounts",
		Type:        "kv",
		Path:        "my-path",
		UUID:        "666666666-6666-6666-6666-6666666666666",
		Accessor:    "mount_666",
		NamespaceID: ns.ID,
	})
	require.NoError(t, err)
	testCore_Invalidate_sneakValueAroundCache(t, rootCtx, c, newEntry)
	mountPath := "ns/my-path"

	// 3. Invalidate Path
	require.NoError(t, c.invalidateSynchronous(storagePath))

	// 4. Check cache was properly invalidated
	// 4.1 Validate custom metadata
	req := logical.TestRequest(t, logical.ReadOperation, "sys/namespaces/ns")
	req.ClientToken = root
	resp := testCore_Invalidate_handleRequest(t, rootCtx, c, req)

	if diff := deep.Equal(resp.Data["custom_metadata"], map[string]string{
		"testkey": "updated value",
	}); diff != nil {
		t.Error(diff)
	}

	// 4.2 validate kv was mounted
	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		req = logical.TestRequest(t, logical.ListOperation, mountPath)
		req.ClientToken = root
		resp = testCore_Invalidate_handleRequest(collect, rootCtx, c, req)
		require.NotNil(collect, resp)
	}, 10*time.Second, 10*time.Millisecond)

	// 5. Manipulate Storage: delete namespace
	testCore_Invalidate_sneakValueAroundCacheDelete(t, rootCtx, c, storagePath)
	testCore_Invalidate_sneakValueAroundCacheDelete(t, rootCtx, c, "namespaces/"+ns.UUID)

	// 6. Invalidate Path
	require.NoError(t, c.invalidateSynchronous(storagePath))

	// 7. Check cache was properly invalidated
	// 7.1 namespace should be gone
	req = logical.TestRequest(t, logical.ReadOperation, "sys/namespaces/ns")
	req.ClientToken = root
	resp = testCore_Invalidate_handleRequest(t, rootCtx, c, req)

	require.Nil(t, resp)

	// 7.2 mount should be gone
	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		req = logical.TestRequest(t, logical.ListOperation, mountPath)
		req.ClientToken = root
		resp = testCore_Invalidate_handleRequest(collect, rootCtx, c, req, "unsupported path")
	}, 10*time.Second, 10*time.Millisecond)
}

func TestCore_Invalidate_Namespaces_NonTransactional(t *testing.T) {
	t.Parallel()

	physical, err := inmem.NewInmem(map[string]string{
		"disable_transactions": "true",
	}, logger)
	require.NoError(t, err)
	c, root := testCore_Invalidate_TestCore(t, &CoreConfig{
		Physical: physical,
	})
	rootCtx := namespace.RootContext(t.Context())

	// 1. Create some namespace to populate cache
	ns := &namespace.Namespace{
		ID:   "ns",
		Path: "ns",
		CustomMetadata: map[string]string{
			"testkey": "initial value",
		},
	}

	TestCoreCreateNamespaces(t, c, ns)
	nsCtx := namespace.ContextWithNamespace(rootCtx, ns)

	// 2. Manipulate Storage
	// 2.1 Inject custom metadata into namespace
	clone := *ns
	clone.CustomMetadata["testkey"] = "updated value"

	storagePath := "core/namespaces/" + ns.UUID
	newEntry, err := logical.StorageEntryJSON(storagePath, clone)
	require.NoError(t, err)

	testCore_Invalidate_sneakValueAroundCache(t, rootCtx, c, newEntry)

	// 2.2 add mount to namespace
	view := c.NamespaceView(ns)
	storageEntry, err := view.Get(nsCtx, coreMountConfigPath)
	require.NoError(t, err)
	require.NotNil(t, storageEntry, "expected mount table to be written at %s", storagePath)

	mountTable := new(routing.MountTable)
	require.NoError(t, jsonutil.DecodeJSON(storageEntry.Value, mountTable))

	mountTable.Entries = append(mountTable.Entries, &routing.MountEntry{
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

	testCore_Invalidate_sneakValueAroundCache(t, nsCtx, c, &logical.StorageEntry{
		Key:   coreMountConfigPath,
		Value: updatedData,
	})

	// 3. Invalidate Path
	require.NoError(t, c.invalidateSynchronous(storagePath))

	// 4. Check cache was properly invalidated
	// 4.1 Validate custom metadata
	req := logical.TestRequest(t, logical.ReadOperation, "sys/namespaces/ns")
	req.ClientToken = root
	resp := testCore_Invalidate_handleRequest(t, rootCtx, c, req)

	if diff := deep.Equal(resp.Data["custom_metadata"], map[string]string{
		"testkey": "updated value",
	}); diff != nil {
		t.Error(diff)
	}

	// 4.2 validate kv was mounted
	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		req = logical.TestRequest(t, logical.ListOperation, mountPath)
		req.ClientToken = root
		resp = testCore_Invalidate_handleRequest(collect, rootCtx, c, req)
		require.NotNil(collect, resp)
	}, 10*time.Second, 10*time.Millisecond)
}

func TestCore_Invalidate_Policy(t *testing.T) {
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

		"unsealed": func(t *testing.T, c *Core) context.Context {
			ns := &namespace.Namespace{
				ID:   "unsealed",
				Path: "unsealed",
			}
			TestCoreCreateUnsealedNamespaces(t, c, ns)

			return namespace.ContextWithNamespace(t.Context(), ns)
		},
	}

	for name, init := range testCases {
		t.Run(name, func(t *testing.T) {
			c, root := testCore_Invalidate_TestCore(t, nil)
			ctx := init(t, c)

			// 1. Create some policy to populate cache
			storagePath := "sys/policy/test-policy"
			req := logical.TestRequest(t, logical.CreateOperation, storagePath)
			req.ClientToken = root
			req.Data = map[string]any{
				"policy": `
					path "test/path/*" {
						capabilities = ["read"]
					}
			`,
			}
			testCore_Invalidate_handleRequest(t, ctx, c, req)

			// 2. Manipulate Storage
			pol, err := c.policyStore.GetPolicy(ctx, "test-policy", policy.TypeACL)
			require.NoError(t, err)

			clone := pol.ShallowClone()
			clone.Expiration = time.Date(2099, 1, 1, 12, 0, 0, 0, time.UTC)

			newEntry, err := logical.StorageEntryJSON(storagePath, clone)
			require.NoError(t, err)

			testCore_Invalidate_sneakValueAroundCache(t, ctx, c, newEntry)

			ns, err := namespace.FromContext(ctx)
			require.NoError(t, err)

			if ns.ID != namespace.RootNamespaceID {
				storagePath = path.Join(barrier.NamespacePrefix, ns.UUID, storagePath)
			}

			// 3. Invalidate Path
			require.NoError(t, c.invalidateSynchronous(storagePath))

			// 4. Check cache was properly invalidated
			updatedPolicy, err := c.policyStore.GetPolicy(ctx, "test-policy", policy.TypeACL)
			require.NoError(t, err)

			require.Equal(t, clone.Expiration, updatedPolicy.Expiration)
		})
	}
}

func TestCore_Invalidate_Quota(t *testing.T) {
	t.Parallel()
	c, root := testCore_Invalidate_TestCore(t, nil)
	rootCtx := namespace.RootContext(t.Context())

	// 1. Create quota to populate cache
	req := logical.TestRequest(t, logical.CreateOperation, "sys/quotas/rate-limit/test-quota")
	req.ClientToken = root
	req.Data = map[string]any{
		"rate":     3.141,
		"interval": "42s",
	}
	testCore_Invalidate_handleRequest(t, rootCtx, c, req)

	// 2. Manipulate storage: write updated quota
	quota, err := c.quotaManager.QuotaByName("rate-limit", "test-quota")
	require.NoError(t, err)

	clone := quota.Clone().(*quotas.RateLimitQuota)
	clone.Interval = 1 * time.Second

	newEntry, err := logical.StorageEntryJSON("sys/quotas/rate-limit/test-quota", clone)
	require.NoError(t, err)

	testCore_Invalidate_sneakValueAroundCache(t, rootCtx, c, newEntry)

	// 3. Invalidate Path
	require.NoError(t, c.invalidateSynchronous(newEntry.Key))

	// 4. Check cache: quota updated
	req = logical.TestRequest(t, logical.ReadOperation, newEntry.Key)
	req.ClientToken = root

	resp := testCore_Invalidate_handleRequest(t, rootCtx, c, req)
	require.Equal(t, 1, resp.Data["interval"])

	// 5. Delete quota
	testCore_Invalidate_sneakValueAroundCacheDelete(t, rootCtx, c, newEntry.Key)

	// 6. Invalidate Path
	require.NoError(t, c.invalidateSynchronous(newEntry.Key))

	// 7. Check cache: quota deleted
	req = logical.TestRequest(t, logical.ReadOperation, newEntry.Key)
	req.ClientToken = root
	resp = testCore_Invalidate_handleRequest(t, rootCtx, c, req)

	require.Nil(t, resp)

	// 8. Manipulate quota in storage: restore quota
	testCore_Invalidate_sneakValueAroundCache(t, rootCtx, c, newEntry)

	// 9. Invalidate path
	require.NoError(t, c.invalidateSynchronous(newEntry.Key))

	// 10. Check cache: quota brought back
	resp = testCore_Invalidate_handleRequest(t, rootCtx, c, req)
	require.NotNil(t, resp.Data)
	require.Equal(t, 1, resp.Data["interval"])
}

func TestCore_Upgrade_Keyring(t *testing.T) {
	t.Parallel()
	testCases := map[string]func(t *testing.T, c *Core) context.Context{
		"global": func(t *testing.T, c *Core) context.Context {
			return namespace.RootContext(t.Context())
		},

		"unsealed": func(t *testing.T, c *Core) context.Context {
			ns := &namespace.Namespace{
				ID:   "unsealed",
				Path: "unsealed",
			}
			TestCoreCreateUnsealedNamespaces(t, c, ns)

			return namespace.ContextWithNamespace(t.Context(), ns)
		},
	}

	for name, init := range testCases {
		t.Run(name, func(t *testing.T) {
			c, root := testCore_Invalidate_TestCore(t, nil)
			ctx := init(t, c)

			ns, err := namespace.FromContext(ctx)
			require.NoError(t, err)

			// 1. Retrieve key status information.
			req := logical.TestRequest(t, logical.ReadOperation, "sys/key-status")
			req.ClientToken = root
			resp := testCore_Invalidate_handleRequest(t, ctx, c, req)
			require.NotNil(t, resp)
			prevTerm := resp.Data["term"].(int)
			require.Equal(t, 1, prevTerm)

			// 2. Manipulate Storage.
			b := c.sealManager.NamespaceBarrier(ns.Path)
			require.NoError(t, err)

			path := fmt.Sprintf("core/upgrade/%d", prevTerm)
			keyring, err := b.Keyring()
			require.NoError(t, err)

			buf, err := keyring.TermKey(uint32(prevTerm)).Serialize()
			require.NoError(t, err)
			value, err := b.Encrypt(ctx, path, buf)
			require.NoError(t, err)

			newTerm, err := b.Rotate(ctx)
			require.NoError(t, err)
			require.Equal(t, uint32(prevTerm+1), newTerm)

			testCore_Invalidate_sneakValueAroundCache(t, ctx, c, &logical.StorageEntry{
				Key:   strings.TrimPrefix(path, c.NamespaceView(ns).Prefix()),
				Value: value,
			})

			// 3. Invalidate path.
			require.NoError(t, c.invalidateSynchronous(path))

			// 4. Check cache was properly invalidated.
			req = logical.TestRequest(t, logical.ReadOperation, "sys/key-status")
			req.ClientToken = root
			resp = testCore_Invalidate_handleRequest(t, ctx, c, req)
			require.Equal(t, prevTerm+1, resp.Data["term"].(int))
		})
	}
}

func TestCore_Invalidate_LoginMFA(t *testing.T) {
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

		"unsealed": func(t *testing.T, c *Core) context.Context {
			ns := &namespace.Namespace{
				ID:   "unsealed",
				Path: "unsealed",
			}
			TestCoreCreateUnsealedNamespaces(t, c, ns)

			return namespace.ContextWithNamespace(t.Context(), ns)
		},
	}

	for name, init := range testCases {
		t.Run(name, func(t *testing.T) {
			c, root := testCore_Invalidate_TestCore(t, nil)
			ctx := init(t, c)

			ns, err := namespace.FromContext(ctx)
			require.NoError(t, err)

			// 1. Create a login MFA to populate the cache.
			req := logical.TestRequest(t, logical.CreateOperation, "identity/mfa/method/totp")
			req.ClientToken = root
			req.Data = map[string]any{
				"method_name": "testing",
				"issuer":      "OpenBao",
			}
			resp := testCore_Invalidate_handleRequest(t, ctx, c, req)
			require.NotNil(t, resp)
			require.Contains(t, resp.Data, "method_id")
			path := resp.Data["method_id"].(string)

			// 2. Manipulate Storage
			barrierView := c.NamespaceView(ns).SubView(barrier.SystemBarrierPrefix + loginMFAConfigPrefix)
			mfa, err := c.loginMFABackend.getMFAConfig(ctx, path, barrierView)
			require.NoError(t, err)
			require.NotNil(t, mfa)
			require.Equal(t, mfa.Name, "testing")

			clone, err := mfa.Clone()
			require.NoError(t, err)

			clone.Name = "my-custom-name"

			fullPath := barrierView.Prefix() + path
			newEntry, err := proto.Marshal(clone)
			require.NoError(t, err)

			writePath := strings.TrimPrefix(fullPath, c.NamespaceView(ns).Prefix())
			testCore_Invalidate_sneakValueAroundCache(t, ctx, c, &logical.StorageEntry{
				Key:   writePath,
				Value: newEntry,
			})

			// 3. Invalidate path
			require.NoError(t, c.invalidateSynchronous(fullPath))

			// 4. Check cache was properly invalidated
			req = logical.TestRequest(t, logical.ReadOperation, "identity/mfa/method/totp/"+path)
			req.ClientToken = root

			resp = testCore_Invalidate_handleRequest(t, ctx, c, req)
			require.Contains(t, resp.Data, "name")
			require.Equal(t, "my-custom-name", resp.Data["name"])
		})
	}
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

		"unsealed": func(t *testing.T, c *Core) (nsPrefix string, ctx context.Context) {
			ns := &namespace.Namespace{
				ID:   "unsealed",
				Path: "unsealed",
			}
			TestCoreCreateNamespaces(t, c, ns)

			return fmt.Sprintf("namespaces/%s/", ns.UUID), namespace.ContextWithNamespace(t.Context(), ns)
		},
	}

	for name, init := range testCases {
		t.Run(name, func(t *testing.T) {
			c, root := testCore_Invalidate_TestCore(t, nil)
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
			require.NoError(t, c.invalidateSynchronous(nsPrefix+"logical/"+uuid+"/foo"))
			require.NoError(t, c.invalidateSynchronous(nsPrefix+"logical/"+uuid+"/bar/bazz"))

			// 5. Check callback was called
			assert.Equal(t, []string{"foo", "bar/bazz"}, invalidatedKey)
		})
	}
}

func TestCore_Invalidate_Audit(t *testing.T) {
	t.Parallel()
	c, root := testCore_Invalidate_TestCore(t, &CoreConfig{
		RawConfig: &server.Config{UnsafeAllowAPIAuditCreation: true, AllowAuditLogPrefixing: true},
	})
	rootCtx := namespace.RootContext(t.Context())

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

	testCore_Invalidate_handleRequest(t, rootCtx, c, registerReq)

	require.EqualValues(t, 1, callCount.Load(), "expected audit factory to be called exactly once")

	// 3. Trigger audit event
	triggerAuditEvent := func() {
		testCore_Invalidate_handleRequest(t, rootCtx, c, &logical.Request{
			Operation:   logical.ReadOperation,
			ClientToken: root,
			Path:        "secret/kv/dummy",
		})
	}
	triggerAuditEvent()

	require.Len(t, currentBackend.Req, 1, "expected 1 audit request event")

	// 4. Manipulate audit table in storage: delete audit
	entry, err := c.barrier.Get(rootCtx, "core/audit")
	require.NoError(t, err)
	require.NotNil(t, entry, "expected audit table to be written")

	auditTable := &routing.MountTable{}
	require.NoError(t, jsonutil.DecodeJSON(entry.Value, auditTable), "failed to decode audit table")

	auditTable.Entries = make([]*routing.MountEntry, 0)

	data, err := jsonutil.EncodeJSON(auditTable)
	require.NoError(t, err)

	testCore_Invalidate_sneakValueAroundCache(t, rootCtx, c, &logical.StorageEntry{
		Key:   "core/audit",
		Value: data,
	})

	// 5. call invalidate
	require.NoError(t, c.invalidateSynchronous("core/audit"))

	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		require.Equal(collect, 0, c.auditBroker.Count())
	}, 10*time.Second, 10*time.Millisecond)

	require.EqualValues(t, 1, callCount.Load(), "expected audit factory to be called exactly once")

	// 6. Trigger audit event (but audit should be disabled)
	triggerAuditEvent()

	require.Len(t, currentBackend.Req, 1, "expected still 1 audit request event")

	// 7. Manipulate audit table in storage: restore audit
	testCore_Invalidate_sneakValueAroundCache(t, rootCtx, c, entry)

	// 8. call invalidate
	require.NoError(t, c.invalidateSynchronous("core/audit"))

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

		"unsealed": func(t *testing.T, c *Core) context.Context {
			ns := &namespace.Namespace{
				ID:   "ns",
				Path: "ns",
			}
			TestCoreCreateUnsealedNamespaces(t, c, ns)

			return namespace.ContextWithNamespace(t.Context(), ns)
		},
	}

	for name, init := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			c, root := testCore_Invalidate_TestCore(t, nil)
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

			// 3. Get mount UUID
			readReq := &logical.Request{
				Operation:   logical.ReadOperation,
				ClientToken: root,
				Path:        "sys/mounts/my-kv-mount",
			}
			resp := testCore_Invalidate_handleRequest(t, ctx, c, readReq)
			uuid := resp.Data["uuid"].(string)
			entryPath := path.Join(coreMountConfigPath, uuid)

			triggerReadCall := func(collect require.TestingT, path string, expectedErrors ...string) {
				testCore_Invalidate_handleRequest(collect, ctx, c, &logical.Request{
					Operation:   logical.ReadOperation,
					ClientToken: root,
					Path:        path,
				}, expectedErrors...)
			}
			triggerReadCall(t, "my-kv-mount")
			require.EqualValues(t, 1, readCallCount.Load(), "expected one read call")

			ns, err := namespace.FromContext(ctx)
			require.NoError(t, err)
			view := c.NamespaceView(ns)

			// 4. Manipulate mount table in storage: delete storageEntry
			storageEntry, err := view.Get(ctx, entryPath)
			require.NoError(t, err)
			require.NotNil(t, storageEntry, "expected mount entry to be written at %s", view.Prefix()+entryPath)

			testCore_Invalidate_sneakValueAroundCacheDelete(t, ctx, c, entryPath)

			// 5. call invalidate
			require.NoError(t, c.invalidateSynchronous(view.Prefix()+entryPath))

			require.EventuallyWithT(t, func(collect *assert.CollectT) {
				c.mountsLock.RLock()
				defer c.mountsLock.RUnlock()
				require.Equal(collect, mountTableCount, len(c.mounts.Entries), "expected mount table to be back at original size")
				require.EqualValues(t, 1, cleanCallCount.Load(), "expected one cleanup call")
			}, 10*time.Second, 10*time.Millisecond)

			require.EqualValues(t, 1, factoryCallCount.Load(), "expected factory to be called exactly once")

			// 6. verify 404
			triggerReadCall(t, "my-kv-mount", "unsupported path")

			// 7. Manipulate mount table in storage: restore mount
			testCore_Invalidate_sneakValueAroundCache(t, ctx, c, storageEntry)

			// 8. call invalidate
			require.NoError(t, c.invalidateSynchronous(view.Prefix()+entryPath))

			require.EventuallyWithT(t, func(collect *assert.CollectT) {
				c.mountsLock.RLock()
				defer c.mountsLock.RUnlock()
				require.Equal(collect, mountTableCount+1, len(c.mounts.Entries), "expected mount table to grew by one")
				require.EqualValues(collect, 2, factoryCallCount.Load(), "expected factory to be called exactly twice")
				triggerReadCall(collect, "my-kv-mount")
			}, 10*time.Second, 10*time.Millisecond)
			require.EqualValues(t, 2, readCallCount.Load(), "expected two read calls")

			// 9. Remount secret mount
			require.NoError(t, c.remountSecretsEngine(ctx, c.splitNamespaceAndMountFromPath(ns.Path, "my-kv-mount"), c.splitNamespaceAndMountFromPath(ns.Path, "new-kv-mount")))

			require.EventuallyWithT(t, func(collect *assert.CollectT) {
				triggerReadCall(t, "my-kv-mount", "unsupported path")
				triggerReadCall(t, "new-kv-mount")
			}, 10*time.Second, 10*time.Millisecond)

			// 10. Manipulate mount table in storage: taint mount
			storageEntry, err = view.Get(ctx, entryPath)
			require.NoError(t, err)
			require.NotNil(t, storageEntry, "expected mount entry to be written at %s", view.Prefix()+entryPath)

			mountEntry := new(routing.MountEntry)
			require.NoError(t, jsonutil.DecodeJSON(storageEntry.Value, mountEntry))
			mountEntry.Tainted = true
			updatedData, err := jsonutil.EncodeJSON(mountEntry)
			require.NoError(t, err)

			testCore_Invalidate_sneakValueAroundCache(t, ctx, c, &logical.StorageEntry{
				Key:   entryPath,
				Value: updatedData,
			})

			// 11. call invalidate
			require.NoError(t, c.invalidateSynchronous(view.Prefix()+entryPath))

			require.EventuallyWithT(t, func(collect *assert.CollectT) {
				triggerReadCall(collect, "new-kv-mount", "unsupported path")
			}, 10*time.Second, 10*time.Millisecond)

			// 12. Manipulate mount table in storage: untaint and allow header
			mountEntry.Tainted = false
			mountEntry.Config.AllowedResponseHeaders = []string{"Test-Header"}

			updatedData, err = jsonutil.EncodeJSON(mountEntry)
			require.NoError(t, err)

			testCore_Invalidate_sneakValueAroundCache(t, ctx, c, &logical.StorageEntry{
				Key:   entryPath,
				Value: updatedData,
			})

			// 13. call invalidate
			require.NoError(t, c.invalidateSynchronous(view.Prefix()+entryPath))

			require.EventuallyWithT(t, func(collect *assert.CollectT) {
				resp := testCore_Invalidate_handleRequest(collect, ctx, c, &logical.Request{
					Operation:   logical.ReadOperation,
					ClientToken: root,
					Path:        "new-kv-mount",
				})
				require.Equal(collect, map[string][]string{
					"Test-Header": {"test-value"},
				}, resp.Headers)
			}, 10*time.Second, 10*time.Millisecond)

			// 14. Manipulate mount table in storage: change kv version
			mountEntry.Options["version"] = "2"

			updatedData, err = jsonutil.EncodeJSON(mountEntry)
			require.NoError(t, err)

			testCore_Invalidate_sneakValueAroundCache(t, ctx, c, &logical.StorageEntry{
				Key:   entryPath,
				Value: updatedData,
			})

			// 15. call invalidate
			require.NoError(t, c.invalidateSynchronous(view.Prefix()+entryPath))

			require.EventuallyWithT(t, func(collect *assert.CollectT) {
				require.EqualValues(collect, 3, factoryCallCount.Load(), "expected factory to be called exactly 3 times")
				triggerReadCall(collect, "new-kv-mount")
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

		"unsealed": func(t *testing.T, c *Core) context.Context {
			ns := &namespace.Namespace{
				ID:   "unsealed",
				Path: "unsealed",
			}
			TestCoreCreateUnsealedNamespaces(t, c, ns)

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
			c, root := testCore_Invalidate_TestCore(t, &CoreConfig{
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

			triggerReadCall := func(collect require.TestingT, path string, expectedErrors ...string) {
				testCore_Invalidate_handleRequest(collect, ctx, c, &logical.Request{
					Operation:   logical.ReadOperation,
					ClientToken: root,
					Path:        path,
				}, expectedErrors...)
			}
			triggerReadCall(t, "my-kv-mount")
			require.EqualValues(t, 1, readCallCount.Load(), "expected one read call")

			ns, err := namespace.FromContext(ctx)
			require.NoError(t, err)
			view := c.NamespaceView(ns)

			// 3. Manipulate mount table in storage: delete entry from mount table
			storageEntry, err := view.Get(ctx, coreMountConfigPath)
			require.NoError(t, err)
			require.NotNil(t, storageEntry, "expected mount table to be written at %s", view.Prefix()+coreMountConfigPath)

			mountTable := new(routing.MountTable)
			require.NoError(t, jsonutil.DecodeJSON(storageEntry.Value, mountTable))

			require.Equal(t, "my-kv-mount/", mountTable.Entries[len(mountTable.Entries)-1].Path)
			mountTable.Entries = mountTable.Entries[:len(mountTable.Entries)-1]

			updatedData, err := jsonutil.EncodeJSON(mountTable)
			require.NoError(t, err)

			testCore_Invalidate_sneakValueAroundCache(t, ctx, c, &logical.StorageEntry{
				Key:   coreMountConfigPath,
				Value: updatedData,
			})

			// 4. call invalidate
			require.NoError(t, c.invalidateSynchronous(view.Prefix()+coreMountConfigPath))

			require.EventuallyWithT(t, func(collect *assert.CollectT) {
				c.mountsLock.RLock()
				defer c.mountsLock.RUnlock()
				require.Equal(collect, mountTableCount, len(c.mounts.Entries), "expected mount table to be back at original size")
				require.EqualValues(t, 1, cleanCallCount.Load(), "expected one cleanup call")
			}, 10*time.Second, 10*time.Millisecond)

			require.EqualValues(t, 1, factoryCallCount.Load(), "expected factory to be called exactly once")

			// 5. verify 404
			triggerReadCall(t, "my-kv-mount", "unsupported path")

			// 6. Manipulate mount table in storage: restore mount
			testCore_Invalidate_sneakValueAroundCache(t, ctx, c, storageEntry)

			// 7. call invalidate
			require.NoError(t, c.invalidateSynchronous(view.Prefix()+coreMountConfigPath))

			require.EventuallyWithT(t, func(collect *assert.CollectT) {
				c.mountsLock.RLock()
				defer c.mountsLock.RUnlock()
				require.Equal(collect, mountTableCount+1, len(c.mounts.Entries), "expected mount table to grew by one")
				require.EqualValues(collect, 2, factoryCallCount.Load(), "expected factory to be called exactly twice")
				triggerReadCall(collect, "my-kv-mount")
			}, 10*time.Second, 10*time.Millisecond)
			require.EqualValues(t, 2, readCallCount.Load(), "expected two read calls")

			// 8. Remount secret mount
			require.NoError(t, c.remountSecretsEngine(ctx, c.splitNamespaceAndMountFromPath(ns.Path, "my-kv-mount"), c.splitNamespaceAndMountFromPath(ns.Path, "new-kv-mount")))

			require.EventuallyWithT(t, func(collect *assert.CollectT) {
				triggerReadCall(t, "my-kv-mount", "unsupported path")
				triggerReadCall(t, "new-kv-mount")
			}, 10*time.Second, 10*time.Millisecond)

			// 9. Manipulate mount table in storage: taint mount
			mountTable.Entries[len(mountTable.Entries)-1].Tainted = true

			updatedData, err = jsonutil.EncodeJSON(mountTable)
			require.NoError(t, err)

			testCore_Invalidate_sneakValueAroundCache(t, ctx, c, &logical.StorageEntry{
				Key:   coreMountConfigPath,
				Value: updatedData,
			})

			// 10. call invalidate
			require.NoError(t, c.invalidateSynchronous(view.Prefix()+coreMountConfigPath))

			require.EventuallyWithT(t, func(collect *assert.CollectT) {
				triggerReadCall(collect, "new-kv-mount", "unsupported path")
			}, 10*time.Second, 10*time.Millisecond)
		})
	}
}

func TestCore_Invalidate_AuthMount(t *testing.T) {
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

		"unsealed": func(t *testing.T, c *Core) context.Context {
			ns := &namespace.Namespace{
				ID:   "unsealed",
				Path: "unsealed",
			}
			TestCoreCreateUnsealedNamespaces(t, c, ns)

			return namespace.ContextWithNamespace(t.Context(), ns)
		},
	}

	for name, init := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			c, root := testCore_Invalidate_TestCore(t, nil)
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

			// 3. Get mount UUID
			readReq := &logical.Request{
				Operation:   logical.ReadOperation,
				ClientToken: root,
				Path:        "sys/auth/my-auth",
			}
			resp := testCore_Invalidate_handleRequest(t, ctx, c, readReq)
			uuid := resp.Data["uuid"].(string)
			entryPath := path.Join(coreAuthConfigPath, uuid)

			callLogin := func(collect require.TestingT, path string, expectedErrors ...string) {
				testCore_Invalidate_handleRequest(collect, ctx, c, &logical.Request{
					Operation:   logical.ReadOperation,
					ClientToken: root,
					Path:        fmt.Sprintf("auth/%s", path),
				}, expectedErrors...)
			}
			callLogin(t, "my-auth")
			require.EqualValues(t, 1, readCallCount.Load(), "expected one read call")

			ns, err := namespace.FromContext(ctx)
			require.NoError(t, err)
			view := c.NamespaceView(ns)

			// 4. Manipulate mount table in storage: delete storageEntry
			storageEntry, err := view.Get(ctx, entryPath)
			require.NoError(t, err)
			require.NotNil(t, storageEntry, "expected mount entry to be written at %s", view.Prefix()+entryPath)

			testCore_Invalidate_sneakValueAroundCacheDelete(t, ctx, c, entryPath)

			// 5. call invalidate
			require.NoError(t, c.invalidateSynchronous(view.Prefix()+entryPath))

			require.EventuallyWithT(t, func(collect *assert.CollectT) {
				c.authLock.RLock()
				defer c.authLock.RUnlock()
				require.Equal(collect, mountTableCount, len(c.auth.Entries), "expected mount table to be back at original size")
				require.EqualValues(t, 1, cleanCallCount.Load(), "expected one cleanup call")
			}, 10*time.Second, 10*time.Millisecond)

			require.EqualValues(t, 1, factoryCallCount.Load(), "expected factory to be called exactly once")

			// 6. verify 404
			callLogin(t, "my-auth", "unsupported path")

			// 7. Manipulate mount table in storage: restore mount
			testCore_Invalidate_sneakValueAroundCache(t, ctx, c, storageEntry)

			// 8. call invalidate
			require.NoError(t, c.invalidateSynchronous(view.Prefix()+entryPath))

			require.EventuallyWithT(t, func(collect *assert.CollectT) {
				c.authLock.RLock()
				defer c.authLock.RUnlock()
				require.Equal(collect, mountTableCount+1, len(c.auth.Entries), "expected mount table to grew by one")
				require.EqualValues(collect, 2, factoryCallCount.Load(), "expected factory to be called exactly twice")
				callLogin(collect, "my-auth")
			}, 10*time.Second, 10*time.Millisecond)
			require.EqualValues(t, 2, readCallCount.Load(), "expected two read calls")

			// 9. Remount credential mount
			require.NoError(t, c.remountCredential(ctx, c.splitNamespaceAndMountFromPath(ns.Path, "auth/my-auth"), c.splitNamespaceAndMountFromPath(ns.Path, "auth/new-auth")))

			require.EventuallyWithT(t, func(collect *assert.CollectT) {
				callLogin(t, "my-auth", "unsupported path")
				callLogin(t, "new-auth")
			}, 10*time.Second, 10*time.Millisecond)

			// 10. Manipulate mount table in storage: taint mount
			storageEntry, err = view.Get(ctx, entryPath)
			require.NoError(t, err)
			require.NotNil(t, storageEntry, "expected mount entry to be written at %s", view.Prefix()+entryPath)

			mountEntry := new(routing.MountEntry)
			require.NoError(t, jsonutil.DecodeJSON(storageEntry.Value, mountEntry))
			mountEntry.Tainted = true
			updatedData, err := jsonutil.EncodeJSON(mountEntry)
			require.NoError(t, err)

			testCore_Invalidate_sneakValueAroundCache(t, ctx, c, &logical.StorageEntry{
				Key:   entryPath,
				Value: updatedData,
			})

			// 11. call invalidate
			require.NoError(t, c.invalidateSynchronous(view.Prefix()+entryPath))

			require.EventuallyWithT(t, func(collect *assert.CollectT) {
				callLogin(collect, "new-auth", "unsupported path")
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

		"unsealed": func(t *testing.T, c *Core) context.Context {
			ns := &namespace.Namespace{
				ID:   "unsealed",
				Path: "unsealed",
			}
			TestCoreCreateUnsealedNamespaces(t, c, ns)

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
			c, root := testCore_Invalidate_TestCore(t, &CoreConfig{
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

			callLogin := func(collect require.TestingT, path string, expectedErrors ...string) {
				testCore_Invalidate_handleRequest(collect, ctx, c, &logical.Request{
					Operation:   logical.ReadOperation,
					ClientToken: root,
					Path:        fmt.Sprintf("auth/%s", path),
				}, expectedErrors...)
			}
			callLogin(t, "my-auth")
			require.EqualValues(t, 1, readCallCount.Load(), "expected one read call")

			ns, err := namespace.FromContext(ctx)
			require.NoError(t, err)
			view := c.NamespaceView(ns)

			// 3. Manipulate mount table in storage: delete entry from mount table
			storageEntry, err := view.Get(ctx, coreAuthConfigPath)
			require.NoError(t, err)
			require.NotNil(t, storageEntry, "expected mount table to be written at %s", view.Prefix()+coreAuthConfigPath)

			mountTable := new(routing.MountTable)
			require.NoError(t, jsonutil.DecodeJSON(storageEntry.Value, mountTable))

			require.Equal(t, "my-auth/", mountTable.Entries[len(mountTable.Entries)-1].Path)
			mountTable.Entries = mountTable.Entries[:len(mountTable.Entries)-1]

			updatedData, err := jsonutil.EncodeJSON(mountTable)
			require.NoError(t, err)

			testCore_Invalidate_sneakValueAroundCache(t, ctx, c, &logical.StorageEntry{
				Key:   coreAuthConfigPath,
				Value: updatedData,
			})

			// 4. call invalidate
			require.NoError(t, c.invalidateSynchronous(view.Prefix()+coreAuthConfigPath))

			require.EventuallyWithT(t, func(collect *assert.CollectT) {
				c.authLock.RLock()
				defer c.authLock.RUnlock()
				require.Equal(collect, mountTableCount, len(c.auth.Entries), "expected mount table to be back at original size")
				require.EqualValues(t, 1, cleanCallCount.Load(), "expected one cleanup call")
			}, 10*time.Second, 10*time.Millisecond)

			require.EqualValues(t, 1, factoryCallCount.Load(), "expected factory to be called exactly once")

			// 5. verify 404
			callLogin(t, "my-auth", "unsupported path")

			// 6. Manipulate mount table in storage: restore mount
			testCore_Invalidate_sneakValueAroundCache(t, ctx, c, storageEntry)

			// 7. call invalidate
			require.NoError(t, c.invalidateSynchronous(view.Prefix()+coreAuthConfigPath))

			require.EventuallyWithT(t, func(collect *assert.CollectT) {
				c.authLock.RLock()
				defer c.authLock.RUnlock()
				require.Equal(collect, mountTableCount+1, len(c.auth.Entries), "expected mount table to grew by one")
				require.EqualValues(collect, 2, factoryCallCount.Load(), "expected factory to be called exactly twice")
				callLogin(collect, "my-auth")
			}, 10*time.Second, 10*time.Millisecond)
			require.EqualValues(t, 2, readCallCount.Load(), "expected two read calls")

			// 8. Remount credential mount
			require.NoError(t, c.remountCredential(ctx, c.splitNamespaceAndMountFromPath(ns.Path, "auth/my-auth"), c.splitNamespaceAndMountFromPath(ns.Path, "auth/new-auth")))

			require.EventuallyWithT(t, func(collect *assert.CollectT) {
				callLogin(t, "my-auth", "unsupported path")
				callLogin(t, "new-auth")
			}, 10*time.Second, 10*time.Millisecond)

			// 9. Manipulate mount table in storage: taint mount
			mountTable.Entries[len(mountTable.Entries)-1].Tainted = true

			updatedData, err = jsonutil.EncodeJSON(mountTable)
			require.NoError(t, err)

			testCore_Invalidate_sneakValueAroundCache(t, ctx, c, &logical.StorageEntry{
				Key:   coreAuthConfigPath,
				Value: updatedData,
			})

			// 10. call invalidate
			require.NoError(t, c.invalidateSynchronous(view.Prefix()+coreAuthConfigPath))

			require.EventuallyWithT(t, func(collect *assert.CollectT) {
				callLogin(collect, "new-auth", "unsupported path")
			}, 10*time.Second, 10*time.Millisecond)
		})
	}
}

func TestCore_Invalidate_SealedNamespaces(t *testing.T) {
	t.Parallel()
	testCases := map[string]func(t *testing.T, c *Core) context.Context{
		"sealed": func(t *testing.T, c *Core) context.Context {
			ns := &namespace.Namespace{
				ID:   "sealed",
				Path: "sealed",
			}
			TestCoreCreateSealedNamespaces(t, c, ns)

			return namespace.ContextWithNamespace(t.Context(), ns)
		},

		"child": func(t *testing.T, c *Core) context.Context {
			ns := &namespace.Namespace{
				ID:   "unsealed",
				Path: "unsealed",
			}
			TestCoreCreateUnsealedNamespaces(t, c, ns)

			child := &namespace.Namespace{
				ID:   "child",
				Path: "unsealed/child",
			}

			TestCoreCreateNamespaces(t, c, child)

			require.NoError(t, c.namespaceStore.SealNamespace(namespace.RootContext(t.Context()), ns.Path))

			return namespace.ContextWithNamespace(t.Context(), child)
		},
	}

	for name, init := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			c, _ := testCore_Invalidate_TestCore(t, nil)
			ctx := init(t, c)

			ns, err := namespace.FromContext(ctx)
			require.NoError(t, err)
			view := c.NamespaceView(ns)

			nsRootView := barrier.NewView(c.barrier, view.Prefix())

			require.NoError(
				t,
				logical.ScanViewPaginated(
					t.Context(),
					nsRootView,
					hclog.NewNullLogger(),
					50,
					func(page int, index int, path string) (cont bool, err error) {
						// Bypass the security barrier and write garbage.
						testCore_Invalidate_sneakValueAroundCache(
							t,
							namespace.RootContext(ctx),
							c,
							&logical.StorageEntry{
								Key:   path,
								Value: []byte("absolute-garbage"),
							},
						)

						// Call invalidate on the full path; this should not err.
						require.NoError(t, c.invalidateSynchronous(view.Prefix()+path))

						return true, nil
					},
				),
			)

			// Try invalidating the namespace entry itself.
			parentPath, ok := ns.ParentPath()
			require.True(t, ok, "expected namespace to have parent")

			parentNs, err := c.namespaceStore.GetNamespaceByPath(namespace.RootContext(t.Context()), parentPath)
			require.NoError(t, err)
			require.NotNil(t, parentNs)

			childNsPath := path.Join(namespaceStoreSubPath, ns.UUID)
			if parentNs.UUID != namespace.RootNamespaceUUID {
				childNsPath = path.Join(barrier.NamespacePrefix, parentNs.UUID, childNsPath)
			}

			// Call invalidate on the full path; this should not err. We've
			// not made any updates but we're more interested in downstream
			// effects.
			require.NoError(t, c.invalidateSynchronous(childNsPath))
		})
	}
}
