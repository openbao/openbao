// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	metrics "github.com/hashicorp/go-metrics/compat"
	"github.com/openbao/openbao/sdk/v2/logical"
	logicalKv "github.com/openbao/openbao/v2/internal/builtin/logical/kv"
	"github.com/openbao/openbao/v2/internal/helper/namespace"
	be "github.com/openbao/openbao/v2/internal/vault/backend"
	"github.com/openbao/openbao/v2/internal/vault/routing"
	"github.com/stretchr/testify/require"
)

func TestCoreMetrics_KvSecretGauge(t *testing.T) {
	// Use the real KV implementation instead of Passthrough
	AddTestLogicalBackend("kv", logicalKv.Factory)
	// Clean up for the next test-- is there a better way?
	defer func() {
		delete(be.TestLogicalBackends, "kv")
	}()
	core, _, root := TestCoreUnsealed(t)

	testMounts := []struct {
		Path          string
		Type          string
		Version       string
		ExpectedCount int
	}{
		{"secret/", "kv", "2", 0},
		{"secret1/", "kv", "1", 3},
		{"secret2/", "kv", "1", 0},
		{"secret3/", "kv", "2", 4},
		{"prefix/secret3/", "kv", "2", 0},
		{"prefix/secret4/", "kv", "2", 5},
		{"generic/", "generic", "1", 3},
	}
	ctx := namespace.RootContext(t.Context())

	// skip 0, secret/ is already mounted
	for _, tm := range testMounts[1:] {
		me := &routing.MountEntry{
			Table:   routing.MountTableType,
			Path:    sanitizePath(tm.Path),
			Type:    tm.Type,
			Options: map[string]string{"version": tm.Version},
		}
		err := core.mount(ctx, me)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
	}

	v1secrets := []string{
		"secret1/a", // 3
		"secret1/b",
		"secret1/c/d",
		"generic/a",
		"generic/b",
		"generic/c",
	}
	v2secrets := []string{
		"secret3/data/a", // 4
		"secret3/data/b",
		"secret3/data/c/d",
		"secret3/data/c/e",
		"prefix/secret4/data/a/secret", // 5
		"prefix/secret4/data/a/secret2",
		"prefix/secret4/data/a/b/c/secret",
		"prefix/secret4/data/a/b/c/secret2",
		"prefix/secret4/data/a/b/c/d/secret3",
	}
	for _, p := range v1secrets {
		req := logical.TestRequest(t, logical.CreateOperation, p)
		req.Data["foo"] = "bar"
		req.ClientToken = root
		resp, err := core.HandleRequest(ctx, req)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if resp != nil {
			t.Fatalf("bad: %#v", resp)
		}
	}
	for _, p := range v2secrets {
		for range 50 {
			req := logical.TestRequest(t, logical.CreateOperation, p)
			req.Data["data"] = map[string]any{"foo": "bar"}
			req.ClientToken = root
			resp, err := core.HandleRequest(ctx, req)
			if err != nil {
				if errors.Is(err, logical.ErrInvalidRequest) {
					// Handle scenario where KVv2 upgrade is ongoing
					time.Sleep(100 * time.Millisecond)
					continue
				}
				t.Fatalf("err: %v", err)
			}
			if resp.Error() != nil {
				t.Fatalf("bad: %#v", resp)
			}
			break
		}
	}

	values, err := core.kvSecretGaugeCollector(ctx)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(values) != len(testMounts) {
		t.Errorf("Got %v values but expected %v mounts", len(values), len(testMounts))
	}

	for _, glv := range values {
		mountPoint := ""
		for _, l := range glv.Labels {
			switch l.Name {
			case "mount_point":
				mountPoint = l.Value
			case "namespace":
				if l.Value != "root" {
					t.Errorf("Namespace is %v, not root", l.Value)
				}
			default:
				t.Errorf("Unexpected label %v", l.Name)
			}
		}
		if mountPoint == "" {
			t.Errorf("No mount point in labels %v", glv.Labels)
			continue
		}
		found := false
		for _, tm := range testMounts {
			if tm.Path == mountPoint {
				found = true
				if glv.Value != float32(tm.ExpectedCount) {
					t.Errorf("Mount %v reported %v, not %v",
						tm.Path, glv.Value, tm.ExpectedCount)
				}
				break
			}
		}
		if !found {
			t.Errorf("Unexpected mount point %v", mountPoint)
		}
	}
}

func TestCoreMetrics_KvSecretGauge_BadPath(t *testing.T) {
	// Use the real KV implementation instead of Passthrough
	AddTestLogicalBackend("kv", logicalKv.Factory)
	// Clean up for the next test.
	defer func() {
		delete(be.TestLogicalBackends, "kv")
	}()
	core, _, _ := TestCoreUnsealed(t)

	me := &routing.MountEntry{
		Table:   routing.MountTableType,
		Path:    sanitizePath("kv1"),
		Type:    "kv",
		Options: map[string]string{"version": "1"},
	}
	ctx := namespace.RootContext(t.Context())
	err := core.mount(ctx, me)
	if err != nil {
		t.Fatalf("mount error: %v", err)
	}

	// I don't think there's any remaining way to create a zero-length
	// key via the API, so we'll fake it by talking to the storage layer directly.
	fake_entry := &logical.StorageEntry{
		Key:   "logical/" + me.UUID + "/foo/",
		Value: []byte{1},
	}
	err = core.barrier.Put(ctx, fake_entry)
	if err != nil {
		t.Fatalf("put error: %v", err)
	}

	values, err := core.kvSecretGaugeCollector(ctx)
	if err != nil {
		t.Fatalf("collector error: %v", err)
	}
	t.Logf("Values: %v", values)
	found := false
	var count float32 = -1
	for _, glv := range values {
		for _, l := range glv.Labels {
			if l.Name == "mount_point" && l.Value == "kv1/" {
				found = true
				count = glv.Value
				break
			}
		}
	}
	if found {
		if count != 1.0 {
			t.Error("bad secret count for kv1/")
		}
	} else {
		t.Error("no secret count for kv1/")
	}
}

func TestCoreMetrics_KvSecretGaugeError(t *testing.T) {
	core, _, _, sink := TestCoreUnsealedWithMetrics(t)
	ctx := namespace.RootContext(t.Context())

	badKvMount := &kvMount{
		Namespace:  namespace.RootNamespace,
		MountPoint: "bad/path",
		Version:    "1",
		NumSecrets: 0,
	}

	core.walkKvMountSecrets(ctx, badKvMount)

	intervals := sink.Data()
	// Test crossed an interval boundary, don't try to deal with it.
	if len(intervals) > 1 {
		t.Skip("Detected interval crossing.")
	}

	// Should be an error
	keyPrefix := "metrics.collection.error"
	var counter *metrics.SampledValue = nil

	for _, c := range intervals[0].Counters {
		if strings.HasPrefix(c.Name, keyPrefix) {
			counter = &c
			break
		}
	}
	if counter == nil {
		t.Fatal("No metrics.collection.error counter found.")
	}
	if counter.Count != 1 {
		t.Errorf("Counter number of samples %v is not 1.", counter.Count)
	}
}

func TestCoreMetrics_EntityGauges(t *testing.T) {
	ctx := namespace.RootContext(t.Context())
	c := testIdentityStoreCore(t, false)
	ns := &namespace.Namespace{Path: "ns/"}
	TestCoreCreateNamespaces(t, c, ns)

	approleAccessor, upAccessor := testEnableAppRoleUserpassAuthMounts(t, ctx, c)
	testCoreCreateEntities(t, ctx, c, approleAccessor, upAccessor)

	approleAccessorNS, upAccessorNS := testEnableAppRoleUserpassAuthMounts(t, namespace.ContextWithNamespace(ctx, ns), c)
	testCoreCreateEntities(t, namespace.ContextWithNamespace(ctx, ns), c, approleAccessorNS, upAccessorNS)

	testCoreMetricsEntityGauges(t, c)
}

// This test verifies that we aren't duplicating the amount of reported entities
// when running with `UnsafeCrossNamespaceIdentity` set to true.
// See more: https://github.com/openbao/openbao/issues/3840
func TestCoreMetrics_EntityGaugesUnsafeSharedIdentity(t *testing.T) {
	ctx := namespace.RootContext(t.Context())
	c := testIdentityStoreCore(t, true)
	ns := &namespace.Namespace{Path: "ns/"}
	TestCoreCreateNamespaces(t, c, ns)

	approleAccessor, upAccessor := testEnableAppRoleUserpassAuthMounts(t, ctx, c)
	testCoreCreateEntities(t, ctx, c, approleAccessor, upAccessor)

	approleAccessorNS, upAccessorNS := testEnableAppRoleUserpassAuthMounts(t, namespace.ContextWithNamespace(ctx, ns), c)
	testCoreCreateEntities(t, namespace.ContextWithNamespace(ctx, ns), c, approleAccessorNS, upAccessorNS)

	testCoreMetricsEntityGauges(t, c)
}

func testCoreCreateEntities(t *testing.T, ctx context.Context, core *Core, approleAccessor, upAccessor string) {
	alias := &logical.Alias{
		MountType:     "approle",
		MountAccessor: approleAccessor,
		Name:          "approleuser",
	}

	entity, _, err := core.identityStore.CreateOrFetchEntity(ctx, alias)
	require.NoError(t, err)

	// Create a second alias for the same entity
	registerReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "entity-alias",
		Data: map[string]any{
			"name":           "userpassuser",
			"canonical_id":   entity.ID,
			"mount_accessor": upAccessor,
		},
	}
	resp, err := core.identityStore.HandleRequest(ctx, registerReq)
	require.NoError(t, err)
	require.NotNil(t, resp)
}

func testCoreMetricsEntityGauges(t *testing.T, core *Core) {
	glv, err := core.entityGaugeCollector(t.Context())
	require.NoError(t, err)

	require.Len(t, glv, 2)
	for _, metric := range glv {
		require.Equal(t, float32(1.0), metric.Value)
		require.Len(t, metric.Labels, 1)
		require.Equal(t, "namespace", metric.Labels[0].Name)
		require.Contains(t, []string{"root", "ns"}, metric.Labels[0].Value)
	}

	glv, err = core.entityGaugeCollectorByMount(t.Context())
	require.NoError(t, err)

	require.Len(t, glv, 4)
	for _, metric := range glv {
		require.Equal(t, float32(1.0), metric.Value)
		require.Len(t, metric.Labels, 3)
		require.Equal(t, "namespace", metric.Labels[0].Name)
		require.Contains(t, []string{"root", "ns"}, metric.Labels[0].Value)
		require.Equal(t, "auth_method", metric.Labels[1].Name)
		require.Contains(t, []string{"userpass", "approle"}, metric.Labels[1].Value)
		require.Equal(t, "mount_point", metric.Labels[2].Name)
		require.Contains(t, []string{"auth/userpass/", "auth/approle/"}, metric.Labels[2].Value)
	}
}
