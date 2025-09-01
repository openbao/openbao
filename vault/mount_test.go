// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/openbao/openbao/helper/testhelpers/corehelpers"
	"github.com/stretchr/testify/require"

	"github.com/armon/go-metrics"
	"github.com/go-test/deep"
	"github.com/openbao/openbao/audit"
	"github.com/openbao/openbao/helper/metricsutil"
	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/helper/versions"
	"github.com/openbao/openbao/sdk/v2/helper/compressutil"
	"github.com/openbao/openbao/sdk/v2/helper/jsonutil"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func TestMount_ReadOnlyViewDuringMount(t *testing.T) {
	c, _, _ := TestCoreUnsealed(t)
	c.logicalBackends["noop"] = func(ctx context.Context, config *logical.BackendConfig) (logical.Backend, error) {
		err := config.StorageView.Put(ctx, &logical.StorageEntry{
			Key:   "bar",
			Value: []byte("baz"),
		})
		if err == nil || !strings.Contains(err.Error(), logical.ErrSetupReadOnly.Error()) {
			t.Fatal("expected a read-only error")
		}
		return &NoopBackend{}, nil
	}

	me := &MountEntry{
		Table: mountTableType,
		Path:  "foo",
		Type:  "noop",
	}
	err := c.mount(namespace.RootContext(nil), me)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
}

func TestLogicalMountMetrics(t *testing.T) {
	c, _, _, _ := TestCoreUnsealedWithMetrics(t)
	c.logicalBackends["noop"] = func(ctx context.Context, config *logical.BackendConfig) (logical.Backend, error) {
		return &NoopBackend{
			BackendType: logical.TypeLogical,
		}, nil
	}
	mountKeyName := "core.mount_table.num_entries.type|logical||local|false||"
	mountMetrics := &c.metricsHelper.LoopMetrics.Metrics
	loadMetric, ok := mountMetrics.Load(mountKeyName)
	var numEntriesMetric metricsutil.GaugeMetric = loadMetric.(metricsutil.GaugeMetric)

	// 3 default nonlocal logical backends
	if !ok || numEntriesMetric.Value != 3 {
		t.Fatalf("Auth values should be: %+v", numEntriesMetric)
	}
	me := &MountEntry{
		Table: mountTableType,
		Path:  "foo",
		Type:  "noop",
	}
	err := c.mount(namespace.RootContext(nil), me)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	mountMetrics = &c.metricsHelper.LoopMetrics.Metrics
	loadMetric, ok = mountMetrics.Load(mountKeyName)
	numEntriesMetric = loadMetric.(metricsutil.GaugeMetric)
	if !ok || numEntriesMetric.Value != 4 {
		t.Fatal("mount metrics for num entries do not match true values")
	}
	if len(numEntriesMetric.Key) != 3 ||
		numEntriesMetric.Key[0] != "core" ||
		numEntriesMetric.Key[1] != "mount_table" ||
		numEntriesMetric.Key[2] != "num_entries" {
		t.Fatal("mount metrics for num entries have wrong key")
	}
	if len(numEntriesMetric.Labels) != 2 ||
		numEntriesMetric.Labels[0].Name != "type" ||
		numEntriesMetric.Labels[0].Value != "logical" ||
		numEntriesMetric.Labels[1].Name != "local" ||
		numEntriesMetric.Labels[1].Value != "false" {
		t.Fatal("mount metrics for num entries have wrong labels")
	}
	mountSizeKeyName := "core.mount_table.size.type|logical||local|false||"
	loadMetric, ok = mountMetrics.Load(mountSizeKeyName)
	sizeMetric := loadMetric.(metricsutil.GaugeMetric)

	if !ok {
		t.Fatal("mount metrics for size do not match exist")
	}
	if len(sizeMetric.Key) != 3 ||
		sizeMetric.Key[0] != "core" ||
		sizeMetric.Key[1] != "mount_table" ||
		sizeMetric.Key[2] != "size" {
		t.Fatal("mount metrics for size have wrong key")
	}
	if len(sizeMetric.Labels) != 2 ||
		sizeMetric.Labels[0].Name != "type" ||
		sizeMetric.Labels[0].Value != "logical" ||
		sizeMetric.Labels[1].Name != "local" ||
		sizeMetric.Labels[1].Value != "false" {
		t.Fatal("mount metrics for size have wrong labels")
	}
}

func TestCore_DefaultMountTable(t *testing.T) {
	c, keys, _ := TestCoreUnsealed(t)
	verifyDefaultTable(t, c.mounts, 4)

	// Start a second core with same physical
	inmemSink := metrics.NewInmemSink(1000000*time.Hour, 2000000*time.Hour)
	conf := &CoreConfig{
		Physical:        c.physical,
		BuiltinRegistry: corehelpers.NewMockBuiltinRegistry(),
		MetricSink:      metricsutil.NewClusterMetricSink("test-cluster", inmemSink),
		MetricsHelper:   metricsutil.NewMetricsHelper(inmemSink, false),
	}
	c2, err := NewCore(conf)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer c2.Shutdown()
	for i, key := range keys {
		unseal, err := TestCoreUnseal(c2, key)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if i+1 == len(keys) && !unseal {
			t.Fatal("should be unsealed")
		}
	}

	if diff := deep.Equal(c.mounts.sortEntriesByPath(), c2.mounts.sortEntriesByPath()); len(diff) > 0 {
		t.Fatalf("mismatch: %v", diff)
	}
}

func TestCore_Mount(t *testing.T) {
	c, keys, _ := TestCoreUnsealed(t)
	me := &MountEntry{
		Table: mountTableType,
		Path:  "foo",
		Type:  "kv",
	}
	err := c.mount(namespace.RootContext(nil), me)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	match := c.router.MatchingMount(namespace.RootContext(nil), "foo/bar")
	if match != "foo/" {
		t.Fatal("missing mount")
	}

	inmemSink := metrics.NewInmemSink(1000000*time.Hour, 2000000*time.Hour)
	conf := &CoreConfig{
		Physical:        c.physical,
		BuiltinRegistry: corehelpers.NewMockBuiltinRegistry(),
		MetricSink:      metricsutil.NewClusterMetricSink("test-cluster", inmemSink),
		MetricsHelper:   metricsutil.NewMetricsHelper(inmemSink, false),
	}
	c2, err := NewCore(conf)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer c2.Shutdown()
	for i, key := range keys {
		unseal, err := TestCoreUnseal(c2, key)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if i+1 == len(keys) && !unseal {
			t.Fatal("should be unsealed")
		}
	}

	// Verify matching mount tables
	if diff := deep.Equal(c.mounts.sortEntriesByPath(), c2.mounts.sortEntriesByPath()); len(diff) > 0 {
		t.Fatalf("mismatch: %v", diff)
	}
}

func TestCore_Mount_secrets_builtin_RunningVersion(t *testing.T) {
	c, _, _ := TestCoreUnsealed(t)
	me := &MountEntry{
		Table: mountTableType,
		Path:  "foo",
		Type:  "generic",
	}
	err := c.mount(namespace.RootContext(nil), me)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	match := c.router.MatchingMount(namespace.RootContext(nil), "foo/bar")
	if match != "foo/" {
		t.Fatal("missing mount")
	}

	raw, _ := c.router.root.Get(match)
	// we override the running version of builtins
	if !versions.IsBuiltinVersion(raw.(*routeEntry).mountEntry.RunningVersion) {
		t.Errorf("Expected mount to have builtin version but got %s", raw.(*routeEntry).mountEntry.RunningVersion)
	}
}

// TestCore_Mount_kv_generic tests that we can successfully mount kv using the
// kv alias "generic"
func TestCore_Mount_kv_generic(t *testing.T) {
	c, keys, _ := TestCoreUnsealed(t)
	me := &MountEntry{
		Table: mountTableType,
		Path:  "foo",
		Type:  "generic",
	}
	err := c.mount(namespace.RootContext(nil), me)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	match := c.router.MatchingMount(namespace.RootContext(nil), "foo/bar")
	if match != "foo/" {
		t.Fatal("missing mount")
	}

	inmemSink := metrics.NewInmemSink(1000000*time.Hour, 2000000*time.Hour)
	conf := &CoreConfig{
		Physical:        c.physical,
		BuiltinRegistry: corehelpers.NewMockBuiltinRegistry(),
		MetricSink:      metricsutil.NewClusterMetricSink("test-cluster", inmemSink),
		MetricsHelper:   metricsutil.NewMetricsHelper(inmemSink, false),
	}
	c2, err := NewCore(conf)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer c2.Shutdown()
	for i, key := range keys {
		unseal, err := TestCoreUnseal(c2, key)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if i+1 == len(keys) && !unseal {
			t.Fatal("should be unsealed")
		}
	}

	// Verify matching mount tables
	if diff := deep.Equal(c.mounts.sortEntriesByPath(), c2.mounts.sortEntriesByPath()); len(diff) > 0 {
		t.Fatalf("mismatch: %v", diff)
	}
}

// Test that the local table actually gets populated as expected with local
// entries, and that upon reading the entries from both are recombined
// correctly
func TestCore_Mount_Local(t *testing.T) {
	c, _, _ := TestCoreUnsealed(t)

	c.mounts = &MountTable{
		Type: mountTableType,
		Entries: []*MountEntry{
			{
				Table:            mountTableType,
				Path:             "noop/",
				Type:             "kv",
				UUID:             "abcd",
				Accessor:         "kv-abcd",
				BackendAwareUUID: "abcde",
				NamespaceID:      namespace.RootNamespaceID,
				namespace:        namespace.RootNamespace,
			},
			{
				Table:            mountTableType,
				Path:             "noop2/",
				Type:             "kv",
				UUID:             "bcde",
				Accessor:         "kv-bcde",
				BackendAwareUUID: "bcdea",
				NamespaceID:      namespace.RootNamespaceID,
				namespace:        namespace.RootNamespace,
			},
		},
	}

	// Both should set up successfully
	err := c.setupMounts(namespace.RootContext(nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.mounts.Entries) != 2 {
		t.Fatalf("expected two entries, got %d", len(c.mounts.Entries))
	}

	localEntries, err := c.barrier.List(context.Background(), coreLocalMountConfigPath+"/")
	if err != nil {
		t.Fatal(err)
	}
	if len(localEntries) != 1 {
		t.Fatalf("expected one entry in local mount table, got %#v", localEntries)
	}
	for _, localEntry := range localEntries {
		rawLocal, err := c.barrier.Get(context.Background(), coreLocalMountConfigPath+"/"+localEntry)
		if err != nil {
			t.Fatal(err)
		}
		if rawLocal == nil {
			t.Fatal("expected non-nil local mounts")
		}

		localMountEntry := &MountEntry{}
		if err := jsonutil.DecodeJSON(rawLocal.Value, localMountEntry); err != nil {
			t.Fatal(err)
		}

		if localMountEntry.Type != "cubbyhole" {
			t.Fatalf("expected only cubbyhole entry in local mount table, got %#v at %v", localMountEntry, coreLocalMountConfigPath+"/"+localEntry)
		}
	}

	c.mounts.Entries[1].Local = true
	if err := c.persistMounts(context.Background(), nil, c.mounts, nil, ""); err != nil {
		t.Fatal(err)
	}

	// This requires some explanation: because we're directly munging the mount
	// table, the table initially when core unseals contains cubbyhole as per
	// above, but then we overwrite it with our own table with one local entry,
	// so we should now only expect the noop2 entry
	localEntries, err = c.barrier.List(context.Background(), coreLocalMountConfigPath+"/")
	if err != nil {
		t.Fatal(err)
	}
	if len(localEntries) != 1 {
		t.Fatalf("expected one entry in local mount table, got %#v", localEntries)
	}
	for _, localEntry := range localEntries {
		rawLocal, err := c.barrier.Get(context.Background(), coreLocalMountConfigPath+"/"+localEntry)
		if err != nil {
			t.Fatal(err)
		}
		if rawLocal == nil {
			t.Fatal("expected non-nil local mounts")
		}

		localMountEntry := &MountEntry{}
		if err := jsonutil.DecodeJSON(rawLocal.Value, localMountEntry); err != nil {
			t.Fatal(err)
		}
		if localMountEntry.Path != "noop2/" {
			t.Fatalf("expected only noop2/ entry in local mount table, got %#v at %v", localMountEntry, coreLocalMountConfigPath+"/"+localEntry)
		}
	}

	oldMounts := c.mounts
	if err := c.loadMounts(context.Background()); err != nil {
		t.Fatal(err)
	}
	compEntries := c.mounts.Entries[:0]
	// Filter out required mounts
	for _, v := range c.mounts.Entries {
		if v.Type == "kv" {
			compEntries = append(compEntries, v)
		}
	}
	c.mounts.Entries = compEntries

	if diff := deep.Equal(oldMounts, c.mounts); diff != nil {
		t.Fatalf("expected\n%#v\ngot\n%#v\ndiff: %#v\n", oldMounts, c.mounts, diff)
	}

	if len(c.mounts.Entries) != 2 {
		t.Fatalf("expected two mount entries, got %#v", c.mounts.Entries)
	}
}

func TestCore_FindOps(t *testing.T) {
	c, _, _ := TestCoreUnsealed(t)
	uuid1 := "80DA741F-3997-4179-B531-EBD7371DFA86"
	uuid2 := "0178594D-F267-445A-89A3-5B5DFC4A4C0F"
	path1 := "kv1"
	path2 := "kv2"

	c.mounts = &MountTable{
		Type: mountTableType,
		Entries: []*MountEntry{
			{
				Table:            mountTableType,
				Path:             path1,
				Type:             "kv",
				UUID:             "abcd",
				Accessor:         "kv-abcd",
				BackendAwareUUID: uuid1,
				NamespaceID:      namespace.RootNamespaceID,
				namespace:        namespace.RootNamespace,
			},
			{
				Table:            mountTableType,
				Path:             path2,
				Type:             "kv",
				UUID:             "bcde",
				Accessor:         "kv-bcde",
				BackendAwareUUID: uuid2,
				NamespaceID:      namespace.RootNamespaceID,
				namespace:        namespace.RootNamespace,
			},
		},
	}

	// Both should set up successfully
	if err := c.setupMounts(namespace.RootContext(nil)); err != nil {
		t.Fatal(err)
	}

	if len(c.mounts.Entries) != 2 {
		t.Fatalf("expected two entries, got %d", len(c.mounts.Entries))
	}

	// Unknown uuids/paths should return nil, nil
	entry, err := c.mounts.findByBackendUUID(namespace.RootContext(nil), "unknown")
	if err != nil || entry != nil {
		t.Fatalf("expected no errors nor matches got, error: %#v entry: %#v", err, entry)
	}
	entry, err = c.mounts.findByPath(namespace.RootContext(nil), "unknown")
	if err != nil || entry != nil {
		t.Fatalf("expected no errors nor matches got, error: %#v entry: %#v", err, entry)
	}

	// Find our entry by its uuid
	entry, err = c.mounts.findByBackendUUID(namespace.RootContext(nil), uuid1)
	if err != nil || entry == nil {
		t.Fatalf("failed finding entry by uuid error: %#v entry: %#v", err, entry)
	}
	if entry.Path != path1 {
		t.Fatalf("found incorrect entry by uuid, entry should had a path of '%s': %#v", path1, entry)
	}

	// Find another entry by its path
	entry, err = c.mounts.findByPath(namespace.RootContext(nil), path2)
	if err != nil || entry == nil {
		t.Fatalf("failed finding entry by path error: %#v entry: %#v", err, entry)
	}
	if entry.BackendAwareUUID != uuid2 {
		t.Fatalf("found incorrect entry by path, entry should had a uuid of '%s': %#v", uuid2, entry)
	}
}

func TestCore_Unmount(t *testing.T) {
	c, keys, _ := TestCoreUnsealed(t)
	err := c.unmount(namespace.RootContext(nil), "secret")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	match := c.router.MatchingMount(namespace.RootContext(nil), "secret/foo")
	if match != "" {
		t.Fatal("backend present")
	}

	inmemSink := metrics.NewInmemSink(1000000*time.Hour, 2000000*time.Hour)
	conf := &CoreConfig{
		Physical:        c.physical,
		BuiltinRegistry: corehelpers.NewMockBuiltinRegistry(),
		MetricSink:      metricsutil.NewClusterMetricSink("test-cluster", inmemSink),
		MetricsHelper:   metricsutil.NewMetricsHelper(inmemSink, false),
	}
	c2, err := NewCore(conf)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer c2.Shutdown()
	for i, key := range keys {
		unseal, err := TestCoreUnseal(c2, key)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if i+1 == len(keys) && !unseal {
			t.Fatal("should be unsealed")
		}
	}

	// Verify matching mount tables
	if diff := deep.Equal(c.mounts, c2.mounts); len(diff) > 0 {
		t.Fatalf("mismatch: %v", diff)
	}
}

func TestCore_Unmount_Cleanup(t *testing.T) {
	testCore_Unmount_Cleanup(t, false)
	testCore_Unmount_Cleanup(t, true)
}

func testCore_Unmount_Cleanup(t *testing.T, causeFailure bool) {
	noop := &NoopBackend{}
	c, _, root := TestCoreUnsealed(t)
	c.logicalBackends["noop"] = func(context.Context, *logical.BackendConfig) (logical.Backend, error) {
		return noop, nil
	}

	// Mount the noop backend
	me := &MountEntry{
		Table: mountTableType,
		Path:  "test/",
		Type:  "noop",
	}
	if err := c.mount(namespace.RootContext(nil), me); err != nil {
		t.Fatalf("err: %v", err)
	}

	// Store the view
	view := c.router.MatchingStorageByAPIPath(namespace.RootContext(nil), "test/")

	// Inject data
	se := &logical.StorageEntry{
		Key:   "plstodelete",
		Value: []byte("test"),
	}
	if err := view.Put(context.Background(), se); err != nil {
		t.Fatalf("err: %v", err)
	}

	// Setup response
	resp := &logical.Response{
		Secret: &logical.Secret{
			LeaseOptions: logical.LeaseOptions{
				TTL: time.Hour,
			},
		},
		Data: map[string]interface{}{
			"foo": "bar",
		},
	}
	noop.Response = resp

	// Generate leased secret
	r := &logical.Request{
		Operation:   logical.ReadOperation,
		Path:        "test/foo",
		ClientToken: root,
	}
	r.SetTokenEntry(&logical.TokenEntry{ID: root, NamespaceID: "root", Policies: []string{"root"}})
	resp, err := c.HandleRequest(namespace.RootContext(nil), r)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if resp.Secret.LeaseID == "" {
		t.Fatalf("bad: %#v", resp)
	}

	if causeFailure {
		view.(BarrierView).SetReadOnlyErr(logical.ErrSetupReadOnly)
	}

	// Unmount, this should cleanup
	err = c.unmount(namespace.RootContext(nil), "test/")
	switch {
	case err != nil && causeFailure:
	case err == nil && causeFailure:
		t.Fatal("expected error")
	case err != nil:
		t.Fatalf("err: %v", err)
	}

	// Rollback should be invoked
	if noop.Requests[1].Operation != logical.RollbackOperation {
		t.Fatalf("bad: %#v", noop.Requests)
	}

	// Revoke should be invoked
	if noop.Requests[2].Operation != logical.RevokeOperation {
		t.Fatalf("bad: %#v", noop.Requests)
	}
	if noop.Requests[2].Path != "foo" {
		t.Fatalf("bad: %#v", noop.Requests)
	}

	// View should be empty
	out, err := logical.CollectKeys(context.Background(), view)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	switch {
	case len(out) == 1 && causeFailure:
	case len(out) == 0 && causeFailure:
		t.Fatal("expected a value")
	case len(out) != 0:
		t.Fatalf("bad: %#v", out)
	case !causeFailure:
		return
	}

	// At this point just in the failure case, check mounting
	if err := c.mount(namespace.RootContext(nil), me); err == nil {
		t.Fatal("expected error")
	} else {
		if !strings.Contains(err.Error(), "path is already in use at") {
			t.Fatalf("expected a path is already in use error, got %v", err)
		}
	}
}

func TestCore_Remount(t *testing.T) {
	c, keys, _ := TestCoreUnsealed(t)
	err := c.remountSecretsEngineCurrentNamespace(namespace.RootContext(nil), "secret", "foo", true)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	match := c.router.MatchingMount(namespace.RootContext(nil), "foo/bar")
	if match != "foo/" {
		t.Fatal("failed remount")
	}

	c.sealInternal()
	for i, key := range keys {
		unseal, err := TestCoreUnseal(c, key)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if i+1 == len(keys) && !unseal {
			t.Fatal("should be unsealed")
		}
	}

	match = c.router.MatchingMount(namespace.RootContext(nil), "foo/bar")
	if match != "foo/" {
		t.Fatal("failed remount")
	}
}

func TestCore_Remount_Cleanup(t *testing.T) {
	noop := &NoopBackend{}
	c, _, root := TestCoreUnsealed(t)
	c.logicalBackends["noop"] = func(context.Context, *logical.BackendConfig) (logical.Backend, error) {
		return noop, nil
	}

	// Mount the noop backend
	me := &MountEntry{
		Table: mountTableType,
		Path:  "test/",
		Type:  "noop",
	}
	if err := c.mount(namespace.RootContext(nil), me); err != nil {
		t.Fatalf("err: %v", err)
	}

	// Store the view
	view := c.router.MatchingStorageByAPIPath(namespace.RootContext(nil), "test/")

	// Inject data
	se := &logical.StorageEntry{
		Key:   "plstokeep",
		Value: []byte("test"),
	}
	if err := view.Put(context.Background(), se); err != nil {
		t.Fatalf("err: %v", err)
	}

	// Setup response
	resp := &logical.Response{
		Secret: &logical.Secret{
			LeaseOptions: logical.LeaseOptions{
				TTL: time.Hour,
			},
		},
		Data: map[string]interface{}{
			"foo": "bar",
		},
	}
	noop.Response = resp

	// Generate leased secret
	r := &logical.Request{
		Operation:   logical.ReadOperation,
		Path:        "test/foo",
		ClientToken: root,
	}
	r.SetTokenEntry(&logical.TokenEntry{ID: root, NamespaceID: "root", Policies: []string{"root"}})
	resp, err := c.HandleRequest(namespace.RootContext(nil), r)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if resp.Secret.LeaseID == "" {
		t.Fatalf("bad: %#v", resp)
	}

	// Remount, this should cleanup
	if err := c.remountSecretsEngineCurrentNamespace(namespace.RootContext(nil), "test/", "new/", true); err != nil {
		t.Fatalf("err: %v", err)
	}

	// Rollback should be invoked
	if noop.Requests[1].Operation != logical.RollbackOperation {
		t.Fatalf("bad: %#v", noop.Requests)
	}

	// Revoke should be invoked
	if noop.Requests[2].Operation != logical.RevokeOperation {
		t.Fatalf("bad: %#v", noop.Requests)
	}
	if noop.Requests[2].Path != "foo" {
		t.Fatalf("bad: %#v", noop.Requests)
	}

	// View should not be empty
	out, err := logical.CollectKeys(context.Background(), view)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(out) != 1 && out[0] != "plstokeep" {
		t.Fatalf("bad: %#v", out)
	}
}

func TestCore_Remount_Protected(t *testing.T) {
	c, _, _ := TestCoreUnsealed(t)
	err := c.remountSecretsEngineCurrentNamespace(namespace.RootContext(nil), "sys", "foo", true)
	if err.Error() != `cannot remount "sys/"` {
		t.Fatalf("err: %v", err)
	}
}

type RemountStruct struct {
	Title        string
	SrcParentCtx context.Context
	DstParentCtx context.Context
	SrcNS        namespace.MountPathDetails
	DstNs        namespace.MountPathDetails
	TestSecret   *logical.Request
}

func TestCore_Remount_Namespaces(t *testing.T) {
	c, keys, token := TestCoreUnsealed(t)
	rootCtx := namespace.RootContext(nil)
	ns1 := testCreateNamespace(t, rootCtx, c.systemBackend, "ns1", nil)
	ns1Ctx := namespace.ContextWithNamespace(rootCtx, ns1)
	ns2 := testCreateNamespace(t, ns1Ctx, c.systemBackend, "ns2", nil)
	// ns2Ctx := namespace.ContextWithNamespace(rootCtx, ns2)
	ns3 := testCreateNamespace(t, ns1Ctx, c.systemBackend, "ns3", nil)
	// ns3Ctx := namespace.ContextWithNamespace(rootCtx, ns3)

	table := []RemountStruct{
		{
			Title:        "Remount Namespace ns1/ns2 to Namespace ns1/ns3",
			SrcParentCtx: ns1Ctx,
			SrcNS: namespace.MountPathDetails{
				Namespace: ns2,
				MountPath: "secret/",
			},
			DstParentCtx: ns1Ctx,
			DstNs: namespace.MountPathDetails{
				Namespace: ns3,
				MountPath: "secret1/",
			},
		},
		{
			Title:        "Remount Namespace ns1 to Root",
			SrcParentCtx: rootCtx,
			SrcNS: namespace.MountPathDetails{
				Namespace: ns1,
				MountPath: "secret/",
			},
			DstParentCtx: rootCtx,
			DstNs: namespace.MountPathDetails{
				Namespace: namespace.RootNamespace,
				MountPath: "secret2/",
			},
		},
		{
			Title:        "Remount Root to Root",
			SrcParentCtx: rootCtx,
			SrcNS: namespace.MountPathDetails{
				Namespace: namespace.RootNamespace,
				MountPath: "secret/",
			},
			DstParentCtx: rootCtx,
			DstNs: namespace.MountPathDetails{
				Namespace: namespace.RootNamespace,
				MountPath: "secretFoo/",
			},
		},
		{
			Title:        "Remount Root to Namespace ns1/ns2",
			SrcParentCtx: rootCtx,
			SrcNS: namespace.MountPathDetails{
				Namespace: namespace.RootNamespace,
				MountPath: "secretFoo/", // Note that this is depending on previous test case
			},
			DstParentCtx: ns1Ctx,
			DstNs: namespace.MountPathDetails{
				Namespace: ns2,
				MountPath: "secret3/",
			},
		},
	}

	for _, test := range table {
		t.Run(test.Title, func(t *testing.T) {
			src := test.SrcNS
			dst := test.DstNs

			srcNSCtx := namespace.ContextWithNamespace(test.SrcParentCtx, src.Namespace)
			dstNSCtx := namespace.ContextWithNamespace(test.DstParentCtx, dst.Namespace)

			srcMountPath := src.MountPath
			dstMountPath := dst.MountPath

			// Create a secret in the source namespace
			// Already present in root
			if src.Namespace != namespace.RootNamespace {
				testCoreAddSecretMountContext(srcNSCtx, t, c, srcMountPath, token)
			}

			match := c.router.MatchingMount(srcNSCtx, srcMountPath+"bar")
			if match != src.Namespace.Path+srcMountPath {
				t.Fatalf("missing mount, match %q", match)
			}

			err := c.remountSecretsEngine(test.SrcParentCtx, src, dst, true)
			if err != nil {
				t.Fatalf("err: %v", err)
			}

			match = c.router.MatchingMount(srcNSCtx, srcMountPath+"bar")
			if match != "" {
				t.Fatalf("secret still at old location, match %q", match)
			}

			match = c.router.MatchingMount(dstNSCtx, dstMountPath+"bar")
			if match != dst.Namespace.Path+dstMountPath {
				t.Fatalf("secret not at new location, match %q", match)
			}

			c.sealInternal()
			for i, key := range keys {
				unseal, err := TestCoreUnseal(c, key)
				if err != nil {
					t.Fatalf("err: %v", err)
				}
				if i+1 == len(keys) && !unseal {
					t.Fatal("should be unsealed")
				}
			}

			match = c.router.MatchingMount(srcNSCtx, srcMountPath+"bar")
			if match != "" {
				t.Fatalf("secret still at old location after unseal, match %q", match)
			}

			match = c.router.MatchingMount(dstNSCtx, dstMountPath+"bar")
			if match != dst.Namespace.Path+dstMountPath {
				t.Fatalf("secret not at new location after unseal, match %q", match)
			}
		})
	}
}

func TestDefaultMountTable(t *testing.T) {
	c, _, _ := TestCoreUnsealed(t)
	table := c.defaultMountTable(context.Background())
	verifyDefaultTable(t, table, 3)
}

func TestCore_MountTable_UpgradeToTyped(t *testing.T) {
	c, _, _ := TestCoreUnsealed(t)

	c.auditBackends["noop"] = func(ctx context.Context, config *audit.BackendConfig) (audit.Backend, error) {
		return &corehelpers.NoopAudit{
			Config: config,
		}, nil
	}

	me := &MountEntry{
		Table: auditTableType,
		Path:  "foo",
		Type:  "noop",
	}
	err := c.enableAudit(namespace.RootContext(nil), me, true)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	c.credentialBackends["noop"] = func(context.Context, *logical.BackendConfig) (logical.Backend, error) {
		return &NoopBackend{
			BackendType: logical.TypeCredential,
		}, nil
	}

	me = &MountEntry{
		Table: credentialTableType,
		Path:  "foo",
		Type:  "noop",
	}
	err = c.enableCredential(namespace.RootContext(nil), me)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	testCore_MountTable_UpgradeToTyped_Common(t, c, "mounts")
	testCore_MountTable_UpgradeToTyped_Common(t, c, "audits")
	testCore_MountTable_UpgradeToTyped_Common(t, c, "credentials")
}

func testCore_MountTable_UpgradeToTyped_Common(
	t *testing.T,
	c *Core,
	testType string,
) {
	var path string
	var mt *MountTable
	switch testType {
	case "mounts":
		path = coreMountConfigPath
		mt = c.mounts
	case "audits":
		path = coreAuditConfigPath
		mt = c.audit
	case "credentials":
		path = coreAuthConfigPath
		mt = c.auth
	}

	// We filter out local entries here since the logic is rather dumb
	// (straight JSON comparison) and doesn't deal well with the separate
	// locations
	newEntries := mt.Entries[:0]
	for _, entry := range mt.Entries {
		if !entry.Local {
			newEntries = append(newEntries, entry)
		}
	}
	mt.Entries = newEntries

	// Save the expected table
	goodJson, err := json.Marshal(mt)
	if err != nil {
		t.Fatal(err)
	}

	// Create a pre-typed version
	mt.Type = ""
	for _, entry := range mt.Entries {
		entry.Table = ""
	}

	raw, err := json.Marshal(mt)
	if err != nil {
		t.Fatal(err)
	}

	if reflect.DeepEqual(raw, goodJson) {
		t.Fatal("bad: values here should be different")
	}

	// Remove any transactional storage entries: we want to replace the mount
	// table with a pre-transactional variant to force upgrades to be run.
	if _, ok := c.barrier.(logical.TransactionalStorage); ok && testType != "audits" {
		postTxnEntries, err := c.barrier.List(context.Background(), path+"/")
		if err != nil {
			t.Fatal(err)
		}

		for _, txnEntry := range postTxnEntries {
			t.Logf("removing entry: %v", path+"/"+txnEntry)
			if err := c.barrier.Delete(context.Background(), path+"/"+txnEntry); err != nil {
				t.Fatal(err)
			}
		}
	}

	// Write the pre-typed version
	entry := &logical.StorageEntry{
		Key:   path,
		Value: raw,
	}
	if err := c.barrier.Put(context.Background(), entry); err != nil {
		t.Fatal(err)
	}

	var persistFunc func(context.Context, logical.Storage, *MountTable, *bool, string) error

	// It should load successfully and be upgraded and persisted
	switch testType {
	case "mounts":
		err = c.loadMounts(context.Background())
		persistFunc = c.persistMounts
		mt = c.mounts
	case "credentials":
		err = c.loadCredentials(context.Background())
		persistFunc = c.persistAuth
		mt = c.auth
	case "audits":
		err = c.loadAudits(context.Background())
		persistFunc = func(ctx context.Context, barrier logical.Storage, mt *MountTable, b *bool, mount string) error {
			if b == nil {
				b = new(bool)
				*b = false
			}
			return c.persistAudit(ctx, mt, *b)
		}
		mt = c.audit
	}
	if err != nil {
		t.Fatal(err)
	}

	// If we are using a transactional backend, validate the migrated path.
	var actual []byte
	if _, ok := c.barrier.(logical.TransactionalStorage); ok && testType != "audits" {
		// Assume we got the outer, implicit type correct.
		postTxnEntries, err := c.barrier.List(context.Background(), path+"/")
		if err != nil {
			t.Fatal(err)
		}

		mapEntries := make(map[string]string)
		for _, txnEntry := range postTxnEntries {
			entry, err = c.barrier.Get(context.Background(), path+"/"+txnEntry)
			if err != nil {
				t.Fatal(err)
			}
			if entry == nil {
				t.Fatal("nil value")
			}

			mapEntries[txnEntry] = strings.TrimSpace(string(entry.Value))
		}

		// Reconstruct them in the correct order.
		var entries string
		for _, entry := range mt.Entries {
			if _, present := mapEntries[entry.UUID]; !present {
				continue
			}

			if len(entries) > 0 {
				entries += ","
			}
			entries += mapEntries[entry.UUID]
		}

		// Assume we would've gotten the outer type correct.
		actual = []byte(`{"type":"` + mt.Type + `","entries":[` + entries + `]}`)

		// Read the old mount table entry and ensure it was deleted.
		entry, err = c.barrier.Get(context.Background(), path)
		if err != nil {
			t.Fatal(err)
		}
		if entry != nil && len(entry.Value) > 0 {
			t.Fatalf("expected empty entry at non-transactional mount table path: %v\n\tentry: %#v", path, string(entry.Value))
		}
	} else {
		entry, err = c.barrier.Get(context.Background(), path)
		if err != nil {
			t.Fatal(err)
		}
		if entry == nil {
			t.Fatal("nil value")
		}

		decompressedBytes, uncompressed, err := compressutil.Decompress(entry.Value)
		if err != nil {
			t.Fatal(err)
		}

		actual = decompressedBytes
		if uncompressed {
			actual = entry.Value
		}
	}

	// Decode actual and expected and compare.
	var expectedDecoded map[string]interface{}
	var actualDecoded map[string]interface{}

	if err := json.Unmarshal(goodJson, &expectedDecoded); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(actual, &actualDecoded); err != nil {
		t.Fatal(err)
	}

	if diff := deep.Equal(actualDecoded, expectedDecoded); len(diff) > 0 {
		t.Fatalf("bad: expected\n%s\nactual\n%s\n\n\tdiff: %#v", string(goodJson), string(actual), diff)
	}

	// Now try saving invalid versions
	origTableType := mt.Type
	mt.Type = "foo"
	if err := persistFunc(context.Background(), nil, mt, nil, ""); err == nil {
		t.Fatal("expected error")
	}

	if len(mt.Entries) > 0 {
		mt.Type = origTableType
		mt.Entries[0].Table = "bar"
		if err := persistFunc(context.Background(), nil, mt, nil, ""); err == nil {
			t.Fatal("expected error")
		}

		mt.Entries[0].Table = mt.Type
		if err := persistFunc(context.Background(), nil, mt, nil, ""); err != nil {
			t.Fatal(err)
		}
	}
}

func verifyDefaultTable(t *testing.T, table *MountTable, expected int) {
	if len(table.Entries) != expected {
		t.Fatalf("bad: %v", table.Entries)
	}
	table.sortEntriesByPath()
	for _, entry := range table.Entries {
		switch entry.Path {
		case "cubbyhole/":
			if entry.Type != "cubbyhole" {
				t.Fatalf("bad: %v", entry)
			}
		case "secret/":
			if entry.Type != "kv" {
				t.Fatalf("bad: %v", entry)
			}
		case "sys/":
			if entry.Type != "system" {
				t.Fatalf("bad: %v", entry)
			}
			if !entry.SealWrap {
				t.Fatalf("expected SealWrap to be enabled: %v", entry)
			}
		case "identity/":
			if entry.Type != "identity" {
				t.Fatalf("bad: %v", entry)
			}
		}
		if entry.Table != mountTableType {
			t.Fatalf("bad: %v", entry)
		}
		if entry.Description == "" {
			t.Fatalf("bad: %v", entry)
		}
		if entry.UUID == "" {
			t.Fatalf("bad: %v", entry)
		}
	}
}

func TestSingletonMountTableFunc(t *testing.T) {
	c, _, _ := TestCoreUnsealed(t)

	mounts, auth := c.singletonMountTables()

	if len(mounts.Entries) != 2 {
		t.Fatalf("length of mounts is wrong; expected 2, got %d", len(mounts.Entries))
	}

	for _, entry := range mounts.Entries {
		switch entry.Type {
		case "system":
		case "identity":
		default:
			t.Fatalf("unknown type %s", entry.Type)
		}
	}

	if len(auth.Entries) != 1 {
		t.Fatal("length of auth is wrong")
	}

	if auth.Entries[0].Type != "token" {
		t.Fatal("unexpected entry type for auth")
	}
}

func TestCore_MountInitialize(t *testing.T) {
	{
		backend := &InitializableBackend{
			&NoopBackend{
				BackendType: logical.TypeLogical,
			}, false,
		}

		c, _, _ := TestCoreUnsealed(t)
		c.logicalBackends["initable"] = func(context.Context, *logical.BackendConfig) (logical.Backend, error) {
			return backend, nil
		}

		// Mount the noop backend
		me := &MountEntry{
			Table: mountTableType,
			Path:  "foo/",
			Type:  "initable",
		}
		if err := c.mount(namespace.RootContext(nil), me); err != nil {
			t.Fatalf("err: %v", err)
		}

		if !backend.isInitialized {
			t.Fatal("backend is not initialized")
		}
	}
	{
		backend := &InitializableBackend{
			&NoopBackend{
				BackendType: logical.TypeLogical,
			}, false,
		}

		c, _, _ := TestCoreUnsealed(t)
		c.logicalBackends["initable"] = func(context.Context, *logical.BackendConfig) (logical.Backend, error) {
			return backend, nil
		}

		c.mounts = &MountTable{
			Type: mountTableType,
			Entries: []*MountEntry{
				{
					Table:            mountTableType,
					Path:             "foo/",
					Type:             "initable",
					UUID:             "abcd",
					Accessor:         "initable-abcd",
					BackendAwareUUID: "abcde",
					NamespaceID:      namespace.RootNamespaceID,
					namespace:        namespace.RootNamespace,
				},
			},
		}

		err := c.setupMounts(namespace.RootContext(nil))
		if err != nil {
			t.Fatal(err)
		}

		// run the postUnseal funcs, so that the backend will be inited
		for _, f := range c.postUnsealFuncs {
			f()
		}

		if !backend.isInitialized {
			t.Fatal("backend is not initialized")
		}
	}
}

func TestCore_MountEntryView(t *testing.T) {
	t.Parallel()
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	c, _, _ := TestCoreUnsealed(t)
	s := c.namespaceStore

	testMountEntryUUID := "mount-entry-uuid"
	testNamespace1 := &namespace.Namespace{Path: "ns1/"}
	testNamespace2 := &namespace.Namespace{Path: "ns1/ns2/"}

	err := s.SetNamespace(ctx, testNamespace1)
	require.NoError(t, err)
	err = s.SetNamespace(ctx, testNamespace2)
	require.NoError(t, err)

	tests := []struct {
		name       string
		mountEntry *MountEntry

		wantViewPrefix string
		wantError      bool
	}{
		{
			name: "entry without type nor table type leading to error",
			mountEntry: &MountEntry{
				UUID: testMountEntryUUID,
			},

			wantError: true,
		},
		{
			name: "entry of 'system' mount type",
			mountEntry: &MountEntry{
				UUID: testMountEntryUUID,
				Type: mountTypeSystem,
			},

			wantViewPrefix: systemBarrierPrefix,
		},
		{
			name: "entry of 'token' mount type",
			mountEntry: &MountEntry{
				UUID: testMountEntryUUID,
				Type: mountTypeToken,
			},

			wantViewPrefix: systemBarrierPrefix + tokenSubPath,
		},
		{
			name: "entry of 'credential' table type",
			mountEntry: &MountEntry{
				UUID:  testMountEntryUUID,
				Type:  "approle",
				Table: credentialTableType,
			},

			wantViewPrefix: credentialBarrierPrefix + testMountEntryUUID + "/",
		},
		{
			name: "entry of 'audit' table type",
			mountEntry: &MountEntry{
				UUID:  testMountEntryUUID,
				Table: auditTableType,
			},

			wantViewPrefix: auditBarrierPrefix + testMountEntryUUID + "/",
		},
		{
			name: "entry of 'mount' table type and 'identity' type",
			mountEntry: &MountEntry{
				UUID:  testMountEntryUUID,
				Table: mountTableType,
				Type:  mountTypeIdentity,
			},

			wantViewPrefix: backendBarrierPrefix + testMountEntryUUID + "/",
		},
		{
			name: "entry of 'mount' table type, and 'cubbyholeNS' type",
			mountEntry: &MountEntry{
				UUID:        testMountEntryUUID,
				Table:       mountTableType,
				Type:        mountTypeNSCubbyhole,
				NamespaceID: testNamespace1.ID,
				namespace:   testNamespace1,
			},

			wantViewPrefix: namespaceBarrierPrefix + testNamespace1.UUID + "/" + backendBarrierPrefix + testMountEntryUUID + "/",
		},
		{
			name: "entry of 'mount' table type, and 'cubbyholeNS' type with namespace not present in store",
			mountEntry: &MountEntry{
				UUID:  testMountEntryUUID,
				Table: mountTableType,
				Type:  mountTypeNSCubbyhole,
				// does not exist in store
				NamespaceID: "ns-2",
				namespace:   testNamespace1,
			},

			wantError: true,
		},
		{
			name: "entry of 'mount' table, and 'kv' type with namespace present",
			mountEntry: &MountEntry{
				UUID:        testMountEntryUUID,
				Table:       mountTableType,
				Type:        mountTypeKV,
				NamespaceID: testNamespace1.ID,
				namespace:   testNamespace1,
			},

			wantViewPrefix: namespaceBarrierPrefix + testNamespace1.UUID + "/" + backendBarrierPrefix + testMountEntryUUID + "/",
		},
		{
			name: "entry of 'mount' table, and 'kv' type with nested namespace present",
			mountEntry: &MountEntry{
				UUID:        testMountEntryUUID,
				Table:       mountTableType,
				Type:        mountTypeKV,
				NamespaceID: testNamespace2.ID,
				namespace:   testNamespace2,
			},

			wantViewPrefix: namespaceBarrierPrefix + testNamespace2.UUID + "/" + backendBarrierPrefix + testMountEntryUUID + "/",
		},
		{
			name: "entry of 'mount' table, and 'kv' type without namespace present",
			mountEntry: &MountEntry{
				UUID:  testMountEntryUUID,
				Table: mountTableType,
				Type:  mountTypeKV,
			},

			wantViewPrefix: backendBarrierPrefix + testMountEntryUUID + "/",
		},
		{
			name: "entry of 'auth' table, and 'userpass' type with namespace present",
			mountEntry: &MountEntry{
				UUID:        testMountEntryUUID,
				Table:       credentialTableType,
				Type:        "userpass",
				NamespaceID: testNamespace1.ID,
				namespace:   testNamespace1,
			},

			wantViewPrefix: namespaceBarrierPrefix + testNamespace1.UUID + "/" + credentialBarrierPrefix + testMountEntryUUID + "/",
		},
		{
			name: "entry of 'auth' table, and 'userpass' type with nested namespace present",
			mountEntry: &MountEntry{
				UUID:        testMountEntryUUID,
				Table:       credentialTableType,
				Type:        "userpass",
				NamespaceID: testNamespace2.ID,
				namespace:   testNamespace2,
			},

			wantViewPrefix: namespaceBarrierPrefix + testNamespace2.UUID + "/" + credentialBarrierPrefix + testMountEntryUUID + "/",
		},
		{
			name: "entry of 'auth' table, and 'userpass' type without namespace present",
			mountEntry: &MountEntry{
				UUID:  testMountEntryUUID,
				Table: credentialTableType,
				Type:  "userpass",
			},

			wantViewPrefix: credentialBarrierPrefix + testMountEntryUUID + "/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			gotView, err := c.mountEntryView(tt.mountEntry)

			require.Equalf(t, tt.wantError, (err != nil), "(*Core).mountEntryView() got unexpected error: %v", err)
			if err == nil {
				require.Equalf(t, tt.wantViewPrefix, gotView.Prefix(), "(*Core).mountEntryView() gotViewPrefix: %v, want: %v", gotView.Prefix(), tt.wantViewPrefix)
			}
		})
	}
}

func TestNamespaceMount_Exclusion(t *testing.T) {
	c, _, _ := TestCoreUnsealed(t)
	c.logicalBackends["noop"] = func(ctx context.Context, config *logical.BackendConfig) (logical.Backend, error) {
		return &NoopBackend{}, nil
	}

	// Creating a mount and then a namespace with the same name should fail.
	me := &MountEntry{
		Table:       mountTableType,
		Path:        "foo/",
		Type:        "noop",
		NamespaceID: namespace.RootNamespaceID,
	}
	err := c.mount(namespace.RootContext(nil), me)
	require.NoError(t, err)

	ns, err := c.namespaceStore.ModifyNamespaceByPath(namespace.RootContext(nil), "foo/", nil)
	require.Error(t, err)
	require.Nil(t, ns)

	// In openbao#1198, the first creation erred but left a ghost namespace
	// object lying around. This meant that list and subsequent create
	// namespace operations returned this ghost structure and did not error
	// properly. Retrying the create ensures no ghost object exists.
	ns, err = c.namespaceStore.ModifyNamespaceByPath(namespace.RootContext(nil), "foo/", nil)
	require.Error(t, err)
	require.Nil(t, ns)

	// Creating a deeply nested mount should also cause failures.
	me = &MountEntry{
		Table:       mountTableType,
		Path:        "fud/bar/baz/foo/",
		Type:        "noop",
		NamespaceID: namespace.RootNamespaceID,
	}
	err = c.mount(namespace.RootContext(nil), me)
	require.NoError(t, err)

	ns, err = c.namespaceStore.ModifyNamespaceByPath(namespace.RootContext(nil), "fud/", nil)
	require.Error(t, err)
	require.Nil(t, ns)

	ns, err = c.namespaceStore.ModifyNamespaceByPath(namespace.RootContext(nil), "fud/", nil)
	require.Error(t, err)
	require.Nil(t, ns)

	// Creating a new namespace should succeed.
	nsBar, err := c.namespaceStore.ModifyNamespaceByPath(namespace.RootContext(nil), "bar/", nil)
	require.NoError(t, err)
	require.NotNil(t, nsBar)

	barCtx := namespace.ContextWithNamespace(context.Background(), nsBar)

	// Doing the above inside bar should behave the same.
	me = &MountEntry{
		Table:       mountTableType,
		Path:        "foo/",
		Type:        "noop",
		NamespaceID: nsBar.ID,
	}
	err = c.mount(barCtx, me)
	require.NoError(t, err)

	ns, err = c.namespaceStore.ModifyNamespaceByPath(barCtx, "foo/", nil)
	require.Error(t, err)
	require.Nil(t, ns)

	ns, err = c.namespaceStore.ModifyNamespaceByPath(barCtx, "foo/", nil)
	require.Error(t, err)
	require.Nil(t, ns)

	me = &MountEntry{
		Table:       mountTableType,
		Path:        "fud/bar/baz/foo/",
		Type:        "noop",
		NamespaceID: nsBar.ID,
	}
	err = c.mount(barCtx, me)
	require.NoError(t, err)

	ns, err = c.namespaceStore.ModifyNamespaceByPath(barCtx, "fud/", nil)
	require.Error(t, err)
	require.Nil(t, ns)

	ns, err = c.namespaceStore.ModifyNamespaceByPath(barCtx, "fud/", nil)
	require.Error(t, err)
	require.Nil(t, ns)

	// Creating a mount at the root level that conflicts with bar/ should fail.
	me = &MountEntry{
		Table:       mountTableType,
		Path:        "bar/",
		Type:        "noop",
		NamespaceID: namespace.RootNamespaceID,
	}
	err = c.mount(namespace.RootContext(nil), me)
	require.Error(t, err)

	me = &MountEntry{
		Table:       mountTableType,
		Path:        "bar/baz/",
		Type:        "noop",
		NamespaceID: namespace.RootNamespaceID,
	}
	err = c.mount(namespace.RootContext(nil), me)
	require.Error(t, err)

	// Ensure creating sibling mounts still works.
	me = &MountEntry{
		Table:       mountTableType,
		Path:        "fud/bar/baz/qux/",
		Type:        "noop",
		NamespaceID: nsBar.ID,
	}
	err = c.mount(barCtx, me)
	require.NoError(t, err)
}
