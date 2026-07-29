// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/v2/internal/helper/namespace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// waitForActiveAndStandbys waits until the cluster has one active core and at
// least one standby core that are ready. This is the inline equivalent of
// testhelpers.WaitForActiveNodeAndStandbys, which cannot be imported here due
// to an import cycle (testhelpers imports vault).
func waitForActiveAndStandbys(t *testing.T, cluster *TestCluster) (*TestClusterCore, []*TestClusterCore) {
	t.Helper()
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		var active int
		var standby int
		for _, core := range cluster.Cores {
			if core.Standby() {
				standby++
			} else {
				active++
			}
		}
		assert.Equal(ct, 1, active, "expected exactly one active core")
		assert.GreaterOrEqual(ct, standby, 1, "expected at least one standby core")
	}, 30*time.Second, 100*time.Millisecond)

	var activeCore *TestClusterCore
	var standbyCores []*TestClusterCore
	for _, core := range cluster.Cores {
		if core.Standby() {
			standbyCores = append(standbyCores, core)
		} else {
			activeCore = core
		}
	}
	require.NotNil(t, activeCore, "expected an active core")
	require.NotEmpty(t, standbyCores, "expected at least one standby core")
	return activeCore, standbyCores
}

func TestNamespaceBackend_MigrateSeal_Cluster(t *testing.T) {
	t.Parallel()

	cluster := NewTestCluster(t, nil, nil)
	cluster.Start()
	defer cluster.Cleanup()

	active, _ := waitForActiveAndStandbys(t, cluster)

	rootCtx := namespace.RootContext(context.Background())
	root := cluster.RootToken
	b := active.systemBackend

	// create normal namespace
	ns := testCreateNamespace(t, rootCtx, b, "cluster-migrate", nil)
	require.Equal(t, namespace.TypeNormal, active.NamespaceType(ns))

	// wait until namespace is propagated
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		for _, core := range cluster.Cores {
			got, err := core.namespaceStore.GetNamespaceByPath(rootCtx, "cluster-migrate")
			assert.NoError(ct, err)
			assert.NotNil(ct, got, "namespace not yet visible on core %d", core.coreNumber)
		}
	}, 10*time.Second, 50*time.Millisecond)

	nsCtx := namespace.ContextWithNamespace(rootCtx, ns)
	writeNamespaceSecret(t, active.Core, b, nsCtx, "my_secrets", "abc", "cluster-before")

	// normal -> sealable
	req := logical.TestRequest(t, logical.UpdateOperation, "namespaces/cluster-migrate/migrate-seal")
	req.ClientToken = root
	req.Data["seal"] = `seal "shamir" {
    shares = 3
    threshold = 2
}`
	res, err := b.HandleRequest(rootCtx, req)
	require.NoError(t, err)
	require.Equal(t, "in-progress", res.Data["status"])

	activeNs, err := active.namespaceStore.GetNamespaceByPath(rootCtx, "cluster-migrate")
	require.NoError(t, err)
	require.True(t, activeNs.Tainted, "namespace should be tainted on active node during migration")

	readReq := logical.TestRequest(t, logical.ReadOperation, "my_secrets/abc")
	readReq.ClientToken = root
	_, err = active.HandleRequest(nsCtx, readReq)
	require.Error(t, err, "request to tainted namespace should fail")

	waitForMigrationToFinish(t, active.Core, ns, namespace.TypeSealable)

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		for _, core := range cluster.Cores {
			got, err := core.namespaceStore.GetNamespaceByPath(rootCtx, "cluster-migrate")
			if assert.NoError(ct, err) && assert.NotNil(ct, got) {
				assert.False(ct, got.Tainted, "namespace should not be tainted on core %d after migration", core.coreNumber)
			}
		}
	}, 5*time.Minute, 100*time.Millisecond)

	require.False(t, active.NamespaceSealed(ns), "namespace should be unsealed after migration")

	// check that data is still readable after migration
	got := readNamespaceSecret(t, active.Core, nsCtx, "my_secrets", "abc")
	require.Equal(t, "cluster-before", got.Data["test_key"])
}
