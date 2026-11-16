package namespaces

import (
	"testing"
	"time"

	"github.com/openbao/openbao/api/v2"
	vaulthttp "github.com/openbao/openbao/v2/internal/http"
	"github.com/openbao/openbao/v2/internal/vault"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createSealedNs(t require.TestingT, client *api.Client, name string, config string) []string {
	// Create a couple of sealed namespaces.
	resp, err := client.Logical().Write("sys/namespaces/"+name, map[string]any{
		"seal": config,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Contains(t, resp.Data, "key_shares")
	rawShares := resp.Data["key_shares"].([]any)

	var shares []string
	for _, share := range rawShares {
		shares = append(shares, share.(string))
	}

	return shares
}

func doUnseal(t require.TestingT, client *api.Client, name string, shares []string) {
	unsealed := false
	for index, share := range shares {
		resp, err := client.Logical().Write("sys/namespaces/"+name+"/unseal", map[string]any{
			"key": share,
		})
		require.NoError(t, err, "with client %v", index)
		require.NotNil(t, resp)
		require.Contains(t, resp.Data, "sealed")
		sealed := resp.Data["sealed"].(bool)
		if !sealed {
			unsealed = true
		}
	}

	require.True(t, unsealed)
}

func doSeal(t require.TestingT, client *api.Client, name string) {
	resp, err := client.Logical().Write("sys/namespaces/"+name+"/seal", nil)
	require.NoError(t, err)
	require.Nil(t, resp)
}

func requireSealed(t require.TestingT, ns string, clients ...*api.Client) {
	for index, client := range clients {
		nsClient := client.WithNamespace(ns)
		mounts, err := nsClient.Sys().ListMounts()
		require.ErrorContains(t, err, "is sealed", "with client: %v", index)
		require.Nil(t, mounts, "with client: %v", index)
	}
}

func requireUnsealed(t require.TestingT, ns string, clients ...*api.Client) {
	for _, client := range clients {
		nsClient := client.WithNamespace(ns)
		mounts, err := nsClient.Sys().ListMounts()
		require.NoError(t, err)
		require.NotEmpty(t, mounts)
	}
}

func TestNamespaceClusterSealing(t *testing.T) {
	t.Parallel()

	cluster := vault.NewTestCluster(t, nil, &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
		NumCores:    3,
	})
	cluster.Start()
	defer cluster.Cleanup()

	client0 := cluster.Cores[0].Client
	client1 := cluster.Cores[1].Client
	client2 := cluster.Cores[2].Client
	allClients := []*api.Client{client0, client1, client2}

	sealConfig := `
seal "shamir" {
	shares = 3
	threshold = 2
}
	`

	// Create some sealed namespaces.
	ns1Shares := createSealedNs(t, client0, "ns1", sealConfig)
	require.Equal(t, 3, len(ns1Shares))

	ns2Shares := createSealedNs(t, client1, "ns2", sealConfig)
	require.Equal(t, 3, len(ns2Shares))

	ns3Shares := createSealedNs(t, client2, "ns3", sealConfig)
	require.Equal(t, 3, len(ns3Shares))

	allNamespaces := map[string][]string{
		"ns1": ns1Shares,
		"ns2": ns2Shares,
		"ns3": ns3Shares,
	}

	// All namespaces should be sealed; this is wrapped in an eventually as
	// the namespaces can take a minute to be created on the standby nodes.
	for ns := range allNamespaces {
		require.EventuallyWithT(t, func(t *assert.CollectT) {
			requireSealed(t, ns, allClients...)
		}, 25*time.Second, 100*time.Millisecond)
	}

	// Unsealing with secondary client should result in namespace immediately
	// being unsealed on active.
	doUnseal(t, client1, "ns1", ns1Shares)
	requireUnsealed(t, "ns1", client0)

	// And eventually unsealed on all other nodes.
	require.EventuallyWithT(t, func(t *assert.CollectT) {
		requireUnsealed(t, "ns1", allClients...)
	}, 25*time.Second, 100*time.Millisecond)

	// Sealing the active node and first standby node should result in the
	// third node taking over.
	require.NoError(t, client0.Sys().Seal())
	require.NoError(t, client1.Sys().Seal())

	// If we unseal ns2, and then step down the node, when the other nodes
	// com back up, we should have ns1 and ns2 eventually once node 2
	// synchronizes the state.
	doUnseal(t, client2, "ns2", ns2Shares)
	requireUnsealed(t, "ns2", client2)
	require.NoError(t, client2.Sys().StepDown())

	cluster.UnsealCore(t, cluster.Cores[0])
	vault.TestWaitActive(t, cluster.Cores[0].Core)

	require.EventuallyWithT(t, func(t *assert.CollectT) {
		requireUnsealed(t, "ns1", client0)
		requireUnsealed(t, "ns2", client0)
	}, 25*time.Second, 100*time.Millisecond)

	// Bringing up node 1 should mean everything is available on all nodes.
	cluster.UnsealCore(t, cluster.Cores[1])
	require.EventuallyWithT(t, func(t *assert.CollectT) {
		requireUnsealed(t, "ns1", allClients...)
		requireUnsealed(t, "ns2", allClients...)
	}, 25*time.Second, 100*time.Millisecond)

	// Now unsealing ns3 should be fine.
	doUnseal(t, client2, "ns3", ns3Shares)
	require.EventuallyWithT(t, func(t *assert.CollectT) {
		for ns := range allNamespaces {
			requireUnsealed(t, ns, allClients...)
		}
	}, 25*time.Second, 100*time.Millisecond)

	// When we seal a namespace, it should lose all information on all
	// nodes.
	doSeal(t, client2, "ns1")
	requireSealed(t, "ns1", client0)
	require.EventuallyWithT(t, func(t *assert.CollectT) {
		requireSealed(t, "ns1", allClients...)
	}, 25*time.Second, 100*time.Millisecond)

	// Unsealing a manually sealed namespace should propagate to all nodes.
	doUnseal(t, client1, "ns1", ns1Shares)
	require.EventuallyWithT(t, func(t *assert.CollectT) {
		requireUnsealed(t, "ns1", allClients...)
	}, 25*time.Second, 100*time.Millisecond)
}
