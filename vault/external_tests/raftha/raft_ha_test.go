// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package raftha

import (
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/helper/testhelpers"
	"github.com/openbao/openbao/helper/testhelpers/teststorage"
	vaulthttp "github.com/openbao/openbao/http"
	"github.com/openbao/openbao/physical/raft"
	"github.com/openbao/openbao/sdk/v2/helper/logging"
	"github.com/openbao/openbao/vault"
)

func TestRaft_HA_NewCluster(t *testing.T) {
	t.Run("file", func(t *testing.T) {
		t.Parallel()

		t.Run("no_client_certs", func(t *testing.T) {
			testRaftHANewCluster(t, teststorage.MakeFileBackend, false)
		})

		t.Run("with_client_certs", func(t *testing.T) {
			testRaftHANewCluster(t, teststorage.MakeFileBackend, true)
		})
	})

	t.Run("inmem", func(t *testing.T) {
		t.Parallel()

		t.Run("no_client_certs", func(t *testing.T) {
			testRaftHANewCluster(t, teststorage.MakeInmemBackend, false)
		})

		t.Run("with_client_certs", func(t *testing.T) {
			testRaftHANewCluster(t, teststorage.MakeInmemBackend, true)
		})
	})
}

func testRaftHANewCluster(t *testing.T, bundler teststorage.PhysicalBackendBundler, addClientCerts bool) {
	var conf vault.CoreConfig
	opts := vault.TestClusterOptions{HandlerFunc: vaulthttp.Handler}

	teststorage.RaftHASetup(&conf, &opts, bundler)
	cluster := vault.NewTestCluster(t, &conf, &opts)
	cluster.Start()
	defer cluster.Cleanup()

	addressProvider := &testhelpers.TestRaftServerAddressProvider{Cluster: cluster}

	leaderCore := cluster.Cores[0]
	vault.TestingUpdateClusterAddr.Store(true)

	// Seal the leader so we can install an address provider
	{
		testhelpers.EnsureCoreSealed(t, leaderCore)
		leaderCore.UnderlyingHAStorage.(*raft.RaftBackend).SetServerAddressProvider(addressProvider)
		cluster.UnsealCore(t, leaderCore)
		vault.TestWaitActive(t, leaderCore.Core)
	}

	// Now unseal core for join commands to work
	testhelpers.EnsureCoresUnsealed(t, cluster)

	joinFunc := func(client *api.Client, addClientCerts bool) {
		req := &api.RaftJoinRequest{
			LeaderCACert: string(cluster.CACertPEM),
		}
		if addClientCerts {
			req.LeaderClientCert = string(cluster.CACertPEM)
			req.LeaderClientKey = string(cluster.CAKeyPEM)
		}
		resp, err := client.Sys().RaftJoin(req)
		if err != nil {
			t.Fatal(err)
		}
		if !resp.Joined {
			t.Fatal("failed to join raft cluster")
		}
	}

	joinFunc(cluster.Cores[1].Client, addClientCerts)
	joinFunc(cluster.Cores[2].Client, addClientCerts)

	// Ensure peers are added
	leaderClient := cluster.Cores[0].Client
	err := testhelpers.VerifyRaftPeers(t, leaderClient, map[string]bool{
		"core-0": true,
		"core-1": true,
		"core-2": true,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Test remove peers
	_, err = leaderClient.Logical().Write("sys/storage/raft/remove-peer", map[string]interface{}{
		"server_id": "core-1",
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = leaderClient.Logical().Write("sys/storage/raft/remove-peer", map[string]interface{}{
		"server_id": "core-2",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Ensure peers are removed
	err = testhelpers.VerifyRaftPeers(t, leaderClient, map[string]bool{
		"core-0": true,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestRaft_HA_ExistingCluster(t *testing.T) {
	t.Parallel()
	conf := vault.CoreConfig{
		DisablePerformanceStandby: true,
	}
	opts := vault.TestClusterOptions{
		HandlerFunc:         vaulthttp.Handler,
		NumCores:            vault.DefaultNumCores,
		KeepStandbysSealed:  true,
		DisableStandbyReads: true,
	}
	logger := logging.NewVaultLogger(hclog.Debug).Named(t.Name())

	physBundle := teststorage.MakeInmemBackend(t, logger)
	physBundle.HABackend = nil

	storage, cleanup := teststorage.MakeReusableStorage(t, logger, physBundle)
	defer cleanup()

	var (
		clusterBarrierKeys [][]byte
		clusterRootToken   string
	)
	createCluster := func(t *testing.T) {
		t.Log("simulating cluster creation without raft as HABackend")

		storage.Setup(&conf, &opts)

		cluster := vault.NewTestCluster(t, &conf, &opts)
		cluster.Start()
		defer func() {
			cluster.Cleanup()
			storage.Cleanup(t, cluster)
		}()

		clusterBarrierKeys = cluster.BarrierKeys
		clusterRootToken = cluster.RootToken
	}

	createCluster(t)

	haStorage, haCleanup := teststorage.MakeReusableRaftHAStorage(t, logger, opts.NumCores, physBundle)
	defer haCleanup()

	updateCluster := func(t *testing.T) {
		t.Log("simulating cluster update with raft as HABackend")

		opts.SkipInit = true
		haStorage.Setup(&conf, &opts)

		cluster := vault.NewTestCluster(t, &conf, &opts)
		cluster.Start()
		defer func() {
			cluster.Cleanup()
			haStorage.Cleanup(t, cluster)
		}()

		// Set cluster values
		cluster.BarrierKeys = clusterBarrierKeys
		cluster.RootToken = clusterRootToken

		addressProvider := &testhelpers.TestRaftServerAddressProvider{Cluster: cluster}
		vault.TestingUpdateClusterAddr.Store(true)

		// Seal the leader so we can install an address provider
		leaderCore := cluster.Cores[0]
		{
			testhelpers.EnsureCoreSealed(t, leaderCore)
			leaderCore.UnderlyingHAStorage.(*raft.RaftBackend).SetServerAddressProvider(addressProvider)
			testhelpers.EnsureCoreUnsealed(t, cluster, leaderCore)
		}

		// Call the bootstrap on the leader and then ensure that it becomes active
		leaderClient := cluster.Cores[0].Client
		leaderClient.SetToken(clusterRootToken)
		{
			_, err := leaderClient.Logical().Write("sys/storage/raft/bootstrap", nil)
			if err != nil {
				t.Fatal(err)
			}
			vault.TestWaitActive(t, leaderCore.Core)
		}

		// Set address provider
		cluster.Cores[1].UnderlyingHAStorage.(*raft.RaftBackend).SetServerAddressProvider(addressProvider)
		cluster.Cores[2].UnderlyingHAStorage.(*raft.RaftBackend).SetServerAddressProvider(addressProvider)

		// Now unseal core for join commands to work
		testhelpers.EnsureCoresUnsealed(t, cluster)

		joinFunc := func(client *api.Client) {
			req := &api.RaftJoinRequest{
				LeaderCACert: string(cluster.CACertPEM),
			}
			resp, err := client.Sys().RaftJoin(req)
			if err != nil {
				t.Fatal(err)
			}
			if !resp.Joined {
				t.Fatal("failed to join raft cluster")
			}
		}

		joinFunc(cluster.Cores[1].Client)
		joinFunc(cluster.Cores[2].Client)

		// Ensure peers are added
		err := testhelpers.VerifyRaftPeers(t, leaderClient, map[string]bool{
			"core-0": true,
			"core-1": true,
			"core-2": true,
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	updateCluster(t)
}
