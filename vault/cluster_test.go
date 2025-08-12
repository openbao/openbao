// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	log "github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/helper/testhelpers/corehelpers"
	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/openbao/openbao/sdk/v2/helper/logging"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/sdk/v2/physical"
	"github.com/openbao/openbao/sdk/v2/physical/inmem"
	"github.com/openbao/openbao/vault/cluster"
)

var clusterTestPausePeriod = 2 * time.Second

func TestClusterFetching(t *testing.T) {
	c, _, _ := TestCoreUnsealed(t)

	err := c.setupCluster(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	cluster, err := c.Cluster(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// Test whether expected values are found
	if cluster == nil || cluster.Name == "" || cluster.ID == "" {
		t.Fatalf("cluster information missing: cluster: %#v", cluster)
	}
}

func TestClusterHAFetching(t *testing.T) {
	logger := logging.NewVaultLogger(log.Trace)

	redirect := "http://127.0.0.1:8200"

	inm, err := inmem.NewInmemHA(nil, logger)
	if err != nil {
		t.Fatal(err)
	}
	inmha, err := inmem.NewInmemHA(nil, logger)
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewCore(&CoreConfig{
		Physical:     inm,
		HAPhysical:   inmha.(physical.HABackend),
		RedirectAddr: redirect,
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer c.Shutdown()
	keys, _ := TestCoreInit(t, c)
	for _, key := range keys {
		if _, err := TestCoreUnseal(c, TestKeyCopy(key)); err != nil {
			t.Fatalf("unseal err: %s", err)
		}
	}

	// Verify unsealed
	if c.Sealed() {
		t.Fatal("should not be sealed")
	}

	// Wait for core to become active
	TestWaitActive(t, c)

	cluster, err := c.Cluster(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// Test whether expected values are found
	if cluster == nil || cluster.Name == "" || cluster.ID == "" {
		t.Fatalf("cluster information missing: cluster:%#v", cluster)
	}
}

func TestCluster_ListenForRequests(t *testing.T) {
	// Make this nicer for tests
	manualStepDownSleepPeriod = 5 * time.Second

	cluster := NewTestCluster(t, nil, &TestClusterOptions{
		KeepStandbysSealed: true,
	})
	cluster.Start()
	defer cluster.Cleanup()
	cores := cluster.Cores

	// Wait for core to become active
	TestWaitActive(t, cores[0].Core)

	clusterListener := cores[0].getClusterListener()
	clusterListener.AddClient(consts.RequestForwardingALPN, &requestForwardingClusterClient{cores[0].Core})
	addrs := cores[0].getClusterListener().Addrs()

	// Use this to have a valid config after sealing since ClusterTLSConfig returns nil
	checkListenersFunc := func(expectFail bool) {
		dialer := clusterListener.GetDialerFunc(context.Background(), consts.RequestForwardingALPN)
		for i := range cores[0].Listeners {

			clnAddr := addrs[i]
			netConn, err := dialer(clnAddr.String(), 0)
			if err != nil {
				if expectFail {
					t.Logf("testing %s unsuccessful as expected", clnAddr)
					continue
				}
				t.Fatalf("error: %v\ncluster listener is %s", err, clnAddr)
			}
			if expectFail {
				t.Fatalf("testing %s not unsuccessful as expected", clnAddr)
			}
			conn := netConn.(*tls.Conn)
			err = conn.Handshake()
			if err != nil {
				t.Fatal(err)
			}
			connState := conn.ConnectionState()
			switch {
			case connState.Version != tls.VersionTLS12 && connState.Version != tls.VersionTLS13:
				t.Fatal("version mismatch")
			case connState.NegotiatedProtocol != consts.RequestForwardingALPN:
				t.Fatal("bad protocol negotiation")
			}
			t.Logf("testing %s successful", clnAddr)
		}
	}

	time.Sleep(clusterTestPausePeriod)
	checkListenersFunc(false)

	err := cores[0].StepDown(context.Background(), &logical.Request{
		Operation:   logical.UpdateOperation,
		Path:        "sys/step-down",
		ClientToken: cluster.RootToken,
	})
	if err != nil {
		t.Fatal(err)
	}

	// StepDown doesn't wait during actual preSeal so give time for listeners
	// to close
	time.Sleep(clusterTestPausePeriod)
	checkListenersFunc(true)

	// After this period it should be active again
	TestWaitActive(t, cores[0].Core)
	cores[0].getClusterListener().AddClient(consts.RequestForwardingALPN, &requestForwardingClusterClient{cores[0].Core})
	checkListenersFunc(false)

	err = cores[0].Core.Seal(cluster.RootToken)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(clusterTestPausePeriod)
	// After sealing it should be inactive again
	checkListenersFunc(true)
}

func TestCluster_ForwardRequests(t *testing.T) {
	// Make this nicer for tests
	manualStepDownSleepPeriod = 5 * time.Second

	t.Run("tcpLayer", func(t *testing.T) {
		testCluster_ForwardRequestsCommon(t, nil)
	})

	t.Run("inmemLayer", func(t *testing.T) {
		// Run again with in-memory network
		inmemCluster, err := cluster.NewInmemLayerCluster("inmem-cluster", 3, log.New(&log.LoggerOptions{
			Mutex: &sync.Mutex{},
			Level: log.Trace,
			Name:  "inmem-cluster",
		}))
		if err != nil {
			t.Fatal(err)
		}

		testCluster_ForwardRequestsCommon(t, &TestClusterOptions{
			ClusterLayers: inmemCluster,
		})
	})
}

func testCluster_ForwardRequestsCommon(t *testing.T, clusterOpts *TestClusterOptions) {
	cluster := NewTestCluster(t, nil, clusterOpts)
	cores := cluster.Cores
	cores[0].Handler.(*http.ServeMux).HandleFunc("/core1", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(201)
		w.Write([]byte("core1"))
	})
	cores[1].Handler.(*http.ServeMux).HandleFunc("/core2", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(202)
		w.Write([]byte("core2"))
	})
	cores[2].Handler.(*http.ServeMux).HandleFunc("/core3", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(203)
		w.Write([]byte("core3"))
	})
	cluster.Start()
	defer cluster.Cleanup()

	root := cluster.RootToken

	// Wait for core to become active
	TestWaitActiveForwardingReady(t, cores[0].Core)

	// Test forwarding a request. Since we're going directly from core to core
	// with no fallback we know that if it worked, request handling is working
	testCluster_ForwardRequests(t, cores[1], root, "core1")
	testCluster_ForwardRequests(t, cores[2], root, "core1")

	//
	// Now we do a bunch of round-robining. The point is to make sure that as
	// nodes come and go, we can always successfully forward to the active
	// node.
	//

	// Ensure active core is cores[1] and test
	testCluster_Forwarding(t, cluster, 0, 1, root, "core2")

	// Ensure active core is cores[2] and test
	testCluster_Forwarding(t, cluster, 1, 2, root, "core3")

	// Ensure active core is cores[0] and test
	testCluster_Forwarding(t, cluster, 2, 0, root, "core1")

	// Ensure active core is cores[1] and test
	testCluster_Forwarding(t, cluster, 0, 1, root, "core2")

	// Ensure active core is cores[2] and test
	testCluster_Forwarding(t, cluster, 1, 2, root, "core3")
}

func testCluster_Forwarding(t *testing.T, cluster *TestCluster, oldLeaderCoreIdx, newLeaderCoreIdx int, rootToken, remoteCoreID string) {
	t.Logf("new leaderidx will be %d, stepping down other cores to make it so", newLeaderCoreIdx)
	err := cluster.Cores[oldLeaderCoreIdx].StepDown(context.Background(), &logical.Request{
		Operation:   logical.UpdateOperation,
		Path:        "sys/step-down",
		ClientToken: rootToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(clusterTestPausePeriod)

	for i := 0; i < 3; i++ {
		if i != oldLeaderCoreIdx && i != newLeaderCoreIdx {
			_ = cluster.Cores[i].StepDown(context.Background(), &logical.Request{
				Operation:   logical.UpdateOperation,
				Path:        "sys/step-down",
				ClientToken: rootToken,
			})
			time.Sleep(clusterTestPausePeriod)
		}
	}

	TestWaitActiveForwardingReady(t, cluster.Cores[newLeaderCoreIdx].Core)

	deadline := time.Now().Add(5 * time.Second)
	var ready int
	for time.Now().Before(deadline) {
		for i := 0; i < 3; i++ {
			if i != newLeaderCoreIdx {
				leaderParams := cluster.Cores[i].clusterLeaderParams.Load().(*ClusterLeaderParams)
				if leaderParams != nil && leaderParams.LeaderClusterAddr == cluster.Cores[newLeaderCoreIdx].ClusterAddr() {
					ready++
				}
			}
		}
		if ready == 2 {
			break
		}
		ready = 0

		time.Sleep(100 * time.Millisecond)
	}
	if ready != 2 {
		t.Fatal("standbys have not discovered the new active node in time")
	}

	for i := 0; i < 3; i++ {
		if i != newLeaderCoreIdx {
			testCluster_ForwardRequests(t, cluster.Cores[i], rootToken, remoteCoreID)
		}
	}
}

func testCluster_ForwardRequests(t *testing.T, c *TestClusterCore, rootToken, remoteCoreID string) {
	t.Helper()

	standby, err := c.Standby()
	if err != nil {
		t.Fatal(err)
	}
	if !standby {
		t.Fatal("expected core to be standby")
	}

	// We need to call Leader as that refreshes the connection info
	isLeader, _, _, err := c.Leader()
	if err != nil {
		t.Fatal(err)
	}
	if isLeader {
		t.Fatal("core should not be leader")
	}
	corehelpers.RetryUntil(t, 5*time.Second, func() error {
		state := c.ActiveNodeReplicationState()
		if state == 0 {
			return fmt.Errorf("heartbeats have not yet returned a valid active node replication state: %d", state)
		}
		return nil
	})

	bodBuf := bytes.NewReader([]byte(`{ "foo": "bar", "zip": "zap" }`))
	req, err := http.NewRequest("PUT", "https://pushit.real.good:9281/"+remoteCoreID, bodBuf)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add(consts.AuthHeaderName, rootToken)
	req = req.WithContext(context.WithValue(req.Context(), "original_request_path", req.URL.Path))

	statusCode, header, respBytes, err := c.ForwardRequest(req)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if header == nil {
		t.Fatal("err: expected at least a content-type header")
	}
	if header.Get("Content-Type") != "application/json" {
		t.Fatalf("bad content-type: %s", header.Get("Content-Type"))
	}

	body := string(respBytes)

	if body != remoteCoreID {
		t.Fatalf("expected %s, got %s", remoteCoreID, body)
	}
	switch body {
	case "core1":
		if statusCode != 201 {
			t.Fatal("bad response")
		}
	case "core2":
		if statusCode != 202 {
			t.Fatal("bad response")
		}
	case "core3":
		if statusCode != 203 {
			t.Fatal("bad response")
		}
	}
}
