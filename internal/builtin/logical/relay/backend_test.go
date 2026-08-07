// Copyright (c) AppsCode Inc.
// SPDX-License-Identifier: MPL-2.0

package relay

import (
	"context"
	"net"
	"testing"

	remotedb "github.com/openbao/openbao/v2/internal/builtin/database/remote-db-plugin"
	"github.com/openbao/openbao/v2/internal/builtin/database/remote-db-plugin/bootstrap"
	"github.com/openbao/openbao/v2/internal/vault/relayfwd"
	"google.golang.org/grpc"
)

// stubNode is a relayfwd.Node whose leadership/seal state is fixed by the test.
type stubNode struct {
	sealed bool
	active bool
}

func (s stubNode) IsActive() bool      { return s.active }
func (s stubNode) Sealed() bool        { return s.sealed }
func (s stubNode) ClusterAddr() string { return "https://127.0.0.1:8201" }

// NodeID is "" so this stub maps to the default proxy-server instance, which is
// what startTestProxy (remotedb.StartProxyServer) brings up. That keeps the
// cleanup path (StopProxyServerForNode) and the assertions (ProxyServerPort)
// pointed at the same instance.
func (s stubNode) NodeID() string                     { return "" }
func (s stubNode) LeaderClusterAddr() (string, error) { return "https://127.0.0.1:8201", nil }
func (s stubNode) Peers() []relayfwd.PeerInfo         { return nil }
func (s stubNode) DialForwarding(context.Context, string) (*grpc.ClientConn, error) {
	return nil, nil
}

var _ relayfwd.Node = stubNode{}

// startTestProxy brings up the proxy listener with a throwaway hub identity so
// the cleanup test has a real listener to observe being torn down (or not).
func startTestProxy(t *testing.T) int {
	t.Helper()
	ca, err := bootstrap.GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	hub, err := ca.IssueHubServerCert([]string{"localhost"}, nil)
	if err != nil {
		t.Fatalf("IssueHubServerCert: %v", err)
	}
	if err := bootstrap.Global().SetIdentity(ca, hub); err != nil {
		t.Fatalf("SetIdentity: %v", err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("probe listen: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	if err := remotedb.StartProxyServer(port); err != nil {
		t.Fatalf("StartProxyServer: %v", err)
	}
	return port
}

// TestCleanupGatesOnSealed is the crux of Step 0: framework.Backend.Cleanup
// fires on every backend unload, including leadership transitions (preSeal runs
// on standby->active promotion and active->standby demotion). The listener must
// come down ONLY on a genuine seal, so spoke streams survive a leadership
// change. cleanup distinguishes the two via node.Sealed().
func TestCleanupGatesOnSealed(t *testing.T) {
	t.Run("transition keeps the listener up", func(t *testing.T) {
		port := startTestProxy(t)
		defer remotedb.StopProxyServer()

		// A leadership transition: node is NOT sealed. cleanup must be a no-op.
		b := &relayBackend{node: stubNode{sealed: false, active: true}}
		b.cleanup(context.Background())

		if got := remotedb.ProxyServerPort(); got != port {
			t.Fatalf("transition cleanup tore the listener down: port = %d, want %d", got, port)
		}
		if !bootstrap.Global().Ready() {
			t.Fatal("transition cleanup cleared the hub identity")
		}
	})

	t.Run("seal tears the listener down", func(t *testing.T) {
		startTestProxy(t)

		// A genuine seal: node reports Sealed()==true.
		b := &relayBackend{node: stubNode{sealed: true}}
		b.cleanup(context.Background())

		if got := remotedb.ProxyServerPort(); got != 0 {
			t.Fatalf("seal cleanup left the listener up: port = %d, want 0", got)
		}
		if bootstrap.Global().Ready() {
			t.Fatal("seal cleanup did not clear the hub identity")
		}
	})

	t.Run("nil node defaults to seal", func(t *testing.T) {
		startTestProxy(t)

		// No Core (unit-test mount): treat Cleanup as a seal, since a node with
		// no Core has no leadership transitions to protect.
		b := &relayBackend{node: nil}
		b.cleanup(context.Background())

		if got := remotedb.ProxyServerPort(); got != 0 {
			t.Fatalf("nil-node cleanup left the listener up: port = %d, want 0", got)
		}
	})
}
