// Copyright (c) AppsCode Inc.
// SPDX-License-Identifier: MPL-2.0

package remotedb

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	agentproto "github.com/openbao/openbao/v2/internal/builtin/database/remote-db-plugin/proto/gen"
	"github.com/openbao/openbao/v2/internal/vault/relayfwd"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

// fakeNode is a relayfwd.Node whose leadership and dial behavior are set by the
// test. DialForwarding ignores the address and returns a preconfigured client
// (an in-memory bufconn), which lets us stand up two independent proxyServer
// instances in one process and route between them despite the production
// singleton.
type fakeNode struct {
	active bool
	sealed bool
	leader string
	dial   func(ctx context.Context) (*grpc.ClientConn, error)
}

func (n *fakeNode) IsActive() bool                     { return n.active }
func (n *fakeNode) Sealed() bool                       { return n.sealed }
func (n *fakeNode) ClusterAddr() string                { return "https://self:8201" }
func (n *fakeNode) NodeID() string                     { return "self" }
func (n *fakeNode) LeaderClusterAddr() (string, error) { return n.leader, nil }
func (n *fakeNode) Peers() []relayfwd.PeerInfo         { return nil }
func (n *fakeNode) DialForwarding(ctx context.Context, _ string) (*grpc.ClientConn, error) {
	return n.dial(ctx)
}

var _ relayfwd.Node = (*fakeNode)(nil)

// attachFakeSpoke installs a spoke connection whose outbound frames are drained
// by a goroutine that answers each request via respond(). It simulates the
// spoke side of runLocalConn without a real gRPC stream.
func attachFakeSpoke(s *proxyServer, name string, respond func(command string) (output, errMsg string)) *spokeConnection {
	conn := newSpokeConnection(nil)
	s.mu.Lock()
	s.spokes[name] = conn
	s.mu.Unlock()
	go func() {
		for {
			select {
			case <-conn.done:
				return
			case msg := <-conn.sendCh:
				if msg == nil || msg.RequestId == "" {
					continue // initial ack / heartbeat frames carry no request id
				}
				out, e := respond(msg.Command)
				conn.deliver(msg.RequestId, pendingResponse{output: out, err: e})
			}
		}
	}()
	return conn
}

// dialBuf builds a client connected to a bufconn listener.
func dialBuf(lis *bufconn.Listener) func(ctx context.Context) (*grpc.ClientConn, error) {
	return func(ctx context.Context) (*grpc.ClientConn, error) {
		return grpc.NewClient(
			"passthrough:///bufnet",
			grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
				return lis.DialContext(ctx)
			}),
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		)
	}
}

func newOwnerServer(t *testing.T, owner *proxyServer) *bufconn.Listener {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	agentproto.RegisterRelayForwardingServer(srv, &relayForwardingService{s: owner})
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return lis
}

// TestRunCommand_ForwardsToOwner is the routing decision: a spoke not in the
// active node's local map is resolved from the registry and forwarded to the
// node that terminates its stream, whose identical local path answers.
func TestRunCommand_ForwardsToOwner(t *testing.T) {
	// Owner node holds spoke s1 locally and echoes the command back.
	owner := &proxyServer{spokes: map[string]*spokeConnection{}}
	attachFakeSpoke(owner, "s1", func(cmd string) (string, string) {
		return `{"echo":` + cmd + `}`, ""
	})
	lis := newOwnerServer(t, owner)

	// Active node has no local spoke; its registry says s1 lives on the owner.
	active := &proxyServer{
		spokes:   map[string]*spokeConnection{},
		registry: newSpokeRegistry(DefaultAnnounceInterval),
		node:     &fakeNode{active: true, dial: dialBuf(lis)},
	}
	active.registry.applyFullAnnounce("https://owner:8201", "owner", []AnnouncedSpoke{{SpokeName: "s1"}})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := active.RunCommand(ctx, "s1", `"hello"`)
	if err != nil {
		t.Fatalf("forwarded RunCommand failed: %v", err)
	}
	if !strings.Contains(out, "hello") {
		t.Fatalf("unexpected forwarded output: %q", out)
	}
}

// TestRunCommand_LocalPreferred: a spoke in the local map is served locally,
// never forwarded (single-node hot path preserved).
func TestRunCommand_LocalPreferred(t *testing.T) {
	s := &proxyServer{
		spokes:   map[string]*spokeConnection{},
		registry: newSpokeRegistry(DefaultAnnounceInterval),
		node: &fakeNode{active: true, dial: func(context.Context) (*grpc.ClientConn, error) {
			t.Fatal("local spoke must not dial a peer")
			return nil, nil
		}},
	}
	attachFakeSpoke(s, "s1", func(cmd string) (string, string) { return "local-ok", "" })
	// A stale registry entry must be ignored when the spoke is local.
	s.registry.applyFullAnnounce("https://elsewhere:8201", "x", []AnnouncedSpoke{{SpokeName: "s1"}})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := s.RunCommand(ctx, "s1", `"x"`)
	if err != nil || out != "local-ok" {
		t.Fatalf("local path failed: out=%q err=%v", out, err)
	}
}

// TestRunCommand_SingleNodePreserved: node nil (single-node hub) returns the
// original "not connected" error without any forwarding.
func TestRunCommand_SingleNodePreserved(t *testing.T) {
	s := &proxyServer{spokes: map[string]*spokeConnection{}}
	_, err := s.RunCommand(context.Background(), "nope", `"x"`)
	if !isSpokeNotConnected(err) {
		t.Fatalf("expected 'not connected', got %v", err)
	}
}

// TestRunCommand_StaleEntrySingleRetry: the recorded owner no longer holds the
// spoke; it answers "not connected". The active node forgets the entry and,
// with no fresh location, surfaces the error (exactly one re-resolve).
func TestRunCommand_StaleEntrySingleRetry(t *testing.T) {
	// Owner does NOT hold s1 (its stream moved away), so runLocalOnly fails.
	owner := &proxyServer{spokes: map[string]*spokeConnection{}}
	lis := newOwnerServer(t, owner)

	active := &proxyServer{
		spokes:   map[string]*spokeConnection{},
		registry: newSpokeRegistry(DefaultAnnounceInterval),
		node:     &fakeNode{active: true, dial: dialBuf(lis)},
	}
	active.registry.applyFullAnnounce("https://owner:8201", "owner", []AnnouncedSpoke{{SpokeName: "s1"}})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := active.RunCommand(ctx, "s1", `"x"`)
	if !isSpokeNotConnected(err) {
		t.Fatalf("expected 'not connected' after stale forward, got %v", err)
	}
	// The stale entry must have been forgotten.
	if _, ok := active.registry.resolve("s1"); ok {
		t.Fatal("stale registry entry should have been forgotten")
	}
}

// TestErrSpokeNotConnected_Sentinel asserts every "spoke not connected" producer
// wraps the typed sentinel (errors.Is holds), including the cross-wire path where
// the owner's FailedPrecondition status is translated back by forwardRunCommand.
func TestErrSpokeNotConnected_Sentinel(t *testing.T) {
	ctx := context.Background()

	// runLocalOnly local-miss.
	s := &proxyServer{spokes: map[string]*spokeConnection{}}
	if _, err := s.runLocalOnly(ctx, "ghost", `"x"`); !errors.Is(err, ErrSpokeNotConnected) {
		t.Fatalf("runLocalOnly miss: errors.Is failed: %v", err)
	}

	// RunCommand local-miss on a single-node hub (node == nil).
	if _, err := s.RunCommand(ctx, "ghost", `"x"`); !errors.Is(err, ErrSpokeNotConnected) {
		t.Fatalf("RunCommand single-node miss: errors.Is failed: %v", err)
	}

	// RunCommand registry-miss on the active node.
	active := &proxyServer{
		spokes:   map[string]*spokeConnection{},
		registry: newSpokeRegistry(DefaultAnnounceInterval),
		node:     &fakeNode{active: true},
	}
	if _, err := active.RunCommand(ctx, "ghost", `"x"`); !errors.Is(err, ErrSpokeNotConnected) {
		t.Fatalf("RunCommand registry miss: errors.Is failed: %v", err)
	}

	// Cross-wire: the owner runs a real RelayForwarding server whose RunCommand
	// handler maps ErrSpokeNotConnected to a FailedPrecondition status (a wrapped
	// Go error cannot cross gRPC). forwardRunCommand must translate it back so
	// errors.Is holds on the active node.
	owner := &proxyServer{spokes: map[string]*spokeConnection{}}
	lis := newOwnerServer(t, owner)
	fwd := &proxyServer{
		spokes:   map[string]*spokeConnection{},
		registry: newSpokeRegistry(DefaultAnnounceInterval),
		node:     &fakeNode{active: true, dial: dialBuf(lis)},
	}
	callCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, err := fwd.forwardRunCommand(callCtx, fwd.node, SpokeLocation{NodeClusterAddr: "https://owner:8201"}, "ghost", `"x"`)
	if !errors.Is(err, ErrSpokeNotConnected) {
		t.Fatalf("forwardRunCommand cross-wire: errors.Is failed: %v", err)
	}
}

// TestAnnouncer_ReannouncePoke: a poke (as SetRelayNode fires on a leadership
// transition) drives an immediate announce, without waiting for the periodic
// tick. The announce interval is set to an hour so any announce the test sees
// can only have come from the poke.
func TestAnnouncer_ReannouncePoke(t *testing.T) {
	restore := TestingSetAnnounceInterval(time.Hour)
	defer TestingSetAnnounceInterval(restore)

	owner := &proxyServer{
		spokes:   map[string]*spokeConnection{},
		registry: newSpokeRegistry(time.Hour),
		node:     &fakeNode{active: true},
	}
	lis := newOwnerServer(t, owner)

	standby := newProxyServer()
	standby.registry = newSpokeRegistry(time.Hour)
	standby.node = &fakeNode{active: false, leader: "https://owner:8201", dial: dialBuf(lis)}
	attachFakeSpoke(standby, "s1", func(string) (string, string) { return "", "" })

	stop := make(chan struct{})
	defer close(stop)
	go standby.runAnnouncer(stop)

	standby.pokeReannounce()

	// The poke must drive the announce well inside the (1h) tick.
	deadline := time.After(3 * time.Second)
	for {
		if _, ok := owner.registry.resolve("s1"); ok {
			return
		}
		select {
		case <-deadline:
			t.Fatal("poke did not trigger an immediate announce to the active node")
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// TestAnnounceSpokes_RejectedByNonActive: an announce arriving at a node that is
// not active is rejected with FailedPrecondition (so a demoted node accrues no
// phantom registry).
func TestAnnounceSpokes_RejectedByNonActive(t *testing.T) {
	s := &proxyServer{
		spokes:   map[string]*spokeConnection{},
		registry: newSpokeRegistry(DefaultAnnounceInterval),
		node:     &fakeNode{active: false, leader: "https://real-leader:8201"},
	}
	rf := &relayForwardingService{s: s}
	_, err := rf.AnnounceSpokes(context.Background(), &agentproto.AnnounceSpokesRequest{
		NodeClusterAddr: "https://b:8201", NodeId: "b",
		Spokes: []*agentproto.SpokeEntry{{SpokeName: "s1"}},
	})
	if err == nil {
		t.Fatal("expected rejection from non-active node")
	}
	if !strings.Contains(err.Error(), "not active") || !strings.Contains(err.Error(), "real-leader") {
		t.Fatalf("expected FailedPrecondition with leader hint, got %v", err)
	}
	if _, ok := s.registry.resolve("s1"); ok {
		t.Fatal("non-active node must not have recorded the announce")
	}
}

// TestAnnounceSpokes_AppliedByActive: the active node records the announcement.
func TestAnnounceSpokes_AppliedByActive(t *testing.T) {
	s := &proxyServer{
		spokes:   map[string]*spokeConnection{},
		registry: newSpokeRegistry(DefaultAnnounceInterval),
		node:     &fakeNode{active: true},
	}
	rf := &relayForwardingService{s: s}
	_, err := rf.AnnounceSpokes(context.Background(), &agentproto.AnnounceSpokesRequest{
		NodeClusterAddr: "https://b:8201", NodeId: "b",
		Spokes: []*agentproto.SpokeEntry{{SpokeName: "s1", CertNotAfter: 9999}},
	})
	if err != nil {
		t.Fatalf("active node should accept announce: %v", err)
	}
	loc, ok := s.registry.resolve("s1")
	if !ok || loc.NodeClusterAddr != "https://b:8201" {
		t.Fatalf("announce not recorded: %+v ok=%v", loc, ok)
	}
}

// TestRejectSpokeIfPinned covers the optional pin-spokes-to-active policy: off
// by default it accepts everywhere; on, the active node still accepts but a
// non-active node rejects with FailedPrecondition carrying the active node's
// relay endpoint as a RelayRedirect detail.
func TestRejectSpokeIfPinned(t *testing.T) {
	standby := &proxyServer{
		spokes:      map[string]*spokeConnection{},
		node:        &fakeNode{active: false, leader: "https://leader-host:8201"},
		startedPort: 50053,
	}

	// Off by default: a non-active node accepts the stream.
	if err := standby.rejectSpokeIfPinned(); err != nil {
		t.Fatalf("policy off must accept the stream, got %v", err)
	}

	prev := pinSpokesToActive
	pinSpokesToActive = true
	defer func() { pinSpokesToActive = prev }()

	// With the policy on, the active node still accepts.
	active := &proxyServer{spokes: map[string]*spokeConnection{}, node: &fakeNode{active: true}}
	if err := active.rejectSpokeIfPinned(); err != nil {
		t.Fatalf("active node must accept even with the policy on, got %v", err)
	}

	// A non-active node rejects and points the spoke at the leader's relay
	// endpoint (leader host + this node's relay port, homogeneous-port
	// assumption).
	err := standby.rejectSpokeIfPinned()
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.FailedPrecondition {
		t.Fatalf("want FailedPrecondition, got %v", err)
	}
	endpoint := ""
	for _, d := range st.Details() {
		if r, ok := d.(*agentproto.RelayRedirect); ok {
			endpoint = r.RelayEndpoint
		}
	}
	if endpoint != "leader-host:50053" {
		t.Fatalf("redirect endpoint = %q, want leader-host:50053", endpoint)
	}
}

// TestClusterSpokesView_ForwardsToActive: a relay/spokes read on a standby
// (empty registry) forwards to the active node and returns its merged view, so
// the operator sees every spoke regardless of which node they read.
func TestClusterSpokesView_ForwardsToActive(t *testing.T) {
	owner := &proxyServer{
		spokes:   map[string]*spokeConnection{},
		registry: newSpokeRegistry(DefaultAnnounceInterval),
		node:     &fakeNode{active: true},
	}
	attachFakeSpoke(owner, "s1", func(string) (string, string) { return "", "" })
	lis := newOwnerServer(t, owner)

	standby := &proxyServer{
		spokes:   map[string]*spokeConnection{},
		registry: newSpokeRegistry(DefaultAnnounceInterval),
		node:     &fakeNode{active: false, leader: "https://owner:8201", dial: dialBuf(lis)},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	view := standby.clusterSpokesView(ctx, standby.node)
	if !view.FromActive {
		t.Fatal("standby view should be marked forwarded-from-active")
	}
	found := false
	for _, sp := range view.Spokes {
		if sp.Name == "s1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("forwarded view missing spoke s1: %+v", view.Spokes)
	}
}

// TestClusterSpokesView_StandbyFallsBackOnForwardFailure: when a standby cannot
// reach the active node, relay/spokes returns its own partial local view flagged
// FromActive=false rather than erroring.
func TestClusterSpokesView_StandbyFallsBackOnForwardFailure(t *testing.T) {
	standby := &proxyServer{
		spokes:   map[string]*spokeConnection{},
		registry: newSpokeRegistry(DefaultAnnounceInterval),
		node: &fakeNode{active: false, leader: "https://dead:8201", dial: func(context.Context) (*grpc.ClientConn, error) {
			return nil, context.DeadlineExceeded
		}},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	view := standby.clusterSpokesView(ctx, standby.node)
	if view.FromActive {
		t.Fatal("failed forward must yield a partial view (FromActive=false)")
	}
}

func TestRenewCertTTLFromSeconds(t *testing.T) {
	if got := renewCertTTLFromSeconds(0); got != RenewCertDefaultTTL {
		t.Fatalf("0 -> %v, want default", got)
	}
	if got := renewCertTTLFromSeconds(-5); got >= 0 {
		t.Fatalf("negative -> %v, want negative sentinel", got)
	}
	huge := int64(1 << 62)
	if got := renewCertTTLFromSeconds(huge); got != RenewCertMaxTTL {
		t.Fatalf("huge -> %v, want max (no overflow)", got)
	}
	if got := renewCertTTLFromSeconds(3600); got != time.Hour {
		t.Fatalf("3600 -> %v, want 1h", got)
	}
}
