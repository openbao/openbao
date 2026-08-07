// Copyright (c) AppsCode Inc.
// SPDX-License-Identifier: MPL-2.0

package remotedb

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/openbao/openbao/v2/internal/builtin/database/remote-db-plugin/bootstrap"
	agentproto "github.com/openbao/openbao/v2/internal/builtin/database/remote-db-plugin/proto/gen"
	"github.com/openbao/openbao/v2/internal/vault/relayfwd"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// pinSpokesToActive gates the optional "pin every spoke to the active node"
// policy. OFF by default: the standard HA design lets a spoke terminate its
// stream on any hub node (the active node forwards credential ops to it), so
// both single- and multi-node hubs accept spoke streams anywhere. When this is
// enabled (BAO_RELAY_PIN_SPOKES_TO_ACTIVE=1|true on a hub node) a non-active
// node instead refuses spoke Connect streams and redirects the spoke to the
// active node. That suits deployments where spokes reach the hub through a VIP
// or DNS record that fans out across all nodes and the operator wants every
// stream anchored on the leader.
var pinSpokesToActive = envPinSpokesToActive()

func envPinSpokesToActive() bool {
	v := os.Getenv("BAO_RELAY_PIN_SPOKES_TO_ACTIVE")
	return v == "1" || strings.EqualFold(v, "true")
}

// relayForwardingCallTimeout bounds a single cross-node CONTROL-PLANE forward
// (the RPC, not the connection): announce, cert-renewal signing, and the
// relay/spokes read. These must not hang on a wedged peer. It is deliberately
// NOT applied to the forwarded credential RunCommand: that path inherits the
// caller's context so it stays symmetric with the local runLocalConn path (a
// slow but legitimate database statement must not be cut off at a fixed 10s
// when forwarded but allowed to run locally). The caller's request context
// bounds it instead.
const relayForwardingCallTimeout = 10 * time.Second

// peerConn returns a cached gRPC connection to the given peer cluster address,
// dialing (once) over the RelayForwarding ALPN via the node. The connection is
// reused across announces and forwards; gRPC manages reconnection internally, so
// there is no per-call dial or close (which is what caused the transient
// "use of closed network connection" churn in the earlier per-call design).
//
// The dial uses a background context deliberately: the dialer is reused for the
// connection's whole lifetime, so it must not be tied to a per-call context
// that gets cancelled. Connections are closed together in closePeerConns on
// seal, or individually via dropPeerConn when a call reveals a dead peer.
func (s *proxyServer) peerConn(node relayfwd.Node, addr string) (*grpc.ClientConn, error) {
	s.peerMu.Lock()
	defer s.peerMu.Unlock()
	if s.peerConns == nil {
		s.peerConns = make(map[string]*grpc.ClientConn)
	}
	if c, ok := s.peerConns[addr]; ok {
		return c, nil
	}
	c, err := node.DialForwarding(context.Background(), addr)
	if err != nil {
		return nil, err
	}
	s.peerConns[addr] = c
	return c, nil
}

// dropPeerConn closes and forgets the cached connection to addr so the next call
// redials. Called when a forward fails at the transport layer, which is the
// signal that the peer may be gone (a fresh dial re-resolves it, and a truly
// dead peer's registry entry expires so no new dial happens).
func (s *proxyServer) dropPeerConn(addr string) {
	s.peerMu.Lock()
	c, ok := s.peerConns[addr]
	delete(s.peerConns, addr)
	s.peerMu.Unlock()
	if ok && c != nil {
		_ = c.Close()
	}
}

// closePeerConns closes every cached peer connection. Called from stop().
func (s *proxyServer) closePeerConns() {
	s.peerMu.Lock()
	conns := s.peerConns
	s.peerConns = make(map[string]*grpc.ClientConn)
	s.peerMu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
}

// SetRelayNode wires the given Core's HA view into the proxy server bound to
// that node and starts its spoke announcer. Called by the relay backend on every
// unseal (both active and standby, since hydrateHubState runs under the
// read-only strategy too), and directly by HA tests. Idempotent: a later call
// just replaces the node view and leaves the running announcer in place.
//
// On a single-node hub this is still called, but node.IsActive() is always true
// and the announcer is a no-op (the active node announces nothing), so the hot
// path stays local-only.
func SetRelayNode(node relayfwd.Node) {
	s := proxyServerForNode(node)
	s.nodeMu.Lock()
	s.node = node
	if s.registry == nil {
		s.registry = newSpokeRegistry(announceInterval)
	}
	s.nodeMu.Unlock()

	s.lifecycleMu.Lock()
	if s.announcerStop == nil {
		stop := make(chan struct{})
		s.announcerStop = stop
		go s.runAnnouncer(stop)
	}
	s.lifecycleMu.Unlock()

	// Poke the announcer to re-announce now. This call is the relay backend
	// re-initializing this node's HA view (startup, or a leadership transition
	// that re-runs the backend), so it is exactly the event that should trigger
	// an immediate re-announce rather than waiting for the next tick. Non-blocking
	// with a depth-1 buffer: a poke is coalesced, never lost, and never blocks.
	s.pokeReannounce()
}

// pokeReannounce wakes the announcer without blocking. Safe on a proxyServer
// built by a struct literal in a test (nil channel): the default branch is taken.
func (s *proxyServer) pokeReannounce() {
	select {
	case s.reannounce <- struct{}{}:
	default:
	}
}

// runAnnouncer periodically pushes this node's full local spoke set to the
// active node, and also re-announces immediately when it observes a leadership
// change. See DESIGN.md "The spoke registry is built by announcement".
//
// Two triggers drive an immediate (not next-tick) re-announce:
//   - The reannounce poke from SetRelayNode: fired when the relay backend
//     re-initializes this node's HA view (startup, or a leadership transition
//     that re-runs the backend, such as a graceful step-down to standby). This
//     is event-driven off the existing transition callback, no core plumbing.
//   - The leader != lastLeader check on the periodic tick: the backstop for a
//     node that observes a NEW leader without its own backend re-initializing
//     (a standby that stays standby across a failover). Core exposes no
//     non-intrusive hook for that edge, so its reaction is bounded by
//     announceInterval, which matches the DESIGN failover timeline.
func (s *proxyServer) runAnnouncer(stop <-chan struct{}) {
	ticker := time.NewTicker(announceInterval)
	defer ticker.Stop()
	lastLeader := ""
	for {
		select {
		case <-stop:
			return
		case <-s.reannounce:
			// Event-driven re-announce. announceOnce is guarded by the same
			// node==active / sealed checks, so a node that just became active
			// correctly announces nothing.
			lastLeader = s.announceOnce()
		case <-ticker.C:
			leader := s.announceOnce()
			// The periodic tick bounds propagation to one announce interval;
			// re-announcing the instant the leader changes closes the gap on
			// the case that matters most (failover). announceOnce returns the
			// leader it targeted so we can detect the change cheaply.
			if leader != "" && leader != lastLeader {
				lastLeader = leader
				s.announceOnce()
			}
		}
	}
}

// announceOnce sends one full announcement to the active node. Returns the
// leader cluster address it targeted (empty when it did not announce: this node
// is active, sealed, or leadership is unknown), so the caller can detect
// leadership changes.
func (s *proxyServer) announceOnce() string {
	node := s.getNode()
	if node == nil || node.Sealed() || node.IsActive() {
		return ""
	}
	leader, err := node.LeaderClusterAddr()
	if err != nil || leader == "" {
		return ""
	}

	spokes := s.localAnnouncedSpokes()
	ctx, cancel := context.WithTimeout(context.Background(), relayForwardingCallTimeout)
	defer cancel()

	conn, err := s.peerConn(node, leader)
	if err != nil {
		log.Printf("[relay-fwd] announce dial to leader %s failed: %v", leader, err)
		return leader
	}

	client := agentproto.NewRelayForwardingClient(conn)
	_, err = client.AnnounceSpokes(ctx, &agentproto.AnnounceSpokesRequest{
		NodeClusterAddr: node.ClusterAddr(),
		NodeId:          node.NodeID(),
		Spokes:          toProtoSpokes(spokes),
	})
	if err != nil {
		// FailedPrecondition means the target is no longer active; the next
		// tick re-resolves the leader via Core.Leader() and re-announces. On a
		// transport-level failure (Unavailable) the cached connection may be
		// dead, so drop it; the next tick redials. Either way self-heals.
		switch status.Code(err) {
		case codes.FailedPrecondition:
		case codes.Unavailable:
			s.dropPeerConn(leader)
			log.Printf("[relay-fwd] announce to leader %s failed: %v", leader, err)
		default:
			log.Printf("[relay-fwd] announce to leader %s failed: %v", leader, err)
		}
	}
	return leader
}

// localAnnouncedSpokes snapshots the spokes whose streams terminate on this
// node, for announcement to the active node.
func (s *proxyServer) localAnnouncedSpokes() []AnnouncedSpoke {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]AnnouncedSpoke, 0, len(s.spokes))
	for name, c := range s.spokes {
		out = append(out, AnnouncedSpoke{
			SpokeName:    name,
			ConnectedAt:  c.connectedAt,
			LastSeen:     c.lastSeenAt(),
			CertNotAfter: c.certNotAfterAt(),
		})
	}
	return out
}

func toProtoSpokes(in []AnnouncedSpoke) []*agentproto.SpokeEntry {
	out := make([]*agentproto.SpokeEntry, 0, len(in))
	for _, s := range in {
		e := &agentproto.SpokeEntry{
			SpokeName:       s.SpokeName,
			ConnectedAtUnix: s.ConnectedAt.Unix(),
			LastSeenUnix:    s.LastSeen.Unix(),
		}
		if !s.CertNotAfter.IsZero() {
			e.CertNotAfter = s.CertNotAfter.Unix()
		}
		out = append(out, e)
	}
	return out
}

func fromProtoSpokes(in []*agentproto.SpokeEntry) []AnnouncedSpoke {
	out := make([]AnnouncedSpoke, 0, len(in))
	for _, e := range in {
		s := AnnouncedSpoke{
			SpokeName:   e.SpokeName,
			ConnectedAt: time.Unix(e.ConnectedAtUnix, 0),
			LastSeen:    time.Unix(e.LastSeenUnix, 0),
		}
		if e.CertNotAfter != 0 {
			s.CertNotAfter = time.Unix(e.CertNotAfter, 0)
		}
		out = append(out, s)
	}
	return out
}

// forwardRunCommand forwards a credential command to the node that holds the
// spoke stream and returns its result. The peer runs its own identical local
// path (runLocalOnly), so the spoke never learns its frames took an extra hop.
//
// It passes the caller's ctx straight through (no relayForwardingCallTimeout):
// the forwarded path must honor exactly the deadline the local path would, so a
// slow database statement is not cut off just because it crossed a hop. See the
// relayForwardingCallTimeout comment.
func (s *proxyServer) forwardRunCommand(ctx context.Context, node relayfwd.Node, loc SpokeLocation, spokeName, command string) (string, error) {
	conn, err := s.peerConn(node, loc.NodeClusterAddr)
	if err != nil {
		return "", fmt.Errorf("cannot reach spoke owner %s: %w", loc.NodeClusterAddr, err)
	}

	client := agentproto.NewRelayForwardingClient(conn)
	resp, err := client.RunCommand(ctx, &agentproto.RelayRunCommandRequest{
		SpokeName: spokeName,
		Command:   command,
	})
	if err != nil {
		// Cross-wire detection of "spoke not connected": the owner's handler
		// maps ErrSpokeNotConnected to a FailedPrecondition status (a wrapped Go
		// error cannot cross gRPC), so translate it back to the sentinel here.
		// RunCommand's staleness check is then the same errors.Is used on the
		// in-process path, keeping one detection rule for both.
		if status.Code(err) == codes.FailedPrecondition {
			return "", fmt.Errorf("spoke %q: %w", spokeName, ErrSpokeNotConnected)
		}
		// A dead connection (Unavailable) is dropped so the next forward
		// redials; the caller re-resolves the owner from the registry.
		if status.Code(err) == codes.Unavailable {
			s.dropPeerConn(loc.NodeClusterAddr)
		}
		return "", err
	}
	if resp.Error != "" {
		return "", errors.New(resp.Error)
	}
	return resp.Output, nil
}

// forwardRenewCert forwards a spoke's renewal CSR to the active node for
// signing and returns the signed cert. The standby holding the stream records
// the fresh NotAfter on its own spokeConnection (under the same lock as
// RenewCert's local path) and returns the cert to the spoke over the existing
// stream, so the spoke sees an ordinary renewal.
func (s *proxyServer) forwardRenewCert(ctx context.Context, node relayfwd.Node, peerCN string, req *agentproto.RenewCertRequest) (*agentproto.RenewCertResponse, error) {
	leader, err := node.LeaderClusterAddr()
	if err != nil || leader == "" {
		return nil, fmt.Errorf("cannot resolve active node for cert signing: %v", err)
	}
	dctx, cancel := context.WithTimeout(ctx, relayForwardingCallTimeout)
	defer cancel()

	conn, err := s.peerConn(node, leader)
	if err != nil {
		return nil, fmt.Errorf("cannot reach active node %s for cert signing: %w", leader, err)
	}

	client := agentproto.NewRelayForwardingClient(conn)
	resp, err := client.SignSpokeCSR(dctx, &agentproto.RelaySignCSRRequest{
		CsrPem:     req.CsrPem,
		SpokeName:  peerCN,
		TtlSeconds: req.TtlSeconds,
	})
	if err != nil {
		if status.Code(err) == codes.Unavailable {
			s.dropPeerConn(leader)
		}
		return nil, err
	}

	// Renewal happens in place over the live stream (the spoke does not
	// reconnect), so refresh the connection's recorded expiry from the fresh
	// cert. Best-effort, mirroring the active-node path in RenewCert.
	if newNotAfter, perr := certNotAfterFromPEM(resp.CertPem); perr == nil {
		s.mu.RLock()
		sc, ok := s.spokes[peerCN]
		s.mu.RUnlock()
		if ok {
			sc.setCertNotAfter(newNotAfter)
		}
	}

	return &agentproto.RenewCertResponse{
		CertPem:   resp.CertPem,
		CaCertPem: resp.CaCertPem,
	}, nil
}

// runLocalOnly looks up the spoke in the local map and runs the command over its
// stream, never forwarding. It is what the RelayForwarding.RunCommand handler
// calls on the node that terminates the stream, so a forwarded frame cannot hop
// again and loop.
func (s *proxyServer) runLocalOnly(ctx context.Context, spokeName, command string) (string, error) {
	s.mu.RLock()
	conn, ok := s.spokes[spokeName]
	s.mu.RUnlock()
	if !ok {
		return "", fmt.Errorf("spoke %q: %w", spokeName, ErrSpokeNotConnected)
	}
	return s.runLocalConn(ctx, conn, spokeName, command)
}

// rejectSpokeIfPinned enforces the optional pin-spokes-to-active policy on an
// incoming spoke Connect. When the policy is on and this node is not active, it
// returns a FailedPrecondition error carrying a RelayRedirect detail (the active
// node's relay endpoint) so bao relay run can chase the redirect and reconnect
// to the leader. It returns nil (accept the stream here) when the policy is off,
// this node is active, or this is a single-node hub.
func (s *proxyServer) rejectSpokeIfPinned() error {
	if !pinSpokesToActive {
		return nil
	}
	node := s.getNode()
	if node == nil || node.IsActive() {
		return nil
	}
	leader, _ := node.LeaderClusterAddr()
	st := status.New(codes.FailedPrecondition,
		"hub node is not active; reconnect to the active node's relay endpoint")
	if ep := s.activeRelayEndpoint(leader); ep != "" {
		if ds, err := st.WithDetails(&agentproto.RelayRedirect{RelayEndpoint: ep}); err == nil {
			st = ds
		}
	}
	return st.Err()
}

// activeRelayEndpoint derives the active node's relay listener endpoint from the
// leader's cluster address and this node's own relay listener port. It assumes a
// homogeneous relay port across the cluster (every node's bao relay init used the
// same port), which is the deployment shape the pin-to-active policy targets: the
// cluster-address host identifies the leader and the local port stands in for the
// leader's relay port. Empty when leadership or the local port is unknown.
func (s *proxyServer) activeRelayEndpoint(leaderClusterAddr string) string {
	if leaderClusterAddr == "" {
		return ""
	}
	u, err := url.Parse(leaderClusterAddr)
	if err != nil {
		return ""
	}
	host := u.Hostname()
	port := s.port()
	if host == "" || port == 0 {
		return ""
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

// ErrSpokeNotConnected is the sentinel every "spoke not connected" site wraps
// (with %w, keeping the spoke name in the message). Routing keys off this to
// re-resolve a stale registry entry exactly once, so the signal must not depend
// on the exact wording of the surrounding message.
var ErrSpokeNotConnected = errors.New("spoke not connected")

// isSpokeNotConnected reports whether err is the "spoke not connected" signal
// (from a stale registry entry pointing at a node that no longer holds the
// stream), so RunCommand can re-resolve exactly once.
//
// This is the in-process (same-Go-error) detection path. The forwarded path
// crosses a gRPC boundary where the wrapped error cannot survive, so
// forwardRunCommand translates the owner's FailedPrecondition status back into
// this sentinel (see forwardRunCommand and the RunCommand handler); once that is
// done, both paths funnel through this single errors.Is check.
func isSpokeNotConnected(err error) bool {
	return errors.Is(err, ErrSpokeNotConnected)
}

// --- RelayForwarding gRPC service (rides the cluster port) -------------------

// relayForwardingService implements agentproto.RelayForwardingServer. It is a
// distinct type from proxyServer only because proxyServer already has a
// RunCommand method with a different signature; both delegate to the same
// proxyServer state.
type relayForwardingService struct {
	agentproto.UnimplementedRelayForwardingServer
	s *proxyServer
}

// RelayForwardingService returns the default instance's service implementation.
func RelayForwardingService() agentproto.RelayForwardingServer {
	return &relayForwardingService{s: proxyServerInstance}
}

// RelayForwardingServiceForNode returns the service implementation backed by the
// proxy server bound to the given node. The vault-side ALPN handler registers
// this so a forwarded RunCommand lands on the right node's spoke map.
func RelayForwardingServiceForNode(node relayfwd.Node) agentproto.RelayForwardingServer {
	return &relayForwardingService{s: proxyServerForNode(node)}
}

// AnnounceSpokes records a peer's full local spoke set. Rejected unless this
// node is active, with the current leader in the message so the announcer can
// re-resolve and re-announce (prevents a demoted node from accumulating a
// phantom registry).
func (rf *relayForwardingService) AnnounceSpokes(ctx context.Context, req *agentproto.AnnounceSpokesRequest) (*agentproto.AnnounceSpokesResponse, error) {
	node := rf.s.getNode()
	if node == nil || !node.IsActive() {
		leader := ""
		if node != nil {
			leader, _ = node.LeaderClusterAddr()
		}
		return nil, status.Errorf(codes.FailedPrecondition, "node is not active; leader=%s", leader)
	}
	reg := rf.s.getRegistry()
	if reg == nil {
		return nil, status.Error(codes.FailedPrecondition, "relay registry not initialized")
	}
	reg.applyFullAnnounce(req.NodeClusterAddr, req.NodeId, fromProtoSpokes(req.Spokes))
	return &agentproto.AnnounceSpokesResponse{}, nil
}

// RunCommand executes a forwarded command against a spoke this node terminates.
// It never forwards again: if the spoke is not local, it returns the "not
// connected" signal so the active node re-resolves.
func (rf *relayForwardingService) RunCommand(ctx context.Context, req *agentproto.RelayRunCommandRequest) (*agentproto.RelayRunCommandResponse, error) {
	out, err := rf.s.runLocalOnly(ctx, req.SpokeName, req.Command)
	if err != nil {
		// A wrapped Go error cannot survive the gRPC boundary, so the "spoke not
		// connected" signal is carried as a typed status (FailedPrecondition)
		// rather than in the response Error string; forwardRunCommand maps it
		// back to ErrSpokeNotConnected so the active node re-resolves. Every
		// other error stays in the response body as before.
		if errors.Is(err, ErrSpokeNotConnected) {
			return nil, status.Error(codes.FailedPrecondition, err.Error())
		}
		return &agentproto.RelayRunCommandResponse{Error: err.Error()}, nil
	}
	return &agentproto.RelayRunCommandResponse{Output: out}, nil
}

// SignSpokeCSR signs a spoke renewal CSR on the active node, keeping cert
// issuance a single-issuer authority operation even though the spoke-CA key is
// in memory on every unsealed node. The CN the cert is signed for is the peer
// cert CN the requesting node already authenticated (req.SpokeName), not
// whatever the CSR claims; a mismatch is rejected.
func (rf *relayForwardingService) SignSpokeCSR(ctx context.Context, req *agentproto.RelaySignCSRRequest) (*agentproto.RelaySignCSRResponse, error) {
	node := rf.s.getNode()
	if node == nil || !node.IsActive() {
		leader := ""
		if node != nil {
			leader, _ = node.LeaderClusterAddr()
		}
		return nil, status.Errorf(codes.FailedPrecondition, "node is not active; leader=%s", leader)
	}
	if req.SpokeName == "" {
		return nil, status.Error(codes.InvalidArgument, "spoke_name is required")
	}
	if len(req.CsrPem) == 0 {
		return nil, status.Error(codes.InvalidArgument, "csr_pem is required")
	}

	csrDER, err := bootstrap.DecodeCSRPEM(req.CsrPem)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "parse CSR: %v", err)
	}
	if csr.Subject.CommonName != req.SpokeName {
		return nil, status.Errorf(codes.InvalidArgument,
			"CSR CN %q does not match authenticated spoke %q", csr.Subject.CommonName, req.SpokeName)
	}

	caCertPEM, caKeyPEM := bootstrap.Global().CABundlePEM()
	if len(caCertPEM) == 0 || len(caKeyPEM) == 0 {
		return nil, status.Error(codes.FailedPrecondition, "hub identity not initialized")
	}
	ca := &bootstrap.CABundle{CertPEM: caCertPEM, KeyPEM: caKeyPEM}

	ttl := renewCertTTLFromSeconds(req.TtlSeconds)
	if ttl <= 0 {
		return nil, status.Errorf(codes.InvalidArgument, "ttl_seconds must be non-negative (got %d)", req.TtlSeconds)
	}
	certPEM, err := ca.SignSpokeCSR(csrDER, req.SpokeName, ttl)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}
	return &agentproto.RelaySignCSRResponse{
		CertPem:   certPEM,
		CaCertPem: caCertPEM,
	}, nil
}

// ListSpokes serves the merged cluster-wide relay/spokes view. A standby's
// registry is empty (only the active node accumulates announcements), so a
// relay/spokes read on a standby forwards here to get the complete picture.
// Rejected unless this node is active, with the current leader in the message so
// the caller can retry against the right node.
func (rf *relayForwardingService) ListSpokes(ctx context.Context, _ *agentproto.RelayListSpokesRequest) (*agentproto.RelayListSpokesResponse, error) {
	node := rf.s.getNode()
	if node == nil || !node.IsActive() {
		leader := ""
		if node != nil {
			leader, _ = node.LeaderClusterAddr()
		}
		return nil, status.Errorf(codes.FailedPrecondition, "node is not active; leader=%s", leader)
	}
	return spokesViewToProto(rf.s.localSpokesView()), nil
}

// localSpokesView snapshots this node's own view (its local + registry-known
// spokes and the peer-derived hub-node list). Complete only on the active node;
// a standby's view is partial (its registry is empty), which is why relay/spokes
// forwards from a standby to the active node.
func (s *proxyServer) localSpokesView() SpokesView {
	return SpokesView{
		Spokes:            s.listConnectedSpokes(),
		HubNodes:          s.listHubNodes(),
		ListenerPort:      s.port(),
		StaleAfterSeconds: int64(SpokeStaleAfter / time.Second),
		FromActive:        true,
	}
}

// clusterSpokesView returns the cluster-wide relay/spokes payload. On the active
// node it is the local merged view. On a standby it forwards to the active node
// so the operator sees every spoke; if that forward fails it falls back to the
// standby's own partial view with FromActive=false, so the endpoint still
// answers (best-effort) and the caller can flag the result as incomplete.
func (s *proxyServer) clusterSpokesView(ctx context.Context, node relayfwd.Node) SpokesView {
	if node == nil || node.IsActive() {
		return s.localSpokesView()
	}
	if v, err := s.remoteSpokesView(ctx, node); err == nil {
		return v
	} else {
		// Log only the gRPC status code (an enum), not the error string: the
		// error can carry response metadata that static analysis flags as
		// clear-text logging of header-derived data, and the code is enough to
		// tell an operator why the forward fell back to the local partial view.
		log.Printf("[relay-fwd] relay/spokes forward to active failed (%s); returning local partial view", status.Code(err))
	}
	// Forwarding failed: return this standby's own partial view, flagged so the
	// caller can warn that the list may be incomplete.
	partial := s.localSpokesView()
	partial.FromActive = false
	return partial
}

// remoteSpokesView forwards a relay/spokes read from a standby to the active
// node and returns the merged view it reports.
func (s *proxyServer) remoteSpokesView(ctx context.Context, node relayfwd.Node) (SpokesView, error) {
	leader, err := node.LeaderClusterAddr()
	if err != nil || leader == "" {
		return SpokesView{}, fmt.Errorf("cannot resolve active node: %v", err)
	}
	conn, err := s.peerConn(node, leader)
	if err != nil {
		return SpokesView{}, fmt.Errorf("cannot reach active node %s: %w", leader, err)
	}
	callCtx, cancel := context.WithTimeout(ctx, relayForwardingCallTimeout)
	defer cancel()
	resp, err := agentproto.NewRelayForwardingClient(conn).ListSpokes(callCtx, &agentproto.RelayListSpokesRequest{})
	if err != nil {
		if status.Code(err) == codes.Unavailable {
			s.dropPeerConn(leader)
		}
		return SpokesView{}, err
	}
	return spokesViewFromProto(resp), nil
}

// ClusterSpokesForNode returns the cluster-wide relay/spokes view for the given
// node: the active node's merged view directly, or (on a standby) forwarded from
// the active node. This is what the relay backend's spokes path calls so a read
// on any node returns the whole cluster's spokes.
func ClusterSpokesForNode(ctx context.Context, node relayfwd.Node) SpokesView {
	return proxyServerForNode(node).clusterSpokesView(ctx, node)
}

func spokesViewToProto(v SpokesView) *agentproto.RelayListSpokesResponse {
	resp := &agentproto.RelayListSpokesResponse{
		ListenerPort:      int32(v.ListenerPort),
		StaleAfterSeconds: int32(v.StaleAfterSeconds),
	}
	for _, sp := range v.Spokes {
		e := &agentproto.RelaySpokeStatus{
			SpokeName:       sp.Name,
			ConnectedAtUnix: sp.ConnectedAt.Unix(),
			LastSeenUnix:    sp.LastSeen.Unix(),
			Healthy:         sp.Healthy,
			NodeClusterAddr: sp.NodeClusterAddr,
			NodeId:          sp.NodeID,
			NodeIsActive:    sp.NodeIsActive,
		}
		if !sp.CertNotAfter.IsZero() {
			e.CertNotAfter = sp.CertNotAfter.Unix()
		}
		resp.Spokes = append(resp.Spokes, e)
	}
	for _, hn := range v.HubNodes {
		resp.HubNodes = append(resp.HubNodes, &agentproto.RelayHubNode{
			ClusterAddr: hn.ClusterAddr,
			NodeId:      hn.NodeID,
			IsActive:    hn.IsActive,
			SpokeCount:  int32(hn.SpokeCount),
		})
	}
	return resp
}

func spokesViewFromProto(resp *agentproto.RelayListSpokesResponse) SpokesView {
	v := SpokesView{
		ListenerPort:      int(resp.ListenerPort),
		StaleAfterSeconds: int64(resp.StaleAfterSeconds),
		FromActive:        true,
	}
	for _, e := range resp.Spokes {
		sp := SpokeStatus{
			Name:            e.SpokeName,
			ConnectedAt:     time.Unix(e.ConnectedAtUnix, 0),
			LastSeen:        time.Unix(e.LastSeenUnix, 0),
			Healthy:         e.Healthy,
			NodeClusterAddr: e.NodeClusterAddr,
			NodeID:          e.NodeId,
			NodeIsActive:    e.NodeIsActive,
		}
		if e.CertNotAfter != 0 {
			sp.CertNotAfter = time.Unix(e.CertNotAfter, 0)
		}
		v.Spokes = append(v.Spokes, sp)
	}
	for _, e := range resp.HubNodes {
		v.HubNodes = append(v.HubNodes, HubNode{
			ClusterAddr: e.ClusterAddr,
			NodeID:      e.NodeId,
			IsActive:    e.IsActive,
			SpokeCount:  int(e.SpokeCount),
		})
	}
	return v
}

// renewCertTTLFromSeconds clamps a requested TTL to the RenewCert bounds. Mirror
// of the arithmetic in RenewCert: clamp in seconds BEFORE multiplying by
// time.Second so a huge request cannot overflow into a negative duration.
// Returns a negative value only for a negative input (caller rejects it).
func renewCertTTLFromSeconds(seconds int64) time.Duration {
	const maxSeconds = int64(RenewCertMaxTTL / time.Second)
	switch {
	case seconds < 0:
		return -1
	case seconds == 0:
		return RenewCertDefaultTTL
	case seconds >= maxSeconds:
		return RenewCertMaxTTL
	default:
		return time.Duration(seconds) * time.Second
	}
}
