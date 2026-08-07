// Copyright (c) AppsCode Inc.
// SPDX-License-Identifier: MPL-2.0

// Package remotedb provides a proxy plugin that forwards database plugin
// requests to spoke-agent, which then executes the actual built-in plugins.
package remotedb

import (
	"context"
	cryptorand "crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"sort"
	"sync"
	"time"

	dbplugin "github.com/openbao/openbao/sdk/v2/database/dbplugin/v5"
	"github.com/openbao/openbao/v2/internal/builtin/database/remote-db-plugin/bootstrap"
	agentproto "github.com/openbao/openbao/v2/internal/builtin/database/remote-db-plugin/proto/gen"
	"github.com/openbao/openbao/v2/internal/vault/relayfwd"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/peer"
)

const (
	// SpokeStaleAfter is the freshness threshold the hub uses to decide
	// whether a spoke is healthy. A spoke is healthy if any message arrived
	// (heartbeat, response, registration) within this window.
	//
	// Picked to be 3x the spoke's default heartbeat interval so a single
	// dropped heartbeat (or a slow network burst) doesn't flip the state.
	SpokeStaleAfter = 45 * time.Second

	// HubKeepaliveInterval is how often the gRPC server sends an HTTP/2 PING
	// when no data is flowing. Catches dead TCP sessions much faster than
	// gRPC's two-hour default and protects against silent NAT timeouts.
	HubKeepaliveInterval = 30 * time.Second
	HubKeepaliveTimeout  = 10 * time.Second

	// MaxMessageBytes raises gRPC's default 4 MB cap. Database configs and
	// long creation_statements / revocation_statements lists can comfortably
	// fit under the default, but combined with verbose error messages and
	// large CSR/cert PEMs flowing through Connect, headroom is cheap. Apply
	// symmetrically on the server (proxy.go) and the client (relay_run.go,
	// relay_renew.go) so neither side bottlenecks the other.
	MaxMessageBytes = 16 * 1024 * 1024
)

// proxyServer is the gRPC server that brokers requests between the hub and
// spoke-agents. In production there is exactly one per process (one OpenBao
// node = one process), reached through the default instance and the package
// funcs below. It is instance-scoped rather than a bare singleton so that an
// in-process multi-node test cluster (three *Core in one process) can give each
// node its own proxy server, spoke map, and listener, which is what makes the
// HA forwarding path testable in-process. Each Core resolves its instance by
// raft node id via proxyServerForNode.
//
// Its lifecycle (listener, gRPC server, announcer) lives on the instance, not
// in package globals, so two instances in one process do not stomp each other.
type proxyServer struct {
	agentproto.UnimplementedAgentServiceServer
	mu     sync.RWMutex
	spokes map[string]*spokeConnection

	// nodeMu guards node and registry, which are populated by the relay backend
	// (SetRelayNode) once the local Core's HA view is available. On a
	// single-node hub node stays nil and every path below reduces to the
	// original local-only behavior.
	nodeMu   sync.RWMutex
	node     relayfwd.Node
	registry *spokeRegistry

	// lifecycleMu guards the listener/announcer lifecycle fields below.
	lifecycleMu   sync.Mutex
	grpcSrv       *grpc.Server  // the running spoke listener's server, for Stop
	startedPort   int           // 0 = not started
	announcerStop chan struct{} // closed to stop the announcer; nil when stopped

	// reannounce is a coalescing wake-up for the announcer: SetRelayNode pokes it
	// (non-blocking) whenever the relay backend re-initializes this node's HA
	// view, which happens on startup and on a leadership transition that re-runs
	// the backend (e.g. a graceful step-down to standby). It makes the re-announce
	// event-driven for those cases instead of waiting up to announceInterval.
	// Buffered depth 1 so a poke is never lost and never blocks the caller.
	reannounce chan struct{}

	// peerMu guards peerConns: cached gRPC connections to other hub nodes'
	// cluster ports, one per peer cluster address. gRPC ClientConns are safe for
	// concurrent use and reconnect internally, so a single connection is reused
	// across announces and forwards instead of being dialed and closed per call.
	peerMu    sync.Mutex
	peerConns map[string]*grpc.ClientConn
}

func newProxyServer() *proxyServer {
	return &proxyServer{
		spokes:     make(map[string]*spokeConnection),
		peerConns:  make(map[string]*grpc.ClientConn),
		reannounce: make(chan struct{}, 1),
	}
}

// proxyServers holds every proxyServer in this process, keyed by raft node id
// ("" for a non-raft single node). In production this map has exactly one
// entry; an in-process test cluster has one per node. proxyServerInstance is
// the "" default, kept for the package-level funcs and the unit tests that use
// them.
var (
	proxyServersMu sync.Mutex
	proxyServers   = map[string]*proxyServer{}
)

// proxyServerForNode returns (creating on first use) the proxyServer bound to
// the given node, keyed by its raft node id. A nil node or an empty node id
// maps to the default "" instance, so a non-raft single node and the package
// funcs share one server.
func proxyServerForNode(node relayfwd.Node) *proxyServer {
	key := ""
	if node != nil {
		key = node.NodeID()
	}
	return proxyServerForKey(key)
}

// proxyServerForKey returns (creating on first use) the instance for a raw key.
func proxyServerForKey(key string) *proxyServer {
	proxyServersMu.Lock()
	defer proxyServersMu.Unlock()
	ps, ok := proxyServers[key]
	if !ok {
		ps = newProxyServer()
		proxyServers[key] = ps
	}
	return ps
}

// activeProxyServer returns the proxyServer PluginProxy should route through:
// the instance whose node is the active (leader) node. PluginProxy runs only on
// the active node and holds no node handle of its own, so it discovers the
// active instance here. In a normal one-node-per-process deployment this is the
// sole instance; the scan only has more than one candidate in an in-process
// test cluster, where the active node's instance is still the right one.
func activeProxyServer() *proxyServer {
	proxyServersMu.Lock()
	defer proxyServersMu.Unlock()
	var fallback *proxyServer
	for _, ps := range proxyServers {
		fallback = ps
		if n := ps.getNode(); n != nil && n.IsActive() {
			return ps
		}
	}
	if fallback != nil {
		return fallback
	}
	return proxyServerInstance
}

func (s *proxyServer) getNode() relayfwd.Node {
	s.nodeMu.RLock()
	defer s.nodeMu.RUnlock()
	return s.node
}

func (s *proxyServer) getRegistry() *spokeRegistry {
	s.nodeMu.RLock()
	defer s.nodeMu.RUnlock()
	return s.registry
}

// pendingResponse carries a successful output or an error back to a waiting
// RunCommand caller, dispatched by request_id.
type pendingResponse struct {
	output string
	err    string
}

type spokeConnection struct {
	stream      agentproto.AgentService_ConnectServer
	connectedAt time.Time

	// sendCh serializes all outbound frames through a single goroutine.
	// grpc.ServerStream.Send is not safe for concurrent use.
	//
	// Deliberately never closed. RunCommand callers (PluginProxy.NewUser etc.
	// invoked from arbitrary OpenBao request goroutines) outlive any single
	// Connect handler and can be mid-`conn.sendCh <- msg` when the spoke
	// reconnects or the stream tears down. Closing the channel from the
	// Connect handler would race with those sends and panic. The senders
	// already select on `<-conn.done` to bail out cleanly; the sender
	// goroutine returns on the same signal. The channel itself is GCd when
	// the last waiter releases the spokeConnection. (The spoke side closes
	// its sendCh because every sender is scoped to bao relay run's Run()
	// and has already been torn down by the time the defer fires.)
	sendCh chan *agentproto.AgentMessage
	// done is closed when the Connect handler returns (stream broke or the
	// spoke reconnected). Waiters unblock and return an error. Always close it
	// via closeDone, never directly: the seal loop, the reconnect teardown, the
	// recv defer, and the sender goroutine can all reach it concurrently.
	done chan struct{}
	// closeDoneOnce guards done so those concurrent closers cannot double-close.
	closeDoneOnce sync.Once

	// inflight maps a request_id to a one-shot channel the waiter is parked
	// on. Allows many concurrent in-flight requests per spoke.
	inflightMu sync.Mutex
	inflight   map[string]chan pendingResponse

	lastSeenMu sync.Mutex
	lastSeen   time.Time
	// certNotAfter is the NotAfter of the spoke's verified mTLS client (leaf)
	// cert. Captured at connect and refreshed by RenewCert, which renews the
	// cert in place over this same live stream (the spoke does not reconnect),
	// so a value captured only at connect time would go stale after a renewal.
	// Guarded by lastSeenMu; zero when unknown.
	certNotAfter time.Time
}

func newSpokeConnection(stream agentproto.AgentService_ConnectServer) *spokeConnection {
	now := time.Now()
	return &spokeConnection{
		stream:      stream,
		connectedAt: now,
		lastSeen:    now,
		sendCh:      make(chan *agentproto.AgentMessage, 16),
		done:        make(chan struct{}),
		inflight:    make(map[string]chan pendingResponse),
	}
}

// closeDone closes done exactly once. Multiple goroutines race to close it (the
// seal loop in stop(), the reconnect teardown, the recv-loop defer, and the
// sender goroutine on a Send error). The bare `select { case <-done: default:
// close(done) }` idiom is NOT safe for that: two goroutines can both observe
// done still open, both fall through to close, and the second close panics. A
// sync.Once makes it race-free.
func (c *spokeConnection) closeDone() {
	c.closeDoneOnce.Do(func() { close(c.done) })
}

func (c *spokeConnection) touch() {
	c.lastSeenMu.Lock()
	c.lastSeen = time.Now()
	c.lastSeenMu.Unlock()
}

func (c *spokeConnection) lastSeenAt() time.Time {
	c.lastSeenMu.Lock()
	defer c.lastSeenMu.Unlock()
	return c.lastSeen
}

func (c *spokeConnection) setCertNotAfter(t time.Time) {
	c.lastSeenMu.Lock()
	c.certNotAfter = t
	c.lastSeenMu.Unlock()
}

func (c *spokeConnection) certNotAfterAt() time.Time {
	c.lastSeenMu.Lock()
	defer c.lastSeenMu.Unlock()
	return c.certNotAfter
}

// register parks a waiter for the given request_id.
func (c *spokeConnection) register(reqID string) chan pendingResponse {
	ch := make(chan pendingResponse, 1)
	c.inflightMu.Lock()
	c.inflight[reqID] = ch
	c.inflightMu.Unlock()
	return ch
}

func (c *spokeConnection) cancel(reqID string) {
	c.inflightMu.Lock()
	delete(c.inflight, reqID)
	c.inflightMu.Unlock()
}

// deliver hands a response to the waiter and clears the inflight entry. No-op
// if the waiter already gave up (context cancelled).
func (c *spokeConnection) deliver(reqID string, resp pendingResponse) {
	c.inflightMu.Lock()
	ch, ok := c.inflight[reqID]
	delete(c.inflight, reqID)
	c.inflightMu.Unlock()
	if !ok {
		return
	}
	select {
	case ch <- resp:
	default:
		// channel is buffered (1) so this is only reached if a duplicate
		// response arrives — ignore the duplicate.
	}
}

// failAll unblocks every parked waiter with the given error string. Called
// when the stream tears down so no caller hangs forever.
func (c *spokeConnection) failAll(errMsg string) {
	c.inflightMu.Lock()
	pending := c.inflight
	c.inflight = make(map[string]chan pendingResponse)
	c.inflightMu.Unlock()
	for _, ch := range pending {
		select {
		case ch <- pendingResponse{err: errMsg}:
		default:
		}
	}
}

// proxyServerInstance is the default ("") proxy server: the one production
// single-node hubs and the package-level funcs use. It is also registered in
// proxyServers under the "" key so proxyServerForNode(nil) returns it.
var proxyServerInstance = func() *proxyServer {
	ps := newProxyServer()
	proxyServers[""] = ps
	return ps
}()

func getProxyServer() *proxyServer { return proxyServerInstance }

// StartProxyServer brings up the default instance's mTLS gRPC listener. Kept as
// a package func for the unit tests and any single-node caller that has no node
// handle. Production goes through StartProxyServerForNode.
func StartProxyServer(port int) error {
	return proxyServerInstance.start(port)
}

// StartProxyServerForNode brings up the listener for the proxy server bound to
// the given node. This is what the relay backend calls, so each Core in an
// in-process cluster binds its own port.
func StartProxyServerForNode(node relayfwd.Node, port int) error {
	return proxyServerForNode(node).start(port)
}

// start brings up this instance's mTLS gRPC listener on the given port. It is
// idempotent: calling it twice with the same port is a no-op; calling it with a
// different port returns an error rather than rebinding (a port change requires
// a process restart).
//
// Callers must have already populated bootstrap.Global() via SetIdentity.
func (s *proxyServer) start(port int) error {
	if port <= 0 {
		return fmt.Errorf("invalid port %d", port)
	}
	if !bootstrap.Global().Ready() {
		return fmt.Errorf("hub identity not initialized; run `bao relay init` first")
	}

	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()

	if s.startedPort != 0 {
		if s.startedPort != port {
			return fmt.Errorf("proxy listener already started on :%d; cannot rebind to :%d without process restart",
				s.startedPort, port)
		}
		return nil
	}

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return err
	}
	creds := credentials.NewTLS(bootstrap.Global().TLSConfig())
	srv := grpc.NewServer(
		grpc.Creds(creds),
		grpc.MaxRecvMsgSize(MaxMessageBytes),
		grpc.MaxSendMsgSize(MaxMessageBytes),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:    HubKeepaliveInterval,
			Timeout: HubKeepaliveTimeout,
		}),
		// Allow spoke heartbeats more frequent than the server's own ping
		// cadence without the server tearing the connection down for "ping
		// flood" (the default MinTime is 5m).
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             5 * time.Second,
			PermitWithoutStream: true,
		}),
	)
	agentproto.RegisterAgentServiceServer(srv, s)
	go func() {
		if err := srv.Serve(lis); err != nil {
			log.Printf("[proxy] gRPC server stopped: %v", err)
		}
	}()
	s.grpcSrv = srv
	s.startedPort = port
	log.Printf("[proxy] mTLS server listening on :%d", port)
	return nil
}

// StopProxyServer tears the default instance down (unit tests, single-node).
func StopProxyServer() { proxyServerInstance.stop() }

// StopProxyServerForNode tears down the proxy server bound to the given node.
// The relay backend calls this from its Clean hook on a genuine seal.
func StopProxyServerForNode(node relayfwd.Node) { proxyServerForNode(node).stop() }

// stop tears the proxy listener down. It is the seal-path inverse of start,
// called from the relay backend's Cleanup so a sealed node announces nothing and
// holds nothing (see DESIGN.md "Prerequisite: stop the listener on seal").
//
// It gracefully stops the gRPC server (which returns the Connect handlers and
// runs their teardown defers), stops the announcer, then fails any parked
// waiters and clears the spoke map defensively, zeroes the started-port guard so
// a later unseal can rebind, and clears the bootstrap identity so the spoke-CA
// key does not linger in memory on a sealed node.
//
// Idempotent: calling it when nothing is running is a no-op. Note the instance
// itself is intentionally NOT discarded — a standby that unseals read-only keeps
// its listener across a standby-to-active transition (which re-runs the
// backend's InitializeFunc but not Cleanup), so spoke streams survive a
// leadership change. Only an actual seal calls this.
func (s *proxyServer) stop() {
	s.lifecycleMu.Lock()
	srv := s.grpcSrv
	s.grpcSrv = nil
	s.startedPort = 0
	if s.announcerStop != nil {
		close(s.announcerStop)
		s.announcerStop = nil
	}
	s.lifecycleMu.Unlock()

	if srv != nil {
		// GracefulStop returns once all in-flight RPCs (including the
		// long-lived Connect streams, which we cancel below by closing their
		// done channels) have finished. Force a hard Stop after a short grace
		// window so a wedged stream cannot hold the seal path open.
		stopped := make(chan struct{})
		go func() {
			srv.GracefulStop()
			close(stopped)
		}()
		go func() {
			timer := time.NewTimer(2 * time.Second)
			defer timer.Stop()
			select {
			case <-stopped:
			case <-timer.C:
				srv.Stop()
			}
		}()
	}

	// Fail every parked waiter and drop every connection from the map. The
	// Connect handlers' own defers also do this as the server stops, but doing
	// it here makes "sealed => empty map" hold immediately and independently of
	// how fast GracefulStop drains.
	s.mu.Lock()
	conns := s.spokes
	s.spokes = make(map[string]*spokeConnection)
	s.mu.Unlock()
	for _, c := range conns {
		c.closeDone()
		c.failAll("hub node sealed")
	}

	// Close cached connections to peer hub nodes.
	s.closePeerConns()

	// Drop the spoke-CA key + hub cert from memory. A sealed node must not hold
	// signing material.
	bootstrap.Global().Clear()

	log.Printf("[proxy] listener stopped (node sealed)")
}

func (s *proxyServer) Connect(stream agentproto.AgentService_ConnectServer) error {
	// Identity comes from the verified client cert, NOT from msg.ClientName.
	// This is the load-bearing security check now that bootstrap tokens have
	// been exchanged for client certs — the wire-level claim is spoofable, the
	// CN is not.
	leaf, err := spokeLeafFromPeer(stream.Context())
	if err != nil {
		return err
	}
	spokeName := leaf.Subject.CommonName
	if spokeName == "" {
		return fmt.Errorf("client cert has no Common Name")
	}

	// Optional pin-spokes-to-active policy (off by default): a non-active node
	// refuses the stream and redirects the spoke to the leader's relay endpoint.
	// Checked before installing the connection so a rejected stream is never
	// recorded in the spoke map.
	if err := s.rejectSpokeIfPinned(); err != nil {
		return err
	}

	conn := newSpokeConnection(stream)
	// Record the leaf's expiry so the hub can surface per-spoke cert expiry.
	conn.setCertNotAfter(leaf.NotAfter)

	// Reconnect handling: if the same spoke already had a stream open, cancel
	// the old one so it doesn't leak. Order matters — install the NEW conn
	// first, then tear down the old. A concurrent RunCommand reader that
	// arrives in this window now sees the new conn immediately; the previous
	// order ("close old, then assign new") left a brief slot where the same
	// reader saw the old conn with done already closed and returned a
	// transient "spoke disconnected" even though the fresh stream was one
	// mutex acquisition away. The old Connect goroutine's cleanup defer
	// uses an identity check (`cur == conn`) so it does not remove the new
	// entry from the map.
	s.mu.Lock()
	old, hadOld := s.spokes[spokeName]
	s.spokes[spokeName] = conn
	s.mu.Unlock()
	if hadOld {
		log.Printf("[proxy] spoke %q reconnected; tearing down old stream", spokeName)
		old.closeDone()
		old.failAll(fmt.Sprintf("spoke %q reconnected", spokeName))
	}
	// This node's local spoke set just changed. On a standby, poke the announcer
	// so the active node's registry learns the new spoke in ~1 RTT instead of up
	// to one announce interval, shrinking the window where a credential op for a
	// freshly-landed spoke resolves to nothing. No-op on the active node (it
	// announces nothing) and coalesced, so a reconnect burst is cheap.
	s.pokeReannounce()

	defer func() {
		s.mu.Lock()
		if cur, ok := s.spokes[spokeName]; ok && cur == conn {
			delete(s.spokes, spokeName)
		}
		s.mu.Unlock()
		conn.closeDone()
		conn.failAll("spoke disconnected")
		// The local set shrank; re-announce so the active node drops this spoke
		// promptly rather than waiting for it to expire after missed announces.
		s.pokeReannounce()
	}()

	// Sender goroutine: drains sendCh and serializes all writes. stream.Send
	// is not safe for concurrent calls, so every outbound frame must go
	// through here.
	sendErrCh := make(chan error, 1)
	go func() {
		for {
			select {
			case msg := <-conn.sendCh:
				if err := stream.Send(msg); err != nil {
					select {
					case sendErrCh <- err:
					default:
					}
					// Close conn.done so parked RunCommand callers (waiting
					// on respCh / sendCh / done) unblock immediately
					// instead of sitting for ~40s until gRPC keepalive
					// notices the broken stream. closeDone is idempotent, so
					// racing the recv-loop defer is safe.
					conn.closeDone()
					return
				}
			case <-conn.done:
				return
			}
		}
	}()

	// Initial ack. We push it through sendCh like everything else so the
	// sender goroutine catches any early error. (Earlier code dropped the
	// send error here entirely.)
	//
	// Select on <-conn.done for symmetry with every other producer on this
	// channel. The buffer is large enough today that a bare send wouldn't
	// block, but a future capacity tweak (or, more plausibly, a path that
	// queues frames before the Connect handler reaches this line) would
	// leave the initial-ack send as the only producer that can wedge if
	// the stream tore down between newSpokeConnection and here.
	select {
	case conn.sendCh <- &agentproto.AgentMessage{
		ClientName: spokeName,
		Output:     "Connected",
		IsResponse: true,
	}:
	case <-conn.done:
		return fmt.Errorf("spoke %q: stream torn down before initial ack", spokeName)
	}

	for {
		msg, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		select {
		case sendErr := <-sendErrCh:
			return fmt.Errorf("send: %w", sendErr)
		default:
		}

		// Every received frame is liveness evidence: heartbeats, responses,
		// even the initial registration. This is the "response acts as
		// heartbeat" half of the design — the explicit heartbeat is only
		// needed when the spoke is idle.
		conn.touch()

		switch {
		case msg.IsHeartbeat:
			// touch() above is the whole point.
		case msg.IsResponse && msg.RequestId != "":
			conn.deliver(msg.RequestId, pendingResponse{
				output: msg.Output,
				err:    msg.Error,
			})
		}
	}
}

// spokeLeafFromPeer returns the verified client (leaf) cert of the incoming
// mTLS connection. Requires the gRPC server to be configured with mTLS
// (RequireAndVerifyClientCert).
func spokeLeafFromPeer(ctx context.Context) (*x509.Certificate, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil, fmt.Errorf("no peer info on incoming stream")
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return nil, fmt.Errorf("connection is not TLS")
	}
	if len(tlsInfo.State.VerifiedChains) == 0 || len(tlsInfo.State.VerifiedChains[0]) == 0 {
		return nil, fmt.Errorf("no verified client cert chain")
	}
	return tlsInfo.State.VerifiedChains[0][0], nil
}

// spokeNameFromPeer extracts the spoke identity from the verified client cert.
// Requires the gRPC server to be configured with mTLS (RequireAndVerifyClientCert).
func spokeNameFromPeer(ctx context.Context) (string, error) {
	leaf, err := spokeLeafFromPeer(ctx)
	if err != nil {
		return "", err
	}
	if leaf.Subject.CommonName == "" {
		return "", fmt.Errorf("client cert has no Common Name")
	}
	return leaf.Subject.CommonName, nil
}

// RunCommand sends a request to spokeName and waits for the correlated
// response. Many callers can be in-flight concurrently against the same spoke;
// each parks on its own channel keyed by request_id.
// RenewCertMaxTTL caps the validity period RenewCert will sign for, regardless
// of what the spoke requested. The mTLS handshake proves the caller holds a
// currently-valid spoke cert, but a compromised cert that requests 10 years
// would give the attacker decade-long persistence; the cap limits the
// blast radius even when the mTLS check passes.
const RenewCertMaxTTL = 90 * 24 * time.Hour

// RenewCertDefaultTTL is what we sign for when the spoke requests 0. Kept
// equal to the initial bao relay join cert validity so the default renewal
// cadence (bao relay run -renew-threshold=0.5) lines up with operators'
// expectations.
const RenewCertDefaultTTL = 30 * 24 * time.Hour

// RenewCert is the spoke-cert renewal RPC. The caller is already authenticated
// at the transport layer via mTLS — completing the gRPC handshake proves the
// spoke holds a valid client cert signed by the spoke-CA. We then refuse any
// CSR whose CN does not match the peer cert's CN, so renewal cannot rebind to
// a different identity, and we cap the requested TTL at RenewCertMaxTTL.
func (s *proxyServer) RenewCert(ctx context.Context, req *agentproto.RenewCertRequest) (*agentproto.RenewCertResponse, error) {
	peerCN, err := spokeNameFromPeer(ctx)
	if err != nil {
		return nil, err
	}
	if len(req.CsrPem) == 0 {
		return nil, fmt.Errorf("csr_pem is required")
	}

	// The spoke-CA key is in memory on every unsealed node, so a standby COULD
	// sign locally. It must not: that would give the cluster N independent
	// issuers with no single audit point. If this node is not the active node,
	// forward the CSR to the active node (RelayForwarding.SignSpokeCSR), then
	// return the signed cert to the spoke over this same live stream. See
	// DESIGN.md "Authority operations go to the active node".
	if node := s.getNode(); node != nil && !node.IsActive() {
		return s.forwardRenewCert(ctx, node, peerCN, req)
	}

	csrDER, err := bootstrap.DecodeCSRPEM(req.CsrPem)
	if err != nil {
		return nil, err
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, fmt.Errorf("parse CSR: %w", err)
	}
	if csr.Subject.CommonName != peerCN {
		return nil, fmt.Errorf("CSR CN %q does not match authenticated spoke %q",
			csr.Subject.CommonName, peerCN)
	}

	caCertPEM, caKeyPEM := bootstrap.Global().CABundlePEM()
	if len(caCertPEM) == 0 || len(caKeyPEM) == 0 {
		return nil, fmt.Errorf("hub identity not initialized")
	}
	ca := &bootstrap.CABundle{CertPEM: caCertPEM, KeyPEM: caKeyPEM}

	// Compute the cap in seconds and clamp BEFORE multiplying by time.Second.
	// time.Duration(req.TtlSeconds) * time.Second overflows int64 around
	// TtlSeconds ≈ 9.2e9 and silently produces a negative duration that
	// then falls through to the "ttl <= 0 → default" branch — a 100-year
	// request would become a 30-day cert with no error to the caller.
	const renewCertMaxSeconds = int64(RenewCertMaxTTL / time.Second)
	if req.TtlSeconds < 0 {
		return nil, fmt.Errorf("ttl_seconds must be non-negative (got %d)", req.TtlSeconds)
	}
	var ttl time.Duration
	switch {
	case req.TtlSeconds == 0:
		ttl = RenewCertDefaultTTL
	case req.TtlSeconds >= renewCertMaxSeconds:
		ttl = RenewCertMaxTTL
	default:
		ttl = time.Duration(req.TtlSeconds) * time.Second
	}
	certPEM, err := ca.SignSpokeCSR(csrDER, peerCN, ttl)
	if err != nil {
		return nil, err
	}

	// Renewal happens in place over the live stream — the spoke does not
	// reconnect — so refresh the connection's recorded expiry from the cert we
	// just signed. Otherwise `relay/spokes` would keep reporting the old
	// NotAfter until the spoke happens to reconnect. Best-effort: if the spoke
	// has no live connection or the cert fails to parse, leave the old value.
	if newNotAfter, perr := certNotAfterFromPEM(certPEM); perr == nil {
		s.mu.RLock()
		conn, ok := s.spokes[peerCN]
		s.mu.RUnlock()
		if ok {
			conn.setCertNotAfter(newNotAfter)
		}
	}

	return &agentproto.RenewCertResponse{
		CertPem:   certPEM,
		CaCertPem: caCertPEM,
	}, nil
}

// certNotAfterFromPEM parses the first CERTIFICATE block of a PEM bundle and
// returns its NotAfter.
func certNotAfterFromPEM(certPEM []byte) (time.Time, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return time.Time{}, fmt.Errorf("no PEM block in cert")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, err
	}
	return cert.NotAfter, nil
}

// RunCommand routes a request to spokeName. It tries the local connected-spoke
// map first: on a single-node hub (and whenever the spoke's stream terminates
// on this node) this is byte-for-byte the original hot path. Only when the
// spoke is NOT local does it consult the HA registry and forward to the node
// that holds the stream (DESIGN.md "Route in proxyServer.RunCommand").
func (s *proxyServer) RunCommand(ctx context.Context, spokeName, command string) (string, error) {
	s.mu.RLock()
	conn, ok := s.spokes[spokeName]
	s.mu.RUnlock()
	if ok {
		return s.runLocalConn(ctx, conn, spokeName, command)
	}

	// Not local. On a single-node hub (node == nil) or when we are not the
	// active node, there is nothing to forward to: preserve the original error.
	node := s.getNode()
	reg := s.getRegistry()
	if node == nil || reg == nil || !node.IsActive() {
		return "", fmt.Errorf("spoke %q: %w", spokeName, ErrSpokeNotConnected)
	}

	loc, ok := reg.resolve(spokeName)
	if !ok {
		return "", fmt.Errorf("spoke %q: %w", spokeName, ErrSpokeNotConnected)
	}
	out, err := s.forwardRunCommand(ctx, node, loc, spokeName, command)
	if err != nil && isSpokeNotConnected(err) {
		// Stale registry entry: the recorded owner no longer holds the stream.
		// Drop it with a compare-and-delete (only if it still names that owner),
		// so a fresh announce that moved the spoke to another node is preserved,
		// then re-resolve exactly once and forward to the new owner if there is
		// one; otherwise surface not-connected.
		reg.forgetIf(spokeName, loc.NodeClusterAddr)
		if loc2, ok := reg.resolve(spokeName); ok && loc2.NodeClusterAddr != loc.NodeClusterAddr {
			return s.forwardRunCommand(ctx, node, loc2, spokeName, command)
		}
		return "", fmt.Errorf("spoke %q: %w", spokeName, ErrSpokeNotConnected)
	}
	return out, err
}

// runLocalConn is the original in-process request/response exchange over a spoke
// stream this node terminates. Shared by the direct RunCommand caller and the
// RelayForwarding.RunCommand handler (a forwarded command from the active node),
// so a forwarded frame takes the identical local path a direct one would.
func (s *proxyServer) runLocalConn(ctx context.Context, conn *spokeConnection, spokeName, command string) (string, error) {
	reqID, err := newRequestID()
	if err != nil {
		return "", err
	}
	respCh := conn.register(reqID)
	defer conn.cancel(reqID)

	select {
	case conn.sendCh <- &agentproto.AgentMessage{
		ClientName: "proxy",
		TargetName: spokeName,
		Command:    command,
		RequestId:  reqID,
		IsResponse: false,
	}:
	case <-ctx.Done():
		return "", ctx.Err()
	case <-conn.done:
		return "", fmt.Errorf("spoke %q disconnected", spokeName)
	}

	select {
	case resp := <-respCh:
		if resp.err != "" {
			return "", fmt.Errorf("spoke: %s", resp.err)
		}
		return resp.output, nil
	case <-ctx.Done():
		return "", ctx.Err()
	case <-conn.done:
		return "", fmt.Errorf("spoke %q disconnected", spokeName)
	}
}

func newRequestID() (string, error) {
	var b [12]byte
	if _, err := cryptorand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// PluginProxy forwards all database plugin operations to spoke-agent
type PluginProxy struct {
	pluginName    string
	spokeName     string
	connectionURL string
	// instanceID is the stable handle the spoke uses to cache the plugin
	// instance across calls. Generated on first Initialize, persisted in the
	// mount config so the same handle is reused on plugin reloads and Vault
	// restarts.
	instanceID string
	config     map[string]interface{}
}

var _ dbplugin.Database = (*PluginProxy)(nil)

func New(pluginName string) func() (interface{}, error) {
	return func() (interface{}, error) {
		db := &PluginProxy{
			pluginName: pluginName,
		}
		return dbplugin.NewDatabaseErrorSanitizerMiddleware(db, db.secretValues), nil
	}
}

// secretSensitiveKeys lists config map keys whose values must be masked in
// any error returned from the spoke. Note we deliberately do NOT include
// "username" here: the operator-configured root username often appears in
// legitimate non-sensitive plugin output ("user X already exists"), and
// masking it everywhere by global substring replace makes those messages
// unreadable. The credential channel (connection_url) is masked as a
// whole, which already covers the most common path where the username
// appears alongside the password.
var secretSensitiveKeys = []string{
	"password",
	"private_key",
	"client_key",
	"tls_key",
	"token",
	"secret",
}

func (p *PluginProxy) secretValues() map[string]string {
	out := map[string]string{}
	if p.connectionURL != "" {
		out[p.connectionURL] = "[connection_url]"
	}
	for _, k := range secretSensitiveKeys {
		v, ok := p.config[k].(string)
		if !ok || v == "" {
			continue
		}
		out[v] = "[" + k + "]"
	}
	return out
}

const proxyInstanceIDKey = "plugin_instance_id"

func (p *PluginProxy) Initialize(ctx context.Context, req dbplugin.InitializeRequest) (dbplugin.InitializeResponse, error) {
	spokeName, err := proxyGetConfigString(req.Config, "spoke_name")
	if err != nil {
		return dbplugin.InitializeResponse{}, err
	}

	// PluginProxy runs on the active node and holds no node handle, so it routes
	// through the active node's proxy server (activeProxyServer), which in a
	// normal one-node-per-process deployment is the sole instance.
	if activeProxyServer().port() == 0 {
		return dbplugin.InitializeResponse{}, fmt.Errorf(
			"proxy listener not running; run `bao relay init` on the hub before configuring database mounts",
		)
	}

	// Reuse the persisted instance_id when present; otherwise mint a fresh one.
	// This is the handle the spoke uses to cache its long-lived dbplugin
	// instance. Stable across plugin reloads so the spoke does not
	// re-Initialize (re-open a DB connection) on every call.
	//
	// A wrong-type value (e.g. the storage round-trip turned it from string
	// to json.Number for some reason) silently used to mint a new id and
	// orphan the spoke's cached plugin. Log loudly so operators see it.
	var instanceID string
	if v, present := req.Config[proxyInstanceIDKey]; present {
		s, ok := v.(string)
		if !ok {
			log.Printf("[proxy] %s in mount config is %T, expected string; minting a fresh id (the spoke's previously cached plugin instance will be orphaned and idle-evicted)",
				proxyInstanceIDKey, v)
		} else {
			instanceID = s
		}
	}
	if instanceID == "" {
		instanceID, err = newRequestID() // 12-byte hex is plenty unique here
		if err != nil {
			return dbplugin.InitializeResponse{}, err
		}
	}

	p.spokeName = spokeName
	p.instanceID = instanceID
	p.config = req.Config

	if connURL, ok := req.Config["connection_url"].(string); ok {
		p.connectionURL = connURL
	}

	pluginConfig := p.getPluginConfig()

	request := map[string]interface{}{
		"method":            "Initialize",
		"plugin_name":       p.pluginName,
		"instance_id":       instanceID,
		"config":            pluginConfig,
		"verify_connection": req.VerifyConnection,
	}

	response, err := p.callPlugin(ctx, request)
	if err != nil {
		return dbplugin.InitializeResponse{}, err
	}

	var initResp struct {
		Config map[string]interface{} `json:"config"`
	}
	if err := json.Unmarshal([]byte(response), &initResp); err != nil {
		return dbplugin.InitializeResponse{}, fmt.Errorf("parse response failed: %w", err)
	}

	if initResp.Config == nil {
		initResp.Config = make(map[string]interface{})
	}
	// Persist the proxy-specific fields back into the mount config so the
	// next Vault restart (or plugin reload) hands them to us again.
	initResp.Config["spoke_name"] = spokeName
	initResp.Config[proxyInstanceIDKey] = instanceID

	return dbplugin.InitializeResponse{Config: initResp.Config}, nil
}

// port returns the port this instance's listener is bound to, or 0.
func (s *proxyServer) port() int {
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	return s.startedPort
}

// ProxyServerPort returns the default instance's bound port (unit tests,
// single-node). Production reads ProxyServerPortForNode.
func ProxyServerPort() int { return proxyServerInstance.port() }

// ProxyServerPortForNode returns the bound port of the proxy server for the
// given node.
func ProxyServerPortForNode(node relayfwd.Node) int { return proxyServerForNode(node).port() }

// SpokeStatus is the health snapshot used by `bao relay list` and relay/spokes.
type SpokeStatus struct {
	Name        string
	ConnectedAt time.Time
	LastSeen    time.Time
	Healthy     bool
	// CertNotAfter is the spoke's current mTLS client-cert expiry. Zero when
	// unknown (e.g. no verified peer cert was captured).
	CertNotAfter time.Time
	// NodeClusterAddr / NodeID identify the hub node that terminates this
	// spoke's stream. NodeIsActive reports whether that node is the active
	// (leader) node. In an HA hub a spoke on a standby is normal and fully
	// functional: the active node forwards to it. These are empty/true on a
	// single-node hub.
	NodeClusterAddr string
	NodeID          string
	NodeIsActive    bool
}

// HubNode is one hub node in the cluster. The top-level hub_nodes list in
// relay/spokes is built from these so an operator can see the cluster's stream
// ownership at a glance.
type HubNode struct {
	ClusterAddr string
	NodeID      string
	IsActive    bool
	SpokeCount  int
}

// SpokesView is the cluster-wide relay/spokes payload. FromActive reports
// whether it reflects the active node's merged view (the complete picture):
// true on the active node and on a standby whose read was forwarded to the
// active, false on a standby that fell back to its own partial local view
// because forwarding failed.
type SpokesView struct {
	Spokes            []SpokeStatus
	HubNodes          []HubNode
	ListenerPort      int
	StaleAfterSeconds int64
	FromActive        bool
}

// ListConnectedSpokes returns the default instance's snapshot (unit tests,
// single-node). Production reads the whole-cluster view via ClusterSpokesForNode.
func ListConnectedSpokes() []SpokeStatus { return proxyServerInstance.listConnectedSpokes() }

// listConnectedSpokes returns the cluster-wide health snapshot: the spokes whose
// streams terminate on this node PLUS, when this is the active node, the spokes
// other nodes have announced. Sorted by name. Point-in-time — safe to race with
// disconnects. On a single-node hub this reduces to the local map.
func (s *proxyServer) listConnectedSpokes() []SpokeStatus {
	node := s.getNode()
	reg := s.getRegistry()

	selfActive := true // single-node default
	var selfAddr, selfID string
	if node != nil {
		selfActive = node.IsActive()
		selfAddr = node.ClusterAddr()
		selfID = node.NodeID()
	}

	now := time.Now()
	s.mu.RLock()
	out := make([]SpokeStatus, 0, len(s.spokes))
	local := make(map[string]struct{}, len(s.spokes))
	for name, c := range s.spokes {
		last := c.lastSeenAt()
		local[name] = struct{}{}
		out = append(out, SpokeStatus{
			Name:            name,
			ConnectedAt:     c.connectedAt,
			LastSeen:        last,
			Healthy:         now.Sub(last) < SpokeStaleAfter,
			CertNotAfter:    c.certNotAfterAt(),
			NodeClusterAddr: selfAddr,
			NodeID:          selfID,
			NodeIsActive:    selfActive,
		})
	}
	s.mu.RUnlock()

	// Merge spokes owned by other nodes from the registry (active node only;
	// the registry is empty elsewhere). A spoke that is both local and in the
	// registry is served locally, so the local entry wins.
	if reg != nil {
		for _, loc := range reg.snapshot() {
			if _, isLocal := local[loc.SpokeName]; isLocal {
				continue
			}
			out = append(out, SpokeStatus{
				Name:            loc.SpokeName,
				ConnectedAt:     loc.ConnectedAt,
				LastSeen:        loc.LastSeen,
				Healthy:         now.Sub(loc.LastSeen) < SpokeStaleAfter,
				CertNotAfter:    loc.CertNotAfter,
				NodeClusterAddr: loc.NodeClusterAddr,
				NodeID:          loc.NodeID,
				NodeIsActive:    false, // registry only holds non-active nodes' spokes
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// ListHubNodes returns the default instance's hub-node view (unit tests,
// single-node). Production reads the whole-cluster view via ClusterSpokesForNode.
func ListHubNodes() []HubNode { return proxyServerInstance.listHubNodes() }

// listHubNodes returns every hub node in the cluster with its spoke count. It
// seeds from the HA peer membership (node.Peers()), so a hub node that
// terminates zero spokes still appears, then adds per-node spoke counts from
// listConnectedSpokes. On a single-node hub or a standby (empty peer cache) it
// reduces to the nodes that own streams.
func (s *proxyServer) listHubNodes() []HubNode {
	byKey := make(map[string]*HubNode)
	order := make([]string, 0)
	get := func(addr, id string, active bool) *HubNode {
		key := addr + "|" + id
		hn, ok := byKey[key]
		if !ok {
			hn = &HubNode{ClusterAddr: addr, NodeID: id, IsActive: active}
			byKey[key] = hn
			order = append(order, key)
		}
		return hn
	}

	// Seed with the full peer set so zero-spoke nodes are visible.
	if node := s.getNode(); node != nil {
		for _, p := range node.Peers() {
			get(p.ClusterAddr, p.NodeID, p.IsActive)
		}
	}
	// Add spoke counts (and any owning node the peer set did not list).
	for _, sp := range s.listConnectedSpokes() {
		get(sp.NodeClusterAddr, sp.NodeID, sp.NodeIsActive).SpokeCount++
	}

	out := make([]HubNode, 0, len(order))
	for _, k := range order {
		out = append(out, *byKey[k])
	}
	sort.Slice(out, func(i, j int) bool { return out[i].NodeID < out[j].NodeID })
	return out
}

func (p *PluginProxy) NewUser(ctx context.Context, req dbplugin.NewUserRequest) (dbplugin.NewUserResponse, error) {
	request := map[string]interface{}{
		"method":      "NewUser",
		"plugin_name": p.pluginName,
		"instance_id": p.instanceID,
		"config":      p.getPluginConfig(),
		"username_config": map[string]interface{}{
			"display_name": req.UsernameConfig.DisplayName,
			"role_name":    req.UsernameConfig.RoleName,
		},
		"credential_type":     req.CredentialType.String(),
		"password":            req.Password,
		"public_key":          string(req.PublicKey),
		"subject":             req.Subject,
		"expiration":          req.Expiration.Unix(),
		"statements":          req.Statements.Commands,
		"rollback_statements": req.RollbackStatements.Commands,
	}

	response, err := p.callPlugin(ctx, request)
	if err != nil {
		return dbplugin.NewUserResponse{}, err
	}

	var newUserResp struct {
		Username string `json:"username"`
	}
	if err := json.Unmarshal([]byte(response), &newUserResp); err != nil {
		return dbplugin.NewUserResponse{}, fmt.Errorf("parse response failed: %w", err)
	}

	return dbplugin.NewUserResponse{Username: newUserResp.Username}, nil
}

func (p *PluginProxy) UpdateUser(ctx context.Context, req dbplugin.UpdateUserRequest) (dbplugin.UpdateUserResponse, error) {
	request := map[string]interface{}{
		"method":          "UpdateUser",
		"plugin_name":     p.pluginName,
		"instance_id":     p.instanceID,
		"config":          p.getPluginConfig(),
		"username":        req.Username,
		"credential_type": req.CredentialType.String(),
	}

	if req.Password != nil {
		request["password"] = map[string]interface{}{
			"new_password": req.Password.NewPassword,
			"statements":   req.Password.Statements.Commands,
		}
	}

	if req.PublicKey != nil {
		request["public_key"] = map[string]interface{}{
			"new_public_key": string(req.PublicKey.NewPublicKey),
			"statements":     req.PublicKey.Statements.Commands,
		}
	}

	if req.Expiration != nil {
		request["expiration"] = map[string]interface{}{
			"new_expiration": req.Expiration.NewExpiration.Unix(),
			"statements":     req.Expiration.Statements.Commands,
		}
	}

	_, err := p.callPlugin(ctx, request)
	return dbplugin.UpdateUserResponse{}, err
}

func (p *PluginProxy) DeleteUser(ctx context.Context, req dbplugin.DeleteUserRequest) (dbplugin.DeleteUserResponse, error) {
	request := map[string]interface{}{
		"method":      "DeleteUser",
		"plugin_name": p.pluginName,
		"instance_id": p.instanceID,
		"config":      p.getPluginConfig(),
		"username":    req.Username,
		"statements":  req.Statements.Commands,
	}

	_, err := p.callPlugin(ctx, request)
	return dbplugin.DeleteUserResponse{}, err
}

func (p *PluginProxy) Type() (string, error) {
	return p.pluginName, nil
}

// Close asks the spoke to drop the cached plugin instance, which closes its DB
// connection. Best-effort: a failure (spoke offline, missing instance) is
// logged but not returned, since OpenBao would do nothing useful with it
// during mount teardown.
//
// Idempotent: a second call short-circuits at the guard below. Without the
// instanceID reset the second call would send another round-trip to the
// spoke, which would respond "instance_id not found" (the first Close
// already evicted it) and we would log a spurious error on every shutdown
// path that calls Close twice.
func (p *PluginProxy) Close() error {
	if p.instanceID == "" || p.spokeName == "" {
		return nil
	}
	request := map[string]interface{}{
		"method":      "Close",
		"plugin_name": p.pluginName,
		"instance_id": p.instanceID,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := p.callPlugin(ctx, request); err != nil {
		log.Printf("[proxy] close on spoke %q (instance %s): %v", p.spokeName, p.instanceID, err)
	}
	p.instanceID = ""
	return nil
}

func (p *PluginProxy) callPlugin(ctx context.Context, request map[string]interface{}) (string, error) {
	reqJSON, err := json.Marshal(request)
	if err != nil {
		return "", err
	}

	// Wire format is now bare JSON. The "plugin-runner <json>" prefix used by
	// the old subprocess-per-request design is gone — the spoke daemon
	// dispatches to a long-lived in-process plugin instance.
	output, err := activeProxyServer().RunCommand(ctx, p.spokeName, string(reqJSON))
	if err != nil {
		return "", err
	}
	return output, nil
}

func proxyGetConfigString(config map[string]interface{}, key string) (string, error) {
	v, ok := config[key]
	if !ok {
		return "", fmt.Errorf("missing %q", key)
	}
	s, ok := v.(string)
	if !ok || s == "" {
		return "", fmt.Errorf("%q must be non-empty string", key)
	}
	return s, nil
}

func (p *PluginProxy) getPluginConfig() map[string]interface{} {
	// Strip proxy-only fields. These are persisted into the mount config by
	// the hub so that they survive plugin reload, but the spoke must hand
	// the real built-in plugin a config that contains only its own fields
	// (postgres/mysql/… reject unknown keys via their schema validation).
	pluginConfig := make(map[string]interface{}, len(p.config))
	for k, v := range p.config {
		switch k {
		case "spoke_name", "relay_port", proxyInstanceIDKey:
			continue
		}
		pluginConfig[k] = v
	}
	return pluginConfig
}
