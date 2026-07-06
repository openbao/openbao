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

	"github.com/openbao/openbao/plugins/database/remote-db-plugin/bootstrap"
	agentproto "github.com/openbao/openbao/plugins/database/remote-db-plugin/proto/gen"
	dbplugin "github.com/openbao/openbao/sdk/v2/database/dbplugin/v5"
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

// proxyServer is the singleton gRPC server that brokers requests between the
// hub and spoke-agents. It is started exactly once by StartProxyServer, which
// is called from the relay backend (on `relay/ca/init` and on backend
// hydration after a restart). Database mounts no longer touch its lifecycle.
type proxyServer struct {
	agentproto.UnimplementedAgentServiceServer
	mu     sync.RWMutex
	spokes map[string]*spokeConnection
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
	// spoke reconnected). Waiters unblock and return an error.
	done chan struct{}

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

var (
	proxyServerInstance = &proxyServer{spokes: make(map[string]*spokeConnection)}

	proxyServerLifecycleMu sync.Mutex
	proxyServerStartedPort int // 0 = not started
)

func getProxyServer() *proxyServer { return proxyServerInstance }

// StartProxyServer brings up the mTLS gRPC listener on the given port. It is
// idempotent: calling it twice with the same port is a no-op; calling it with
// a different port returns an error rather than rebinding (a port change
// requires a process restart).
//
// Callers must have already populated bootstrap.Global() via SetIdentity.
func StartProxyServer(port int) error {
	if port <= 0 {
		return fmt.Errorf("invalid port %d", port)
	}
	if !bootstrap.Global().Ready() {
		return fmt.Errorf("hub identity not initialized; run `bao relay init` first")
	}

	proxyServerLifecycleMu.Lock()
	defer proxyServerLifecycleMu.Unlock()

	if proxyServerStartedPort != 0 {
		if proxyServerStartedPort != port {
			return fmt.Errorf("proxy listener already started on :%d; cannot rebind to :%d without process restart",
				proxyServerStartedPort, port)
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
	agentproto.RegisterAgentServiceServer(srv, proxyServerInstance)
	go func() {
		if err := srv.Serve(lis); err != nil {
			log.Printf("[proxy] gRPC server stopped: %v", err)
		}
	}()
	proxyServerStartedPort = port
	log.Printf("[proxy] mTLS server listening on :%d", port)
	return nil
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
		close(old.done)
		old.failAll(fmt.Sprintf("spoke %q reconnected", spokeName))
	}

	defer func() {
		s.mu.Lock()
		if cur, ok := s.spokes[spokeName]; ok && cur == conn {
			delete(s.spokes, spokeName)
		}
		s.mu.Unlock()
		// closing twice would panic; only close if we own this connection
		select {
		case <-conn.done:
		default:
			close(conn.done)
		}
		conn.failAll("spoke disconnected")
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
					// notices the broken stream. The recv-loop defer also
					// closes done with the same guarded select, so a double
					// close is impossible.
					select {
					case <-conn.done:
					default:
						close(conn.done)
					}
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

func (s *proxyServer) RunCommand(ctx context.Context, spokeName, command string) (string, error) {
	s.mu.RLock()
	conn, ok := s.spokes[spokeName]
	s.mu.RUnlock()
	if !ok {
		return "", fmt.Errorf("spoke %q not connected", spokeName)
	}

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

	if ProxyServerPort() == 0 {
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

// ProxyServerPort returns the port the proxy is bound to, or 0 if not started.
// Used by PluginProxy.Initialize to fail fast when the operator forgot to run
// `bao relay init`.
func ProxyServerPort() int {
	proxyServerLifecycleMu.Lock()
	defer proxyServerLifecycleMu.Unlock()
	return proxyServerStartedPort
}

// SpokeStatus is the health snapshot used by `bao relay list`.
type SpokeStatus struct {
	Name        string
	ConnectedAt time.Time
	LastSeen    time.Time
	Healthy     bool
	// CertNotAfter is the spoke's current mTLS client-cert expiry. Zero when
	// unknown (e.g. no verified peer cert was captured).
	CertNotAfter time.Time
}

// ListConnectedSpokes returns the health snapshot of every spoke with an open
// Connect stream, sorted by name. Point-in-time and lock-free at the caller —
// safe to race with disconnects.
func ListConnectedSpokes() []SpokeStatus {
	s := getProxyServer()
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]SpokeStatus, 0, len(s.spokes))
	now := time.Now()
	for name, c := range s.spokes {
		last := c.lastSeenAt()
		out = append(out, SpokeStatus{
			Name:         name,
			ConnectedAt:  c.connectedAt,
			LastSeen:     last,
			Healthy:      now.Sub(last) < SpokeStaleAfter,
			CertNotAfter: c.certNotAfterAt(),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
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
	output, err := getProxyServer().RunCommand(ctx, p.spokeName, string(reqJSON))
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
