// Copyright (c) AppsCode Inc.
// SPDX-License-Identifier: MPL-2.0

package command

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/cli"
	"github.com/openbao/openbao/v2/internal/builtin/database/remote-db-plugin/bootstrap"
	proto "github.com/openbao/openbao/v2/internal/builtin/database/remote-db-plugin/proto/gen"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

// TestRedirectFromErr covers the redirect-handling helper the pin-spokes-to-active
// chase relies on: a FailedPrecondition carrying a RelayRedirect detail yields the
// endpoint to chase, while every other error (including a FailedPrecondition with
// no or an empty endpoint detail) is a normal error, not a redirect.
func TestRedirectFromErr(t *testing.T) {
	withDetail := func(t *testing.T, ep string) error {
		t.Helper()
		st, err := status.New(codes.FailedPrecondition, "hub node is not active").
			WithDetails(&proto.RelayRedirect{RelayEndpoint: ep})
		if err != nil {
			t.Fatalf("WithDetails: %v", err)
		}
		return st.Err()
	}

	t.Run("FailedPrecondition with endpoint is a redirect", func(t *testing.T) {
		ep, ok := redirectFromErr(withDetail(t, "active-host:50053"))
		if !ok || ep != "active-host:50053" {
			t.Fatalf("got (%q, %v), want (active-host:50053, true)", ep, ok)
		}
	})

	t.Run("FailedPrecondition with empty endpoint is not a redirect", func(t *testing.T) {
		if ep, ok := redirectFromErr(withDetail(t, "")); ok {
			t.Fatalf("empty endpoint treated as redirect: %q", ep)
		}
	})

	t.Run("FailedPrecondition without a detail is a normal error", func(t *testing.T) {
		if ep, ok := redirectFromErr(status.Error(codes.FailedPrecondition, "not active")); ok {
			t.Fatalf("bare FailedPrecondition treated as redirect: %q", ep)
		}
	})

	t.Run("other status codes are normal errors", func(t *testing.T) {
		if _, ok := redirectFromErr(status.Error(codes.Unavailable, "down")); ok {
			t.Fatal("Unavailable treated as redirect")
		}
	})

	t.Run("non-status error is a normal error", func(t *testing.T) {
		if _, ok := redirectFromErr(errors.New("boom")); ok {
			t.Fatal("plain error treated as redirect")
		}
	})
}

// TestRedirectChaseCap drives the real chase helper (not a re-implementation of
// its guard) with a synthetic connect func that always redirects between two
// distinct addresses, so the self-redirect short-circuit never fires and the cap
// is what stops the loop: chase makes exactly redirectChaseLimit+1 connect calls
// (the initial attempt plus the capped redirects) and returns exit code 1.
func TestRedirectChaseCap(t *testing.T) {
	restore := redirectBackoff
	redirectBackoff = time.Millisecond
	t.Cleanup(func() { redirectBackoff = restore })

	cmd := &RelayRunCommand{BaseCommand: &BaseCommand{UI: cli.NewMockUi()}}
	cmd.flagServer = "hub-a:1"

	calls := 0
	connect := func(server string) (int, string) {
		calls++
		if server == "hub-a:1" {
			return 0, "hub-b:1"
		}
		return 0, "hub-a:1"
	}

	code := cmd.chase(make(chan struct{}), connect)
	if code != 1 {
		t.Fatalf("code = %d, want 1 (chase should give up at the cap)", code)
	}
	if calls != redirectChaseLimit+1 {
		t.Fatalf("connect called %d times, want %d (initial + capped redirects)", calls, redirectChaseLimit+1)
	}
}

// redirectHub is a mock hub whose Connect handler consumes the spoke's
// registration frame and then rejects the stream with a FailedPrecondition
// carrying a RelayRedirect to its peer, exactly as a pin-spokes-to-active
// non-active node does. It counts how many Connect calls (real dials) it served.
type redirectHub struct {
	proto.UnimplementedAgentServiceServer
	redirectTo string // peer hub address, set before Serve starts
	count      atomic.Int64
}

func (h *redirectHub) Connect(stream grpc.BidiStreamingServer[proto.AgentMessage, proto.AgentMessage]) error {
	h.count.Add(1)
	// Consume the registration frame so the spoke's Send completes and the
	// redirect is delivered deterministically as the error from its first Recv.
	_, _ = stream.Recv()
	st, err := status.New(codes.FailedPrecondition, "not active").
		WithDetails(&proto.RelayRedirect{RelayEndpoint: h.redirectTo})
	if err != nil {
		return status.Error(codes.Internal, err.Error())
	}
	return st.Err()
}

// TestRedirectChaseEndToEnd drives the real bao relay run chase loop against two
// mock hubs over real mTLS. It proves: (a) a FailedPrecondition + RelayRedirect
// returned from a live Connect handler surfaces through connectAndServe as a
// redirect, (b) the per-hop SNI/CN retargeting (pinned via -server-name) does not
// break the chase, and (c) the loop makes exactly redirectChaseLimit+1 real
// connection attempts, then gives up with exit code 1. This is what the synthetic
// TestRedirectChaseCap cannot assert: that the network attempts actually happened.
func TestRedirectChaseEndToEnd(t *testing.T) {
	restore := redirectBackoff
	redirectBackoff = time.Millisecond
	t.Cleanup(func() { redirectBackoff = restore })

	// One CA; one server cert with SAN "hub" so a single cert serves both hubs
	// (the spoke pins -server-name=hub, so every hop validates the same name);
	// one spoke client cert (CN spoke-1).
	ca, err := bootstrap.GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	srvCert, err := ca.IssueHubServerCert([]string{"hub"}, nil)
	if err != nil {
		t.Fatalf("IssueHubServerCert: %v", err)
	}
	spokeCertPEM, spokeKeyPEM := issueSpokeCert(t, ca, "spoke-1")

	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "cert.pem"), spokeCertPEM)
	writeFile(t, filepath.Join(dir, "key.pem"), spokeKeyPEM)
	writeFile(t, filepath.Join(dir, "ca.pem"), ca.CertPEM)

	// Server-side mTLS: present the hub cert, require and verify the spoke cert
	// against the CA. Matches the spoke's TLS 1.3 floor.
	serverTLS, err := tls.X509KeyPair(srvCert.CertPEM, srvCert.KeyPEM)
	if err != nil {
		t.Fatalf("server keypair: %v", err)
	}
	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(ca.CertPEM) {
		t.Fatal("append CA to client pool")
	}
	creds := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{serverTLS},
		ClientCAs:    clientCAs,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	})

	// Two listeners so the chase bounces A -> B -> A ... and the self-redirect
	// guard never short-circuits; only the hop cap stops it.
	lisA, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen A: %v", err)
	}
	lisB, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen B: %v", err)
	}
	aAddr, bAddr := lisA.Addr().String(), lisB.Addr().String()

	hubA := &redirectHub{redirectTo: bAddr}
	hubB := &redirectHub{redirectTo: aAddr}
	srvA := serveHub(t, creds, lisA, hubA)
	srvB := serveHub(t, creds, lisB, hubB)
	t.Cleanup(srvA.Stop)
	t.Cleanup(srvB.Stop)

	cmd := &RelayRunCommand{BaseCommand: &BaseCommand{UI: cli.NewMockUi()}}
	cmd.flagServer = aAddr
	cmd.flagServerName = "hub"
	cmd.flagCredentialsDir = dir
	// The redirect is delivered before heartbeat/renewal start, but keep them
	// off so nothing lingers.
	cmd.flagHeartbeatInterval = 0
	cmd.flagRenewCheckEvery = 0

	baseTLS, err := loadSpokeTLS(dir, "hub", aAddr)
	if err != nil {
		t.Fatalf("loadSpokeTLS: %v", err)
	}
	spokeName := baseTLS.Certificates[0].Leaf.Subject.CommonName

	// Drive the real chase with the real gRPC connectAndServe (no stubbing).
	// shutdownCh is never signaled: the hubs always redirect, so the cap is what
	// ends the loop.
	shutdownCh := make(chan struct{})
	code := cmd.chase(shutdownCh, func(server string) (int, string) {
		return cmd.connectAndServe(server, baseTLS, spokeName, shutdownCh)
	})

	if code != 1 {
		t.Fatalf("exit code = %d, want 1 (hub kept redirecting)", code)
	}
	total := hubA.count.Load() + hubB.count.Load()
	if total != int64(redirectChaseLimit+1) {
		t.Fatalf("hub Connect calls = %d, want %d (initial attempt + capped redirects)", total, redirectChaseLimit+1)
	}
}

// serveHub registers h on a new mTLS gRPC server and starts serving lis.
func serveHub(t *testing.T, creds credentials.TransportCredentials, lis net.Listener, h *redirectHub) *grpc.Server {
	t.Helper()
	srv := grpc.NewServer(grpc.Creds(creds))
	proto.RegisterAgentServiceServer(srv, h)
	go func() { _ = srv.Serve(lis) }()
	return srv
}

// issueSpokeCert mints an ECDSA client cert for cn, signed by ca via the same
// CSR path a real spoke uses, and returns its cert and key PEMs.
func issueSpokeCert(t *testing.T, ca *bootstrap.CABundle, cn string) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("spoke key: %v", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}, key)
	if err != nil {
		t.Fatalf("spoke CSR: %v", err)
	}
	certPEM, err = ca.SignSpokeCSR(csrDER, cn, time.Hour)
	if err != nil {
		t.Fatalf("SignSpokeCSR: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal spoke key: %v", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
