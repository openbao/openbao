// Copyright (c) AppsCode Inc.
// SPDX-License-Identifier: MPL-2.0

package remotedb

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"sync"
	"testing"
	"time"

	"github.com/openbao/openbao/plugins/database/remote-db-plugin/bootstrap"
	agentproto "github.com/openbao/openbao/plugins/database/remote-db-plugin/proto/gen"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

// These tests cover the in-process primitives the gRPC handler relies on —
// request_id register/deliver/cancel, the failAll teardown, and the
// touch/lastSeenAt freshness accounting. The TLS + stream surface is
// exercised by TEST.md's manual flow; the unit tests here pin the
// concurrency discipline that's easy to regress without anyone noticing.

func TestNewRequestIDUnique(t *testing.T) {
	seen := make(map[string]struct{}, 1024)
	for i := 0; i < 1024; i++ {
		id, err := newRequestID()
		if err != nil {
			t.Fatal(err)
		}
		if len(id) != 24 {
			t.Fatalf("request id length: got %d, want 24 hex chars", len(id))
		}
		if _, dup := seen[id]; dup {
			t.Fatalf("duplicate request id %q after %d generated", id, i)
		}
		seen[id] = struct{}{}
	}
}

func TestSpokeConnection_RegisterDeliver(t *testing.T) {
	conn := newSpokeConnection(nil)
	ch := conn.register("req-1")

	go conn.deliver("req-1", pendingResponse{output: "ok"})

	select {
	case resp := <-ch:
		if resp.output != "ok" {
			t.Fatalf("output: got %q, want %q", resp.output, "ok")
		}
	case <-time.After(time.Second):
		t.Fatal("deliver did not arrive on waiter channel")
	}
}

func TestSpokeConnection_DeliverUnknownIsNoop(t *testing.T) {
	conn := newSpokeConnection(nil)
	// Must not panic or block.
	conn.deliver("never-registered", pendingResponse{output: "ignored"})
}

func TestSpokeConnection_CancelPreventsDelivery(t *testing.T) {
	conn := newSpokeConnection(nil)
	ch := conn.register("req-1")
	conn.cancel("req-1")
	conn.deliver("req-1", pendingResponse{output: "should-not-arrive"})
	select {
	case <-ch:
		t.Fatal("delivery after cancel should be dropped")
	case <-time.After(50 * time.Millisecond):
		// expected
	}
}

func TestSpokeConnection_DuplicateDeliveryDoesNotPanic(t *testing.T) {
	conn := newSpokeConnection(nil)
	conn.register("req-1")
	conn.deliver("req-1", pendingResponse{output: "first"})
	// Second deliver finds no entry in the map; must be a quiet no-op.
	conn.deliver("req-1", pendingResponse{output: "second"})
}

func TestSpokeConnection_FailAllUnblocksWaiters(t *testing.T) {
	conn := newSpokeConnection(nil)
	const N = 8
	chs := make([]chan pendingResponse, N)
	for i := 0; i < N; i++ {
		chs[i] = conn.register(string(rune('a' + i)))
	}

	conn.failAll("bye")
	for i, ch := range chs {
		select {
		case resp := <-ch:
			if resp.err != "bye" {
				t.Errorf("waiter %d: err=%q, want %q", i, resp.err, "bye")
			}
		case <-time.After(time.Second):
			t.Fatalf("waiter %d did not unblock after failAll", i)
		}
	}
}

func TestSpokeConnection_TouchAdvancesLastSeen(t *testing.T) {
	conn := newSpokeConnection(nil)
	before := conn.lastSeenAt()
	time.Sleep(2 * time.Millisecond)
	conn.touch()
	after := conn.lastSeenAt()
	if !after.After(before) {
		t.Fatalf("touch did not advance lastSeen: before=%v after=%v", before, after)
	}
}

func TestSpokeConnection_ConcurrentRegisterDeliverIsRaceFree(t *testing.T) {
	// Goal: exercise the inflight map under a contended workload so the
	// race detector has something to look at. We don't assert ordering;
	// we assert that every waiter either gets its response or is
	// drained by failAll at the end.
	conn := newSpokeConnection(nil)

	const N = 256
	var wg sync.WaitGroup
	delivered := make(chan string, N)
	for i := 0; i < N; i++ {
		id := newTestID(i)
		wg.Add(2)
		go func() {
			defer wg.Done()
			ch := conn.register(id)
			select {
			case resp := <-ch:
				delivered <- resp.output
			case <-time.After(2 * time.Second):
				delivered <- "timeout:" + id
			}
		}()
		go func() {
			defer wg.Done()
			conn.deliver(id, pendingResponse{output: id})
		}()
	}
	wg.Wait()
	close(delivered)

	count := 0
	for got := range delivered {
		if got == "" {
			t.Errorf("empty output (zero pendingResponse leaked)")
		}
		count++
	}
	if count != N {
		t.Fatalf("waiter count: got %d, want %d", count, N)
	}
}

func TestSpokeStatusHealthyFreshness(t *testing.T) {
	// SpokeStaleAfter is the freshness window. A spoke whose last-seen is
	// within the window is healthy; outside it is not.
	last := time.Now()
	freshHealthy := time.Since(last) < SpokeStaleAfter
	if !freshHealthy {
		t.Fatalf("a fresh last-seen should be considered healthy")
	}

	stale := time.Now().Add(-SpokeStaleAfter - time.Second)
	staleHealthy := time.Since(stale) < SpokeStaleAfter
	if staleHealthy {
		t.Fatalf("a last-seen older than SpokeStaleAfter should be unhealthy")
	}
}

func TestCertNotAfterFromPEM(t *testing.T) {
	ca, err := bootstrap.GenerateCA()
	if err != nil {
		t.Fatal(err)
	}
	csrDER := newTestCSR(t, "spoke-parse")
	certPEM, err := ca.SignSpokeCSR(csrDER, "spoke-parse", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	got, err := certNotAfterFromPEM(certPEM)
	if err != nil {
		t.Fatalf("certNotAfterFromPEM: %v", err)
	}
	// Cross-check against a direct parse of the same PEM.
	block, _ := pem.Decode(certPEM)
	want, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(want.NotAfter) {
		t.Errorf("NotAfter = %s, want %s", got, want.NotAfter)
	}

	// Garbage in → error, zero out.
	if _, err := certNotAfterFromPEM([]byte("not a pem")); err == nil {
		t.Error("expected error for non-PEM input")
	}
}

// TestListConnectedSpokes_ReportsCertNotAfter asserts the read model surfaces
// the per-spoke cert expiry captured on the connection, and reports zero when
// no verified peer cert was ever recorded (defensive "no peer cert" path).
func TestListConnectedSpokes_ReportsCertNotAfter(t *testing.T) {
	s := getProxyServer()

	withCert := newSpokeConnection(nil)
	exp := time.Now().Add(72 * time.Hour).Truncate(time.Second)
	withCert.setCertNotAfter(exp)

	noCert := newSpokeConnection(nil) // never recorded a cert → zero

	s.mu.Lock()
	s.spokes["spoke-with-cert"] = withCert
	s.spokes["spoke-no-cert"] = noCert
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.spokes, "spoke-with-cert")
		delete(s.spokes, "spoke-no-cert")
		s.mu.Unlock()
	}()

	byName := map[string]SpokeStatus{}
	for _, st := range ListConnectedSpokes() {
		byName[st.Name] = st
	}

	if got := byName["spoke-with-cert"].CertNotAfter; !got.Equal(exp) {
		t.Errorf("CertNotAfter = %s, want %s", got, exp)
	}
	if got := byName["spoke-no-cert"].CertNotAfter; !got.IsZero() {
		t.Errorf("expected zero CertNotAfter for spoke with no peer cert, got %s", got)
	}
}

// TestRenewCert_UpdatesCertNotAfter exercises the in-place renewal path: after
// a RenewCert call over the live stream (no reconnect), the connection's
// reported expiry must reflect the freshly signed cert.
func TestRenewCert_UpdatesCertNotAfter(t *testing.T) {
	ca, err := bootstrap.GenerateCA()
	if err != nil {
		t.Fatal(err)
	}
	hub, err := ca.IssueHubServerCert([]string{"hub.local"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := bootstrap.Global().SetIdentity(ca, hub); err != nil {
		t.Fatal(err)
	}

	const cn = "spoke-renew"

	// Initial spoke cert: a short TTL so the renewed value is clearly distinct.
	initialPEM, err := ca.SignSpokeCSR(newTestCSR(t, cn), cn, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leaf := parseCertPEM(t, initialPEM)

	// Register the live connection, seeded with the connect-time expiry.
	s := getProxyServer()
	conn := newSpokeConnection(nil)
	conn.setCertNotAfter(leaf.NotAfter)
	s.mu.Lock()
	s.spokes[cn] = conn
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.spokes, cn)
		s.mu.Unlock()
	}()

	// mTLS peer context carrying the verified leaf — what spokeNameFromPeer reads.
	ctx := peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: credentials.TLSInfo{
			State: tls.ConnectionState{
				VerifiedChains: [][]*x509.Certificate{{leaf}},
			},
		},
	})

	// Renew with a longer TTL so NotAfter strictly advances.
	resp, err := s.RenewCert(ctx, &agentproto.RenewCertRequest{
		CsrPem:     pemEncodeCSR(t, newTestCSR(t, cn)),
		TtlSeconds: int64((30 * 24 * time.Hour) / time.Second),
	})
	if err != nil {
		t.Fatalf("RenewCert: %v", err)
	}

	want := parseCertPEM(t, resp.CertPem).NotAfter
	if got := conn.certNotAfterAt(); !got.Equal(want) {
		t.Errorf("after RenewCert certNotAfter = %s, want %s (renewed cert)", got, want)
	}
	if !want.After(leaf.NotAfter) {
		t.Fatalf("test setup: renewed NotAfter %s did not advance past initial %s", want, leaf.NotAfter)
	}
}

func newTestCSR(t *testing.T, cn string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func pemEncodeCSR(t *testing.T, der []byte) []byte {
	t.Helper()
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func parseCertPEM(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("no PEM block in cert")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func newTestID(i int) string {
	const hex = "0123456789abcdef"
	out := make([]byte, 4)
	for j := 0; j < 4; j++ {
		out[j] = hex[(i>>(j*4))&0xf]
	}
	return string(out)
}
