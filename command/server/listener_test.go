// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"testing"
)

type testListenerConnFn func(net.Listener) (net.Conn, error)

func testListenerImpl(t *testing.T, ln net.Listener, connFn testListenerConnFn, certName string, expectedVersion uint16, expectedAddr string, expectError bool) {
	serverCh := make(chan net.Conn, 1)
	go func() {
		server, err := ln.Accept()
		if err != nil {
			if !expectError {
				t.Errorf("err: %s", err)
			}
			close(serverCh)
			return
		}
		if certName != "" {
			tlsConn := server.(*tls.Conn)
			tlsConn.Handshake()
		}
		serverCh <- server
		if expectedAddr == "" {
			return
		}
		addr, _, err := net.SplitHostPort(server.RemoteAddr().String())
		if err != nil {
			t.Error(err)
		}
		if addr != expectedAddr {
			t.Errorf("expected: %s, got: %s", expectedAddr, addr)
		}
	}()

	client, err := connFn(ln)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	if certName != "" {
		tlsConn := client.(*tls.Conn)
		if expectedVersion != 0 && tlsConn.ConnectionState().Version != expectedVersion {
			t.Fatalf("expected version %d, got %d", expectedVersion, tlsConn.ConnectionState().Version)
		}
		if len(tlsConn.ConnectionState().PeerCertificates) != 1 {
			t.Fatal("err: number of certs too long")
		}
		peerName := tlsConn.ConnectionState().PeerCertificates[0].Subject.CommonName
		if peerName != certName {
			t.Fatalf("err: bad cert name %s, expected %s", peerName, certName)
		}
	}

	server := <-serverCh

	if server == nil {
		if !expectError {
			// Something failed already so we abort the test early
			t.Fatal("aborting test because the server did not accept the connection")
		}
		return
	}

	defer client.Close()
	defer server.Close()

	var buf bytes.Buffer
	copyCh := make(chan struct{})
	go func() {
		io.Copy(&buf, server)
		close(copyCh)
	}()

	if _, err := client.Write([]byte("foo")); err != nil {
		t.Fatalf("err: %s", err)
	}

	client.Close()

	<-copyCh
	if (buf.String() != "foo" && !expectError) || (buf.String() == "foo" && expectError) {
		t.Fatalf("bad: %q, expectError: %t", buf.String(), expectError)
	}
}

func TestProfilingUnauthenticatedInFlightAccess(t *testing.T) {
	config, err := LoadConfigFile("./test-fixtures/unauth_in_flight_access.hcl", nil)
	if err != nil {
		t.Fatalf("Error encountered when loading config %+v", err)
	}
	if !config.Listeners[0].InFlightRequestLogging.UnauthenticatedInFlightAccess {
		t.Fatal("failed to read UnauthenticatedInFlightAccess")
	}
}
