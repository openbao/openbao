// Copyright (c) AppsCode Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"math"
	"net/http"
	"sync"
	"time"

	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/openbao/openbao/v2/internal/vault/cluster"
	"github.com/openbao/openbao/v2/internal/vault/forwarding"
	"golang.org/x/net/http2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"

	remotedb "github.com/openbao/openbao/v2/internal/builtin/database/remote-db-plugin"
	agentproto "github.com/openbao/openbao/v2/internal/builtin/database/remote-db-plugin/proto/gen"
)

// relayForwardingHandler serves the RelayForwarding gRPC service over the hub
// cluster port (consts.RelayForwardingALPN). Unlike request forwarding, its
// handler is registered on EVERY unsealed node, not just the active one: a
// standby receives forwarded RunCommand calls for spokes it terminates, and the
// active receives AnnounceSpokes / SignSpokeCSR. It rides the same cluster mTLS
// trust domain, so no new key material is involved.
//
// This mirrors vault/forwarding.requestForwardingHandler; it is a separate,
// smaller handler so a database-plugin concept never leaks into the core
// request-forwarding path.
type relayForwardingHandler struct {
	fws     *http2.Server
	grpcSrv *grpc.Server
	core    *Core
	stopCh  chan struct{}
}

// startRelayForwarding registers the RelayForwarding handler (and the matching
// cluster client for the dialer) on the cluster listener. Safe to call on both
// active and standby unseal; a no-op when there is no cluster listener (single
// node, no HA). Idempotent: AddHandler/AddClient overwrite any prior
// registration.
func (c *Core) startRelayForwarding() error {
	clusterListener := c.getClusterListener()
	if clusterListener == nil {
		return nil
	}

	grpcSrv := grpc.NewServer(
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time: 2 * c.clusterHeartbeatInterval,
		}),
		grpc.MaxRecvMsgSize(math.MaxInt32),
		grpc.MaxSendMsgSize(math.MaxInt32),
	)
	// Bind the service to THIS node's proxy server, so a forwarded RunCommand
	// lands on the node that actually terminates the spoke stream. In an
	// in-process test cluster each Core has its own proxy server keyed by node
	// id; in production there is one per process.
	agentproto.RegisterRelayForwardingServer(grpcSrv, remotedb.RelayForwardingServiceForNode(c.relayNodeView()))

	h := &relayForwardingHandler{
		fws:     clusterListener.Server(),
		grpcSrv: grpcSrv,
		core:    c,
		stopCh:  make(chan struct{}),
	}
	clusterListener.AddHandler(consts.RelayForwardingALPN, h)
	// Register a client so the dialer can present this node's cluster cert when
	// forwarding to a peer. The RequestForwarding cluster client is generic over
	// the cluster cert, so we reuse it.
	clusterListener.AddClient(consts.RelayForwardingALPN, forwarding.NewRequestForwardingClusterClient(c))

	c.logger.Debug("relay forwarding handler registered on cluster listener")
	return nil
}

// stopRelayForwarding tears the handler and client down. Called from preSeal.
func (c *Core) stopRelayForwarding() {
	clusterListener := c.getClusterListener()
	if clusterListener == nil {
		return
	}
	clusterListener.StopHandler(consts.RelayForwardingALPN)
	clusterListener.RemoveClient(consts.RelayForwardingALPN)
}

// ServerLookup returns this node's cluster server cert for the mTLS handshake.
func (rf *relayForwardingHandler) ServerLookup(ctx context.Context, clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	currCert := *rf.core.LocalClusterCert()
	if len(currCert) == 0 {
		return nil, errors.New("got relay forwarding connection but no local cert")
	}
	localCert := make([]byte, len(currCert))
	copy(localCert, currCert)
	return &tls.Certificate{
		Certificate: [][]byte{localCert},
		PrivateKey:  rf.core.LocalClusterPrivateKey(),
		Leaf:        rf.core.LocalClusterParsedCert(),
	}, nil
}

// CALookup returns this node's cluster CA cert for verifying the peer.
func (rf *relayForwardingHandler) CALookup(ctx context.Context) ([]*x509.Certificate, error) {
	parsedCert := rf.core.LocalClusterParsedCert()
	if parsedCert == nil {
		return nil, errors.New("relay forwarding connection but no local cert")
	}
	return []*x509.Certificate{parsedCert}, nil
}

// Handoff serves a relay forwarding connection over the shared HTTP/2 server.
func (rf *relayForwardingHandler) Handoff(ctx context.Context, shutdownWg *sync.WaitGroup, closeCh chan struct{}, tlsConn *tls.Conn) error {
	shutdownWg.Add(2)
	quitCh := make(chan struct{})
	go func() {
		select {
		case <-quitCh:
		case <-closeCh:
		case <-rf.stopCh:
		}
		if err := tlsConn.Close(); err != nil {
			rf.core.logger.Warn("failed to close relay forwarding tls connection", "error", err)
		}
		shutdownWg.Done()
	}()

	go func() {
		rf.fws.ServeConn(tlsConn, &http2.ServeConnOpts{
			Handler: rf.grpcSrv,
			BaseConfig: &http.Server{
				ErrorLog: rf.core.logger.StandardLogger(nil),
			},
		})
		close(quitCh)
		shutdownWg.Done()
	}()

	return nil
}

// Stop drains and stops the relay forwarding gRPC server.
func (rf *relayForwardingHandler) Stop() error {
	time.Sleep(cluster.ListenerAcceptDeadline)
	close(rf.stopCh)
	rf.grpcSrv.Stop()
	return nil
}
