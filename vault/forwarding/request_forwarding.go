// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package forwarding

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"math"
	"net/http"
	"sync"
	"time"

	log "github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/physical/raft"
	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/openbao/openbao/sdk/v2/physical"
	"github.com/openbao/openbao/vault/cluster"
	"golang.org/x/net/http2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
)

type clusterInfoGetter interface {
	ClusterAddr() string
	ReplicationState() consts.ReplicationState
	SetActiveNodeReplicationState(consts.ReplicationState)
	RedirectAddr() string
	LocalClusterPrivateKey() *ecdsa.PrivateKey
	LocalClusterParsedCert() *x509.Certificate
	LocalClusterCert() *[]byte
	EffectiveSDKVersion() string
}

type core interface {
	clusterInfoGetter
	GetRaftBackend() *raft.RaftBackend
	Logger() log.Logger
}

type clusterPeerClusterAddrsCache interface {
	Set(string, NodeHAConnectionInfo)
}

type ForwardingConfig struct {
	HA                           physical.HABackend
	ClusterHandler               http.Handler
	ClusterHeartbeatInterval     time.Duration
	RaftFollowerStates           *raft.FollowerStates
	ClusterPeerClusterAddrsCache clusterPeerClusterAddrsCache
}

type requestForwardingHandler struct {
	fws         *http2.Server
	fwRPCServer *grpc.Server
	logger      log.Logger
	ha          bool
	core        clusterInfoGetter
	stopCh      chan struct{}
}

type RequestForwardingClusterClient struct {
	core core
}

// NewRequestForwardingHandler creates a cluster handler for use with request
// forwarding.
func NewRequestForwardingHandler(c core, cfg ForwardingConfig, fws *http2.Server) (*requestForwardingHandler, error) {
	// Resolve locally to avoid races
	ha := cfg.HA != nil

	fwRPCServer := grpc.NewServer(
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time: 2 * cfg.ClusterHeartbeatInterval,
		}),
		grpc.MaxRecvMsgSize(math.MaxInt32),
		grpc.MaxSendMsgSize(math.MaxInt32),
	)

	if ha && cfg.ClusterHandler != nil {
		RegisterRequestForwardingServer(fwRPCServer, &forwardedRequestRPCServer{
			core:                         c,
			handler:                      cfg.ClusterHandler,
			clusterPeerClusterAddrsCache: cfg.ClusterPeerClusterAddrsCache,
			raftFollowerStates:           cfg.RaftFollowerStates,
		})
	}

	return &requestForwardingHandler{
		fws:         fws,
		fwRPCServer: fwRPCServer,
		ha:          ha,
		logger:      c.Logger().Named("request-forward"),
		core:        c,
		stopCh:      make(chan struct{}),
	}, nil
}

func NewRequestForwardingClusterClient(core core) *RequestForwardingClusterClient {
	return &RequestForwardingClusterClient{
		core: core,
	}
}

// ClientLookup satisfies the ClusterClient interface and returns the ha tls
// client certs.
func (c *RequestForwardingClusterClient) ClientLookup(ctx context.Context, requestInfo *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	parsedCert := c.core.LocalClusterParsedCert()
	if parsedCert == nil {
		return nil, nil //nolint:nilnil
	}
	currCert := *c.core.LocalClusterCert()
	if len(currCert) == 0 {
		return nil, nil //nolint:nilnil
	}
	localCert := make([]byte, len(currCert))
	copy(localCert, currCert)

	for _, subj := range requestInfo.AcceptableCAs {
		if bytes.Equal(subj, parsedCert.RawIssuer) {
			return &tls.Certificate{
				Certificate: [][]byte{localCert},
				PrivateKey:  c.core.LocalClusterPrivateKey(),
				Leaf:        c.core.LocalClusterParsedCert(),
			}, nil
		}
	}

	return nil, nil //nolint:nilnil
}

func (c *RequestForwardingClusterClient) ServerName() string {
	parsedCert := c.core.LocalClusterParsedCert()
	if parsedCert == nil {
		return ""
	}

	return parsedCert.Subject.CommonName
}

func (c *RequestForwardingClusterClient) CACert(ctx context.Context) *x509.Certificate {
	return c.core.LocalClusterParsedCert()
}

// ServerLookup satisfies the ClusterHandler interface and returns the server's
// tls certs.
func (rf *requestForwardingHandler) ServerLookup(ctx context.Context, clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	currCert := *rf.core.LocalClusterCert()
	if len(currCert) == 0 {
		return nil, errors.New("got forwarding connection but no local cert")
	}

	localCert := make([]byte, len(currCert))
	copy(localCert, currCert)

	return &tls.Certificate{
		Certificate: [][]byte{localCert},
		PrivateKey:  rf.core.LocalClusterPrivateKey(),
		Leaf:        rf.core.LocalClusterParsedCert(),
	}, nil
}

// CALookup satisfies the ClusterHandler interface and returns the ha ca cert.
func (rf *requestForwardingHandler) CALookup(ctx context.Context) ([]*x509.Certificate, error) {
	parsedCert := rf.core.LocalClusterParsedCert()

	if parsedCert == nil {
		return nil, errors.New("forwarding connection client but no local cert")
	}

	return []*x509.Certificate{parsedCert}, nil
}

// Handoff serves a request forwarding connection.
func (rf *requestForwardingHandler) Handoff(ctx context.Context, shutdownWg *sync.WaitGroup, closeCh chan struct{}, tlsConn *tls.Conn) error {
	if !rf.ha {
		if err := tlsConn.Close(); err != nil {
			rf.logger.Warn("failed to close tls connection", "error", err)
		}
		return nil
	}

	rf.logger.Debug("got request forwarding connection")

	shutdownWg.Add(2)
	// quitCh is used to close the connection and the second
	// goroutine if the server closes before closeCh.
	quitCh := make(chan struct{})
	go func() {
		select {
		case <-quitCh:
		case <-closeCh:
		case <-rf.stopCh:
		}
		if err := tlsConn.Close(); err != nil {
			rf.logger.Warn("failed to close tls connection", "error", err)
		}
		shutdownWg.Done()
	}()

	go func() {
		rf.fws.ServeConn(tlsConn, &http2.ServeConnOpts{
			Handler: rf.fwRPCServer,
			BaseConfig: &http.Server{
				ErrorLog: rf.logger.StandardLogger(nil),
			},
		})

		// close the quitCh which will close the connection and
		// the other goroutine.
		close(quitCh)
		shutdownWg.Done()
	}()

	return nil
}

// Stop stops the request forwarding server and closes connections.
func (rf *requestForwardingHandler) Stop() error {
	// Give some time for existing RPCs to drain.
	time.Sleep(cluster.ListenerAcceptDeadline)
	close(rf.stopCh)
	rf.fwRPCServer.Stop()
	return nil
}
