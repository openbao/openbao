// Copyright (c) AppsCode Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/url"

	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/openbao/openbao/v2/internal/vault/forwarding"
	"github.com/openbao/openbao/v2/internal/vault/relayfwd"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
)

// relayNode is the Core-backed implementation of relayfwd.Node. It is bound to
// a single *Core, so an in-process multi-node test cluster hands each mount its
// own node view (via the extended system view) instead of a process global.
//
// It carries no state of its own; every method reads live from the Core, so it
// tracks leadership changes, seal state, and cluster identity rotation without
// needing to be refreshed.
type relayNode struct {
	core *Core
}

var _ relayfwd.Node = (*relayNode)(nil)

// RelayNode returns this Core's relayfwd.Node view. The relay backend reaches
// it by asserting the extended system view against
// `interface{ RelayNode() relayfwd.Node }`, which keeps internal/builtin/logical/relay
// from importing vault internals directly.
func (e extendedSystemViewImpl) RelayNode() relayfwd.Node {
	return &relayNode{core: e.core}
}

// relayNodeView returns this Core's relayfwd.Node. Used by the RelayForwarding
// cluster handler (to bind its service to this node's proxy server) and by HA
// integration tests.
func (c *Core) relayNodeView() relayfwd.Node { return &relayNode{core: c} }

// RelayNodeView is the exported form of relayNodeView for HA integration tests,
// which wire a per-node proxy server (remotedb.SetRelayNode) directly rather
// than through the relay backend mount.
func (c *Core) RelayNodeView() relayfwd.Node { return c.relayNodeView() }

func (n *relayNode) IsActive() bool {
	c := n.core
	// Active == unsealed and not standby. Standby (including read-enabled
	// standby) nodes terminate spoke streams but never originate credential
	// operations, so they announce to the active node rather than route.
	return !c.Sealed() && !c.Standby()
}

func (n *relayNode) Sealed() bool { return n.core.Sealed() }

func (n *relayNode) ClusterAddr() string { return n.core.ClusterAddr() }

func (n *relayNode) NodeID() string { return n.core.GetRaftNodeID() }

// Peers returns this node plus, on the active node, every standby that has
// echoed within the HA heartbeat window (clusterPeerClusterAddrsCache). The
// cache carries each peer's cluster address and raft node id. On a standby the
// cache is empty, so only the local node is returned; the merged relay/spokes
// view is built on the active node, which is where relay/spokes forwards to.
func (n *relayNode) Peers() []relayfwd.PeerInfo {
	c := n.core
	peers := []relayfwd.PeerInfo{{
		ClusterAddr: c.ClusterAddr(),
		NodeID:      c.GetRaftNodeID(),
		IsActive:    n.IsActive(),
	}}
	if c.clusterPeerClusterAddrsCache != nil {
		for addr, item := range c.clusterPeerClusterAddrsCache.Items() {
			nodeID := ""
			if item.Object.NodeInfo != nil {
				nodeID = item.Object.NodeInfo.NodeID
			}
			peers = append(peers, relayfwd.PeerInfo{
				ClusterAddr: addr,
				NodeID:      nodeID,
				IsActive:    false, // echo-cached peers are followers of this active node
			})
		}
	}
	return peers
}

// LeaderClusterAddr returns the leader's cluster address, which is where a
// standby sends spoke announcements. Empty (with nil error) when leadership is
// currently unknown; the caller retries on the next announce tick.
func (n *relayNode) LeaderClusterAddr() (string, error) {
	_, _, clusterAddr, err := n.core.Leader()
	if err != nil {
		return "", err
	}
	return clusterAddr, nil
}

// DialForwarding dials a peer's cluster port over RelayForwardingALPN using
// this node's cluster certificate, mirroring how
// Core.refreshRequestForwardingConnection dials for HTTP request forwarding.
// The dialer is direction-agnostic, so the same code path reaches
// active->standby and standby->active.
func (n *relayNode) DialForwarding(ctx context.Context, clusterAddr string) (*grpc.ClientConn, error) {
	if clusterAddr == "" {
		return nil, errors.New("empty peer cluster address")
	}
	c := n.core
	if c.LocalClusterParsedCert() == nil {
		return nil, errors.New("no cluster certificate; node not fully unsealed")
	}
	clusterListener := c.getClusterListener()
	if clusterListener == nil {
		return nil, errors.New("no cluster listener configured")
	}
	clusterURL, err := url.Parse(clusterAddr)
	if err != nil {
		return nil, fmt.Errorf("parse peer cluster address %q: %w", clusterAddr, err)
	}

	// Register a client for our ALPN so the dialer can present this node's
	// cluster cert. AddClient is idempotent (it overwrites the map entry with
	// an equivalent client), and the RequestForwarding cluster client is
	// generic over the cluster cert, so we reuse it rather than duplicate it.
	clusterListener.AddClient(consts.RelayForwardingALPN, forwarding.NewRequestForwardingClusterClient(c))

	conn, err := grpc.NewClient(
		fmt.Sprintf("passthrough:///%s", clusterURL.Host),
		grpc.WithContextDialer(clusterListener.GetContextDialerFunc(ctx, consts.RelayForwardingALPN)),
		// Not actually insecure: the dialer performs the cluster mTLS handshake
		// itself with the ALPN set. gRPC just isn't managing the TLS state.
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time: 2 * c.clusterHeartbeatInterval,
		}),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(math.MaxInt32),
			grpc.MaxCallSendMsgSize(math.MaxInt32),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("dial relay forwarding to %q: %w", clusterAddr, err)
	}
	return conn, nil
}
