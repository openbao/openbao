// Copyright (c) AppsCode Inc.
// SPDX-License-Identifier: MPL-2.0

// Package relayfwd is the narrow seam between OpenBao's core (the cluster
// listener, leadership state, and per-node cluster identity) and the relay
// hub-and-spoke database plugin. It exists so that the relay backend and the
// remote-db-plugin never import vault/ internals directly: vault/ supplies a
// Core-backed implementation of Node, and the relay code consumes only this
// interface.
//
// See internal/builtin/database/remote-db-plugin/DESIGN.md, section "HA: standby nodes
// and spoke stream ownership", for how this plumbing is used.
package relayfwd

import (
	"context"

	"google.golang.org/grpc"
)

// PeerInfo identifies one hub node for the cluster-wide observability view.
type PeerInfo struct {
	ClusterAddr string
	NodeID      string
	IsActive    bool
}

// Node is the view of the local hub cluster node that the relay backend needs
// to route spoke traffic across an HA hub. A Core-backed implementation lives
// in package vault; the relay backend obtains it from its extended system view
// so each mount is bound to its own Core (this is what makes an in-process
// multi-node test cluster behave like separate nodes).
type Node interface {
	// IsActive reports whether this node is the active (leader) node. Only the
	// active node owns database mounts and originates credential operations, so
	// only it needs to resolve spoke owners and forward.
	IsActive() bool

	// Sealed reports whether the barrier is sealed. During the pre-seal
	// teardown of a genuine seal this is already true (sealInternalWithOptions
	// marks the node sealed before running preSeal); during a
	// leadership-transition teardown (standby->active promotion or
	// active->standby demotion) it is false. The relay backend uses this to
	// tell "seal" (stop the listener, drop the spoke-CA from memory) apart from
	// "transition" (keep spoke streams alive so a leadership change is not a
	// relay outage).
	Sealed() bool

	// ClusterAddr returns this node's own cluster address (the value a peer
	// dials to reach this node's cluster port). This is what an announcer puts
	// in AnnounceSpokesRequest.node_cluster_addr so the active node learns
	// where to dial back from the announcement itself.
	ClusterAddr() string

	// NodeID returns this node's raft node id. Display only (shown in
	// `bao relay list` and relay/spokes); never used for routing.
	NodeID() string

	// LeaderClusterAddr returns the current leader's cluster address, which is
	// where a standby sends its spoke announcements. Empty string with a nil
	// error means "leadership currently unknown" (e.g. mid-election); the
	// caller should retry on the next announce tick.
	LeaderClusterAddr() (string, error)

	// Peers returns every hub node this node knows about: itself plus, on the
	// active node, the standbys that have echoed within the HA heartbeat window.
	// Used to report a cluster-wide hub-node list (including nodes that
	// terminate zero spokes) in relay/spokes. On a standby the echo cache is
	// empty, so this returns just the local node; the merged view is built on
	// the active node, which relay/spokes forwards to.
	Peers() []PeerInfo

	// DialForwarding returns a gRPC client connection to the given peer cluster
	// address over the RelayForwarding ALPN, using this node's cluster
	// certificate for mTLS. The connection is direction-agnostic: the same
	// dialer reaches active->standby (RunCommand) and standby->active
	// (AnnounceSpokes, SignSpokeCSR). The caller owns the returned connection
	// and must Close it. A nil Node or an unconfigured cluster listener returns
	// an error rather than a nil connection.
	DialForwarding(ctx context.Context, clusterAddr string) (*grpc.ClientConn, error)
}
