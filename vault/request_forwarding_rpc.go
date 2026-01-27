// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"net/http"
	"os"
	"runtime/debug"
	"time"

	metrics "github.com/hashicorp/go-metrics/compat"
	"github.com/openbao/openbao/helper/forwarding"
	"github.com/openbao/openbao/physical/raft"
	"github.com/openbao/openbao/sdk/v2/helper/consts"
)

type forwardedRequestRPCServer struct {
	UnimplementedRequestForwardingServer

	core               *Core
	handler            http.Handler
	raftFollowerStates *raft.FollowerStates
}

func (s *forwardedRequestRPCServer) ForwardRequest(ctx context.Context, freq *forwarding.Request) (*forwarding.Response, error) {
	// Parse an http.Request out of it
	req, err := forwarding.ParseForwardedRequest(freq)
	if err != nil {
		return nil, err
	}

	// A very dummy response writer that doesn't follow normal semantics, just
	// lets you write a status code (last written wins) and a body. But it
	// meets the interface requirements.
	w := forwarding.NewRPCResponseWriter()

	resp := &forwarding.Response{}

	runRequest := func() {
		defer func() {
			if err := recover(); err != nil {
				s.core.logger.Error("panic serving forwarded request", "path", req.URL.Path, "error", err, "stacktrace", string(debug.Stack()))
			}
		}()
		s.handler.ServeHTTP(w, req)
	}
	runRequest()
	resp.StatusCode = uint32(w.StatusCode())
	resp.Body = w.Body().Bytes()

	header := w.Header()
	if header != nil {
		resp.HeaderEntries = make(map[string]*forwarding.HeaderEntry, len(header))
		for k, v := range header {
			resp.HeaderEntries[k] = &forwarding.HeaderEntry{
				Values: v,
			}
		}
	}

	return resp, nil
}

type nodeHAConnectionInfo struct {
	nodeInfo       *NodeInformation
	lastHeartbeat  time.Time
	version        string
	upgradeVersion string
}

func (s *forwardedRequestRPCServer) Echo(ctx context.Context, in *EchoRequest) (*EchoReply, error) {
	incomingNodeConnectionInfo := nodeHAConnectionInfo{
		nodeInfo:       in.NodeInfo,
		lastHeartbeat:  time.Now(),
		version:        in.SdkVersion,
		upgradeVersion: in.RaftUpgradeVersion,
	}
	if in.ClusterAddr != "" {
		s.core.clusterPeerClusterAddrsCache.Set(in.ClusterAddr, incomingNodeConnectionInfo)
	}

	if in.RaftAppliedIndex > 0 && len(in.RaftNodeID) > 0 && s.raftFollowerStates != nil {
		s.raftFollowerStates.Update(&raft.EchoRequestUpdate{
			NodeID:          in.RaftNodeID,
			AppliedIndex:    in.RaftAppliedIndex,
			Term:            in.RaftTerm,
			DesiredSuffrage: in.RaftDesiredSuffrage,
			SDKVersion:      in.SdkVersion,
			UpgradeVersion:  in.RaftUpgradeVersion,
		})
	}

	reply := &EchoReply{
		Message:          "pong",
		ReplicationState: uint32(s.core.ReplicationState()),
	}

	if raftBackend := s.core.getRaftBackend(); raftBackend != nil {
		reply.RaftAppliedIndex = raftBackend.AppliedIndex()
		reply.RaftNodeID = raftBackend.NodeID()
	}

	return reply, nil
}

type forwardingClient struct {
	RequestForwardingClient
	core        *Core
	echoTicker  *time.Ticker
	echoContext context.Context
}

// NOTE: we also take advantage of gRPC's keepalive bits, but as we send data
// with these requests it's useful to keep this as well
func (c *forwardingClient) startHeartbeat() {
	go func() {
		clusterAddr := c.core.ClusterAddr()
		hostname, _ := os.Hostname()
		ni := NodeInformation{
			ApiAddr:  c.core.redirectAddr,
			Hostname: hostname,
			Mode:     "standby",
		}
		tick := func() {
			labels := make([]metrics.Label, 0, 1)
			now := time.Now()

			req := &EchoRequest{
				Message:     "ping",
				ClusterAddr: clusterAddr,
				NodeInfo:    &ni,
				SdkVersion:  c.core.effectiveSDKVersion,
			}

			if raftBackend := c.core.getRaftBackend(); raftBackend != nil {
				req.RaftAppliedIndex = raftBackend.AppliedIndex()
				req.RaftNodeID = raftBackend.NodeID()
				req.RaftTerm = raftBackend.Term()
				req.RaftDesiredSuffrage = raftBackend.DesiredSuffrage()
				req.RaftUpgradeVersion = raftBackend.EffectiveVersion()
				labels = append(labels, metrics.Label{Name: "peer_id", Value: raftBackend.NodeID()})
			}
			defer metrics.MeasureSinceWithLabels([]string{"ha", "rpc", "client", "echo"}, now, labels)

			ctx, cancel := context.WithTimeout(c.echoContext, 2*time.Second)
			resp, err := c.Echo(ctx, req)
			cancel()
			if err != nil {
				metrics.IncrCounter([]string{"ha", "rpc", "client", "echo", "errors"}, 1)
				c.core.logger.Debug("forwarding: error sending echo request to active node", "error", err)
				return
			}
			if resp == nil {
				c.core.logger.Debug("forwarding: empty echo response from active node")
				return
			}
			if resp.Message != "pong" {
				c.core.logger.Debug("forwarding: unexpected echo response from active node", "message", resp.Message)
				return
			}
			// Store the active node's replication state to display in
			// sys/health calls
			c.core.activeNodeReplicationState.Store(resp.ReplicationState)
		}

		tick()

		for {
			select {
			case <-c.echoContext.Done():
				c.echoTicker.Stop()
				c.core.logger.Debug("forwarding: stopping heartbeating")
				c.core.activeNodeReplicationState.Store(uint32(consts.ReplicationUnknown))
				return
			case <-c.echoTicker.C:
				tick()
			}
		}
	}()
}
