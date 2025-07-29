// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"net/http"
	"os"
	"runtime/debug"
	"sync/atomic"
	"time"

	"github.com/armon/go-metrics"
	"github.com/openbao/openbao/helper/forwarding"
	"github.com/openbao/openbao/physical/raft"
	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/openbao/openbao/sdk/v2/physical"
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
		s.core.clusterPeerClusterAddrsCache.Set(in.ClusterAddr, incomingNodeConnectionInfo, 0)
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

	if in.Checkpoint != "" {
		// XXX(ascheel): make configurable the multiple
		s.core.notifyPhysicalStandby(in.NodeInfo.Uuid, in.Checkpoint, time.Now().Add(10*s.core.clusterHeartbeatInterval))
	}

	checkpoint, err := s.core.getActivePhysicalCheckpoint(ctx)
	if err != nil {
		s.core.logger.Debug("forwarding: error getting current checkpoint; continuing without", "error", err)
		err = nil
	}

	reply := &EchoReply{
		Message:          "pong",
		ReplicationState: uint32(s.core.ReplicationState()),
		Checkpoint:       checkpoint,
	}

	if raftBackend := s.core.getRaftBackend(); raftBackend != nil {
		reply.RaftAppliedIndex = raftBackend.AppliedIndex()
		reply.RaftNodeID = raftBackend.NodeID()
	}

	return reply, nil
}

func (s *forwardedRequestRPCServer) NotifyInvalidation(ctx context.Context, req *InvalidationRequest) (*InvalidationResponse, error) {
	confirming, ok := s.core.ha.(physical.HAGRPCInvalidateConfirm)
	if ok {
		confirming.ConfirmedInvalidate(req.Node, req.Value)
	}

	reply := &InvalidationResponse{}
	return reply, nil
}

type forwardingClient struct {
	RequestForwardingClient
	core        *Core
	echoTicker  *time.Ticker
	echoContext context.Context
	uuid        string
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
			Uuid:     c.uuid,
		}
		tick := func() {
			labels := make([]metrics.Label, 0, 1)
			defer metrics.MeasureSinceWithLabels([]string{"ha", "rpc", "client", "echo"}, time.Now(), labels)

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

			checkpoint, err := c.core.getStandbyPhysicalCheckpoint(c.echoContext)
			if err != nil {
				c.core.logger.Debug("forwarding: error getting physical checkpoint; continuing without", "error", err)
				err = nil
			} else {
				req.Checkpoint = checkpoint
			}

			ctx, cancel := context.WithTimeout(c.echoContext, 2*time.Second)
			resp, err := c.RequestForwardingClient.Echo(ctx, req)
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
			atomic.StoreUint32(c.core.activeNodeReplicationState, resp.ReplicationState)
		}

		tick()

		for {
			select {
			case <-c.echoContext.Done():
				c.echoTicker.Stop()
				c.core.logger.Debug("forwarding: stopping heartbeating")
				atomic.StoreUint32(c.core.activeNodeReplicationState, uint32(consts.ReplicationUnknown))
				return
			case <-c.echoTicker.C:
				tick()
			}
		}
	}()
}

func (c *forwardingClient) ConfirmInvalidate(identifier string) error {
	_, err := c.RequestForwardingClient.NotifyInvalidation(c.core.rpcClientConnContext, &InvalidationRequest{
		Node:  c.uuid,
		Value: identifier,
	})
	return err
}
