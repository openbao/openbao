// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package forwarding

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"runtime/debug"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	metrics "github.com/hashicorp/go-metrics/compat"
	"github.com/hashicorp/go-multierror"
	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/openbao/openbao/v2/internal/helper/forwarding"
	"github.com/openbao/openbao/v2/internal/physical/raft"
	"google.golang.org/grpc"
)

type forwardedRequestRPCServer struct {
	UnimplementedRequestForwardingServer

	core                         core
	handler                      http.Handler
	raftFollowerStates           *raft.FollowerStates
	clusterPeerClusterAddrsCache clusterPeerClusterAddrsCache
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
				s.core.Logger().Error("panic serving forwarded request", "path", req.URL.Path, "error", err, "stacktrace", string(debug.Stack()))
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

type NodeHAConnectionInfo struct {
	NodeInfo       *NodeInformation
	LastHeartbeat  time.Time
	Version        string
	UpgradeVersion string
}

func (s *forwardedRequestRPCServer) Echo(ctx context.Context, in *EchoRequest) (*EchoReply, error) {
	incomingNodeConnectionInfo := NodeHAConnectionInfo{
		NodeInfo:       in.NodeInfo,
		LastHeartbeat:  time.Now(),
		Version:        in.SdkVersion,
		UpgradeVersion: in.RaftUpgradeVersion,
	}
	if in.ClusterAddr != "" {
		s.clusterPeerClusterAddrsCache.Set(in.ClusterAddr, incomingNodeConnectionInfo)
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

	if raftBackend := s.core.GetRaftBackend(); raftBackend != nil {
		reply.RaftAppliedIndex = raftBackend.AppliedIndex()
		reply.RaftNodeID = raftBackend.NodeID()
	}

	return reply, nil
}

func (s *forwardedRequestRPCServer) AdvertiseNamespaceKeys(ctx context.Context, in *AdvertiseNamespaceKeysRequest) (*AdvertiseNamespaceKeysReply, error) {
	missing := s.core.NamespacesMissingKeys()
	ret := &AdvertiseNamespaceKeysReply{}
	for _, uuid := range missing {
		if slices.Contains(in.Namespaces, uuid) {
			ret.Namespaces = append(ret.Namespaces, uuid)
		}
	}

	return ret, nil
}

func (s *forwardedRequestRPCServer) StartInvalidations(ctx context.Context, req *StartInvalidationRequest) (*StartInvalidationResponse, error) {
	index, err := s.core.MarkPeerStarted(ctx, req.Uuid)

	var errMsg string
	if err != nil {
		s.core.Logger().Error("invalidation: failed to mark peer as started", "err", err)
		errMsg = "failed to start invalidations; check active logs for more info"
	}

	return &StartInvalidationResponse{
		Err:   errMsg,
		Index: index,
	}, nil
}

func (s *forwardedRequestRPCServer) CheckInvalidations(req *CheckInvalidationRequest, stream grpc.ServerStreamingServer[CheckInvalidationResponse]) error {
	uuid, stopCh, err := s.core.AddInvalidationPeer(stream)
	if err != nil {
		s.core.Logger().Error("invalidation: failed registering invalidation peer", "err", err)
		return fmt.Errorf("not registered; check active server's logs for information")
	}

	s.core.Logger().Trace("invalidation: starting invalidation handling for peer", "uuid", uuid)

	// Wait for the peer's connection to be closed. When we call
	// AddInvalidationPeer(...) above, we effectively consume the stream
	// and sending of events on it. But this function returning closes the
	// stream so we need to block until we're done with the stream.
	<-stopCh
	s.core.Logger().Trace("invalidation: finished invalidation handling for peer", "uuid", uuid)

	return nil
}

func (s *forwardedRequestRPCServer) SendNamespaceKeys(ctx context.Context, in *SendNamespaceKeysRequest) (*SendNamespaceKeysReply, error) {
	keys := make(map[string][]byte, len(in.Keys))

	for _, key := range in.Keys {
		keys[key.Uuid] = key.Key
	}

	if err := s.core.SetNamespaceKeys(ctx, keys); err != nil {
		s.core.Logger().Error("failed to set namespace keys", "error", err)
		return &SendNamespaceKeysReply{
			Retry: true,
		}, nil
	}

	return &SendNamespaceKeysReply{}, nil
}

func (s *forwardedRequestRPCServer) GetNamespaceKeys(ctx context.Context, in *GetNamespaceKeysRequest) (*GetNamespaceKeysReply, error) {
	keys, err := s.core.NamespaceKeys(ctx, in.Namespaces)
	if err != nil && len(keys) == 0 {
		s.core.Logger().Error("call to get namespace keys failed", "error", err)
		return &GetNamespaceKeysReply{}, nil
	} else if err != nil {
		s.core.Logger().Warn("call to get namespace keys failed, but continuing with keys", "error", err, "keys", len(keys))
	}

	resp := &GetNamespaceKeysReply{}
	for uuid, rootKey := range keys {
		resp.Keys = append(resp.Keys, &NamespaceKey{
			Uuid: uuid,
			Key:  rootKey,
		})
	}

	return resp, nil
}

type Client struct {
	RequestForwardingClient
	core         core
	taskContext  context.Context
	echoTicker   *time.Ticker
	nsSyncTicker *time.Ticker

	invalidationsContext       context.Context
	invalidationsContextCancel context.CancelFunc
	peerUUID                   atomic.Pointer[string]
}

func NewClient(core core, requestForwardingClient RequestForwardingClient, taskContext context.Context, echoTicker *time.Ticker, nsSyncTicker *time.Ticker) *Client {
	return &Client{
		RequestForwardingClient: requestForwardingClient,
		core:                    core,
		taskContext:             taskContext,
		echoTicker:              echoTicker,
		nsSyncTicker:            nsSyncTicker,
	}
}

// NOTE: we also take advantage of gRPC's keepalive bits, but as we send data
// with these requests it's useful to keep this as well
func (c *Client) Start() {
	go func() {
		clusterAddr := c.core.ClusterAddr()
		hostname, _ := os.Hostname()
		ni := NodeInformation{
			ApiAddr:  c.core.RedirectAddr(),
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
				SdkVersion:  c.core.EffectiveSDKVersion(),
			}

			if raftBackend := c.core.GetRaftBackend(); raftBackend != nil {
				req.RaftAppliedIndex = raftBackend.AppliedIndex()
				req.RaftNodeID = raftBackend.NodeID()
				req.RaftTerm = raftBackend.Term()
				req.RaftDesiredSuffrage = raftBackend.DesiredSuffrage()
				req.RaftUpgradeVersion = raftBackend.EffectiveVersion()
				labels = append(labels, metrics.Label{Name: "peer_id", Value: raftBackend.NodeID()})
			}

			defer metrics.MeasureSinceWithLabels([]string{"ha", "rpc", "client", "echo"}, now, labels)

			ctx, cancel := context.WithTimeout(c.taskContext, 2*time.Second)
			resp, err := c.Echo(ctx, req)
			cancel()
			if err != nil {
				metrics.IncrCounter([]string{"ha", "rpc", "client", "echo", "errors"}, 1)
				c.core.Logger().Debug("forwarding: error sending echo request to active node", "error", err)
				return
			}
			if resp == nil {
				c.core.Logger().Debug("forwarding: empty echo response from active node")
				return
			}
			if resp.Message != "pong" {
				c.core.Logger().Debug("forwarding: unexpected echo response from active node", "message", resp.Message)
				return
			}

			// Store the active node's replication state to display in
			// sys/health calls
			c.core.SetActiveNodeReplicationState(consts.ReplicationState(resp.ReplicationState))
		}

		// The ticker may fire several times before keys are synchronized,
		// so ignore them.
		var syncRunning atomic.Bool
		syncKeys := func() {
			if !syncRunning.CompareAndSwap(false, true) {
				c.core.Logger().Warn("another namespace key synchronization is still running")
				return
			}
			defer syncRunning.Store(false)

			c.core.Logger().Trace("synchronizing namespace keys with active node")

			// We don't want to hang forever waiting to synchronize namespace
			// seal keys with the active node. Bind it to a reasonable length.
			ctx, cancel := context.WithTimeout(c.taskContext, 2*time.Minute)
			defer cancel()

			c.SynchronizeKeys(ctx)
		}

		tick()
		syncKeys()

		for {
			select {
			case <-c.taskContext.Done():
				c.echoTicker.Stop()
				c.core.Logger().Debug("forwarding: stopping heartbeating")
				c.core.SetActiveNodeReplicationState(consts.ReplicationUnknown)
				return
			case <-c.echoTicker.C:
				tick()
			case <-c.nsSyncTicker.C:
				go syncKeys()
			}
		}
	}()
}

func (c *Client) SynchronizeKeys(ctx context.Context) {
	var wg sync.WaitGroup
	wg.Go(func() {
		if err := c.shipKeys(ctx); err != nil {
			c.core.Logger().Error("error sending namespace keys", "error", err)
		}
	})

	wg.Go(func() {
		if err := c.getKeys(ctx); err != nil {
			c.core.Logger().Error("error receiving namespace keys", "error", err)
		}
	})

	wg.Wait()
}

func (c *Client) shipKeys(ctx context.Context) error {
	namespaces := c.core.NamespacesWithKeys()
	if len(namespaces) == 0 {
		// Nothing to do.
		return nil
	}

	advertisement := &AdvertiseNamespaceKeysRequest{
		Namespaces: namespaces,
	}

	response, err := c.AdvertiseNamespaceKeys(ctx, advertisement)
	if err != nil {
		return fmt.Errorf("failed to send unsealed namespace advertisement to active node: %v", err)
	}

	if len(response.Namespaces) == 0 {
		return nil
	}

	// Even if we have errs, if we have a non-empty key set, we should still
	// attempt to send them to the active node.
	keys, errs := c.core.NamespaceKeys(ctx, response.Namespaces)
	if len(keys) == 0 {
		return errs
	}

	reply := &SendNamespaceKeysRequest{}
	for uuid, key := range keys {
		reply.Keys = append(reply.Keys, &NamespaceKey{
			Uuid: uuid,
			Key:  key,
		})
	}

	_, err = c.SendNamespaceKeys(ctx, reply)
	if err != nil {
		return multierror.Append(errs, err)
	}

	return errs
}

func (c *Client) getKeys(ctx context.Context) error {
	namespaces := c.core.NamespacesMissingKeys()
	if len(namespaces) == 0 {
		// No namespaces to update.
		return nil
	}

	keys, err := c.GetNamespaceKeys(ctx, &GetNamespaceKeysRequest{
		Namespaces: namespaces,
	})
	if err != nil {
		return fmt.Errorf("failed getting namespace keys from active node: %w", err)
	}

	if keys == nil || len(keys.Keys) == 0 {
		return nil
	}

	batch := make(map[string][]byte, len(keys.Keys))
	for _, key := range keys.Keys {
		batch[key.Uuid] = key.Key
	}

	if err := c.core.SetNamespaceKeys(ctx, batch); err != nil {
		return fmt.Errorf("failed loading namespace keys: %w", err)
	}

	return nil
}

// CheckReplicationIndex returns the current index on the active node.
func (c *Client) CheckReplicationIndex(ctx context.Context) (string, error) {
	var uuid string

	if value := c.peerUUID.Load(); value != nil && *value != "" {
		uuid = *value
	} else {
		return "", errors.New("active node has not returned a uuid")
	}

	resp, err := c.StartInvalidations(ctx, &StartInvalidationRequest{
		Uuid: uuid,
	})
	if err != nil {
		return "", fmt.Errorf("error checking active node's replication index: %w", err)
	}

	if resp == nil {
		return "", errors.New("no replication index returned by active node")
	}

	if resp.Err != "" {
		return "", fmt.Errorf("error checking replication index: %v", resp.Err)
	}

	return resp.Index, nil
}

func (c *Client) StreamInvalidations(ctx context.Context) error {
	c.peerUUID.Store(nil)
	c.invalidationsContext, c.invalidationsContextCancel = context.WithCancel(c.taskContext)

	commonCleanup := func() {
		c.peerUUID.Store(nil)
		c.invalidationsContextCancel()
	}

	doCleanup := true
	defer func() {
		if doCleanup {
			commonCleanup()
		}
	}()

	// Start streaming invalidations from the active.
	stream, err := c.CheckInvalidations(c.invalidationsContext, &CheckInvalidationRequest{})
	if err != nil {
		return fmt.Errorf("failed starting invalidation stream: %w", err)
	}

	// Receive our first invalidation.
	invalidation, err := stream.Recv()
	if err != nil {
		return fmt.Errorf("error during initial invalidation receive: %w", err)
	}

	// Every response should have UUID.
	uuid := invalidation.Uuid
	c.peerUUID.Store(&uuid)

	// No longer perform cleanup when we exit this function: we're kicking
	// off a background goroutine to handle invalidations including this one.
	doCleanup = false

	go func() {
		cleanup := func() {
			commonCleanup()

			// In our goroutine, the read-enabled standby has already started.
			// If our stream goes away, we need to ensure that we cancel the
			// current read-enabled standby state as we won't be getting any
			// more invalidations and thus be stale. If we were to just
			// re-establish the stream, we'd have lost any invalidations the
			// server has generated in the meantime. We'd also have no way of
			// catching back up to the current state as we don't track read
			// data versus indices.
			//
			// Thus a restart is the cleanest solution here, so that we know
			// we catch up to initial state again on stream re-establishment.
			c.core.Restart()
		}
		defer cleanup()

		// While the server immediately send back an empty invalidation with
		// the uuid in it, we don't hold any exclusive locks so (pending
		// timing) a regular invalidation could be handed to us ahead of it.
		// That's why this loop is inverted: we want to process the above
		// invalidation first before we get a new one.

		var err error
		for {
			select {
			case <-c.invalidationsContext.Done():
				return
			default:
			}

			if invalidation.Restart {
				c.core.Logger().Info("forwarding: active node indicated restart on invalidation")
				return
			}

			c.core.AwaitInvalidation(c.invalidationsContext, cleanup, invalidation.Index, invalidation.Keys...)

			invalidation, err = stream.Recv()
			if err != nil {
				c.core.Logger().Warn("forwarding: error receiving invalidation from active node", "err", err)
				return
			}
		}
	}()

	return nil
}

func (c *Client) StopInvalidations() {
	if c == nil || c.invalidationsContextCancel == nil {
		return
	}

	c.invalidationsContextCancel()
}
