package vault

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/openbao/openbao/v2/internal/helper/fairshare"
	"github.com/openbao/openbao/v2/internal/vault/forwarding"

	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-multierror"
	uuid "github.com/hashicorp/go-uuid"
	"google.golang.org/grpc"
	"zgo.at/zcache/v2"
)

// invalidationPeers manages GRPC invalidation and tracking of peers.
type invalidationPeers struct {
	core   *Core
	logger log.Logger

	// l is for the below items. These are set to nil between state changes.
	// A write lock only needs to be acquired when modifying the actual
	// pointer values of the below; each item should still be thread-safe so
	// a read-lock is only necessary most of the time.
	l sync.RWMutex

	// peers is a cache of all standby nodes the active node is aware of that
	// are requesting GRPC synchronization of invalidations.
	peers *zcache.Cache[string, *invalidationPeerInfo]

	// dispatcher is a job manager for executing invalidations from the GRPC
	// bridge, bidirectionally. It is used on both active nodes (to dispatch
	// events to individual peers without unnecessary blocking) and standby
	// nodes (to handle waiting for the specified invalidation index).
	dispatcher *fairshare.JobManager
}

type invalidationPeerInfo struct {
	stream grpc.ServerStreamingServer[forwarding.CheckInvalidationResponse]
	stopCh chan struct{}

	started bool
}

func (c *Core) NewInvalidationPeers() {
	logger := c.logger.Named("grpc-invalidation")
	c.AddLogger(logger)

	c.connectedInvalidationPeers = &invalidationPeers{
		core:   c,
		logger: logger,
	}
}

func (c *Core) SetupInvalidationPeers() {
	c.connectedInvalidationPeers.Setup()
}

func (c *Core) LocalGRPCDispatching() {
	c.connectedInvalidationPeers.SetupStandby()
}

func (i *invalidationPeers) Setup() {
	i.l.Lock()
	defer i.l.Unlock()

	i.peers = zcache.New[string, *invalidationPeerInfo](16*i.core.clusterHeartbeatInterval, 1*time.Second)
	i.peers.OnEvicted(func(uuid string, peer *invalidationPeerInfo) {
		i.logger.Debug("evicting stale invalidation client for peer", "uuid", uuid)
		close(peer.stopCh)
	})

	i.dispatcher = fairshare.NewJobManager("active-grpc-invalidation", 2+32, i.logger, i.core.metricSink)
	i.dispatcher.Start()

	i.dispatcher.AddJob(&pingInvalidationJob{
		peers: i,
		ctx:   i.core.activeContext.Load(),
	}, "ping")
}

func (i *invalidationPeers) SetupStandby() {
	i.l.Lock()
	defer i.l.Unlock()

	i.dispatcher = fairshare.NewJobManager("standby-grpc-invalidation", 2, i.logger, i.core.metricSink)
	i.dispatcher.Start()
}

func (c *Core) CleanupInvalidationPeers() {
	c.connectedInvalidationPeers.Cleanup()
}

func (i *invalidationPeers) Cleanup() {
	i.l.Lock()
	defer i.l.Unlock()

	if i.peers != nil {
		i.peers.DeleteAll()
	}

	if i.dispatcher != nil {
		i.dispatcher.Stop()
	}

	i.dispatcher = nil
	i.peers = nil
}

// SendInvalidationNotice is used by the GRPCInvalidator mechanism to hook
// back into core and send the notice of invalidation to all participating
// peers.
func (c *Core) SendInvalidationNotice(keys ...string) {
	// Ensure we're called on the active node only.
	if c.standby.Load() {
		return
	}

	// Ensure the active context has not been canceled under us.
	ctx := c.activeContext.Load()
	if ctx.Err() != nil {
		return
	}

	// Get the index from the underlying storage backend.
	index, err := c.indexManager.Latest(ctx)
	if err != nil {
		c.logger.Error("failed to get latest applied replication index", "error", err)
		return
	}

	// Enqueue invalidation notifications to all peers.
	if err := c.connectedInvalidationPeers.SendInvalidation(index, keys); err != nil {
		c.logger.Error("failed to queue invalidation to send to peers", "error", err)
		return
	}
}

// SendInvalidation takes the given invalidation denoted by (index, keys) and
// enqueues jobs per known, ready peer to handle the specified.
func (i *invalidationPeers) SendInvalidation(index string, keys []string) error {
	i.l.RLock()
	defer i.l.RUnlock()

	if i.peers == nil || i.dispatcher == nil {
		return errors.New("core is restarting")
	}

	var failed []string
	var retErr error
	for peerUUID, peerInfoItem := range i.peers.Items() {
		peerInfo := peerInfoItem.Object
		if !peerInfo.started {
			// Peers which have not yet been started and caught up are
			// safe to ignore.
			continue
		}

		if peerInfo.stream == nil {
			retErr = multierror.Append(retErr, fmt.Errorf("while sending invalidation to %v: no active stream", peerUUID))
			failed = append(failed, peerUUID)
			continue
		}

		// We additionally need to grab the state lock here. While we could
		// do this linearly from this thread, using a job manager with
		// per-peer queues ensures that a slow peer does not starve other
		// peers from their invalidations.
		i.dispatcher.AddJob(&dispatchInvalidationToPeer{
			scheduled: time.Now(),
			index:     index,
			keys:      keys,
			peers:     i,
			peer:      peerUUID,
		}, peerUUID)
	}

	for _, failedPeer := range failed {
		i.peers.Delete(failedPeer)
	}

	return retErr
}

// AddInvalidationPeer tracks a new invalidation peer identified by the given
// stream, yielding (an identifier and a cancel channel) or an error.
func (c *Core) AddInvalidationPeer(stream grpc.ServerStreamingServer[forwarding.CheckInvalidationResponse]) (string, chan struct{}, error) {
	return c.connectedInvalidationPeers.AddPeer(stream)
}

// AddPeer handles assignment of the peer to the currently tracked subset,
// using the specified stream. It yields (an identifier and a cancel channel)
// or an error.
func (i *invalidationPeers) AddPeer(stream grpc.ServerStreamingServer[forwarding.CheckInvalidationResponse]) (string, chan struct{}, error) {
	i.l.RLock()
	defer i.l.RUnlock()

	info := &invalidationPeerInfo{
		stream: stream,
		stopCh: make(chan struct{}),
	}

	// Peer identifiers are ephemeral and matched to the stream.
	for {
		peerUUID, err := uuid.GenerateUUID()
		if err != nil {
			return "", nil, err
		}

		if err := i.peers.Add(peerUUID, info); err != nil {
			// This should practically never happen.
			continue
		}

		// Send an initial empty response with the uuid.
		if err := stream.Send(&forwarding.CheckInvalidationResponse{
			Uuid: peerUUID,
		}); err != nil {
			i.peers.Delete(peerUUID)
			return "", nil, fmt.Errorf("failed to send uuid to peer on stream: %w", err)
		}

		return peerUUID, info.stopCh, nil
	}
}

// MarkPeerStarted flags the selected peer as wanting to begin active service;
// it yields an initial index after which all events will be sent.
func (core *Core) MarkPeerStarted(ctx context.Context, uuid string) (string, error) {
	err := core.connectedInvalidationPeers.markPeerStarted(uuid)
	if err != nil {
		return "", fmt.Errorf("failed marking peer as started: %w", err)
	}

	index, err := core.indexManager.Latest(ctx)
	if err != nil {
		return "", fmt.Errorf("failed getting current physical replication index: %w", err)
	}

	return index, nil
}

// markPeerStarted associates the given replication index as the initial
// state of the specified invalidation peer.
func (i *invalidationPeers) markPeerStarted(uuid string) error {
	i.l.RLock()
	defer i.l.RUnlock()

	if _, existing := i.peers.Modify(uuid, func(peerInfo *invalidationPeerInfo) *invalidationPeerInfo {
		peerInfo.started = true
		return peerInfo
	}); !existing {
		return fmt.Errorf("peer %q does not have an active replication stream", uuid)
	}

	return nil
}

// AwaitInvalidation is used by the GRPC layer on standby nodes to dispatch
// events into the invalidation based on the specified storage index being
// replicated from the primary.
func (core *Core) AwaitInvalidation(ctx context.Context, cleanup func(), index string, keys ...string) {
	if len(keys) == 0 || index == "" {
		return
	}

	i := core.connectedInvalidationPeers

	i.l.RLock()
	defer i.l.RUnlock()

	if i.dispatcher == nil {
		i.logger.Error("skipping invalidation as dispatcher is missing", "index", index, "keys", keys)
		cleanup()
		return
	}

	i.dispatcher.AddJob(&awaitInvalidationJob{
		scheduled: time.Now(),
		core:      core,
		ctx:       ctx,
		index:     index,
		keys:      keys,
		cleanup:   cleanup,
		logger:    i.logger,
	}, "invalidations")
}

// AwaitReplication allows us to be sure that all state loaded after this
// point will have been loaded from an index, after which the active node
// will know to send us invalidations for updates. And because we already
// started tracking invalidations, any invalidations which we get will be
// queued locally.
func (core *Core) AwaitReplication(ctx context.Context) error {
	core.requestForwardingConnectionLock.RLock()
	activeIndex, err := core.rpcForwardingClient.CheckReplicationIndex(ctx)
	core.requestForwardingConnectionLock.RUnlock()

	if err != nil {
		return err
	}

	core.logger.Debug("awaiting GRPC-indicated start checkpoint", "index", activeIndex)

	if err := core.indexManager.Await(ctx, activeIndex); err != nil {
		return fmt.Errorf("unable to await storage index %v: %w", activeIndex, err)
	}

	return nil
}

type dispatchInvalidationToPeer struct {
	scheduled time.Time
	index     string
	keys      []string
	peers     *invalidationPeers
	peer      string
}

var _ fairshare.Job = &dispatchInvalidationToPeer{}

func (d *dispatchInvalidationToPeer) Execute() error {
	d.peers.l.RLock()
	defer d.peers.l.RUnlock()

	if d.peers.peers == nil {
		return errors.New("core is restarting")
	}

	peerInfo, ok := d.peers.peers.Get(d.peer)
	if !ok {
		return errors.New("peer disappeared after dispatch")
	}

	if !peerInfo.started {
		return errors.New("peer start index has been reset")
	}

	if peerInfo.stream == nil {
		return errors.New("peer has no active stream")
	}

	err := peerInfo.stream.Send(&forwarding.CheckInvalidationResponse{
		Uuid:    d.peer,
		Index:   d.index,
		Keys:    d.keys,
		Restart: false,
	})
	if err != nil {
		return err
	}

	d.peers.peers.Touch(d.peer)
	return nil
}

func (d *dispatchInvalidationToPeer) OnFailure(err error) {
	d.peers.logger.Error("failed to propagate write to peer", "peer", d.peer, "keys", d.keys, "err", err)

	d.peers.l.RLock()
	defer d.peers.l.RUnlock()

	if d.peers.peers == nil {
		return
	}

	d.peers.peers.Delete(d.peer)
}

type awaitInvalidationJob struct {
	scheduled time.Time
	core      *Core

	ctx   context.Context
	index string
	keys  []string

	logger  log.Logger
	cleanup func()
}

var _ fairshare.Job = &awaitInvalidationJob{}

func (a *awaitInvalidationJob) Execute() error {
	if a.ctx.Err() != nil {
		return a.ctx.Err()
	}

	if err := a.core.indexManager.Await(a.ctx, a.index); err != nil {
		return fmt.Errorf("unable to await invalidation at index %v: %w", a.index, err)
	}

	a.core.Invalidate(a.keys...)
	return nil
}

func (a *awaitInvalidationJob) OnFailure(err error) {
	if !strings.Contains(err.Error(), context.Canceled.Error()) {
		a.logger.Error("failed to await invalidation", "index", a.index, "keys", a.keys, "err", err)
	}

	a.cleanup()
}

type pingInvalidationJob struct {
	peers *invalidationPeers
	ctx   context.Context
}

var _ fairshare.Job = &pingInvalidationJob{}

func (p *pingInvalidationJob) Execute() error {
	// Skip executing if we've shut down.
	if p.ctx.Err() != nil {
		return p.ctx.Err()
	}

	defer p.requeueJob()
	return p.queueNotifications()
}

func (p *pingInvalidationJob) queueNotifications() error {
	p.peers.l.RLock()
	defer p.peers.l.RUnlock()

	if p.peers.peers == nil || p.peers.dispatcher == nil {
		return errors.New("core is restarting")
	}

	for peerUUID := range p.peers.peers.Items() {
		p.peers.dispatcher.AddJob(&dispatchInvalidationToPeer{
			scheduled: time.Now(),
			peers:     p.peers,
			peer:      peerUUID,
		}, peerUUID)
	}

	return nil
}

func (p *pingInvalidationJob) requeueJob() {
	// Dispatcher does not allow adding a job from the same thread and
	// there's no point blocking shutdown for a sleep.
	go func() {
		time.Sleep(1 * time.Second)

		p.peers.l.RLock()
		defer p.peers.l.RUnlock()

		if p.peers.peers == nil || p.peers.dispatcher == nil {
			return
		}

		p.peers.dispatcher.AddJob(&pingInvalidationJob{
			peers: p.peers,
			ctx:   p.ctx,
		}, "ping")
	}()
}

func (p *pingInvalidationJob) OnFailure(err error) {
	if strings.Contains(err.Error(), context.Canceled.Error()) {
		return
	}

	p.peers.logger.Debug("ping invalidation job failure", "error", err)
}
