// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/errwrap"
	metrics "github.com/hashicorp/go-metrics/compat"
	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/go-uuid"
	"github.com/oklog/run"
	"github.com/openbao/openbao/sdk/v2/helper/certutil"
	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/openbao/openbao/sdk/v2/helper/jsonutil"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/sdk/v2/physical"
	"github.com/openbao/openbao/v2/internal/helper/namespace"
	"github.com/openbao/openbao/v2/internal/vault/barrier"
	"github.com/openbao/openbao/v2/internal/vault/policy"
	"github.com/openbao/openbao/v2/internal/vault/seal"
)

const (
	// lockRetryInterval is the interval we re-attempt to acquire the
	// HA lock if an error is encountered
	lockRetryInterval = 10 * time.Second

	// leaderCheckInterval is how often a standby checks for a new leader
	leaderCheckInterval = 2500 * time.Millisecond

	// keyRotateCheckInterval is how often a read-disabled standby checks
	// for a keyring upgrade taking place.
	keyRotateCheckInterval = 10 * time.Second

	// leaderPrefixCleanDelay is how long to wait between deletions
	// of orphaned leader keys, to prevent slamming the backend.
	leaderPrefixCleanDelay = 200 * time.Millisecond
)

// Standby checks if the Vault is in standby mode.
// Usage of this function at core initialization/setup stage is not advised
// as it always evaluates to true until after postUnseal() method.
func (c *Core) Standby() bool {
	return c.standby.Load()
}

func (c *Core) ActiveTime() time.Time {
	c.stateLock.RLock()
	defer c.stateLock.RUnlock()
	return c.activeTime
}

// getHAMembers retrieves cluster membership that doesn't depend on raft. This should only ever be called by the
// active node.
func (c *Core) getHAMembers() ([]HAStatusNode, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return nil, err
	}

	leader := HAStatusNode{
		Hostname:       hostname,
		APIAddress:     c.redirectAddr,
		ClusterAddress: c.ClusterAddr(),
		ActiveNode:     true,
		Version:        c.effectiveSDKVersion,
	}

	if rb := c.GetRaftBackend(); rb != nil {
		leader.UpgradeVersion = rb.EffectiveVersion()
	}

	nodes := []HAStatusNode{leader}

	for _, peerNode := range c.GetHAPeerNodesCached() {
		lastEcho := peerNode.LastEcho
		nodes = append(nodes, HAStatusNode{
			Hostname:       peerNode.Hostname,
			APIAddress:     peerNode.APIAddress,
			ClusterAddress: peerNode.ClusterAddress,
			LastEcho:       &lastEcho,
			Version:        peerNode.Version,
			UpgradeVersion: peerNode.UpgradeVersion,
		})
	}

	sort.Slice(nodes, func(i, j int) bool {
		return nodes[i].APIAddress < nodes[j].APIAddress
	})

	return nodes, nil
}

// Leader is used to get information about the current active leader in relation to the current node (core).
// It utilizes a state lock on the Core by attempting to acquire a read lock. Care should be taken not to
// call this method if a read lock on this Core's state lock is currently held, as this can cause deadlock.
// e.g. if called from within request handling.
func (c *Core) Leader() (isLeader bool, leaderAddr, clusterAddr string, err error) {
	// Check if HA enabled. We don't need the lock for this check as it's set
	// on startup and never modified
	if c.ha == nil {
		return false, "", "", ErrHANotEnabled
	}

	// Check if sealed
	if c.Sealed() {
		return false, "", "", consts.ErrSealed
	}
	c.stateLock.RLock()
	defer c.stateLock.RUnlock()

	return c.LeaderLocked()
}

func (c *Core) LeaderLocked() (isLeader bool, leaderAddr, clusterAddr string, err error) {
	// Check if HA enabled. We don't need the lock for this check as it's set
	// on startup and never modified
	if c.ha == nil {
		return false, "", "", ErrHANotEnabled
	}

	// Check if sealed
	if c.Sealed() {
		return false, "", "", consts.ErrSealed
	}

	// Check if we are the leader
	if !c.standby.Load() {
		return true, c.redirectAddr, c.ClusterAddr(), nil
	}

	// Initialize a lock
	lock, err := c.ha.LockWith(CoreLockPath, "read")
	if err != nil {
		return false, "", "", err
	}

	// Read the value
	held, leaderUUID, err := lock.Value()
	if err != nil {
		return false, "", "", err
	}
	if !held {
		return false, "", "", nil
	}

	var localLeaderUUID, localRedirectAddr, localClusterAddr string
	clusterLeaderParams := c.clusterLeaderParams.Load()
	if clusterLeaderParams != nil {
		localLeaderUUID = clusterLeaderParams.LeaderUUID
		localRedirectAddr = clusterLeaderParams.LeaderRedirectAddr
		localClusterAddr = clusterLeaderParams.LeaderClusterAddr
	}

	// If the leader hasn't changed, return the cached value; nothing changes
	// mid-leadership, and the barrier caches anyways
	if leaderUUID == localLeaderUUID && localRedirectAddr != "" {
		return false, localRedirectAddr, localClusterAddr, nil
	}

	c.logger.Trace("found new active node information, refreshing", "old_uuid", localLeaderUUID, "old_cluster_addr", localClusterAddr, "new_uuid", leaderUUID)

	c.leaderParamsLock.Lock()
	defer c.leaderParamsLock.Unlock()

	// Validate base conditions again
	clusterLeaderParams = c.clusterLeaderParams.Load()
	if clusterLeaderParams != nil {
		localLeaderUUID = clusterLeaderParams.LeaderUUID
		localRedirectAddr = clusterLeaderParams.LeaderRedirectAddr
		localClusterAddr = clusterLeaderParams.LeaderClusterAddr
	} else {
		localLeaderUUID = ""
		localRedirectAddr = ""
		localClusterAddr = ""
	}

	if leaderUUID == localLeaderUUID && localRedirectAddr != "" {
		return false, localRedirectAddr, localClusterAddr, nil
	}

	key := coreLeaderPrefix + leaderUUID
	// Use background because postUnseal isn't run on standby
	entry, err := c.barrier.Get(context.Background(), key)
	if err != nil {
		return false, "", "", err
	}
	if entry == nil {
		return false, "", "", nil
	}

	var oldAdv bool

	var adv activeAdvertisement
	err = jsonutil.DecodeJSON(entry.Value, &adv)
	if err != nil {
		// Fall back to pre-struct handling
		adv.RedirectAddr = string(entry.Value)
		c.logger.Debug("parsed redirect addr for new active node", "redirect_addr", adv.RedirectAddr)
		oldAdv = true
	}

	// At the top of this function we return early when we're the active node.
	// If we're not the active node, and there's a stale advertisement pointing
	// to ourself, there's no point in paying any attention to it.  And by
	// disregarding it, we can avoid a panic in raft tests using the Inmem network
	// layer when we try to connect back to ourself.
	if adv.ClusterAddr == c.ClusterAddr() && adv.RedirectAddr == c.redirectAddr && c.GetRaftBackend() != nil {
		return false, "", "", nil
	}

	if !oldAdv {
		c.logger.Debug("parsing information for new active node", "active_cluster_addr", adv.ClusterAddr, "active_redirect_addr", adv.RedirectAddr)

		// Ensure we are using current values
		err = c.loadLocalClusterTLS(adv)
		if err != nil {
			return false, "", "", err
		}

		// This will ensure that we both have a connection at the ready and that
		// the address is the current known value
		// Since this is standby, we don't use the active context. Later we may
		// use a process-scoped context
		err = c.refreshRequestForwardingConnection(context.Background(), adv.ClusterAddr)
		if err != nil {
			return false, "", "", err
		}
	}

	// Don't set these until everything has been parsed successfully or we'll
	// never try again
	c.clusterLeaderParams.Store(&ClusterLeaderParams{
		LeaderUUID:         leaderUUID,
		LeaderRedirectAddr: adv.RedirectAddr,
		LeaderClusterAddr:  adv.ClusterAddr,
	})

	return false, adv.RedirectAddr, adv.ClusterAddr, nil
}

// StepDown is used to step down from leadership
func (c *Core) StepDown(httpCtx context.Context, req *logical.Request) (retErr error) {
	defer metrics.MeasureSince([]string{"core", "step_down"}, time.Now())

	if req == nil {
		return errors.New("nil request to step-down")
	}

	c.stateLock.RLock()
	defer c.stateLock.RUnlock()

	if c.Sealed() {
		return nil
	}
	if c.ha == nil || c.standby.Load() {
		return nil
	}

	ctx, cancel := context.WithCancel(namespace.RootContext(context.Background()))
	defer cancel()

	go func() {
		select {
		case <-ctx.Done():
		case <-httpCtx.Done():
			cancel()
		}
	}()

	err := c.PopulateTokenEntry(ctx, req)
	if err != nil {
		if errwrap.Contains(err, logical.ErrPermissionDenied.Error()) {
			return logical.ErrPermissionDenied
		}
		return logical.ErrInvalidRequest
	}
	acl, te, entity, identityPolicies, err := c.fetchACLTokenEntryAndEntity(ctx, req)
	if err != nil {
		return err
	}

	// Audit-log the request before going any further
	auth := &logical.Auth{
		ClientToken: req.ClientToken,
		Accessor:    req.ClientTokenAccessor,
	}
	if te != nil {
		auth.IdentityPolicies = identityPolicies[te.NamespaceID]
		delete(identityPolicies, te.NamespaceID)
		auth.ExternalNamespacePolicies = identityPolicies
		auth.TokenPolicies = te.Policies
		auth.Policies = append(te.Policies, identityPolicies[te.NamespaceID]...)
		auth.Metadata = te.Meta
		auth.DisplayName = te.DisplayName
		auth.EntityID = te.EntityID
		auth.TokenType = te.Type
	}

	logInput := &logical.LogInput{
		Auth:    auth,
		Request: req,
	}
	if err := c.auditBroker.LogRequest(ctx, logInput, c.auditedHeaders); err != nil {
		c.logger.Error("failed to audit request", "request_path", req.Path, "error", err)
		return errors.New("failed to audit request, cannot continue")
	}

	if entity != nil && entity.Disabled {
		c.logger.Warn("permission denied as the entity on the token is disabled")
		return logical.ErrPermissionDenied
	}

	if te != nil && te.EntityID != "" && entity == nil {
		c.logger.Warn("permission denied as the entity on the token is invalid")
		return logical.ErrPermissionDenied
	}

	// Attempt to use the token (decrement num_uses)
	if te != nil {
		te, err = c.tokenStore.UseToken(ctx, te)
		if err != nil {
			c.logger.Error("failed to use token", "error", err)
			return ErrInternalError
		}
		if te == nil {
			// Token has been revoked
			return logical.ErrPermissionDenied
		}
	}

	// Verify that this operation is allowed
	authResults := c.performPolicyChecks(ctx, acl, te, req, entity, &policy.CheckOpts{
		RootPrivsRequired: true,
	})
	if !authResults.Allowed {
		retErr = multierror.Append(retErr, authResults.Error)
		if authResults.Error.ErrorOrNil() == nil || authResults.DeniedError {
			retErr = multierror.Append(retErr, logical.ErrPermissionDenied)
		}
		return retErr
	}

	if te != nil && te.NumUses == tokenRevocationPending {
		// Token needs to be revoked. We do this immediately here because
		// we won't have a token store after sealing.
		leaseID, err := c.expiration.CreateOrFetchRevocationLeaseByToken(c.activeContext.Load(), te)
		if err == nil {
			err = c.expiration.Revoke(c.activeContext.Load(), leaseID)
		}
		if err != nil {
			c.logger.Error("token needed revocation before step-down but failed to revoke", "error", err)
			retErr = multierror.Append(retErr, ErrInternalError)
		}
	}

	select {
	case c.manualStepDownCh <- struct{}{}:
	default:
		c.logger.Warn("manual step-down operation already queued")
	}

	return retErr
}

func (c *Core) stopHALoop() {
	haLoopStopCh := c.haLoopStopCh.Load()
	if haLoopStopCh == nil {
		return
	}

	select {
	case haLoopStopCh.(chan struct{}) <- struct{}{}:
	default:
		c.logger.Warn("ignoring HA loop stop request: stop is already in progress")
	}
}

func (c *Core) Restart() {
	restartCh := c.haLoopRestartCh.Load()
	if restartCh == nil {
		return
	}

	select {
	case restartCh.(chan struct{}) <- struct{}{}:
	default:
		c.logger.Warn("ignoring restart request: restart is already in progress")
	}
}

func (c *Core) drainPendingRestarts() {
	for {
		restartCh := c.haLoopRestartCh.Load()
		if restartCh == nil {
			return
		}

		select {
		case <-restartCh.(chan struct{}):
			c.logger.Warn("ignoring restart request: restart is already in progress")

		default:
			return
		}
	}
}

func (c *Core) runStandbyGrabStateLock(stopCh <-chan struct{}) error {
	acquiredCh := make(chan struct{})
	quitCh := make(chan struct{})

	// We want to quit lock acquisition on two conditions:
	//
	// 1. Timeout.
	// 2. If we're told to stop.
	//
	// While technically unnecessary, we only quit lock acquisition
	// if we've not been canceled.
	go func() {
		timeout := time.NewTimer(DefaultMaxRequestDuration)

		canceled := false
		select {
		case <-timeout.C:
			canceled = true
		case <-stopCh:
			canceled = true
		case <-acquiredCh:
		}

		if !timeout.Stop() {
			<-timeout.C
		}

		if canceled {
			select {
			case quitCh <- struct{}{}:
			default:
			}
		}

		close(quitCh)
	}()

	// Grab lock.
	l := newLockGrabber(c.stateLock.Lock, c.stateLock.Unlock, quitCh)
	go l.grab()

	// Check if we got the lock successfully.
	stopped := l.lockOrStop()
	if stopped {
		return fmt.Errorf("failed to acquire state lock")
	}

	close(acquiredCh)

	return nil
}

// runHALoop is a long running process that manages a number of the HA
// subsystems.
// doneCh will be closed once the standby has finished operating in this
// invocation.
// manualStepDownCh is a channel passed to the leadership acquisition process,
// to allow interrupting leadership acquisition by this node. A step-down is
// triggered for every message in the channel and the channel is closed once
// this invocation returns.
// stopCh can be used to stop the standby and shutdown the process.
// restartCh can be used to gracefully reset standby node state, reloading all
// cached information.
//
// stopCh and restartCh differ in that the former is terminal and the latter is
// re-entrant. Both can be triggered by writing to the respective channel.
func (c *Core) runHALoop(doneCh chan<- struct{}, manualStepDownCh chan struct{}, stopCh, restartCh <-chan struct{}) {
	defer close(doneCh)
	defer close(manualStepDownCh)

	for restart := true; restart; {
		restart = c.runHALoopOnce(manualStepDownCh, stopCh, restartCh)
	}

	c.logger.Info("runHALoop stopped")
}

func (c *Core) runHALoopOnce(manualStepDownCh chan struct{}, stopCh, restartCh <-chan struct{}) bool {
	restart := false
	isReadEnabledStandby := c.StandbyReadsEnabled()

	var g run.Group
	{
		// This will cause all the other actors to close when the stop channel
		// is closed or the restartCh is triggered.
		g.Add(func() error {
			select {
			case <-stopCh:
			case <-restartCh:
				restart = true
			}
			return nil
		}, func(error) {})
	}
	{

		keyRotateStop := make(chan struct{})

		g.Add(func() error {
			c.periodicCheckKeyringUpgrades(context.Background(), keyRotateStop, isReadEnabledStandby)
			return nil
		}, func(error) {
			close(keyRotateStop)
			c.logger.Debug("shutting down periodic keyring upgrade checker")
		})
	}
	{
		// Monitor for new leadership
		checkLeaderStop := make(chan struct{})

		g.Add(func() error {
			c.periodicLeaderRefresh(checkLeaderStop)
			return nil
		}, func(error) {
			close(checkLeaderStop)
			c.logger.Debug("shutting down periodic leader refresh")
		})
	}
	{
		metricsStop := make(chan struct{})

		g.Add(func() error {
			c.metricsLoop(metricsStop)
			return nil
		}, func(error) {
			close(metricsStop)
			c.logger.Debug("shutting down periodic metrics")
		})
	}
	{
		// Wait for leadership
		leaderStopCh := make(chan struct{})

		g.Add(func() error {
			c.waitForLeadership(manualStepDownCh, leaderStopCh, isReadEnabledStandby)
			return nil
		}, func(error) {
			close(leaderStopCh)
			c.logger.Debug("shutting down leader elections")
		})
	}

	// Start all the actors; when leadership changes or we're told to restart,
	// we'll exit from this with an error.
	err := g.Run()
	if err != nil {
		c.logger.Error("unexpected error in runHALoop", "error", err.Error())
	}

	return restart
}

// waitForLeadership is a long running routine that is used when an HA backend
// is enabled. It waits until we are leader and switches this Vault to
// active.
func (c *Core) waitForLeadership(manualStepDownCh, stopCh <-chan struct{}, isReadEnabled bool) {
	var manualStepDown bool
	firstIteration := true

	// We pin the current standby or active context to this out-of-loop variable
	// to ensure it gets a deferred cancel if the loop exits due to an error.
	// This method really needs a refactor :)
	ctxCancel := context.CancelFunc(func() {})
	defer func() {
		ctxCancel()
	}()

	for {
		// Cancel any old context from the previous iteration.
		ctxCancel()

		// Check for a shutdown
		select {
		case <-stopCh:
			c.logger.Debug("stop channel triggered in runHALoop")
			return
		default:
		}

		if !firstIteration && !manualStepDown {
			// If we restarted the for loop due to an error, wait a second
			// so that we don't busy loop if the error persists.
			time.Sleep(1 * time.Second)
		}

		firstIteration = false

		c.logger.Info("entering standby mode")

		// Create the standby context (this becomes activeCtx on core, oh well).
		standbyCtx, standbyCtxCancel := context.WithCancel(namespace.RootContext(context.Background()))
		// Cancel if we exit the loop without transitioning to active.
		ctxCancel = standbyCtxCancel

		// If possible, unseal in read-only mode and start acting as a
		// read-enabled standby.
		if isReadEnabled {
			stop, retry := c.runReadEnabledStandby(standbyCtx, standbyCtxCancel, stopCh)
			if stop {
				return
			} else if retry {
				continue
			}
		}

		// If we've just stepped down, we could instantly grab the lock
		// again. Give the other nodes a chance.
		if manualStepDown {
			time.Sleep(manualStepDownSleepPeriod)
			manualStepDown = false
		}

		// Create a lock
		uuid, err := uuid.GenerateUUID()
		if err != nil {
			c.logger.Error("failed to generate uuid", "error", err)
			continue
		}
		lock, err := c.ha.LockWith(CoreLockPath, uuid)
		if err != nil {
			c.logger.Error("failed to create lock", "error", err)
			continue
		}

		// Attempt the acquisition
		leaderLostCh := c.acquireLock(lock, stopCh)

		// Bail if we are being shutdown
		if leaderLostCh == nil {
			return
		}

		// If the backend is a FencingHABackend, register the lock with it so it can
		// correctly fence all writes from now on  (i.e. assert that we still hold
		// the lock atomically with each write).
		if fba, ok := c.ha.(physical.FencingHABackend); ok {
			err := fba.RegisterActiveNodeLock(lock)
			if err != nil {
				// Can't register lock, bail out
				c.heldHALock = nil
				lock.Unlock()
				c.logger.Error("failed registering lock with fencing backend, giving up active state")
				continue
			}
		}

		c.logger.Info("acquired lock, enabling active operation")

		// This is used later to log a metrics event; this can be helpful to
		// detect flapping
		activeTime := time.Now()

		// We're transitioning to active, so cancel the standby context.
		// Spawn this in a goroutine so we can cancel the context and unblock
		// any inflight requests that are holding the state lock.
		go func() {
			timer := time.NewTimer(DefaultMaxRequestDuration)
			select {
			case <-standbyCtx.Done():
				timer.Stop()
			case <-timer.C:
				// Attempt to drain any inflight requests.
				standbyCtxCancel()
			}
		}()

		// Grab the statelock or stop
		l := newLockGrabber(c.stateLock.Lock, c.stateLock.Unlock, stopCh)
		go l.grab()
		if stopped := l.lockOrStop(); stopped {
			lock.Unlock()
			metrics.MeasureSince([]string{"core", "leadership_setup_failed"}, activeTime)
			return
		}

		if c.Sealed() {
			c.logger.Warn("grabbed HA lock but already sealed, exiting")
			lock.Unlock()
			c.stateLock.Unlock()
			metrics.MeasureSince([]string{"core", "leadership_setup_failed"}, activeTime)
			return
		}

		// Cancel the standby context if it hasn't already been.
		standbyCtxCancel()

		// Clear pending standby restarts, not that it matters too much.
		c.drainPendingRestarts()

		// Store the lock so that we can manually clear it later if needed
		c.heldHALock = lock

		// Create the active context
		activeCtx, activeCtxCancel := context.WithCancel(namespace.RootContext(context.Background()))
		c.activeContext.Store(NewAtomicContext(activeCtx, activeCtxCancel))

		// Ensure it gets cancelled eventually.
		ctxCancel = activeCtxCancel

		// Mark storage as readable again.
		c.barrier.SetReadOnly(false)

		// Perform seal migration
		if err := c.migrateSeal(activeCtx); err != nil {
			c.logger.Error("root seal migration error", "error", err)
			// nothing we can do about it here
			_ = c.sealManager.sealAll()
			c.logger.Warn("OpenBao is sealed")
			c.heldHALock = nil
			lock.Unlock()
			c.stateLock.Unlock()
			return
		}

		// This block is used to wipe barrier/seal state and verify that
		// everything is sane. If we have no sanity in the barrier, we actually
		// seal, as there's little we can do.
		{
			c.seal.SetBarrierConfig(activeCtx, nil)
			if c.seal.RecoveryKeySupported() {
				c.seal.SetRecoveryConfig(activeCtx, nil)
			}

			if err := c.performKeyUpgrades(activeCtx); err != nil {
				c.logger.Error("error performing key upgrades", "error", err)

				// If we fail due to anything other than a context canceled
				// error we should shutdown as we may have the incorrect Keys.
				if !strings.Contains(err.Error(), context.Canceled.Error()) {
					// We call this in a goroutine so that we can give up the
					// statelock and have this shut us down; sealInternal has a
					// workflow where it watches for the stopCh to close so we want
					// to return from here
					go c.Shutdown()
				}

				c.heldHALock = nil
				lock.Unlock()
				c.stateLock.Unlock()
				metrics.MeasureSince([]string{"core", "leadership_setup_failed"}, activeTime)

				// If we are shutting down we should return from this function,
				// otherwise continue
				if !strings.Contains(err.Error(), context.Canceled.Error()) {
					continue
				} else {
					return
				}
			}
		}

		{
			// Clear previous local cluster cert info so we generate new. Since the
			// UUID will have changed, standbys will know to look for new info
			c.localClusterParsedCert.Store(nil)
			c.localClusterCert.Store(nil)
			c.localClusterPrivateKey.Store(nil)

			if err := c.setupCluster(activeCtx); err != nil {
				c.heldHALock = nil
				lock.Unlock()
				c.stateLock.Unlock()
				c.logger.Error("cluster setup failed", "error", err)
				metrics.MeasureSince([]string{"core", "leadership_setup_failed"}, activeTime)
				continue
			}

		}
		// Advertise as leader
		if err := c.advertiseLeader(activeCtx, uuid, leaderLostCh); err != nil {
			c.heldHALock = nil
			lock.Unlock()
			c.stateLock.Unlock()
			c.logger.Error("leader advertisement setup failed", "error", err)
			metrics.MeasureSince([]string{"core", "leadership_setup_failed"}, activeTime)
			continue
		}

		// wipe any existing mount tables before stepping up as leader
		if err := c.preSeal(); err != nil {
			c.logger.Error("pre-seal teardown failed", "error", err)
		}

		// Attempt the post-unseal process
		c.replicationState.Store(uint32(consts.ReplicationDRDisabled | consts.ReplicationPerformancePrimary))
		err = c.postUnseal(activeCtx, activeCtxCancel, standardUnsealStrategy{})
		if err == nil {
			c.standby.Store(false)
			c.leaderUUID = uuid
			c.metricSink.SetGaugeWithLabels([]string{"core", "active"}, 1, nil)
		}

		c.stateLock.Unlock()

		// Handle a failure to unseal
		if err != nil {
			c.replicationState.Store(uint32(consts.ReplicationDRDisabled | consts.ReplicationPerformanceStandby))
			c.standby.Store(true)
			c.logger.Error("post-unseal setup failed", "error", err)
			lock.Unlock()
			metrics.MeasureSince([]string{"core", "leadership_setup_failed"}, activeTime)
			continue
		}

		// Monitor a loss of leadership
		select {
		case <-leaderLostCh:
			c.logger.Warn("leadership lost, stopping active operation")
		case <-stopCh:
		case <-manualStepDownCh:
			manualStepDown = true
			c.logger.Warn("stepping down from active operation to standby")
		}

		// Stop Active Duty
		{
			// Spawn this in a goroutine so we can cancel the context and
			// unblock any inflight requests that are holding the state lock.
			go func() {
				timer := time.NewTimer(DefaultMaxRequestDuration)
				select {
				case <-activeCtx.Done():
					timer.Stop()
				case <-timer.C:
					// Attempt to drain any inflight requests.
					activeCtxCancel()
				}
			}()

			// Grab lock if we are not stopped
			l := newLockGrabber(c.stateLock.Lock, c.stateLock.Unlock, stopCh)
			go l.grab()
			stopped := l.lockOrStop()

			// Cancel the context incase the above go routine hasn't done it
			// yet
			activeCtxCancel()
			metrics.MeasureSince([]string{"core", "leadership_lost"}, activeTime)

			// Mark as standby
			c.standby.Store(true)
			c.leaderUUID = ""
			c.metricSink.SetGaugeWithLabels([]string{"core", "active"}, 0, nil)

			// Seal if this was a regular leadership change or stepdown. We
			// do not seal when the stop channel is acquired, as
			// sealInternal(...) handles that for us.
			if !stopped {
				if err := c.preSeal(); err != nil {
					c.logger.Error("pre-seal teardown failed", "error", err)
				}
			}

			if err := c.clearLeader(uuid); err != nil {
				c.logger.Error("clearing leader advertisement failed", "error", err)
			}

			if err := c.heldHALock.Unlock(); err != nil {
				c.logger.Error("unlocking HA lock failed", "error", err)
			}
			c.heldHALock = nil

			// Advertise ourselves as a standby.
			if c.serviceRegistration != nil {
				if err := c.serviceRegistration.NotifyActiveStateChange(false); err != nil {
					c.logger.Warn("failed to notify standby status", "error", err)
				}
			}

			// If we are stopped return, otherwise unlock the statelock
			if stopped {
				return
			}
			c.stateLock.Unlock()
		}
	}
}

func (c *Core) setupGRPCStandbyInvalidations(ctx context.Context) bool {
	// Potentially refresh replication information before we get
	// too far. This ensures we do not attempt to contact a stale
	// leader.
	if _, _, _, err := c.LeaderLocked(); err != nil {
		c.logger.Error("skipping invalidation streaming as unable to read leader information", "err", err)
		return false
	}

	c.requestForwardingConnectionLock.RLock()
	defer c.requestForwardingConnectionLock.RUnlock()

	if c.rpcForwardingClient == nil {
		// When the active node has not indicated a cluster address
		// or there's a problem connecting, we may not have a
		// forwarding client. This renders us unable to perform any
		// invalidations so we're unable to start-up in read-enabled
		// mode.
		c.logger.Error("skipping invalidation streaming as no RPC client is present")
		return false
	}

	// Start tracking any invalidations; we won't begin processing
	// them until after unseal is complete. This is necessary because
	// we'll immediately start receiving events but our underlying data
	// store might be late to arrive. Since we'll only wait to the
	// awaited index, any events that come in for a later index than our
	// awaited one before readOnlyUnseal starts the invalidation subsystem
	// will be silently ignored otherwise. This ensures that they're not
	// dropped and that we'll re-trigger them once both the index has been
	// reached and the startup is complete.
	c.invalidations.Track()

	// Start the dispatch manager on the standby nodes.
	c.LocalGRPCDispatching()

	// Start streaming invalidation events from the primary.
	if err := c.rpcForwardingClient.StreamInvalidations(ctx); err != nil {
		c.logger.Error("failed to begin streaming invalidations", "err", err)
		return false
	}

	return true
}

// runReadEnabledStandby grabs the state lock and unseals in read-only mode. It
// returns two booleans:
// - stop: true if state lock acquisition stopped or timed out
// - retry: if the operation should be retried.
func (c *Core) runReadEnabledStandby(ctx context.Context, ctxCancel context.CancelFunc, stopCh <-chan struct{}) (stop bool, retry bool) {
	c.logger.Info("enabling horizontal scalability (reads)")
	c.barrier.SetReadOnly(true)

	if err := c.runStandbyGrabStateLock(stopCh); err != nil {
		c.logger.Error("unable to grab state lock for standby", "err", err)
		return true, false
	}

	defer c.stateLock.Unlock()

	// Wipe any existing state.
	if err := c.preSeal(); err != nil {
		c.logger.Error("pre-seal teardown failed", "error", err)
	}

	c.drainPendingRestarts()

	// Before unseal, check if we need to do GRPC based invalidation;
	// if so, start streaming invalidations.
	if shouldUseGRPCInvalidation(c.underlyingPhysical) {
		c.logger.Debug("setting up GRPC-backed streaming of invalidations")

		if ok := c.setupGRPCStandbyInvalidations(ctx); !ok {
			// Clear any events we might have received.
			c.CleanupInvalidationPeers()
			c.invalidations.Stop()

			// Try this again.
			return false, true
		}

		// Wait for our initial invalidation checkpoint.
		if err := c.AwaitReplication(ctx); err != nil {
			// Clear any events we might have received.
			c.CleanupInvalidationPeers()
			c.invalidations.Stop()

			c.logger.Error("failed to await replication", "err", err)
			return false, true
		}
	}

	// Unseal, holding the state lock.
	c.replicationState.Store(uint32(consts.ReplicationDRDisabled | consts.ReplicationPerformanceStandby))
	if err := c.postUnseal(ctx, ctxCancel, readonlyUnsealStrategy{}); err != nil {
		c.logger.Error("read-only post-unseal setup failed", "error", err)

		// Clear any events we might have received and quit tracking new ones.
		c.CleanupInvalidationPeers()
		c.invalidations.Stop()

		// We shouldn't attempt to keep grabbing the HA lock if we failed to
		// unseal.
		return false, true
	}

	// All good.
	return false, false
}

// grabLockOrStop returns stopped=false if the lock is acquired. Returns
// stopped=true if the lock is not acquired, because stopCh was closed. If the
// lock was acquired (stopped=false) then it's up to the caller to unlock. If
// the lock was not acquired (stopped=true), the caller does not hold the lock and
// should not call unlock.
// It's probably better to inline the body of grabLockOrStop into your function
// instead of calling it. If multiple functions call grabLockOrStop, when a deadlock
// occurs, we have no way of knowing who launched the grab goroutine, complicating
// investigation.
func grabLockOrStop(lockFunc, unlockFunc func(), stopCh chan struct{}) (stopped bool) {
	l := newLockGrabber(lockFunc, unlockFunc, stopCh)
	go l.grab()
	return l.lockOrStop()
}

type lockGrabber struct {
	// stopCh provides a way to interrupt the grab-or-stop
	stopCh <-chan struct{}
	// doneCh is closed when the child goroutine is done.
	doneCh     chan struct{}
	lockFunc   func()
	unlockFunc func()
	// lock protects these variables which are shared by parent and child.
	lock          sync.Mutex
	parentWaiting bool
	locked        bool
}

func newLockGrabber(lockFunc, unlockFunc func(), stopCh <-chan struct{}) *lockGrabber {
	return &lockGrabber{
		doneCh:        make(chan struct{}),
		lockFunc:      lockFunc,
		unlockFunc:    unlockFunc,
		parentWaiting: true,
		stopCh:        stopCh,
	}
}

// lockOrStop waits for grab to get a lock or give up, see grabLockOrStop for how to use it.
func (l *lockGrabber) lockOrStop() (stopped bool) {
	stop := false
	select {
	case <-l.stopCh:
		stop = true
	case <-l.doneCh:
	}

	// The child goroutine may not have acquired the lock yet.
	l.lock.Lock()
	defer l.lock.Unlock()
	l.parentWaiting = false
	if stop {
		if l.locked {
			l.unlockFunc()
		}
		return true
	}
	return false
}

// grab tries to get a lock, see grabLockOrStop for how to use it.
func (l *lockGrabber) grab() {
	defer close(l.doneCh)
	l.lockFunc()

	// The parent goroutine may or may not be waiting.
	l.lock.Lock()
	defer l.lock.Unlock()
	if !l.parentWaiting {
		l.unlockFunc()
	} else {
		l.locked = true
	}
}

// This checks the leader periodically to ensure that we switch RPC to a new
// leader pretty quickly. There is logic in Leader() already to not make this
// onerous and avoid more traffic than needed, so we just call that and ignore
// the result.
func (c *Core) periodicLeaderRefresh(stopCh chan struct{}) {
	opCount := atomic.Int32{}

	clusterAddr := ""
	for {
		timer := time.NewTimer(leaderCheckInterval)
		select {
		case <-timer.C:
			count := opCount.Add(1)
			if count > 1 {
				opCount.Add(-1)
				continue
			}
			// We do this in a goroutine because otherwise if this refresh is
			// called while we're shutting down the call to Leader() can
			// deadlock, which then means stopCh can never been seen and we can
			// block shutdown
			go func() {
				isLeader, _, newClusterAddr, err := c.Leader()
				if err != nil {
					// This is debug level because it's not really something the user
					// needs to see typically. This will only really fail if we are sealed
					// or the HALock fails (e.g. can't connect to Consul or elect raft
					// leader) and other things in logs should make those kinds of
					// conditions obvious. However when debugging, it is useful to know
					// for sure why a standby is not seeing the leadership update which
					// could be due to errors being returned or could be due to some other
					// bug.
					c.logger.Debug("periodicLeaderRefresh fail to fetch leader info", "err", err)
				}

				// If we are the leader reset the clusterAddr since the next
				// failover might go to the node that was previously active.
				if isLeader {
					clusterAddr = ""
				}

				if !isLeader && newClusterAddr != clusterAddr {
					c.logger.Debug("new leader found", "new", newClusterAddr, "past", clusterAddr)
					clusterAddr = newClusterAddr
				}

				opCount.Add(-1)
			}()
		case <-stopCh:
			timer.Stop()
			return
		}
	}
}

// periodicCheckKeyringUpgrades is used to watch for root namespace keyring
// rotation events as a read-disabled standby. Also watches for Raft TLS key
// upgrades for both types of standby nodes.
func (c *Core) periodicCheckKeyringUpgrades(ctx context.Context, stopCh chan struct{}, isReadEnabled bool) {
	raftBackend := c.GetRaftBackend()
	isRaft := raftBackend != nil

	opCount := atomic.Int32{}
	for {
		timer := time.NewTimer(keyRotateCheckInterval)
		select {
		case <-timer.C:
			count := opCount.Add(1)
			if count > 1 {
				opCount.Add(-1)
				continue
			}

			go func() {
				// Only check if we are a standby
				if !c.standby.Load() {
					opCount.Add(-1)
					return
				}

				// Monitor for keyring upgrades but only for read-disabled nodes.
				// Otherwise read-enabled nodes are handled through invalidation manager.
				if !isReadEnabled {
					if err := c.checkKeyringUpgrade(ctx, c.barrier); err != nil {
						c.logger.Error("root keyring rotation periodic upgrade check failed", "error", err)
					}
				}

				if isRaft {
					hasState, err := raftBackend.HasState()
					if err != nil {
						c.logger.Error("could not check raft state", "error", err)
					}

					if raftBackend.Initialized() && hasState {
						if err := c.checkRaftTLSKeyUpgrades(ctx); err != nil {
							c.logger.Error("raft tls periodic upgrade check failed", "error", err)
						}
					}
				}

				opCount.Add(-1)
			}()
		case <-stopCh:
			timer.Stop()
			return
		}
	}
}

// checkKeyringUpgrade is used to rotate the keyring to the new term
// if there have been any key rotations performed on a leader node.
func (c *Core) checkKeyringUpgrade(ctx context.Context, b barrier.SecurityBarrier) error {
	for {
		didUpgrade, newTerm, err := b.CheckUpgrade(ctx)
		if err != nil {
			return err
		}

		if !didUpgrade {
			break
		}
		c.logger.Info("upgraded to new key term", "term", newTerm)
	}
	return nil
}

func (c *Core) reloadShamirKey(ctx context.Context) error {
	_ = c.seal.SetBarrierConfig(ctx, nil)
	if cfg, _ := c.seal.BarrierConfig(ctx); cfg == nil {
		return nil
	}

	if c.seal.BarrierType() != seal.WrapperTypeShamir {
		return nil
	}

	entry, err := c.barrier.Get(ctx, barrier.ShamirKekPath)
	if err != nil {
		return err
	}
	if entry == nil {
		return nil
	}

	shamirWrapper, err := c.seal.GetShamirWrapper()
	if err != nil {
		return err
	}
	return shamirWrapper.SetAesGcmKeyBytes(entry.Value)
}

func (c *Core) performKeyUpgrades(ctx context.Context) error {
	if err := c.checkKeyringUpgrade(ctx, c.barrier); err != nil {
		return fmt.Errorf("error checking for key upgrades: %w", err)
	}

	if err := c.barrier.ReloadRootKey(ctx); err != nil {
		return fmt.Errorf("error reloading root key: %w", err)
	}

	if err := c.barrier.ReloadKeyring(ctx); err != nil {
		return fmt.Errorf("error reloading keyring: %w", err)
	}

	if err := c.reloadShamirKey(ctx); err != nil {
		return fmt.Errorf("error reloading shamir kek key: %w", err)
	}

	if err := c.scheduleUpgradeCleanup(ctx); err != nil {
		return fmt.Errorf("error scheduling upgrade cleanup: %w", err)
	}

	return nil
}

// scheduleUpgradeCleanup is used to ensure that all the upgrade paths
// are cleaned up in a timely manner if a leader failover takes place.
// Unfortunately we have to this for all sealable namespaces also.
func (c *Core) scheduleUpgradeCleanup(ctx context.Context) error {
	// List the upgrades
	upgrades, err := c.barrier.List(ctx, barrier.KeyringUpgradePrefix)
	if err != nil {
		return fmt.Errorf("failed to list upgrades: %w", err)
	}

	// Nothing to do if no upgrades
	if len(upgrades) == 0 {
		return nil
	}

	// Schedule cleanup for all of them
	time.AfterFunc(c.KeyRotateGracePeriod(), func() {
		if c.barrier.Sealed() {
			c.logger.Warn("barrier sealed at upgrade cleanup time")
			return
		}
		for _, upgrade := range upgrades {
			path := fmt.Sprintf("%s%s", barrier.KeyringUpgradePrefix, upgrade)
			if err := c.barrier.Delete(ctx, path); err != nil {
				c.logger.Error("failed to cleanup upgrade", "path", path, "error", err)
			}
		}
	})
	return nil
}

// acquireLock blocks until the lock is acquired, returning the leaderLostCh
func (c *Core) acquireLock(lock physical.Lock, stopCh <-chan struct{}) <-chan struct{} {
	for {
		// Attempt lock acquisition
		leaderLostCh, err := lock.Lock(stopCh)
		if err == nil {
			return leaderLostCh
		}

		// Retry the acquisition
		c.logger.Error("failed to acquire lock", "error", err)
		timer := time.NewTimer(lockRetryInterval)
		select {
		case <-timer.C:
		case <-stopCh:
			timer.Stop()
			return nil
		}
	}
}

// advertiseLeader is used to advertise the current node as leader
func (c *Core) advertiseLeader(ctx context.Context, uuid string, leaderLostCh <-chan struct{}) error {
	if leaderLostCh != nil {
		go c.cleanLeaderPrefix(ctx, uuid, leaderLostCh)
	}

	key := c.localClusterPrivateKey.Load()
	if key == nil {
		return errors.New("missing local cluster private key")
	}

	keyParams := &certutil.ClusterKeyParams{
		Type: corePrivateKeyTypeP521,
		X:    key.X,
		Y:    key.Y,
		D:    key.D,
	}

	locCert := c.localClusterCert.Load()
	if locCert == nil {
		return errors.New("couldn't load local cluster cert")
	}
	localCert := make([]byte, len(*locCert))
	copy(localCert, *locCert)
	adv := &activeAdvertisement{
		RedirectAddr:     c.redirectAddr,
		ClusterAddr:      c.ClusterAddr(),
		ClusterCert:      localCert,
		ClusterKeyParams: keyParams,
	}
	val, err := jsonutil.EncodeJSON(adv)
	if err != nil {
		return err
	}
	ent := &logical.StorageEntry{
		Key:   coreLeaderPrefix + uuid,
		Value: val,
	}
	err = c.barrier.Put(ctx, ent)
	if err != nil {
		return err
	}

	if c.serviceRegistration != nil {
		if err := c.serviceRegistration.NotifyActiveStateChange(true); err != nil {
			c.logger.Warn("failed to notify active status", "error", err)
		}
	}
	return nil
}

func (c *Core) cleanLeaderPrefix(ctx context.Context, uuid string, leaderLostCh <-chan struct{}) {
	keys, err := c.barrier.List(ctx, coreLeaderPrefix)
	if err != nil {
		c.logger.Error("failed to list entries in core/leader", "error", err)
		return
	}
	for len(keys) > 0 {
		timer := time.NewTimer(leaderPrefixCleanDelay)
		select {
		case <-timer.C:
			if keys[0] != uuid {
				c.barrier.Delete(ctx, coreLeaderPrefix+keys[0])
			}
			keys = keys[1:]
		case <-leaderLostCh:
			timer.Stop()
			return
		}
	}
}

// clearLeader is used to clear our leadership entry
func (c *Core) clearLeader(uuid string) error {
	key := coreLeaderPrefix + uuid
	return c.barrier.Delete(context.Background(), key)
}

// StandbyReadsEnabled returns true iff standby read are enabled and supported
// by the physical backend
func (c *Core) StandbyReadsEnabled() bool {
	if shouldUseGRPCInvalidation(c.underlyingPhysical) {
		if c.rpcForwardingClient == nil {
			return false
		}
	} else if _, ok := c.underlyingPhysical.(physical.CacheInvalidationBackend); !ok {
		return false
	}

	conf := c.rawConfig.Load()
	if conf == nil {
		return false
	}
	return !conf.DisableStandbyReads
}
