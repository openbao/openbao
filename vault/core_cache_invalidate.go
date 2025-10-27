// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/hashicorp/go-hclog"
	metrics "github.com/hashicorp/go-metrics/compat"
	"github.com/openbao/openbao/helper/fairshare"
	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/sdk/v2/physical"
	"github.com/openbao/openbao/vault/quotas"
)

const (
	dispatcherName          = "invalidate-dispatch"
	refresherName           = "invalidate-cache-refresh"
	maxLockTime             = 2 * time.Second
	maxInvalidateTime       = 30 * time.Second
	maxPluginInvalidateTime = 2 * time.Second
	maxDispatchers          = 128
)

func (c *Core) Invalidate(key ...string) {
	c.invalidations.Add(key...)
}

func (c *Core) invalidateSynchronous(key string) {
	job, _ := c.invalidations.buildInvalidateJobForKey(make(chan struct{}), context.Background(), key)
	if err := job.Execute(); err != nil {
		job.OnFailure(err)
	}
}

// invalidationManager is a long-lived subset of Core which is used to handle
// storage-level invalidations.
type invalidationManager struct {
	core *Core

	// Invalidate stages pending invalidations into this queue.
	pendingLock   sync.Mutex
	enabled       atomic.Bool
	pending       []string
	pendingNotify chan struct{}

	// quitCh notifies that we should stop actively processing invalidations.
	//
	// We'll still keep appending to pending, though, assuming enabled=true
	quitCh      chan struct{}
	quitContext context.Context
	doneCh      chan struct{}

	// dispatcher handles processing events from the invalidation queue to
	// subsystems. This is handled separately so that the storage layer
	// doesn't need to make asynchronous calls to the hook, while allowing
	// actual invalidation processing to take longer.
	dispacherLogger log.Logger
	dispatcher      *fairshare.JobManager
}

func (core *Core) NewInvalidationManager() {
	core.invalidations = &invalidationManager{
		core:            core,
		dispacherLogger: core.logger.Named(dispatcherName),

		pendingNotify: make(chan struct{}),
	}
}

func (im *invalidationManager) Track() {
	// Clear any leftover remaining items.
	im.pendingLock.Lock()
	im.pending = nil
	im.pendingLock.Unlock()

	// Start tracking new changes.
	im.enabled.Store(true)
}

func (im *invalidationManager) Start(ctx context.Context) {
	im.dispatcher = fairshare.NewJobManager(dispatcherName, maxDispatchers, im.dispacherLogger, im.core.metricSink)
	im.dispatcher.Start()

	im.quitCh = make(chan struct{})
	im.quitContext = ctx
	im.doneCh = make(chan struct{})

	// Now that we've started, start processing pending invalidations until
	// told to stop.
	go im.processPendingQueue(im.quitCh, im.quitContext, im.doneCh)
}

func (im *invalidationManager) Stop() error {
	im.dispacherLogger.Debug("stop triggered")
	defer im.dispacherLogger.Debug("finished stopping")

	// Prevent enqueuing more items.
	im.enabled.Store(false)

	// Close the quit channel to cancel any yet-to-be-dispatched.
	if im.quitCh != nil {
		close(im.quitCh)
	}

	// Stop processing the ones we have.
	if im.dispatcher != nil {
		im.dispatcher.Stop()
	}

	// Wait for the processing queue to finish.
	if im.doneCh != nil {
		timeout := time.NewTimer(maxInvalidateTime)
		select {
		case <-timeout.C:
			im.dispacherLogger.Warn("failed to stop processing queue")
		case <-im.doneCh:
		}

		if !timeout.Stop() {
			<-timeout.C
		}
	}

	// Clear any remaining items.
	im.pendingLock.Lock()
	im.pending = nil
	im.pendingLock.Unlock()

	// Clear any start-specific state.
	im.quitCh = nil
	im.quitContext = nil
	im.dispatcher = nil
	im.doneCh = nil

	return nil
}

func (im *invalidationManager) processPendingQueue(quitCh chan struct{}, quitContext context.Context, doneCh chan struct{}) {
	go func() {
		defer close(doneCh)
		for {
			select {
			case <-quitCh:
				im.dispacherLogger.Debug("shutting down; skipping pending queue processing")
				return
			case <-quitContext.Done():
				im.dispacherLogger.Debug("core context canceled, skipping pending queue processing")
				return
			case <-im.pendingNotify:
			}

			defer metrics.MeasureSince([]string{dispatcherName, "enqueue-pending"}, time.Now())

			im.pendingLock.Lock()
			pending := im.pending
			im.pending = nil
			im.pendingLock.Unlock()

			im.core.metricSink.SetGauge([]string{dispatcherName, "pending-dequeue-size"}, float32(len(pending)))

			for _, key := range pending {
				job, queue := im.buildInvalidateJobForKey(quitCh, quitContext, key)
				im.dispatcher.AddJob(job, queue)
			}
		}
	}()
}

func (im *invalidationManager) buildInvalidateJobForKey(quitCh chan struct{}, quitContext context.Context, key string) (fairshare.Job, string) {
	// Fairshare ensures we don't starve other queues too long. We need to
	// balance some things here:
	//
	// 1. Total memory consumption.
	// 2. Not starving any one namespace based on the work of others.
	// 3. Prioritizing Core tasks over others.
	//
	// Thus if a change comes into the root namespace's core/, it'll be
	// dispatched on its own queue by key, but all other work in the root
	// namespace or child namespaces will be in their own queues (minus,
	// again, a namespace's core, which will now share a queue).
	//
	// This balances the total number of queues (in most _reasonable_ systems),
	// while allowing prioritization of core updates and prioritizing root
	// updates most of all.
	ns, subkey := im.splitNamespaceFromKey(key)

	queue := ns
	if ns == namespace.RootNamespaceUUID {
		if strings.HasPrefix(subkey, "core/") {
			queue = key
		}
	} else if strings.HasPrefix(subkey, "core/") {
		queue += "-core"
	}

	return &invalidationJob{
		quitCh:      quitCh,
		quitContext: quitContext,
		im:          im,
		key:         key,
		nsUUID:      ns,
		nsKey:       subkey,
	}, queue
}

type invalidationJob struct {
	quitCh      chan struct{}
	quitContext context.Context

	im     *invalidationManager
	key    string
	nsUUID string
	nsKey  string

	fatal bool
}

func isLegacyMountPath(key string) bool {
	return key == coreMountConfigPath ||
		key == coreLocalMountConfigPath ||
		key == coreAuthConfigPath ||
		key == coreLocalAuthConfigPath
}

func isTransactionalMountPath(key string) bool {
	return strings.HasPrefix(key, coreMountConfigPath+"/") ||
		strings.HasPrefix(key, coreLocalMountConfigPath+"/") ||
		strings.HasPrefix(key, coreAuthConfigPath+"/") ||
		strings.HasPrefix(key, coreLocalAuthConfigPath+"/")
}

func isKeyringPath(key string) bool {
	return key == sealConfigPath ||
		key == coreKeyringCanaryPath ||
		key == keyringPath ||
		key == legacyRootKeyPath ||
		key == recoverySealConfigPath ||
		key == recoveryKeyPath ||
		key == rootKeyPath ||
		key == shamirKekPath ||
		key == StoredBarrierKeysPath ||
		strings.HasPrefix(key, keyringUpgradePrefix)
}

func isMissedMountKey(key string) bool {
	return strings.HasPrefix(key, credentialBarrierPrefix) ||
		strings.HasPrefix(key, backendBarrierPrefix) ||
		strings.HasPrefix(key, auditBarrierPrefix)
}

func (ij *invalidationJob) Execute() error {
	ij.im.dispacherLogger.Trace("processing invalidation", "key", ij.key)
	defer ij.im.dispacherLogger.Trace("concluding processing of invalidation", "key", ij.key)

	defer metrics.MeasureSince([]string{dispatcherName, "execute-invalidate"}, time.Now())
	ij.im.core.metricSink.IncrCounterWithLabels([]string{dispatcherName, "pending-dequeue-size"}, 1.0, nil)

	// Exit early if we're shut down before we get a chance to execute.
	select {
	case <-ij.quitCh:
		ij.im.dispacherLogger.Debug("shutting down; skipping job", "key", ij.key)
		return nil
	case <-ij.quitContext.Done():
		ij.im.dispacherLogger.Debug("core context canceled, skipping job", "key", ij.key)
		return nil
	default:
	}

	if ij.im.core.Sealed() {
		ij.im.dispacherLogger.Trace("refusing to process event when core is sealed", "key", ij.key)
		return nil
	}

	// State lock acquisition is usually very fast: we have many potential
	// readers of it and it only gets exclusively locked when HA status
	// changes, in which case, we're likely to restart our own state anyways.
	lockCtx, lockCancel := context.WithTimeout(ij.quitContext, maxLockTime)
	defer lockCancel()

	// Acquire state lock. We're running in a goroutine; while active context
	// should be sufficient to prevent races here, we want to ensure no core
	// state changes during processing of the request. We bind this to our
	// time-limited channel to ensure it processes in a reasonable amount of
	// time.
	l := newLockGrabber(ij.im.core.stateLock.RLock, ij.im.core.stateLock.RUnlock, lockCtx.Done())
	go l.grab()

	if stopped := l.lockOrStop(); stopped {
		// Failure to grab a lock is never fatal: HA state change will mean
		// that we'll restart the invalidation manager anyways.
		ij.im.dispacherLogger.Trace("unable to acquire read statelock", "key", ij.key, "context", ij.quitContext.Err())
		return nil
	}

	defer ij.im.core.stateLock.RUnlock()

	// Any storage operations we dispatch here should be time-bounded and
	// context refreshed.
	ctx, cancel := context.WithTimeout(ij.quitContext, maxInvalidateTime)
	defer cancel()

	// Always refresh physical cache for operations performed during
	// invalidation.
	ctx = physical.CacheRefreshContext(ctx, true)

	// Notify physical cache that our entry is stale if it is cached. This
	// ensures parallel reads see up-to-date data now that we're processing
	// invalidations.
	ij.im.core.physicalCache.Invalidate(ctx, ij.key)

	// Get a full namespace entry; it may be out of date since when the job
	// started and we need it for routing.
	//
	// Note that we never need to invalidate the namespace store here, before
	// we fetch this: namespace invalidation happens when the entry for the
	// child namespace is updated in the parent namespace, invalidating the
	// child. But the namespace UUID we have here is of the parent, which
	// (while it might be stale), cannot yet be invalidated as a separate
	// invalidation would occur for that. The exception of course is the root
	// namespace which is a virtual, storage-less namespace.
	ns, err := ij.im.core.namespaceStore.GetNamespace(ctx, ij.nsUUID)
	if err != nil {
		ij.fatal = true
		return fmt.Errorf("failed to load namespace %q from store: %w", ij.nsUUID, err)
	}
	if ns == nil {
		// Namespace was deleted; this is safe to ignore, because it occurs in
		// one of two scenarios:
		//
		// 1. The namespace was deleted already (invalidation on
		//    core/namespaces/<uuid> was processed first) and we're getting an
		//    invalidation for a child entry.
		// 2. The namespace has just been created (and the
		//    core/namespaces/<uuid> key was not yet invalidated) and we're
		//    getting an invalidation for the child entry.
		//
		// We will also receive a subsequent invalidation request for the
		// core/namespaces/<uuid> key in both cases, so we are fine to exit
		// silently.
		return nil
	}

	ctx = namespace.ContextWithNamespace(ctx, ns)

	// Lastly, create a short version of the context for plugin invalidations.
	shortCtx, shortCancel := context.WithTimeout(ctx, maxPluginInvalidateTime)
	defer shortCancel()

	// Now handle the actual event.
	key := ij.nsKey
	switch {
	case strings.HasPrefix(key, namespaceStoreSubPath):
		ij.fatal = true
		return ij.namespaceInvalidation(ctx)
	case strings.HasPrefix(key, systemBarrierPrefix+policyACLSubPath):
		// Policy invalidation is not fatal as it contains a LRU cache: we
		// know removal is strict and it is only potentially preloading an
		// entry which may err.
		return ij.policyInvalidation(ctx)
	case strings.HasPrefix(key, systemBarrierPrefix+quotas.StoragePrefix):
		ij.fatal = true
		return ij.quotaInvalidation(ctx)
	case key == coreAuditConfigPath || key == coreLocalAuditConfigPath:
		ij.fatal = true
		return ij.auditInvalidation(ctx)
	case isLegacyMountPath(key):
		ij.fatal = true
		return ij.legacyMountInvalidation(ctx)
	case isTransactionalMountPath(key):
		ij.fatal = true
		return ij.transactionalMountInvalidation(ctx)
	case isKeyringPath(key):
		// The HA subsystem handles keyring rotations via the
		// periodicCheckKeyUpgrades(...) actor.
	case strings.HasPrefix(ij.key, coreLeaderPrefix):
		// The HA subsystem handles leadership changes.
	case strings.HasPrefix(ij.key, pluginCatalogPath):
		// There is nothing to do to invalidate a plugin catalog write.
	case ij.key == CoreLockPath:
		// The lock path isn't really a key that we invalidate; it is a lock
		// file written by some backends which lack an out-of-storage locking
		// mechanism. It is also handled by the HA mechanism and so is safe
		// to ignore.
	case strings.HasPrefix(ij.key, "autopilot/") || ij.key == raftAutopilotConfigurationStoragePath:
		// Raft context is reloaded when a standby becomes active, so it is
		// safe to ignore changes to autopilot state.
	case ij.im.core.router.Invalidate(shortCtx, ij.key):
		// if router.Invalidate returns true, a matching plugin was found and
		// the invalidation is therefore dispatched.
	case isMissedMountKey(ij.key):
		// router.Invalidate(...) may return false when a matching plugin was
		// not yet loaded, even though this was under a path we'd expect to
		// be a mount key (auth/, audit/, or logical/) prefix. Ignoring it is
		// fine: a later change to a subsequent entry will actually load the
		// mount, loading any data this entry would've contained for the first
		// time.
		//
		// This is true in reverse for deletions.
	default:
		ij.im.dispacherLogger.Warn("no mechanism to invalidate cache for specified key", "key", key)
	}

	return nil
}

func (ij *invalidationJob) namespaceInvalidation(ctx context.Context) error {
	ij.im.dispacherLogger.Trace("issuing namespace invalidation")

	// The namespace name is the final path segment; ij.nsUUID contains the
	// parent namespace UUID.
	namespaceUUID := strings.TrimPrefix(ij.nsKey, namespaceStoreSubPath)

	// First notify the namespace storage that our next lookup might be stale.
	ij.im.core.namespaceStore.invalidate(ctx, ij.key)

	// Invalidate all policies within the namespace.
	ij.im.core.policyStore.invalidateNamespace(ctx, namespaceUUID)

	// Now reload all mounts within the namespace.
	if err := ij.im.core.reloadNamespaceMounts(ctx, namespaceUUID); err != nil {
		return fmt.Errorf("unable to invalidate mounts in namespace %q: %w", ij.nsUUID, err)
	}

	return nil
}

func (ij *invalidationJob) policyInvalidation(ctx context.Context) error {
	policyPath := strings.TrimPrefix(ij.nsKey, systemBarrierPrefix+policyACLSubPath)
	return ij.im.core.policyStore.invalidate(ctx, policyPath, PolicyTypeACL)
}

func (ij *invalidationJob) quotaInvalidation(ctx context.Context) error {
	quotaPath := strings.TrimPrefix(ij.nsKey, systemBarrierPrefix+quotas.StoragePrefix)
	return ij.im.core.quotaManager.Invalidate(quotaPath)
}

func (ij *invalidationJob) auditInvalidation(ctx context.Context) error {
	if ij.nsUUID != namespace.RootNamespaceUUID {
		ij.im.dispacherLogger.Warn("skipping invalidating audit table in non-root namespace", "ns", ij.nsUUID, "key", ij.nsKey)
		return nil
	}

	return ij.im.core.invalidateAudits(ctx)
}

func (ij *invalidationJob) legacyMountInvalidation(ctx context.Context) error {
	if ij.nsUUID != namespace.RootNamespaceUUID {
		ij.im.dispacherLogger.Warn("skipping invalidating legacy mount table in non-root namespace", "ns", ij.nsUUID, "key", ij.nsKey)
		return nil
	}

	return ij.im.core.reloadLegacyMounts(ctx, ij.nsKey)
}

func (ij *invalidationJob) transactionalMountInvalidation(ctx context.Context) error {
	if err := ij.im.core.reloadMount(ctx, ij.nsKey); err != nil {
		return fmt.Errorf("unable to invalidate mount for key %q in namespace %q: %w", ij.nsKey, ij.nsUUID, err)
	}

	return nil
}

func (ij *invalidationJob) OnFailure(err error) {
	// Decide if we need to restart the core.
	if ij.quitContext.Err() != nil {
		return
	}

	if !ij.fatal {
		return
	}

	// This was a fatal failure; dispatch a restart.
	ij.im.dispacherLogger.Error("fatal failure dispatching invalidation; restarting core", "key", ij.key, "err", err)
	ij.im.core.restart()
}

func (im *invalidationManager) Add(key ...string) {
	// Skip invalidations if we're not enabled yet.
	if !im.enabled.Load() {
		return
	}

	// Skip invalidations if we're not the standby. The InmemHA backend in
	// particular dispatches invalidations on every node which isn't
	// necessary as the active is expected to invalidate itself in the course
	// of writing the data.
	if !im.core.standby.Load() {
		return
	}

	// Likewise if we're sealed, ignore the invalidation.
	if im.core.Sealed() {
		return
	}

	// Add the keys.
	im.pendingLock.Lock()
	im.pending = append(im.pending, key...)
	im.pendingLock.Unlock()

	// Notify the processor.
	select {
	case im.pendingNotify <- struct{}{}:
	default:
	}
}

func (im *invalidationManager) splitNamespaceFromKey(key string) (string, string) {
	namespaceUUID := namespace.RootNamespaceUUID
	namespacedKey := key

	if keySuffix, ok := strings.CutPrefix(key, namespaceBarrierPrefix); ok {
		namespaceUUID, namespacedKey, _ = strings.Cut(keySuffix, "/")
	}

	return namespaceUUID, namespacedKey
}
