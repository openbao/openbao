// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"path"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/go-hclog"
	metrics "github.com/hashicorp/go-metrics/compat"
	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/go-secure-stdlib/base62"
	uuid "github.com/hashicorp/go-uuid"
	"github.com/openbao/openbao/helper/fairshare"
	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/vault/barrier"
	"github.com/openbao/openbao/vault/policy"
)

// Namespace id length; upstream uses 5 characters so we use one more to
// differentiate OpenBao from Vault Enterprise. This allows 2^35 entries; with
// fairly high probability, we'll hit a conflict here and have to regenerate
// but we shouldn't ever run out. This is also different from mount accessors
// (8 hex characters).
//
// See: https://developer.hashicorp.com/vault/api-docs/system/namespaces
const namespaceIdLength = 6

const (
	// Namespace storage location.
	namespaceStoreSubPath = "core/namespaces/"

	// nsDispatcherName is the name of the jobmanager instance for metrics.
	nsDispatcherName = "namespace-deletion"

	// nsMaxWorkers is the number of parallel namespace deletion workers. This
	// is set conservatively low due to different lock acquisitions; see
	// clearNamespaceResources for exact details. Add two to the number of
	// locks to handle the global namespace store lock acquisition and
	// overhead.
	nsMaxWorkers = 2 + /* namespace and overhead */
		1 + /* policies */
		3 + /* reload + auth + mount */
		1 + /* identity */
		1 + /* quotas */
		1 + /* locked user entries */
		1 /* final view clearing */
)

// NamespaceStore is used to provide durable storage of namespace. It is
// a singleton store across the Core and contains all child namespaces.
type NamespaceStore struct {
	core    *Core
	storage logical.Storage

	// This lock ensures we don't concurrently modify the store while using
	// a namespace entry. We also store an atomic to check if we need to
	// reload all namespaces.
	lock        sync.RWMutex
	invalidated atomic.Bool

	// List of all namespaces within the store. This is loaded at store
	// initialization time and persisted throughout the lifetime of the
	// instance. Entries should not be returned directly but instead be
	// copied to prevent modification.
	namespacesByPath     *namespaceTree
	namespacesByUUID     map[string]*namespace.Namespace
	namespacesByAccessor map[string]*namespace.Namespace

	// creationDeletionMap tracks actively created or deleted namespaces,
	// enabling us to retry the deletion process if the namespace is tainted,
	// but isn't present in the said map.
	//
	// A namespace may not be marked tainted (in memory) if it is in this
	// list, so results need to be combined when namespaces are externally
	// exposed.
	creationDeletionMap           map[string]bool
	deletionDispatcher            *fairshare.JobManager
	creationDeletionJobContext    context.Context
	creationDeletionJobCancelFunc context.CancelFunc

	// logger is the server logger copied over from core
	logger hclog.Logger
}

// NewNamespaceStore creates a new NamespaceStore that is backed
// using a given view. It used used to durable store and manage named namespace.
func NewNamespaceStore(ctx context.Context, core *Core, logger hclog.Logger) (*NamespaceStore, error) {
	ns := &NamespaceStore{
		core:                 core,
		storage:              core.barrier,
		logger:               logger,
		namespacesByPath:     newNamespaceTree(nil),
		namespacesByUUID:     make(map[string]*namespace.Namespace),
		namespacesByAccessor: make(map[string]*namespace.Namespace),
		creationDeletionMap:  make(map[string]bool),
	}

	ns.creationDeletionJobContext, ns.creationDeletionJobCancelFunc = context.WithCancel(core.activeContext.Load())
	ns.deletionDispatcher = fairshare.NewJobManager(nsDispatcherName, nsMaxWorkers, ns.logger, core.metricSink)
	ns.deletionDispatcher.Start()

	// Add namespaces from storage to our table. We can do this without
	// holding a lock as we've not returned ns to anyone yet.
	if err := ns.loadNamespacesLocked(ctx); err != nil {
		return nil, fmt.Errorf("error loading initial namespaces: %w", err)
	}

	return ns, nil
}

// NamespaceScopedView scopes the passed storage down to the passed namespace.
func NamespaceScopedView(storage logical.Storage, ns *namespace.Namespace) barrier.View {
	return barrier.NewView(storage, NamespaceStoragePathPrefix(ns))
}

// NamespaceStoragePathPrefix returns the namespace's storage prefix.
func NamespaceStoragePathPrefix(ns *namespace.Namespace) string {
	if ns == nil || ns.ID == namespace.RootNamespaceID {
		return ""
	}

	return path.Join(barrier.NamespacePrefix, ns.UUID) + "/"
}

// cancelNamespaceDeletion cancels goroutine that runs namespace deletion.
func (c *Core) cancelNamespaceDeletion() {
	if c.namespaceStore == nil {
		return
	}

	c.namespaceStore.CancelNamespaceDeletion()
}

func (ns *NamespaceStore) CancelNamespaceDeletion() {
	// Cancel pending operations.
	ns.creationDeletionJobCancelFunc()

	// Stop jobs.
	ns.deletionDispatcher.Stop()
}

// checkInvalidation checks if the store has been marked as invalidated, and if
// so, reloads namespaces from disk.
// checkInvalidation returns true if it acquired a write-lock as part of the
// store reload and is handing the lock over to the caller.
// If checkInvalidation returns an error, it never keeps a write lock for the
// caller, so there is no need to check the bool before propagating an error.
func (ns *NamespaceStore) checkInvalidation(ctx context.Context) (bool, error) {
	if ctx.Err() != nil {
		return false, ctx.Err()
	}

	if !ns.invalidated.Load() {
		return false, nil
	}

	ns.lock.Lock()

	// Status might have changed
	if !ns.invalidated.Load() {
		return true, nil
	}

	if err := ns.loadNamespacesLocked(ctx); err != nil {
		// Caller likely just wants to propagate the error,
		// so don't keep the lock for them.
		ns.lock.Unlock()
		return false, fmt.Errorf("error handling invalidation: %w", err)
	}

	ns.invalidated.Store(false)
	return true, nil
}

// lockWithInvalidation is a helper calls [checkInvalidation] and acquires the
// desired type of lock, potentially carrying it over from [checkInvalidation].
// This is useful for most namespace store operations that initially revalidate
// the store and then need a lock to perform the main read and/or write
// operation.
//
// lockWithInvalidation in write = false mode may actually yield a write lock if
// one was acquired by [checkInvalidation].
// lockWithInvalidation in write = true mode will always yield a write lock.
//
// The returned unlock function will be the correct one to unlock the respective
// type of lock acquired under the hood. The caller must not call the unlock
// function if a non-nil error is returned.
func (ns *NamespaceStore) lockWithInvalidation(ctx context.Context, write bool) (func(), error) {
	locked, err := ns.checkInvalidation(ctx)
	if err != nil {
		return nil, err
	}

	switch {
	case locked:
		return ns.lock.Unlock, nil
	case write:
		ns.lock.Lock()
		return ns.lock.Unlock, nil
	default:
		ns.lock.RLock()
		return ns.lock.RUnlock, nil
	}
}

// loadNamespaces loads all stored namespaces from disk. It assumes the lock
// is held when required.
func (ns *NamespaceStore) loadNamespacesLocked(ctx context.Context) error {
	// Assume we roughly have as many namespaces as we have presently. During
	// invalidation this will pre-allocate enough space to reload everything
	// as we'll likely be essentially in sync already. However, at startup, this
	// will mostly just give us space for the root namespace.
	namespacesByPath := newNamespaceTree(namespace.RootNamespace)
	namespacesByUUID := make(map[string]*namespace.Namespace, len(ns.namespacesByUUID)+1)
	namespacesByAccessor := make(map[string]*namespace.Namespace, len(ns.namespacesByAccessor)+1)
	namespacesByUUID[namespace.RootNamespaceUUID] = namespace.RootNamespace
	namespacesByAccessor[namespace.RootNamespaceID] = namespace.RootNamespace

	loadNamespaceInsert := func(namespace *namespace.Namespace) error {
		ns.logger.Info("discovered namespace", "path", namespace.Path, "uuid", namespace.UUID)

		if _, ok := namespacesByUUID[namespace.UUID]; ok {
			return fmt.Errorf("namespace with UUID %q is not unique in storage", namespace.UUID)
		}
		if err := namespacesByPath.Insert(namespace); err != nil {
			return err
		}
		namespacesByUUID[namespace.UUID] = namespace
		namespacesByAccessor[namespace.ID] = namespace
		return nil
	}

	if err := logical.WithTransaction(ctx, ns.storage, func(s logical.Storage) error {
		return ns.loadNamespacesRecursive(ctx, s, s, loadNamespaceInsert)
	}); err != nil {
		return err
	}

	err := namespacesByPath.validate()
	if err != nil {
		return err
	}

	ns.namespacesByPath = namespacesByPath
	ns.namespacesByUUID = namespacesByUUID
	ns.namespacesByAccessor = namespacesByAccessor

	return nil
}

// loadNamespacesRecursive reads all namespaces from a given namespace store view,
// recursing into the respective namespace store views of any discovered namespaces
// to load an entire namespace tree.
func (ns *NamespaceStore) loadNamespacesRecursive(
	ctx context.Context, barrier, view logical.Storage,
	callback func(*namespace.Namespace) error,
) error {
	return logical.HandleListPage(ctx, view, namespaceStoreSubPath, 100, func(page int, index int, entry string) (bool, error) {
		item, err := view.Get(ctx, namespaceStoreSubPath+entry)
		if err != nil {
			return false, fmt.Errorf("failed to fetch namespace %v (page %v / index %v): %w", entry, page, index, err)
		}

		if item == nil {
			return false, fmt.Errorf("%v has an empty namespace definition (page %v / index %v)", entry, page, index)
		}

		var namespace namespace.Namespace
		if err := item.DecodeJSON(&namespace); err != nil {
			return false, fmt.Errorf("failed to decode namespace %v (page %v / index %v): %w", entry, page, index, err)
		}

		namespace.Locked = namespace.UnlockKey != ""

		if err := callback(&namespace); err != nil {
			return false, err
		}

		childView := NamespaceScopedView(barrier, &namespace)

		// Check if this namespace has a seal config, i.e., it is a sealable
		// namespace. In that case, we can stop recursing this branch as the
		// namespace isn't unsealed yet, as we would not be able to read any
		// children.
		if sealConfigEntry, err := childView.Get(ctx, barrierSealConfigPath); err != nil {
			return false, fmt.Errorf("failed to read seal config entry for namespace %s: %w", namespace.ID, err)
		} else if sealConfigEntry != nil {
			var sealConfig SealConfig
			if err := sealConfigEntry.DecodeJSON(&sealConfig); err != nil {
				return false, fmt.Errorf("failed to decode seal config entry for namespace %s: %w", namespace.ID, err)
			}
			return true, ns.core.sealManager.SetSeal(ctx, &sealConfig, &namespace, false)
		}

		if err := ns.loadNamespacesRecursive(ctx, barrier, childView, callback); err != nil {
			return false, err
		}

		return true, nil
	}, nil)
}

// setupNamespaceStore is used to initialize the namespace store
// when the vault is being unsealed.
func (c *Core) setupNamespaceStore(ctx context.Context) error {
	// Create the Namespace store
	var err error
	nsLogger := c.baseLogger.Named("namespace")
	c.AddLogger(nsLogger)
	c.namespaceStore, err = NewNamespaceStore(ctx, c, nsLogger)
	return err
}

// teardownNamespaceStore is used to reverse setupNamespaceStore
// when the vault is being sealed.
func (c *Core) teardownNamespaceStore() error {
	c.namespaceStore = nil
	return nil
}

func (ns *NamespaceStore) invalidate(ctx context.Context, path string) {
	// We want to keep invalidation proper fast (as it holds up replication),
	// so defer invalidation to the next load.
	//
	// TODO(ascheel): handle individual entry invalidation correctly. We'll
	// need to handle child namespace invalidation as well. sync.Map could be
	// used instead in the future alongside the actual boolean.
	ns.invalidated.Store(true)
}

// SetNamespace is used to create or update a namespace.
func (ns *NamespaceStore) SetNamespace(ctx context.Context, entry *namespace.Namespace) error {
	defer metrics.MeasureSince([]string{"namespace", "set_namespace"}, time.Now())

	if _, err := ns.lockWithInvalidation(ctx, true); err != nil {
		return err
	}

	_, err := ns.setNamespaceLocked(ctx, entry, nil)
	return err
}

// SetNamespaceWithSeal is used to create namespace in sealed state.
// It's not possible to update the Seal config of a namespace with this function;
// only add a seal config to a net-new namespace.
func (ns *NamespaceStore) SetNamespaceWithSeal(ctx context.Context, entry *namespace.Namespace, sealConfig *SealConfig) ([][]byte, error) {
	defer metrics.MeasureSince([]string{"namespace", "set_namespace_with_seal"}, time.Now())

	if _, err := ns.lockWithInvalidation(ctx, true); err != nil {
		return nil, err
	}

	return ns.setNamespaceLocked(ctx, entry, sealConfig)
}

// setNamespaceLocked must be called while holding a write lock over the
// NamespaceStore. This function unlocks the lock once finished.
func (ns *NamespaceStore) setNamespaceLocked(ctx context.Context, nsEntry *namespace.Namespace, sealConfig *SealConfig) ([][]byte, error) {
	// If we are creating a net-new namespace, we have to unlock before
	// creating required mounts as the mount type will call
	// GetNamespaceByAccessor. In that case, we will manually call
	// ns.lock.Unlock() but in all other cases (including early exit)
	// we _also_ need to unlock. So using a defer is preferable. Calling
	// unlock twice may fail (either incorrectly releasing the write lock
	// if someone else grabbed it or panicing if it was double unlocked)
	// so we need a boolean here to determine whether or not our deferred
	// unlock should actually be run.
	var unlocked bool
	defer func() {
		if !unlocked {
			ns.lock.Unlock()
			unlocked = true
		}
	}()

	// Copy the entry before validating and potentially mutating it.
	entry := nsEntry.Clone(true /* preserve unlock */)
	if err := entry.Validate(); err != nil {
		return nil, logical.CodedError(http.StatusBadRequest, err.Error())
	}

	// Validate that we have a parent namespace.
	parent, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("error loading parent namespace from context: %w", err)
	}

	var exists bool
	if entry.UUID == "" {
		id, err := ns.assignIdentifier(entry.Path)
		if err != nil {
			return nil, err
		}

		entry.ID = id
		entry.UUID, err = uuid.GenerateUUID()
		if err != nil {
			return nil, err
		}
	} else {
		var existing *namespace.Namespace
		existing, exists = ns.namespacesByUUID[entry.UUID]
		if !exists {
			return nil, errors.New("trying to update a non-existent namespace")
		}

		if existing.ID != entry.ID {
			return nil, errors.New("accessor ID does not match")
		}

		if existing.Path != entry.Path {
			return nil, errors.New("unable to remount namespace at new path")
		}

		// reject update calls with seal config provided.
		if sealConfig != nil {
			return nil, errors.New("cannot modify existing namespace seal config")
		}
	}

	if !exists {
		// Before attempting to create it, ensure we don't have a mount table
		// entry that conflicts with this new namespace. We assume we only
		// need to look at our parent's namespace's mount table for the last
		// path component of this new namespace; while mount paths can have
		// any number of components, our namespace only has one and is relative
		// to some parent path.
		path := entry.Path
		if parent.ID != namespace.RootNamespaceID {
			if !entry.HasParent(parent) {
				return nil, errors.New("namespace path lacks parent as a prefix")
			}

			path = namespace.Canonicalize(parent.TrimmedPath(entry.Path))
		}

		if conflict := ns.core.router.MatchingPrefixInternal(ctx, path); conflict != "" {
			return nil, fmt.Errorf("new namespace conflicts with existing mount: %v", conflict)
		}
	}

	// Order of storage operations is important:
	//
	// 1. Write the durable storage entry as tainted. This helps signal
	//    standby nodes to ignore the update.
	// 2. Update the in-mem namespace store, marking the namespace as
	//    undergoing an asynchronous modification.
	// 3. Write the in-namespace entries.
	// 4. Finalize the namespace by re-writing the durable storage entry
	//    as not tainted.
	//
	// Cleanup thus needs to handle partial deletion and remove any storage
	// using the background context, not our primary context. We delete the
	// storage entry while holding the lock, but Tainted status ensures
	// nobody else attempts to mutate until we're done.
	failed := true

	cleanupFailed := func() {
		if !failed {
			return
		}

		if exists {
			return
		}

		// Do mount cleanup without holding the namespace lock to prevent
		// re-entrant locking.
		if !unlocked {
			ns.lock.Unlock()
			unlocked = true
		}

		// Queue partially created namespace deletion for the background
		// workers rather than doing it synchronously.
		ns.deletionDispatcher.AddJob(ns.newNamespaceCreationFailureJob(parent, entry), parent.UUID)
	}

	defer cleanupFailed()

	parentView := ns.core.NamespaceView(parent)
	if !exists {
		// This initial write sets up the namespace as tainted, preventing
		// a lot of subsystems from using it if it is reloaded from storage.
		entry.Tainted = true
		if err := ns.writeNamespace(ctx, parentView, entry); err != nil {
			return nil, fmt.Errorf("failed to persist initial tainted namespace: %w", err)
		}

		// But we don't mark our in-memory version as being tainted so that
		// initial mounts can succeed.
		entry.Tainted = false
		ns.creationDeletionMap[entry.UUID] = true
	}

	ns.namespacesByPath.Insert(entry)
	ns.namespacesByUUID[entry.UUID] = entry
	ns.namespacesByAccessor[entry.ID] = entry

	var sealKeyShares [][]byte
	if !exists {
		if sealConfig != nil {
			if err := ns.core.sealManager.SetSeal(ctx, sealConfig, entry, true); err != nil {
				return nil, fmt.Errorf("failed to set namespace seal: %w", err)
			}

			sealKeyShares, err = ns.core.sealManager.InitializeBarrier(ctx, entry)
			if err != nil {
				return nil, fmt.Errorf("failed to initialize namespace barrier: %w", err)
			}
		}

		// unlock before initializeNamespace since that will re-acquire the lock.
		ns.lock.Unlock()
		unlocked = true

		// Create sys/, token/ mounts and policies for the new namespace.
		if err := ns.initializeNamespace(ctx, entry); err != nil {
			return nil, fmt.Errorf("failed to initialize namespace: %w", err)
		}

		// Reacquire the lock to undo tainting in storage. We need the lock
		// here to ensure we don't race to update storage across multiple
		// callers.
		ns.lock.Lock()
		unlocked = false
	}

	// Finally, write the non-tainted namespace or perform our only write if
	// we are modifying an existing entry.
	if err := ns.writeNamespace(ctx, parentView, entry); err != nil {
		return nil, fmt.Errorf("failed to persist namespace: %w", err)
	}

	// Seal the namespace, as we've finished the setup.
	if sealConfig != nil {
		if err := ns.sealNamespaceLocked(ctx, entry); err != nil {
			return nil, fmt.Errorf("failed to seal namespace: %w", err)
		}
	}

	// Since the write succeeded, copy back any potentially changed values.
	nsEntry.UUID = entry.UUID
	nsEntry.ID = entry.ID
	nsEntry.Path = entry.Path
	delete(ns.creationDeletionMap, entry.UUID)
	failed = false

	// Lastly, push the change to all mounts.
	return sealKeyShares, ns.pushToMounts(ctx, entry)
}

func (ns *NamespaceStore) writeNamespace(ctx context.Context, storage barrier.View, entry *namespace.Namespace) error {
	item, err := logical.StorageEntryJSON(entry.UUID, &entry)
	if err != nil {
		return fmt.Errorf("error marshalling storage entry: %w", err)
	}

	if err := storage.SubView(namespaceStoreSubPath).Put(ctx, item); err != nil {
		return fmt.Errorf("error writing namespace: %w", err)
	}

	return nil
}

// assignIdentifier assumes the lock is held.
func (ns *NamespaceStore) assignIdentifier(path string) (string, error) {
	if ns := ns.namespacesByPath.Get(path); ns != nil {
		return "", errors.New("unable to update when a namespace with this path already exists")
	}

	for {
		id, err := base62.Random(namespaceIdLength)
		if err != nil {
			return "", fmt.Errorf("unable to generate namespace identifier: %w", err)
		}

		// accessor id already exists
		if _, ok := ns.namespacesByAccessor[id]; ok {
			continue
		}

		return id, nil
	}
}

// initializeNamespace initializes default policies and  sys/ and token/ mounts for a new namespace
func (ns *NamespaceStore) initializeNamespace(ctx context.Context, entry *namespace.Namespace) error {
	// ctx may have a namespace of the parent of our newly created namespace,
	// so create a new context with the newly created child namespace.
	nsCtx := namespace.ContextWithNamespace(ctx, entry.Clone(false))

	// TODO(ascheel): PolicyStore is hard to externally transactionalize;
	// while we'd like to, it has cache interaction semantics which makes
	// it difficult to do correctly. This likely requires hooks such as
	// https://github.com/openbao/openbao/issues/1988.
	if err := ns.initializeNamespacePolicies(nsCtx); err != nil {
		return err
	}

	return ns.createMounts(nsCtx, ns.core.NamespaceView(entry))
}

// initializeNamespacePolicies loads the default policies for the namespace store.
func (ns *NamespaceStore) initializeNamespacePolicies(ctx context.Context) error {
	if err := ns.core.policyStore.LoadDefaultPolicies(ctx); err != nil {
		return fmt.Errorf("error creating default policies: %w", err)
	}
	return nil
}

// createMounts handles creation of sys/ and token/ mounts for this new
// namespace.
//
// This is a two-step process:
//
// 1. Create in-memory versions of the mount.
// 2. Persist into storage using the passed transaction.
//
// In particular, mountInternal and enableCredentialInternal do not easily
// support passing external storage transactions just for persisting the
// mount.
func (ns *NamespaceStore) createMounts(ctx context.Context, storage logical.Storage) error {
	// Do not persist mounts yet.
	mounts, err := ns.core.requiredMountTable(ctx)
	if err != nil {
		return fmt.Errorf("for new namespace: %w", err)
	}

	credentials, err := ns.core.defaultAuthTable(ctx)
	if err != nil {
		return fmt.Errorf("for new namespace: %w", err)
	}

	// Grab all locks in the correct order. We hold these locks over updating
	// both the in-memory mount table and the transaction.
	ns.core.mountsLock.Lock()
	ns.core.authLock.Lock()
	defer ns.core.authLock.Unlock()
	defer ns.core.mountsLock.Unlock()

	for _, mount := range mounts.Entries {
		if err := ns.core.mountInternalWithLock(ctx, mount, false); err != nil {
			return err
		}
	}

	for _, credential := range credentials.Entries {
		if err := ns.core.enableCredentialInternalWithLock(ctx, credential, false); err != nil {
			return err
		}
	}

	// Persist the mounts using the above storage transaction.
	return logical.WithTransaction(ctx, storage, func(txn logical.Storage) error {
		for _, mount := range mounts.Entries {
			if err := ns.core.persistMounts(ctx, txn, ns.core.mounts, &mount.Local, mount.UUID); err != nil {
				return fmt.Errorf("failed to persist secret mount (path=%v): %w", mount.Path, err)
			}
		}

		for _, mount := range credentials.Entries {
			if err := ns.core.persistAuth(ctx, txn, ns.core.auth, &mount.Local, mount.UUID); err != nil {
				return fmt.Errorf("failed to persist auth mount (path=%v): %w", mount.Path, err)
			}
		}

		return nil
	})
}

// undoCreateMounts handles commit failure for in-memory resources. Note
// that we do not modify storage here as our context has (usually) been
// canceled and so we'd need activeContext or similar.
func (ns *NamespaceStore) undoCreateMounts(nsCtx context.Context, namespaceToDelete *namespace.Namespace) bool {
	success := true

	// clear auth mounts
	ns.core.authLock.RLock()
	authMountEntries, err := ns.core.auth.FindAllNamespaceMounts(nsCtx)
	ns.core.authLock.RUnlock()
	if err != nil {
		ns.logger.Error("failed to retrieve namespace credentials", "namespace", namespaceToDelete.Path, "error", err.Error())
		success = false
	} else {
		for _, me := range authMountEntries {
			err := ns.core.disableCredentialInternal(nsCtx, me.Path, false)
			if err != nil {
				if errors.Is(err, errNoMatchingMount) {
					continue
				}

				ns.logger.Error(fmt.Sprintf("failed to unmount %q", me.Path), "namespace", namespaceToDelete.Path, "error", err.Error())
				success = false
				continue
			}
		}
	}

	// clear mounts
	ns.core.mountsLock.RLock()
	mountEntries, err := ns.core.mounts.FindAllNamespaceMounts(nsCtx)
	ns.core.mountsLock.RUnlock()
	if err != nil {
		ns.logger.Error("failed to retrieve namespace mounts", "namespace", namespaceToDelete.Path, "error", err.Error())
		success = false
	} else {
		for _, me := range mountEntries {
			err := ns.core.unmountInternal(nsCtx, me.Path, false)
			if err != nil {
				if errors.Is(err, errNoMatchingMount) {
					continue
				}

				ns.logger.Error(fmt.Sprintf("failed to unmount %q", me.Path), "namespace", namespaceToDelete.Path, "error", err.Error())
				success = false
				continue
			}
		}
	}

	return success
}

func (ns *NamespaceStore) pushToMounts(ctx context.Context, entry *namespace.Namespace) error {
	ns.core.mountsLock.Lock()
	defer ns.core.mountsLock.Unlock()

	ns.core.authLock.Lock()
	defer ns.core.authLock.Unlock()

	for _, mount := range ns.core.auth.Entries {
		if mount.NamespaceID != entry.ID {
			continue
		}

		mount.Namespace = entry
	}

	for _, mount := range ns.core.mounts.Entries {
		if mount.NamespaceID != entry.ID {
			continue
		}

		mount.Namespace = entry
	}

	return nil
}

// GetNamespace is used to fetch the namespace with the given uuid.
func (ns *NamespaceStore) GetNamespace(ctx context.Context, uuid string) (*namespace.Namespace, error) {
	defer metrics.MeasureSince([]string{"namespace", "get_namespace"}, time.Now())

	unlock, err := ns.lockWithInvalidation(ctx, false)
	if err != nil {
		return nil, err
	}
	defer unlock()

	item, ok := ns.namespacesByUUID[uuid]
	if !ok {
		return nil, nil
	}

	entry := item.Clone(false)
	entry.Tainted = entry.Tainted || ns.creationDeletionMap[entry.UUID]

	return entry, nil
}

// GetNamespaceByAccessor is used to fetch the namespace with the given accessor.
func (ns *NamespaceStore) GetNamespaceByAccessor(ctx context.Context, id string) (*namespace.Namespace, error) {
	defer metrics.MeasureSince([]string{"namespace", "get_namespace_by_accessor"}, time.Now())

	unlock, err := ns.lockWithInvalidation(ctx, false)
	if err != nil {
		return nil, err
	}
	defer unlock()

	item, ok := ns.namespacesByAccessor[id]
	if !ok {
		return nil, nil
	}

	entry := item.Clone(false)
	entry.Tainted = entry.Tainted || ns.creationDeletionMap[entry.UUID]

	return entry, nil
}

func (ns *NamespaceStore) GetNamespaceByLongestPrefix(ctx context.Context, path string) (*namespace.Namespace, string) {
	ctxNs, err := namespace.FromContext(ctx)
	if err != nil {
		ctxNs = namespace.RootNamespace
	}

	combinedPath := ctxNs.Path + path
	ns.lock.RLock()
	prefix, entry, _ := ns.namespacesByPath.LongestPrefix(combinedPath)
	entry.Tainted = entry.Tainted || ns.creationDeletionMap[entry.UUID]
	ns.lock.RUnlock()
	return entry, strings.TrimPrefix(combinedPath, prefix)
}

// GetNamespaceByPath is used to fetch the namespace with the given full path.
func (ns *NamespaceStore) GetNamespaceByPath(ctx context.Context, path string) (*namespace.Namespace, error) {
	defer metrics.MeasureSince([]string{"namespace", "get_namespace_by_path"}, time.Now())

	unlock, err := ns.lockWithInvalidation(ctx, false)
	if err != nil {
		return nil, err
	}
	defer unlock()

	return ns.getNamespaceByPathLocked(ctx, path, false)
}

func (ns *NamespaceStore) getNamespaceByPathLocked(
	ctx context.Context, path string, withUnlockKey bool,
) (*namespace.Namespace, error) {
	parent, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, err
	}
	path = namespace.Canonicalize(parent.Path + path)
	item := ns.namespacesByPath.Get(path)
	if item == nil {
		return nil, nil
	}

	entry := item.Clone(withUnlockKey)
	entry.Tainted = entry.Tainted || ns.creationDeletionMap[entry.UUID]

	return entry, nil
}

// ModifyNamespace is used to perform modifications to a namespace while
// holding a write lock to prevent other changes to namespaces from occurring
// at the same time.
func (ns *NamespaceStore) ModifyNamespaceByPath(ctx context.Context, path string, sealConfig *SealConfig, callback func(context.Context, *namespace.Namespace) (*namespace.Namespace, error)) (*namespace.Namespace, [][]byte, error) {
	defer metrics.MeasureSince([]string{"namespace", "modify_namespace"}, time.Now())

	parent, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, nil, err
	}

	path = namespace.Canonicalize(parent.Path + path)
	if path == "" {
		return nil, nil, logical.CodedError(http.StatusBadRequest, "refusing to modify root namespace")
	}

	unlock, err := ns.lockWithInvalidation(ctx, true)
	if err != nil {
		return nil, nil, err
	}

	entry := ns.namespacesByPath.Get(path)
	if entry != nil {
		if entry.Tainted {
			unlock()
			return nil, nil, errors.New("namespace with that name exists and is currently tainted")
		}
		if value := ns.creationDeletionMap[entry.UUID]; value {
			unlock()
			return nil, nil, errors.New("namespace with that name exists and is currently being created or deleted")
		}

		entry = entry.Clone(true /* preserve unlock key so we can copy it */)
	} else {
		entry = &namespace.Namespace{
			Path:           path,
			CustomMetadata: make(map[string]string),
		}
	}

	unlockKey := entry.UnlockKey

	if callback != nil {
		entry.UnlockKey = ""
		entry, err = callback(ctx, entry)
		if err != nil {
			unlock()
			return nil, nil, err
		}

		// ModifyNamespaceByPath can never modify lock status.
		entry.UnlockKey = unlockKey
	}

	// setNamespaceLocked will unlock ns.lock.
	nsKeyShares, err := ns.setNamespaceLocked(ctx, entry, sealConfig)
	if err != nil {
		ns.logger.Error("set namespace failed", "error", err)
		return nil, nil, err
	}

	return entry.Clone(false), nsKeyShares, nil
}

// ListNamespaceOpts is passed to [NamespaceStore.ListNamespaces].
type ListNamespaceOpts struct {
	// Whether to list recursively, or at the current level only.
	Recursive bool
	// Whether to include the parent namespace that we're listing at.
	IncludeParent bool
	// Whether to include sealed namespaces.
	IncludeSealed bool
}

// ListNamespaces is used to list namespaces below a parent namespace. Precise
// listing behavior can be tuned via the passed [ListNamespaceOpts].
func (ns *NamespaceStore) ListNamespaces(ctx context.Context, opts ListNamespaceOpts) ([]*namespace.Namespace, error) {
	defer metrics.MeasureSince([]string{"namespace", "list_namespaces"}, time.Now())

	parent, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	unlock, err := ns.lockWithInvalidation(ctx, false)
	if err != nil {
		return nil, err
	}
	defer unlock()

	var namespaces []*namespace.Namespace

	// This enqueues a namespace to be returned.
	push := func(entry *namespace.Namespace) {
		if !opts.IncludeSealed && ns.core.NamespaceSealed(entry) {
			return
		}
		entry = entry.Clone(false)
		entry.Tainted = entry.Tainted || ns.creationDeletionMap[entry.UUID]
		namespaces = append(namespaces, entry)
	}

	// Fast-path avoid tree traversal in case we're listing recursively starting
	// from the root namespace.
	if parent.ID == namespace.RootNamespaceID && opts.Recursive {
		namespaces = make([]*namespace.Namespace, 0, len(ns.namespacesByAccessor))
		for id, entry := range ns.namespacesByAccessor {
			if opts.IncludeParent || id != parent.ID {
				push(entry)
			}
		}
		return namespaces, nil
	}

	if opts.IncludeParent {
		push(parent)
	}

	// Defer to the namespace tree for any queries that are not easily handled
	// by the flat lookup maps.
	if err := ns.namespacesByPath.Walk(parent.Path, opts.Recursive, push); err != nil {
		return nil, err
	}

	return namespaces, nil
}

// SealNamespace acquires a read lock, and seals provided namespace,
// cleaning up namespace resources.
func (ns *NamespaceStore) SealNamespace(ctx context.Context, path string) error {
	defer metrics.MeasureSince([]string{"namespace", "seal_namespace"}, time.Now())

	unlock, err := ns.lockWithInvalidation(ctx, true)
	if err != nil {
		return err
	}
	defer unlock()

	namespaceToSeal, err := ns.getNamespaceByPathLocked(ctx, path, false)
	if err != nil {
		return err
	}

	if namespaceToSeal == nil {
		return errors.New("namespace doesn't exist")
	}

	if namespaceToSeal.ID == namespace.RootNamespaceID {
		return errors.New("unable to seal root namespace")
	}

	if namespaceToSeal.Tainted {
		return errors.New("unable to seal tainted namespace")
	}

	parent, err := namespace.FromContext(ctx)
	if err != nil {
		return fmt.Errorf("failed to get parent namespace from context: %w", err)
	}

	if !namespaceToSeal.HasParent(parent) {
		return errors.New("namespace from context is not the parent of the target namespace to seal")
	}

	// Mark the namespace as sealed before we seal it; this ensures future
	// loads will reflect the desired status.
	if !ns.core.Standby() {
		// Now modify just this one namespace in storage to mark it sealed,
		// forgetting the keys from all other nodes.
		namespaceToSeal.ManuallySealed = true
		nsCopy := namespaceToSeal.Clone(true /* preserve unlock */)
		if err := ns.writeNamespace(ctx, ns.core.NamespaceView(parent), nsCopy); err != nil {
			return fmt.Errorf("failed to persist namespace: %w", err)
		}
	}

	return ns.sealNamespaceLocked(ctx, namespaceToSeal)
}

// sealNamespaceLocked assumes the read lock is hold, and seals provided namespace,
// cleaning up namespace resources.
func (ns *NamespaceStore) sealNamespaceLocked(ctx context.Context, namespaceToSeal *namespace.Namespace) error {
	var errs error
	ns.namespacesByPath.PostOrderTraversal(namespaceToSeal.Path, func(entry *namespace.Namespace) {
		if entry.ID == namespace.RootNamespaceID {
			return
		}

		if !ns.core.NamespaceSealed(entry) {
			errs = ns.clearNamespaceResources(namespace.ContextWithNamespace(ctx, entry), entry, false)
		}

		if barrier := ns.core.sealManager.NamespaceBarrier(entry.Path); barrier != nil {
			if err := barrier.Seal(); err != nil {
				errs = errors.Join(errs, err)
			}
		}

		if entry.UUID != namespaceToSeal.UUID {
			// Remove the namespace itself from our records if it isn't the
			// sealed namespace. We want to forget child namespaces of a
			// namespaces which was marked sealed, but retain the pointer to
			// the sealed namespace itself.
			if err := ns.namespacesByPath.Delete(entry.Path); err != nil {
				panic(err)
			}
			delete(ns.namespacesByUUID, entry.UUID)
			delete(ns.namespacesByAccessor, entry.ID)
		}
	})

	return errs
}

// UnsealNamespace attempts unsealing namespace with a given path, using provided unseal key.
func (ns *NamespaceStore) UnsealNamespace(ctx context.Context, path string, key []byte) (bool, error) {
	defer metrics.MeasureSince([]string{"namespace", "unseal_namespace"}, time.Now())

	parent, err := namespace.FromContext(ctx)
	if err != nil {
		return false, fmt.Errorf("error loading parent namespace from context: %w", err)
	}

	unlocker, err := ns.lockWithInvalidation(ctx, false)
	if err != nil {
		return false, err
	}

	// We have multiple code paths we want to call unlock on.
	var unlocked atomic.Bool
	unlock := func() {
		if !unlocked.CompareAndSwap(false, true) {
			return
		}

		unlocker()
	}
	defer unlock()

	namespaceToUnseal, err := ns.getNamespaceByPathLocked(ctx, path, false)
	if err != nil {
		return false, err
	}

	if namespaceToUnseal == nil {
		return false, fmt.Errorf("namespace %q not found", path)
	}

	if namespaceToUnseal.ID == namespace.RootNamespaceID {
		return false, errors.New("cannot unseal root namespace with this operation")
	}

	if !namespaceToUnseal.HasParent(parent) {
		return false, errors.New("namespace from context is not the parent of the target namespace to unseal")
	}

	// Namespace wasn't sealed before the call.
	if !ns.core.NamespaceSealed(namespaceToUnseal) {
		return true, nil
	}

	unsealed, err := ns.core.sealManager.UnsealNamespace(ctx, namespaceToUnseal, key)
	if err != nil {
		return false, err
	}

	// We do not have enough shards yet, namespace is still sealed, return
	// early.
	if !unsealed {
		return false, nil
	}

	// Now modify just this one namespace in storage to mark it unsealed,
	// letting other nodes unseal it as well.
	namespaceToUnseal.ManuallySealed = false
	nsCopy := namespaceToUnseal.Clone(true /* preserve unlock */)
	if err := ns.writeNamespace(ctx, ns.core.NamespaceView(parent), nsCopy); err != nil {
		return true, fmt.Errorf("failed to modify namespace: %w", err)
	}

	// Unlock before calling unsealNamespace; we recurse back into the
	// namespace store here.
	unlock()

	return true, ns.unsealNamespace(ctx, namespaceToUnseal)
}

func (ns *NamespaceStore) unsealNamespace(ctx context.Context, namespaceToUnseal *namespace.Namespace) error {
	var collected []*namespace.Namespace
	collected = append(collected, namespaceToUnseal.Clone(false))

	// Recurse loading all new namespaces starting at this one.
	if err := func() error {
		unlock, err := ns.lockWithInvalidation(ctx, true)
		if err != nil {
			return err
		}

		defer func() {
			if unlock != nil {
				unlock()
			}
		}()

		if err := ns.namespacesByPath.Insert(namespaceToUnseal); err != nil {
			return err
		}
		ns.namespacesByUUID[namespaceToUnseal.UUID] = namespaceToUnseal
		ns.namespacesByAccessor[namespaceToUnseal.ID] = namespaceToUnseal

		nsStorage := ns.core.NamespaceView(namespaceToUnseal)
		return logical.WithTransaction(ctx, nsStorage, func(s logical.Storage) error {
			return ns.loadNamespacesRecursive(ctx, s, s, func(newNs *namespace.Namespace) error {
				if _, ok := ns.namespacesByUUID[newNs.UUID]; ok {
					return fmt.Errorf("namespace with UUID %q is not unique in storage", newNs.UUID)
				}
				if err := ns.namespacesByPath.Insert(newNs); err != nil {
					return err
				}
				ns.namespacesByUUID[newNs.UUID] = newNs
				ns.namespacesByAccessor[newNs.ID] = newNs

				collected = append(collected, newNs.Clone(false))

				return nil
			})
		})
	}(); err != nil {
		return err
	}

	for index, newNs := range collected {
		ns.logger.Info("calling post-unseal for namespace", "ns_path", newNs.Path, "ns_uuid", newNs.UUID)

		if err := ns.postNamespaceUnseal(ctx, newNs); err != nil {
			return fmt.Errorf("failed to run namespace post-unseal [%d/%v]: %w", index, newNs.ID, err)
		}
	}

	return nil
}

// postNamespaceUnseal loads namespace credential and secret mounts,
// initializes the backends and updates the router.
// If any step fails the namespace is sealed back to avoid a dirty partial state.
func (ns *NamespaceStore) postNamespaceUnseal(ctx context.Context, unsealedNamespace *namespace.Namespace) (retErr error) {
	defer func() {
		if retErr != nil {
			if err := ns.SealNamespace(ns.core.activeContext.Load(), unsealedNamespace.Path); err != nil {
				ns.logger.Error("failed to re-seal namespace after failed unseal", "namespace", unsealedNamespace.Path)
			}
		}
	}()

	if err := ns.core.loadMountsForNamespace(ctx, unsealedNamespace); err != nil {
		return fmt.Errorf("failed to load mounts for namespace: %w", err)
	}

	var postUnsealFuncs []func()
	if postUnsealMountFuncs, err := ns.core.setupMountsForNamespace(ctx, unsealedNamespace); err != nil {
		return fmt.Errorf("failed to setup mounts for namespace: %w", err)
	} else {
		postUnsealFuncs = append(postUnsealFuncs, postUnsealMountFuncs...)
	}

	if err := ns.core.loadCredentialsForNamespace(ctx, unsealedNamespace); err != nil {
		return fmt.Errorf("failed to load credential mounts for namespace: %w", err)
	}

	if postUnsealCredFuncs, err := ns.core.setupCredentialsForNamespace(ctx, unsealedNamespace); err != nil {
		return fmt.Errorf("failed to setup credential mounts for namespace: %w", err)
	} else {
		postUnsealFuncs = append(postUnsealFuncs, postUnsealCredFuncs...)
	}

	if err := ns.core.loadIdentityStoreArtifactsForNamespace(ctx, unsealedNamespace, ns.core.Standby()); err != nil {
		return fmt.Errorf("failed to load identity store artifacts for namespace: %w", err)
	}

	if err := ns.core.loadLoginMFAConfigsForNamespace(ctx, unsealedNamespace); err != nil {
		return err
	}

	// load expirations
	if err := ns.core.expiration.RestoreNamespace(unsealedNamespace, func() {
		go func() {
			if err := ns.SealNamespace(ns.core.activeContext.Load(), unsealedNamespace.Path); err != nil {
				ns.logger.Error("failed to re-seal namespace after erring loading leases", "err", err)
			}
		}()
	}); err != nil {
		return err
	}

	// now we run the collected post unseal functions to finalize unsealing
	ns.core.runPostUnsealFuncs(postUnsealFuncs)
	return nil
}

// taintNamespace is used to taint the namespace designated to be deleted.
func (ns *NamespaceStore) taintNamespace(ctx context.Context, parent, namespaceToTaint *namespace.Namespace) error {
	// to be extra safe
	if namespaceToTaint.ID == namespace.RootNamespaceID {
		return errors.New("cannot taint root namespace")
	}

	ns.namespacesByUUID[namespaceToTaint.UUID].Tainted = true
	ns.namespacesByAccessor[namespaceToTaint.ID].Tainted = true
	namespaceToTaint.Tainted = true

	err := ns.namespacesByPath.Insert(namespaceToTaint)
	if err != nil {
		return fmt.Errorf("failed to modify namespace tree: %w", err)
	}

	nsCopy := namespaceToTaint.Clone(true /* preserve unlock */)
	if err := ns.writeNamespace(ctx, ns.core.NamespaceView(parent), nsCopy); err != nil {
		return fmt.Errorf("failed to persist namespace taint: %w", err)
	}

	// Push the update to all mounts.
	return ns.pushToMounts(ctx, namespaceToTaint.Clone(false))
}

// DeleteNamespace deletes an unsealed namespace.
func (ns *NamespaceStore) DeleteNamespace(ctx context.Context, path string) (string, error) {
	defer metrics.MeasureSince([]string{"namespace", "delete_namespace"}, time.Now())

	unlock, err := ns.lockWithInvalidation(ctx, true)
	if err != nil {
		return "", err
	}
	defer unlock()

	namespaceToDelete, err := ns.getNamespaceByPathLocked(ctx, path, false)
	if err != nil {
		return "", err
	}
	if namespaceToDelete == nil {
		return "", nil
	}

	isNamespaceDeleting := ns.creationDeletionMap[namespaceToDelete.UUID]
	if namespaceToDelete.Tainted && isNamespaceDeleting {
		return "in-progress", nil
	}

	if namespaceToDelete.ID == namespace.RootNamespaceID {
		return "", errors.New("unable to delete root namespace")
	}

	if ns.core.NamespaceSealed(namespaceToDelete) {
		return "", errors.New("namespace is sealed")
	}

	if !ns.namespacesByPath.IsLeaf(namespaceToDelete.Path) {
		return "", logical.CodedError(
			http.StatusConflict,
			"unable to delete namespace containing child namespaces",
		)
	}

	parent, err := namespace.FromContext(ctx)
	if err != nil {
		return "", fmt.Errorf("error loading parent namespace from context: %w", err)
	}

	if !namespaceToDelete.Tainted {
		if err = ns.taintNamespace(ctx, parent, namespaceToDelete); err != nil {
			return "", err
		}
	}

	ns.creationDeletionMap[namespaceToDelete.UUID] = true
	ns.deletionDispatcher.AddJob(&namespaceDeletionJob{
		store:  ns,
		parent: parent,
		target: namespaceToDelete,
		cleanup: func(ctx context.Context) error {
			return ns.clearNamespaceResources(ctx, namespaceToDelete, true)
		},
	}, parent.UUID)

	return "in-progress", nil
}

// DeleteSealedNamespace physically deletes a sealed namespace by wiping its
// storage through the root barrier. If the namespace has child namespaces,
// force must be true to authorize recursive deletion of the entire subtree.
func (ns *NamespaceStore) DeleteSealedNamespace(ctx context.Context, path string, force bool) (string, error) {
	defer metrics.MeasureSince([]string{"namespace", "delete_sealed_namespace"}, time.Now())

	unlock, err := ns.lockWithInvalidation(ctx, true)
	if err != nil {
		return "", err
	}
	defer unlock()

	namespaceToDelete, err := ns.getNamespaceByPathLocked(ctx, path, false)
	if err != nil || namespaceToDelete == nil {
		return "", err
	}

	parent, err := namespace.FromContext(ctx)
	if err != nil {
		return "", err
	}

	isNamespaceDeleting := ns.creationDeletionMap[namespaceToDelete.UUID]
	if namespaceToDelete.Tainted && isNamespaceDeleting {
		return "in-progress", nil
	}

	if namespaceToDelete.ID == namespace.RootNamespaceID {
		return "", errors.New("unable to delete root namespace")
	}

	if !ns.core.NamespaceSealed(namespaceToDelete) {
		return "", errors.New("namespace is not sealed")
	}

	// Physical storage check for child namespaces. Child namespaces nested
	// below a sealed namespace are not available via in-memory lookups, but
	// their keys in storage are visible through the root barrier.
	view := NamespaceScopedView(ns.core.barrier, namespaceToDelete)
	children, err := view.List(ctx, namespaceStoreSubPath)
	if err != nil {
		return "", fmt.Errorf("cannot verify child namespaces for %q: %w", namespaceToDelete.Path, err)
	}

	if len(children) > 0 && !force {
		return "", logical.CodedError(
			http.StatusConflict,
			"sealed namespace has leftover child namespaces; "+
				"pass force=true to delete the entire tree, "+
				"or unseal the namespace and delete children individually",
		)
	}

	if !namespaceToDelete.Tainted {
		if err = ns.taintNamespace(ctx, parent, namespaceToDelete); err != nil {
			return "", err
		}
	}

	ns.creationDeletionMap[namespaceToDelete.UUID] = true
	ns.deletionDispatcher.AddJob(&namespaceDeletionJob{
		store:  ns,
		parent: parent,
		target: namespaceToDelete,
		cleanup: func(ctx context.Context) error {
			return ns.wipeStorageTree(ctx, namespaceToDelete)
		},
	}, parent.UUID)

	return "in-progress", nil
}

func (ns *NamespaceStore) clearNamespaceResources(nsCtx context.Context, entry *namespace.Namespace, updateStorage bool) error {
	// clear expirations.
	ns.core.expiration.StopNamespace(entry)

	// clear ACL policies
	if err := ns.clearNamespacePolicies(nsCtx, entry, updateStorage); err != nil {
		return err
	}

	if updateStorage {
		// To clear auth+secret mounts, we first need to load that portion of the
		// mount table that this namespace has. Otherwise, things like lease cleanup
		// will not run if the mount was not already loaded.
		nonTaintedNs := entry.Clone(false)
		nonTaintedNs.Tainted = false
		nonTaintedCtx := namespace.ContextWithNamespace(nsCtx, nonTaintedNs)

		if err := ns.core.reloadNamespaceMounts(nonTaintedCtx, entry.UUID, false /* not yet deleted */); err != nil {
			return fmt.Errorf("failed to reload namespace mounts: %w", err)
		}
	}

	// clear auth mounts
	ns.core.authLock.RLock()
	authMountEntries, err := ns.core.auth.FindAllNamespaceMounts(nsCtx)
	ns.core.authLock.RUnlock()
	if err != nil {
		return fmt.Errorf("failed to retrieve namespace auth mounts: %w", err)
	}

	for _, me := range authMountEntries {
		err := ns.core.disableCredentialInternal(nsCtx, me.Path, updateStorage)
		if err != nil {
			if errors.Is(err, errNoMatchingMount) {
				continue
			}

			return fmt.Errorf("failed to unmount namespace auth mount (%v): %w", me.Path, err)
		}
	}

	// clear mounts
	ns.core.mountsLock.RLock()
	mountEntries, err := ns.core.mounts.FindAllNamespaceMounts(nsCtx)
	ns.core.mountsLock.RUnlock()
	if err != nil {
		return fmt.Errorf("failed to retrieve namespace secret mounts: %w", err)
	}

	for _, me := range mountEntries {
		err := ns.core.unmountInternal(nsCtx, me.Path, updateStorage)
		if err != nil {
			if errors.Is(err, errNoMatchingMount) {
				continue
			}

			return fmt.Errorf("failed to unmount namespace secret mount (%v): %w", me.Path, err)
		}
	}

	// clear identity store
	if err := ns.core.identityStore.RemoveNamespaceView(entry); err != nil {
		return fmt.Errorf("failed to clean identity store: %w", err)
	}

	// clear login mfa
	if err := ns.core.loginMFABackend.CleanupNamespace(nsCtx, entry, updateStorage); err != nil {
		return fmt.Errorf("failed to cleanup mfa login configs: %w", err)
	}

	if updateStorage {
		// clear quotas
		if err := ns.core.quotaManager.HandleNamespaceDeletion(nsCtx, entry.Path); err != nil {
			return fmt.Errorf("failed to update quotas after deleting namespace: %w", err)
		}

		// clear locked users entries
		if _, err := ns.core.runLockedUserEntryUpdatesForNamespace(nsCtx, entry, true); err != nil {
			return fmt.Errorf("failed to clean up locked user entries: %w", err)
		}

		// clear any remaining storage; while ideally this would not occur, it
		// gives us now a signal if it did (debug entries) and additionally
		// gives us a clear path to remediate.
		//
		// This is in contrast to the current method where storage entries would
		// be silently left lying around.
		view := ns.core.NamespaceView(entry)
		if err := logical.ScanViewPaginated(nsCtx, view, ns.logger, logical.DefaultScanViewPageLimit, func(page int, index int, path string) (cont bool, err error) {
			if err := view.Delete(nsCtx, path); err != nil {
				return false, fmt.Errorf("failed removing entry: %w", err)
			}

			ns.logger.Debug("bug: removing entry remaining in namespace storage after all mounts were removed", "namespace", entry.Path, "path", path)
			return true, nil
		}); err != nil {
			return fmt.Errorf("failed to clear namespace view: %w", err)
		}
	}

	return nil
}

func (ns *NamespaceStore) clearNamespacePolicies(ctx context.Context, namespace *namespace.Namespace, physicalDeletion bool) error {
	policiesToClear, err := ns.core.policyStore.ListPolicies(ctx, policy.TypeACL, false)
	if err != nil {
		ns.logger.Error("failed to retrieve namespace policies", "namespace", namespace.Path, "error", err.Error())
		return err
	}

	for _, pol := range policiesToClear {
		if physicalDeletion {
			if err := ns.core.policyStore.DeletePolicyForce(ctx, pol, policy.TypeACL); err != nil {
				ns.logger.Error(fmt.Sprintf("failed to delete policy %q", pol), "namespace", namespace.Path, "error", err.Error())
				return err
			}
		} else {
			if err := ns.core.policyStore.Invalidate(ctx, pol, policy.TypeACL); err != nil {
				ns.logger.Error(fmt.Sprintf("failed to invalidate policy %q", pol), "namespace", namespace.Path, "error", err.Error())
				return err
			}
		}
	}
	return nil
}

// wipeStorageTree recursively wipes the storage of the passed namespace and all
// of its children via depth-first traversal.
func (ns *NamespaceStore) wipeStorageTree(ctx context.Context, root *namespace.Namespace) error {
	// The queue of namespaces to delete, by UUID.
	queue := []string{root.UUID}
	// This keeps track of namespaces that we've checked for children already.
	checked := make(map[string]struct{})

	for len(queue) != 0 {
		uuid := queue[len(queue)-1]

		view := logical.NewStorageView(
			ns.storage,
			path.Join(barrier.NamespacePrefix, uuid)+"/",
		)

		// Check this namespace for children if we haven't.
		if _, ok := checked[uuid]; !ok {
			checked[uuid] = struct{}{}
			// Find any child namespaces.
			if err := logical.HandleListPage(
				ctx, view, namespaceStoreSubPath,
				logical.DefaultScanViewPageLimit, nil,
				func(_ int, entries []string) (bool, error) {
					queue = append(queue, entries...)
					return true, nil
				},
			); err != nil {
				return fmt.Errorf("failed to list child namespaces for %q: %w", uuid, err)
			}
			continue
		}

		// Pop off the queue.
		queue = queue[:len(queue)-1]
		delete(checked, uuid)

		// Then wipe the namespace.
		if err := logical.ScanViewPaginated(
			ctx, view, ns.logger,
			logical.DefaultScanViewPageLimit,
			func(page int, index int, path string) (bool, error) {
				err := view.Delete(ctx, path)
				return err == nil, err
			},
		); err != nil {
			return fmt.Errorf("failed to clear namespace view for %q: %w", uuid, err)
		}
	}

	return nil
}

// ResolveNamespaceFromRequest resolves a namespace from the 'X-Vault-Namespace'
// header combined with the request path, returning the namespace and the
// "trimmed" request path devoid of any namespace components.
func (ns *NamespaceStore) ResolveNamespaceFromRequest(nsHeader, reqPath string) (*namespace.Namespace, string) {
	nsHeader = namespace.Canonicalize(nsHeader)

	// Re-route a header that's literally "root" to the root namespace by
	// clearing it.
	if nsHeader == "root/" {
		nsHeader = ""
	}

	// Naively stack header ahead of request path.
	reqPath = nsHeader + reqPath

	// Find namespace that matches the longest prefix of reqPath.
	ns.lock.RLock()
	_, resolvedNs, trimmedPath := ns.namespacesByPath.LongestPrefix(reqPath)
	resolvedNs.Tainted = resolvedNs.Tainted || ns.creationDeletionMap[resolvedNs.UUID]
	ns.lock.RUnlock()

	// Ensure that entire header was matched, so unmatched paths don't leak
	// into the request path.
	if !strings.HasPrefix(resolvedNs.Path, nsHeader) {
		return nil, ""
	}

	return resolvedNs, trimmedPath
}

// GetLockingNamespace walks the namespace tree structure looking for
// a locked namespace, starting from one of the root children,
// ending at the namespace provided as a argument to the function.
func (ns *NamespaceStore) GetLockingNamespace(n *namespace.Namespace) *namespace.Namespace {
	ns.lock.RLock()
	defer ns.lock.RUnlock()

	return ns.getLockingNamespace(n)
}

func (ns *NamespaceStore) getLockingNamespace(n *namespace.Namespace) *namespace.Namespace {
	var lockedNS *namespace.Namespace
	ns.namespacesByPath.WalkPath(n.Path, func(curNS *namespace.Namespace) bool {
		if curNS.Locked {
			lockedNS = curNS
			return true
		}
		return false
	})
	if lockedNS != nil {
		return lockedNS.Clone(false)
	}

	return nil
}

// UnlockNamespace attempts to unlock the namespace with provided namespace path.
func (ns *NamespaceStore) UnlockNamespace(ctx context.Context, unlockKey, path string) error {
	defer metrics.MeasureSince([]string{"namespace", "unlock_namespace"}, time.Now())

	unlock, err := ns.lockWithInvalidation(ctx, true)
	if err != nil {
		return err
	}

	defer func() {
		if unlock != nil {
			unlock()
		}
	}()

	namespaceToUnlock, err := ns.getNamespaceByPathLocked(ctx, path, true)
	if err != nil {
		return err
	}

	if namespaceToUnlock == nil {
		return errors.New("requested namespace does not exist")
	}

	if namespaceToUnlock.ID == namespace.RootNamespaceID {
		return errors.New("root namespace cannot be locked/unlocked")
	}

	if !namespaceToUnlock.Locked {
		return fmt.Errorf("namespace %q is not locked", namespaceToUnlock.Path)
	}

	lockingNamespace := ns.getLockingNamespace(namespaceToUnlock)
	if lockingNamespace.ID != namespaceToUnlock.ID {
		return fmt.Errorf("cannot unlock %q with namespace %q being locked", namespaceToUnlock.Path, lockingNamespace.Path)
	}

	// verify lock or skip when provided unlock key is empty
	// (meaning namespace is unlocked using root capability)
	if unlockKey != "" &&
		subtle.ConstantTimeCompare([]byte(namespaceToUnlock.UnlockKey), []byte(unlockKey)) != 1 {
		return errors.New("incorrect unlock key")
	}

	namespaceToUnlock.Locked = false
	namespaceToUnlock.UnlockKey = ""

	parentPath, _ := namespaceToUnlock.ParentPath()
	parentNs := ns.namespacesByPath.Get(parentPath)
	if parentNs == nil {
		return fmt.Errorf("namespace %q has no parent", namespaceToUnlock.Path)
	}
	parentCtx := namespace.ContextWithNamespace(ctx, parentNs)

	// setNamespaceLocked now handles unlocking.
	unlock = nil
	if _, err = ns.setNamespaceLocked(parentCtx, namespaceToUnlock, nil); err != nil {
		return fmt.Errorf("unable to save unlocked namespace %q", namespaceToUnlock.Path)
	}
	return nil
}

// LockNamespace attempts to lock the namespace with provided path.
func (ns *NamespaceStore) LockNamespace(ctx context.Context, path string) (string, error) {
	defer metrics.MeasureSince([]string{"namespace", "lock_namespace"}, time.Now())

	unlock, err := ns.lockWithInvalidation(ctx, true)
	if err != nil {
		return "", err
	}

	defer func() {
		if unlock != nil {
			unlock()
		}
	}()

	namespaceToLock, err := ns.getNamespaceByPathLocked(ctx, path, false)
	if err != nil {
		return "", err
	}

	if namespaceToLock == nil {
		return "", errors.New("requested namespace does not exist")
	}

	if namespaceToLock.ID == namespace.RootNamespaceID {
		return "", errors.New("root namespace cannot be locked/unlocked")
	}

	lockedNamespace := ns.getLockingNamespace(namespaceToLock)
	if lockedNamespace != nil && lockedNamespace.ID == namespaceToLock.ID {
		return "", fmt.Errorf("cannot lock namespace %q: is already locked", namespaceToLock.Path)
	} else if lockedNamespace != nil {
		return "", fmt.Errorf("cannot lock namespace %q: ancestor namespace %q is already locked", namespaceToLock.Path, lockedNamespace.Path)
	}

	// create lock
	lockKey, err := base62.Random(24)
	if err != nil {
		return "", fmt.Errorf("unable to generate namespace lock key: %w", err)
	}

	namespaceToLock.Locked = true
	namespaceToLock.UnlockKey = lockKey

	parentPath, _ := namespaceToLock.ParentPath()
	parentNs := ns.namespacesByPath.Get(parentPath)
	if parentNs == nil {
		return "", fmt.Errorf("namespace %q has no parent", namespaceToLock.Path)
	}
	parentCtx := namespace.ContextWithNamespace(ctx, parentNs)

	// setNamespaceLocked now handles unlocking.
	unlock = nil
	if _, err = ns.setNamespaceLocked(parentCtx, namespaceToLock, nil); err != nil {
		return "", fmt.Errorf("unable to save locked namespace %q", namespaceToLock.Path)
	}

	return lockKey, nil
}

// NamespaceByStoragePath parses an absolute storage path and returns the
// matching namespace that the path belongs to.
func (c *Core) NamespaceByStoragePath(ctx context.Context, path string) (*namespace.Namespace, string, error) {
	rest, ok := strings.CutPrefix(path, barrier.NamespacePrefix)
	if !ok || rest == "" {
		return namespace.RootNamespace, path, nil
	}

	uuid, rest, ok := strings.Cut(rest, "/")
	if !ok {
		return namespace.RootNamespace, path, nil
	}

	ns, err := c.namespaceStore.GetNamespace(ctx, uuid)
	if err != nil {
		return nil, path, err
	}

	return ns, rest, nil
}

// namespaceDeletionJob is used with NamespaceStore.deletionDispatcher to
// gradually remove items from the namespace store.
type namespaceDeletionJob struct {
	store   *NamespaceStore
	parent  *namespace.Namespace
	target  *namespace.Namespace
	cleanup func(ctx context.Context) error
}

func (j *namespaceDeletionJob) Execute() error {
	// Clearing needs to happen without holding the namespace lock.
	ctx := namespace.ContextWithNamespace(j.store.creationDeletionJobContext, j.target)
	err := j.cleanup(ctx)

	j.store.lock.Lock()
	defer j.store.lock.Unlock()

	// Make sure this happens _before_ the unlock.
	defer delete(j.store.creationDeletionMap, j.target.UUID)

	// If we failed to clear any resources, stop here and don't delete the namespace.
	if err != nil {
		return fmt.Errorf("failed clearing namespace resources: %w", err)
	}

	// Remove the namespace's storage entry:
	view := NamespaceScopedView(j.store.storage, j.parent).SubView(namespaceStoreSubPath)
	if err := view.Delete(ctx, j.target.UUID); err != nil {
		return fmt.Errorf("failed to delete namespace storage entry: %w", err)
	}

	// Finally, remove entries from memory:
	if err := j.store.namespacesByPath.Delete(j.target.Path); err != nil {
		return fmt.Errorf("failed to delete namespace entry in namespace tree: %w", err)
	}
	delete(j.store.namespacesByUUID, j.target.UUID)
	delete(j.store.namespacesByAccessor, j.target.ID)
	j.store.core.sealManager.RemoveNamespace(j.target)

	return nil
}

func (j *namespaceDeletionJob) OnFailure(err error) {
	j.store.logger.Error("failed to handle namespace deletion; job may be retried", "namespace", j.target.Path, "ns_uuid", j.target.UUID, "error", err.Error())
}

// namespaceCreationFailureJob is used with NamespaceStore.setNamespaceLocked
// to gracefully handle long-lived deletion.
type namespaceCreationFailureJob struct {
	store  *NamespaceStore
	parent *namespace.Namespace
	target *namespace.Namespace
}

func (ns *NamespaceStore) newNamespaceCreationFailureJob(parent *namespace.Namespace, target *namespace.Namespace) fairshare.Job {
	return &namespaceCreationFailureJob{
		store:  ns,
		parent: parent,
		target: target,
	}
}

func (j *namespaceCreationFailureJob) Execute() error {
	// Handle in-memory mount table entries that we should also clean
	// up.
	nsCtx := namespace.ContextWithNamespace(j.store.creationDeletionJobContext, j.target)
	cleanupSuccess := j.store.undoCreateMounts(nsCtx, j.target)

	var retErr error

	// Clear the view corresponding with the namespace for
	// completeness.
	view := NamespaceScopedView(j.store.core.barrier, j.target)
	if err := logical.ClearViewWithLogging(j.store.creationDeletionJobContext, view, j.store.logger); err != nil {
		retErr = fmt.Errorf("failed to remove remaining namespace storage: %w", err)
		cleanupSuccess = false
	}

	// Now grab the lock again to handle updating the namespace store.
	j.store.lock.Lock()
	defer j.store.lock.Unlock()

	// Cleanup finished either way.
	delete(j.store.creationDeletionMap, j.target.UUID)

	// Only perform cleanup from in-memory and stored contexts if we had
	// success removing entries. Otherwise, we'll treat this as a failed
	// deletion.
	j.target.Tainted = true

	if cleanupSuccess {
		// When cleanup succeeds and the namespace did not exist, we should back
		// out the entry from our in-memory and stored versions.
		if err := j.store.namespacesByPath.Delete(j.target.Path); err != nil {
			err = fmt.Errorf("failed to remove namespace from path manager: %w", err)
			retErr = multierror.Append(retErr, err)
		}

		delete(j.store.namespacesByUUID, j.target.UUID)
		delete(j.store.namespacesByAccessor, j.target.ID)

		j.store.core.sealManager.RemoveNamespace(j.target)

		nsView := NamespaceScopedView(j.store.storage, j.parent).SubView(namespaceStoreSubPath)
		if err := nsView.Delete(nsCtx, j.target.UUID); err != nil {
			err = fmt.Errorf("failed to remove created namespace storage entry on failure: %w", err)
			retErr = multierror.Append(retErr, err)
		}
	}

	return retErr
}

func (j *namespaceCreationFailureJob) OnFailure(err error) {
	j.store.logger.Error("failed to handle namespace deletion following failed creation; job may be retried via deletion of tainted namespace", "namespace", j.target.Path, "ns_uuid", j.target.UUID, "error", err.Error())
}
