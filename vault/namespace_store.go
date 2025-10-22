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

	"github.com/armon/go-metrics"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-secure-stdlib/base62"
	uuid "github.com/hashicorp/go-uuid"
	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/sdk/v2/logical"
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

	// namespaceBarrierPrefix is the prefix to the UUID of a namespaces
	// used in the barrier view for the namespace-owned backends.
	namespaceBarrierPrefix = "namespaces/"
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

	// deletionMap tracks actively deleted namespaces, enabling us to
	// retry the deletion process if the namespace is tainted, but isn't
	// present in the said map.
	deletionMap           map[string]bool
	deletionJobGroup      sync.WaitGroup
	deletionJobContext    context.Context
	deletionJobCancelFunc context.CancelFunc

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
		deletionMap:          make(map[string]bool),
	}

	ns.deletionJobContext, ns.deletionJobCancelFunc = context.WithCancel(core.activeContext)

	// Add namespaces from storage to our table. We can do this without
	// holding a lock as we've not returned ns to anyone yet.
	if err := ns.loadNamespacesLocked(ctx); err != nil {
		return nil, fmt.Errorf("error loading initial namespaces: %w", err)
	}

	return ns, nil
}

// NamespaceView uses given barrier and namespace to return back a view scoped to that namespace.
func NamespaceView(barrier logical.Storage, ns *namespace.Namespace) BarrierView {
	if ns.ID == namespace.RootNamespaceID {
		return NewBarrierView(barrier, "")
	}

	return NewBarrierView(barrier, path.Join(namespaceBarrierPrefix, ns.UUID)+"/")
}

// cancelNamespaceDeletion cancels goroutine that runs namespace deletion.
func (c *Core) cancelNamespaceDeletion() {
	if c.namespaceStore == nil {
		return
	}
	c.namespaceStore.deletionJobCancelFunc()
	c.namespaceStore.deletionJobGroup.Wait()
}

// checkInvalidation checks if the store has been marked as invalidated, and if
// so, reloads namespaces from disk.
// checkInvalidation returns true if it acquired a write-lock as part of the
// store reload and is handing the lock over to the caller.
// If checkInvalidation returns an error, it never keeps a write lock for the
// caller, so there is no need to check the bool before propagating an error.
func (ns *NamespaceStore) checkInvalidation(ctx context.Context) (bool, error) {
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

	loadingCallback := func(namespace *namespace.Namespace) error {
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
		rootStoreView := NewBarrierView(s, namespaceStoreSubPath)
		return ns.loadNamespacesRecursive(ctx, s, rootStoreView, loadingCallback)
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
	return logical.HandleListPage(ctx, view, "", 100, func(page int, index int, entry string) (bool, error) {
		item, err := view.Get(ctx, entry)
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

		childView := NamespaceView(barrier, &namespace).SubView(namespaceStoreSubPath)
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

// invalidate will be used in the future for implementing read replica nodes
//
//nolint:unused
func (ns *NamespaceStore) invalidate(ctx context.Context, path string) error {
	// We want to keep invalidation proper fast (as it holds up replication),
	// so defer invalidation to the next load.
	//
	// TODO(ascheel): handle individual entry invalidation correctly. We'll
	// need to handle child namespace invalidation as well. sync.Map could be
	// used instead in the future alongside the actual boolean.
	ns.invalidated.Store(true)
	return nil
}

// SetNamespace is used to create or update a given namespace
func (ns *NamespaceStore) SetNamespace(ctx context.Context, namespace *namespace.Namespace) error {
	defer metrics.MeasureSince([]string{"namespace", "set_namespace"}, time.Now())

	if _, err := ns.lockWithInvalidation(ctx, true); err != nil {
		return err
	}

	return ns.setNamespaceLocked(ctx, namespace)
}

// setNamespaceLocked must be called while holding a write lock over the
// NamespaceStore. This function unlocks the lock once finished.
func (ns *NamespaceStore) setNamespaceLocked(ctx context.Context, nsEntry *namespace.Namespace) error {
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
		return logical.CodedError(http.StatusBadRequest, err.Error())
	}

	// Validate that we have a parent namespace.
	parent, err := namespace.FromContext(ctx)
	if err != nil {
		return fmt.Errorf("error loading parent namespace from context: %w", err)
	}

	var exists bool
	if entry.UUID == "" {
		id, err := ns.assignIdentifier(entry.Path)
		if err != nil {
			return err
		}

		entry.ID = id
		entry.UUID, err = uuid.GenerateUUID()
		if err != nil {
			return err
		}
	} else {
		var existing *namespace.Namespace
		existing, exists = ns.namespacesByUUID[entry.UUID]
		if !exists {
			return errors.New("trying to update a non-existent namespace")
		}

		if existing.ID != entry.ID {
			return errors.New("accessor ID does not match")
		}

		if existing.Path != entry.Path {
			return errors.New("unable to remount namespace at new path")
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
				return errors.New("namespace path lacks parent as a prefix")
			}

			path = namespace.Canonicalize(parent.TrimmedPath(entry.Path))
		}

		conflict := ns.core.router.matchingPrefixInternal(ctx, path)
		if conflict != "" {
			return fmt.Errorf("new namespace conflicts with existing mount: %v", conflict)
		}
	}

	if err := ns.writeNamespace(ctx, entry); err != nil {
		return fmt.Errorf("failed to persist namespace: %w", err)
	}
	ns.namespacesByPath.Insert(entry)
	ns.namespacesByUUID[entry.UUID] = entry
	ns.namespacesByAccessor[entry.ID] = entry

	// Since the write succeeded, copy back any potentially changed values.
	nsEntry.UUID = entry.UUID
	nsEntry.ID = entry.ID
	nsEntry.Path = entry.Path

	if !exists {
		// unlock before initializeNamespace since that will re-acquire the lock
		ns.lock.Unlock()
		unlocked = true

		// Create sys/, token/ mounts and policies for the new namespace.
		if err := ns.initializeNamespace(ctx, entry); err != nil {
			return err
		}
	}

	return nil
}

func (ns *NamespaceStore) writeNamespace(ctx context.Context, entry *namespace.Namespace) error {
	parent, err := namespace.FromContext(ctx)
	if err != nil {
		return err
	}

	view := NamespaceView(ns.storage, parent).SubView(namespaceStoreSubPath)
	if err := logical.WithTransaction(ctx, view, func(s logical.Storage) error {
		item, err := logical.StorageEntryJSON(entry.UUID, &entry)
		if err != nil {
			return fmt.Errorf("error marshalling storage entry: %w", err)
		}

		if err := s.Put(ctx, item); err != nil {
			return err
		}

		return nil
	}); err != nil {
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

	if err := ns.initializeNamespacePolicies(nsCtx); err != nil {
		return err
	}

	if err := ns.createMounts(nsCtx); err != nil {
		return err
	}

	return nil
}

// initializeNamespacePolicies loads the default policies for the namespace store.
func (ns *NamespaceStore) initializeNamespacePolicies(ctx context.Context) error {
	if err := ns.core.policyStore.loadDefaultPolicies(ctx); err != nil {
		return fmt.Errorf("error creating default policies: %w", err)
	}
	return nil
}

// createMounts handles creation of sys/ and token/ mounts for this new
// namespace.
func (ns *NamespaceStore) createMounts(ctx context.Context) error {
	mounts, err := ns.core.requiredMountTable(ctx)
	if err != nil {
		return fmt.Errorf("for new namespace: %w", err)
	}

	for _, mount := range mounts.Entries {
		if err := ns.core.mountInternal(ctx, mount, MountTableUpdateStorage); err != nil {
			return err
		}
	}

	credentials, err := ns.core.defaultAuthTable(ctx)
	if err != nil {
		return fmt.Errorf("for new namespace: %w", err)
	}

	for _, credential := range credentials.Entries {
		if err := ns.core.enableCredentialInternal(ctx, credential, MountTableUpdateStorage); err != nil {
			return err
		}
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

	return item.Clone(false), nil
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

	return item.Clone(false), nil
}

func (ns *NamespaceStore) GetNamespaceByLongestPrefix(ctx context.Context, path string) (*namespace.Namespace, string) {
	ctxNs, err := namespace.FromContext(ctx)
	if err != nil {
		ctxNs = namespace.RootNamespace
	}

	combinedPath := ctxNs.Path + path
	ns.lock.RLock()
	prefix, entry, _ := ns.namespacesByPath.LongestPrefix(combinedPath)
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

	return item.Clone(withUnlockKey), nil
}

// ModifyNamespace is used to perform modifications to a namespace while
// holding a write lock to prevent other changes to namespaces from occurring
// at the same time.
func (ns *NamespaceStore) ModifyNamespaceByPath(ctx context.Context, path string, callback func(context.Context, *namespace.Namespace) (*namespace.Namespace, error)) (*namespace.Namespace, error) {
	defer metrics.MeasureSince([]string{"namespace", "modify_namespace"}, time.Now())

	parent, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	path = namespace.Canonicalize(parent.Path + path)
	if path == "" {
		return nil, logical.CodedError(http.StatusBadRequest, "refusing to modify root namespace")
	}

	unlock, err := ns.lockWithInvalidation(ctx, true)
	if err != nil {
		return nil, err
	}

	entry := ns.namespacesByPath.Get(path)
	if entry != nil {
		if entry.Tainted {
			unlock()
			return nil, errors.New("namespace with that name exists and is currently tainted")
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
			return nil, err
		}

		// ModifyNamespaceByPath can never modify lock status.
		entry.UnlockKey = unlockKey
	}

	// setNamespaceLocked will unlock ns.lock
	if err := ns.setNamespaceLocked(ctx, entry); err != nil {
		return nil, err
	}

	return entry.Clone(false), nil
}

// ListAllNamespaces lists all available namespaces, optionally including the
// root namespace.
func (ns *NamespaceStore) ListAllNamespaces(ctx context.Context, includeRoot bool) ([]*namespace.Namespace, error) {
	defer metrics.MeasureSince([]string{"namespace", "list_all_namespaces"}, time.Now())

	unlock, err := ns.lockWithInvalidation(ctx, false)
	if err != nil {
		return nil, err
	}
	defer unlock()

	namespaces := make([]*namespace.Namespace, 0, len(ns.namespacesByUUID))
	for _, entry := range ns.namespacesByUUID {
		if !includeRoot && entry.ID == namespace.RootNamespaceID {
			continue
		}
		namespaces = append(namespaces, entry.Clone(false))
	}

	return namespaces, nil
}

// ListNamespaces is used to list namespaces below a parent namespace.
// Optionally it can include the parent namespace itself and/or include all
// descendants of the child namespaces.
func (ns *NamespaceStore) ListNamespaces(ctx context.Context, includeParent bool, recursive bool) ([]*namespace.Namespace, error) {
	defer metrics.MeasureSince([]string{"namespace", "list_namespace_entries"}, time.Now())

	parent, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	unlock, err := ns.lockWithInvalidation(ctx, false)
	if err != nil {
		return nil, err
	}
	defer unlock()

	return ns.namespacesByPath.List(parent.Path, includeParent, recursive)
}

// taintNamespace is used to taint the namespace designated to be deleted
func (ns *NamespaceStore) taintNamespace(ctx context.Context, namespaceToTaint *namespace.Namespace) error {
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
	if err := ns.writeNamespace(ctx, nsCopy); err != nil {
		return fmt.Errorf("failed to persist namespace taint: %w", err)
	}

	return nil
}

// DeleteNamespace is used to delete the named namespace
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

	isNamespaceDeleting := ns.deletionMap[namespaceToDelete.UUID]
	if namespaceToDelete.Tainted && isNamespaceDeleting {
		return "in-progress", nil
	}

	if namespaceToDelete.ID == namespace.RootNamespaceID {
		return "", errors.New("unable to delete root namespace")
	}

	// checking whether namespace has child namespaces
	childNS, err := ns.namespacesByPath.List(namespaceToDelete.Path, false, false)
	if err != nil {
		return "", err
	}

	if len(childNS) > 0 {
		return "", fmt.Errorf("cannot delete namespace (%q) containing child namespaces", namespaceToDelete.Path)
	}

	if !namespaceToDelete.Tainted {
		// taint the namespace
		err = ns.taintNamespace(ctx, namespaceToDelete)
	}

	parent, err := namespace.FromContext(ctx)
	if err != nil {
		return "", fmt.Errorf("error loading parent namespace from context: %w", err)
	}

	ns.deletionJobGroup.Add(1)
	ns.deletionMap[namespaceToDelete.UUID] = true

	go func() {
		ctx := namespace.ContextWithNamespace(ns.deletionJobContext, namespaceToDelete)
		defer ns.deletionJobGroup.Done()
		ok := ns.clearNamespaceResources(ctx, namespaceToDelete)

		ns.lock.Lock()
		defer ns.lock.Unlock()

		// Make sure this happens _before_ the unlock.
		defer delete(ns.deletionMap, namespaceToDelete.UUID)

		// If we failed to clear any resources, stop here and don't delete the namespace.
		if !ok {
			return
		}

		err = ns.namespacesByPath.Delete(namespaceToDelete.Path)
		if err != nil {
			ns.logger.Error("failed to delete namespace entry in namespace tree", "namespace", namespaceToDelete.Path, "error", err.Error())
		}
		delete(ns.namespacesByUUID, namespaceToDelete.UUID)
		delete(ns.namespacesByAccessor, namespaceToDelete.ID)

		view := NamespaceView(ns.storage, parent).SubView(namespaceStoreSubPath)
		err = logical.WithTransaction(ctx, view, func(s logical.Storage) error {
			return s.Delete(ctx, namespaceToDelete.UUID)
		})
		if err != nil {
			ns.logger.Error("failed to delete namespace storage", "namespace", namespaceToDelete.Path, "error", err.Error())
		}
	}()

	return "in-progress", nil
}

func (ns *NamespaceStore) clearNamespaceResources(nsCtx context.Context, namespaceToDelete *namespace.Namespace) bool {
	// clear ACL policies
	policiesToClear, err := ns.core.policyStore.ListPolicies(nsCtx, PolicyTypeACL, false)
	if err != nil {
		ns.logger.Error("failed to retrieve namespace policies", "namespace", namespaceToDelete.Path, "error", err.Error())
		return false
	}

	for _, policy := range policiesToClear {
		err := ns.core.policyStore.deletePolicyForce(nsCtx, policy, PolicyTypeACL)
		if err != nil {
			ns.logger.Error(fmt.Sprintf("failed to delete policy %q", policy), "namespace", namespaceToDelete.Path, "error", err.Error())
			return false
		}
	}

	// clear auth mounts
	authMountEntries, err := ns.core.auth.findAllNamespaceMounts(nsCtx)
	if err != nil {
		ns.logger.Error("failed to retrieve namespace credentials", "namespace", namespaceToDelete.Path, "error", err.Error())
		return false
	}

	for _, me := range authMountEntries {
		err := ns.core.disableCredentialInternal(nsCtx, me.Path, true)
		if err != nil {
			ns.logger.Error(fmt.Sprintf("failed to unmount %q", me.Path), "namespace", namespaceToDelete.Path, "error", err.Error())
			return false
		}
	}

	// clear mounts
	mountEntries, err := ns.core.mounts.findAllNamespaceMounts(nsCtx)
	if err != nil {
		ns.logger.Error("failed to retrieve namespace mounts", "namespace", namespaceToDelete.Path, "error", err.Error())
		return false
	}

	for _, me := range mountEntries {
		err := ns.core.unmountInternal(nsCtx, me.Path, true)
		if err != nil {
			if errors.Is(err, errNoMatchingMount) {
				continue
			}
			ns.logger.Error(fmt.Sprintf("failed to unmount %q", me.Path), "namespace", namespaceToDelete.Path, "error", err.Error())
			return false
		}
	}

	// clear identity store
	if err := ns.core.identityStore.RemoveNamespaceView(namespaceToDelete); err != nil {
		ns.logger.Error("failed to clean identity store", "namespace", namespaceToDelete.Path, "error", err.Error())
		return false
	}

	// clear quotas
	err = ns.core.quotaManager.HandleNamespaceDeletion(nsCtx, namespaceToDelete.Path)
	if err != nil {
		ns.logger.Error("failed to update quotas after deleting namespace", "namespace", namespaceToDelete.Path, "error", err.Error())
		return false
	}

	// clear locked users entries
	_, err = ns.core.runLockedUserEntryUpdatesForNamespace(nsCtx, namespaceToDelete, true)
	if err != nil {
		ns.logger.Error("failed to clean up locked user entries", "namespace", namespaceToDelete.Path, "error", err.Error())
		return false
	}
	return true
}

// ResolveNamespaceFromRequest resolves a namespace from the 'X-Vault-Namespace'
// header combined with the request path, returning the namespace and the
// "trimmed" request path devoid of any namespace components.
func (ns *NamespaceStore) ResolveNamespaceFromRequest(nsHeader, reqPath string) (*namespace.Namespace, string) {
	nsHeader = namespace.Canonicalize(nsHeader)
	// Naively stack header ahead of request path.
	reqPath = nsHeader + reqPath
	// Find namespace that matches the longest prefix of reqPath.
	ns.lock.RLock()
	_, resolvedNs, trimmedPath := ns.namespacesByPath.LongestPrefix(reqPath)
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
	return ns.setNamespaceLocked(parentCtx, namespaceToUnlock)
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
	if err := ns.setNamespaceLocked(parentCtx, namespaceToLock); err != nil {
		return "", fmt.Errorf("unable to save locked namespace %q", namespaceToLock.Path)
	}

	return lockKey, nil
}
