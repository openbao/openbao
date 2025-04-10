// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
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
	namespaceStoreRoot = "core/namespaces/"

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
	}

	// Add namespaces from storage to our table. We can do this without
	// holding a lock as we've not returned ns to anyone yet.
	if err := ns.loadNamespacesLocked(ctx); err != nil {
		return nil, fmt.Errorf("error loading initial namespaces: %w", err)
	}

	return ns, nil
}

func (ns *NamespaceStore) checkInvalidation(ctx context.Context) error {
	if !ns.invalidated.Load() {
		return nil
	}

	ns.lock.Lock()
	defer ns.lock.Unlock()

	// Status might have changed
	if !ns.invalidated.Load() {
		return nil
	}

	if err := ns.loadNamespacesLocked(ctx); err != nil {
		return fmt.Errorf("error handling invalidation: %w", err)
	}

	ns.invalidated.Store(false)
	return nil
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

	if err := logical.WithTransaction(ctx, ns.storage, func(s logical.Storage) error {
		if err := logical.HandleListPage(s, namespaceStoreRoot, 100, func(page int, index int, entry string) (bool, error) {
			path := path.Join(namespaceStoreRoot, entry)

			item, err := s.Get(ctx, path)
			if err != nil {
				return false, fmt.Errorf("failed to fetch namespace %v (page %v / index %v): %w", path, page, index, err)
			}

			if item == nil {
				return false, fmt.Errorf("%v has an empty namespace definition (page %v / index %v)", path, page, index)
			}

			var namespace namespace.Namespace
			if err := item.DecodeJSON(&namespace); err != nil {
				return false, fmt.Errorf("failed to decode namespace %v (page %v / index %v): %w", path, page, index, err)
			}

			namespacesByPath.unsafeInsert(&namespace)
			namespacesByUUID[namespace.UUID] = &namespace
			namespacesByAccessor[namespace.ID] = &namespace

			return true, nil
		}, nil); err != nil {
			return err
		}

		return nil
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

	if err := ns.checkInvalidation(ctx); err != nil {
		return err
	}

	// Now grab write lock so that we can write to storage.
	ns.lock.Lock()
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
	entry := nsEntry.Clone()
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
	if err := logical.WithTransaction(ctx, ns.storage, func(s logical.Storage) error {
		storagePath := path.Join(namespaceStoreRoot, entry.UUID)
		item, err := logical.StorageEntryJSON(storagePath, &entry)
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
	nsCtx := namespace.ContextWithNamespace(ctx, entry.Clone())

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

	if err := ns.checkInvalidation(ctx); err != nil {
		return nil, err
	}

	ns.lock.RLock()
	defer ns.lock.RUnlock()

	item, ok := ns.namespacesByUUID[uuid]
	if !ok {
		return nil, nil
	}

	return item.Clone(), nil
}

// GetNamespaceByAccessor is used to fetch the namespace with the given accessor.
func (ns *NamespaceStore) GetNamespaceByAccessor(ctx context.Context, id string) (*namespace.Namespace, error) {
	defer metrics.MeasureSince([]string{"namespace", "get_namespace_by_accessor"}, time.Now())

	if err := ns.checkInvalidation(ctx); err != nil {
		return nil, err
	}

	ns.lock.RLock()
	defer ns.lock.RUnlock()

	item, ok := ns.namespacesByAccessor[id]
	if !ok {
		return nil, nil
	}

	return item.Clone(), nil
}

func (ns *NamespaceStore) GetNamespaceByLongestPrefix(ctx context.Context, path string) (*namespace.Namespace, string) {
	ctxNs, err := namespace.FromContext(ctx)
	if err != nil {
		ctxNs = namespace.RootNamespace
	}

	// e.g. needed for /sys/unseal, where the namespace store is not yet initialized
	if ns == nil {
		return ctxNs, path
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

	if err := ns.checkInvalidation(ctx); err != nil {
		return nil, err
	}

	ns.lock.RLock()
	defer ns.lock.RUnlock()

	return ns.getNamespaceByPathLocked(ctx, path)
}

func (ns *NamespaceStore) getNamespaceByPathLocked(ctx context.Context, path string) (*namespace.Namespace, error) {
	parent, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, err
	}
	path = namespace.Canonicalize(parent.Path + path)
	item := ns.namespacesByPath.Get(path)
	if item == nil {
		return nil, nil
	}

	return item.Clone(), nil
}

// ModifyNamespace is used to perform modifications to a namespace while
// holding a write lock to prevent other changes to namespaces from occurring
// at the same time.
func (ns *NamespaceStore) ModifyNamespaceByPath(ctx context.Context, path string, callback func(context.Context, *namespace.Namespace) (*namespace.Namespace, error)) (*namespace.Namespace, error) {
	defer metrics.MeasureSince([]string{"namespace", "modify_namespace"}, time.Now())

	if err := ns.checkInvalidation(ctx); err != nil {
		return nil, err
	}

	parent, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	path = namespace.Canonicalize(parent.Path + path)
	if path == "" {
		return nil, logical.CodedError(http.StatusBadRequest, "refusing to modify root namespace")
	}

	ns.lock.Lock()

	entry := ns.namespacesByPath.Get(path)
	if entry != nil {
		if entry.Tainted {
			ns.lock.Unlock()
			return nil, errors.New("namespace with that name exists and is currently tainted")
		}
		entry = entry.Clone()
	} else {
		entry = &namespace.Namespace{
			Path:           path,
			CustomMetadata: make(map[string]string),
		}
	}

	if callback != nil {
		entry, err = callback(ctx, entry)
		if err != nil {
			ns.lock.Unlock()
			return nil, err
		}
	}

	// setNamespaceLocked will unlock ns.lock
	if err := ns.setNamespaceLocked(ctx, entry); err != nil {
		return nil, err
	}

	return entry.Clone(), nil
}

// ListAllNamespaces lists all available namespaces, optionally including the
// root namespace.
func (ns *NamespaceStore) ListAllNamespaces(ctx context.Context, includeRoot bool) ([]*namespace.Namespace, error) {
	defer metrics.MeasureSince([]string{"namespace", "list_all_namespaces"}, time.Now())

	namespaces := make([]*namespace.Namespace, 0, len(ns.namespacesByUUID))
	for _, entry := range ns.namespacesByUUID {
		if !includeRoot && entry.ID == namespace.RootNamespaceID {
			continue
		}
		namespaces = append(namespaces, entry.Clone())
	}

	return namespaces, nil
}

// ListNamespaces is used to list namespaces below a parent namespace.
// Optionally it can include the parent namespace itself and/or include all
// decendents of the child namespaces.
func (ns *NamespaceStore) ListNamespaces(ctx context.Context, includeParent bool, recursive bool) ([]*namespace.Namespace, error) {
	defer metrics.MeasureSince([]string{"namespace", "list_namespace_entries"}, time.Now())

	if err := ns.checkInvalidation(ctx); err != nil {
		return nil, err
	}

	parent, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	ns.lock.RLock()
	defer ns.lock.RUnlock()

	return ns.namespacesByPath.List(parent.Path, includeParent, recursive)
}

// taintNamespace is used to taint the namespace designated to be deleted
func (ns *NamespaceStore) taintNamespace(ctx context.Context, namespaceToTaint *namespace.Namespace) error {
	// to be extra safe
	if namespaceToTaint.ID == namespace.RootNamespaceID {
		return errors.New("cannot taint root namespace")
	}

	if err := ns.checkInvalidation(ctx); err != nil {
		return err
	}

	// We've got to grab write lock because we modify the namespace tree structure
	ns.lock.Lock()
	defer ns.lock.Unlock()

	ns.namespacesByUUID[namespaceToTaint.UUID].Tainted = true
	ns.namespacesByUUID[namespaceToTaint.UUID].IsDeleting = true
	ns.namespacesByAccessor[namespaceToTaint.ID].Tainted = true
	ns.namespacesByAccessor[namespaceToTaint.ID].IsDeleting = true
	namespaceToTaint.Tainted = true
	namespaceToTaint.IsDeleting = true
	err := ns.namespacesByPath.Insert(namespaceToTaint)
	if err != nil {
		return fmt.Errorf("failed to modify namespace tree: %w", err)
	}

	nsCopy := namespaceToTaint.Clone()
	if err := ns.writeNamespace(ctx, nsCopy); err != nil {
		return fmt.Errorf("failed to persist namespace taint: %w", err)
	}

	return nil
}

// DeleteNamespace is used to delete the named namespace
func (ns *NamespaceStore) DeleteNamespace(ctx context.Context, uuid string) (string, error) {
	defer metrics.MeasureSince([]string{"namespace", "delete_namespace"}, time.Now())

	if err := ns.checkInvalidation(ctx); err != nil {
		return "", err
	}

	namespaceToDelete, ok := ns.namespacesByUUID[uuid]
	if !ok {
		return "", nil
	}

	if namespaceToDelete.Tainted && namespaceToDelete.IsDeleting {
		return "in-progress", nil
	}

	if namespaceToDelete.ID == namespace.RootNamespaceID {
		return "", errors.New("unable to delete root namespace")
	}

	nsCtx := namespace.ContextWithNamespace(ctx, namespaceToDelete)

	// checking whether namespace has child namespaces
	childNS, err := ns.ListNamespaces(nsCtx, false, false)
	if err != nil {
		return "", err
	}

	if len(childNS) > 0 {
		return "", fmt.Errorf("cannot delete namespace (%q) containing child namespaces", namespaceToDelete.Path)
	}

	if !namespaceToDelete.Tainted {
		// taint the namespace
		err = ns.taintNamespace(nsCtx, namespaceToDelete)
	}

	quitCtx := namespace.ContextWithNamespace(ns.core.activeContext, namespaceToDelete)
	go clearNamespaceResources(quitCtx, ns, namespaceToDelete)

	return "in-progress", nil
}

func clearNamespaceResources(ctx context.Context, ns *NamespaceStore, namespaceToDelete *namespace.Namespace) {
	// clear ACL policies
	policiesToClear, err := ns.core.policyStore.ListPolicies(ctx, PolicyTypeACL, false)
	if err != nil {
		ns.logger.Error("failed to retrieve namespace policies", "namespace", namespaceToDelete.Path, "error", err.Error())
		return
	}

	for _, policy := range policiesToClear {
		err := ns.core.policyStore.deletePolicyForce(ctx, policy, PolicyTypeACL)
		if err != nil {
			ns.logger.Error(fmt.Sprintf("failed to delete policy %q", policy), "namespace", namespaceToDelete.Path, "error", err.Error())
			return
		}
	}

	// clear auth mounts
	authMountEntries, err := ns.core.auth.findAllNamespaceMounts(ctx)
	if err != nil {
		ns.logger.Error("failed to retrieve namespace credentials", "namespace", namespaceToDelete.Path, "error", err.Error())
		return
	}

	for _, me := range authMountEntries {
		err := ns.core.disableCredentialInternal(ctx, me.Path, true)
		if err != nil {
			ns.logger.Error(fmt.Sprintf("failed to unmount %q", me.Path), "namespace", namespaceToDelete.Path, "error", err.Error())
			return
		}
	}

	// clear mounts
	mountEntries, err := ns.core.mounts.findAllNamespaceMounts(ctx)
	if err != nil {
		ns.logger.Error("failed to retrieve namespace mounts", "namespace", namespaceToDelete.Path, "error", err.Error())
		return
	}

	for _, me := range mountEntries {
		err := ns.core.unmountInternal(ctx, me.Path, true)
		if err != nil {
			ns.logger.Error(fmt.Sprintf("failed to unmount %q", me.Path), "namespace", namespaceToDelete.Path, "error", err.Error())
			return
		}
	}

	// Now grab write lock so that we can write to storage.
	ns.lock.Lock()
	defer ns.lock.Unlock()

	err = ns.namespacesByPath.Delete(namespaceToDelete.Path)
	if err != nil {
		ns.logger.Error("failed to delete namespace entry in namespace tree", "namespace", namespaceToDelete.Path, "error", err.Error())
		return
	}
	delete(ns.namespacesByUUID, namespaceToDelete.UUID)
	delete(ns.namespacesByAccessor, namespaceToDelete.ID)

	err = logical.WithTransaction(ctx, ns.storage, func(s logical.Storage) error {
		storagePath := path.Join(namespaceStoreRoot, namespaceToDelete.UUID)
		return s.Delete(ctx, storagePath)
	})
	if err != nil {
		ns.logger.Error("failed to delete namespace storage", "namespace", namespaceToDelete.Path, "error", err.Error())
	}

	return
}

// copyNamespaceFromCtx copies the namespace from fromCtx into intoCtx, ensuring that the namespace exists.
func (ns *NamespaceStore) copyNamespaceFromCtx(intoCtx context.Context, fromCtx context.Context) (context.Context, *namespace.Namespace, error) {
	rawNs, err := namespace.FromContext(fromCtx)
	if err != nil {
		return intoCtx, nil, fmt.Errorf("could not parse namespace from http context: %w", err)
	}

	// in practice intoCtx should already have the root namespace set, but let's make it explicit that this is necessary here
	entry, err := ns.GetNamespaceByPath(namespace.RootContext(intoCtx), rawNs.Path)
	if err != nil {
		return intoCtx, nil, fmt.Errorf("could not fetch namespace by path: %w", err)
	}

	if entry == nil {
		return intoCtx, nil, fmt.Errorf("requested namespace was not found")
	}

	intoCtx = namespace.ContextWithNamespace(intoCtx, entry)
	return intoCtx, entry, nil
}

// ResolveNamespaceFromRequest merges the given base context with the
// namespace from httpCtx, combining it with any namespaces within the
// request path itself. We remove the prefix from the path, if given,
// because logic elsewhere in vault/ combines the namespace with the
// path again.
func (ns *NamespaceStore) ResolveNamespaceFromRequest(baseCtx context.Context, httpCtx context.Context, reqPath string) (context.Context, *namespace.Namespace, string, error) {
	// We stack the namespace context ahead of any namespace in path.
	newCtx, parentNs, err := ns.copyNamespaceFromCtx(baseCtx, httpCtx)
	if err != nil {
		return newCtx, parentNs, reqPath, err
	}

	// prepend namespace path from request context
	reqPath = parentNs.Path + reqPath
	// find namespace that matches the longest prefix of reqPath
	nsPath, parentNs, _ := ns.namespacesByPath.LongestPrefix(reqPath)
	// trim matched prefix from reqPath
	reqPath = reqPath[len(nsPath):]

	// TODO(ascheel): Fix global uses of comparison by pointer.
	if parentNs.ID == namespace.RootNamespaceID {
		parentNs = namespace.RootNamespace
	}

	finalCtx := namespace.ContextWithNamespace(baseCtx, parentNs)
	return finalCtx, parentNs, reqPath, nil
}
