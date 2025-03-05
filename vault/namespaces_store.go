// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"errors"
	"fmt"
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
	namespacesByPath     map[string]*NamespaceEntry
	namespacesByUUID     map[string]*NamespaceEntry
	namespacesByAccessor map[string]*NamespaceEntry

	// logger is the server logger copied over from core
	logger hclog.Logger
}

// NamespaceEntry is used to store a namespace. We wrap namespace.Namespace
// in case there is additional data we wish to store that isn't relevant to
// a namespace instance.
type NamespaceEntry struct {
	UUID      string               `json:"uuid"`
	Namespace *namespace.Namespace `json:"namespace"`
}

// Clone performs a deep copy of the given entry.
func (ne *NamespaceEntry) Clone() *NamespaceEntry {
	meta := make(map[string]string, len(ne.Namespace.CustomMetadata))
	for k, v := range ne.Namespace.CustomMetadata {
		meta[k] = v
	}
	return &NamespaceEntry{
		UUID: ne.UUID,
		Namespace: &namespace.Namespace{
			ID:             ne.Namespace.ID,
			Path:           ne.Namespace.Path,
			CustomMetadata: meta,
		},
	}
}

func (ne *NamespaceEntry) Validate() error {
	if ne.Namespace == nil {
		return errors.New("interior namespace object is nil")
	}

	return ne.Namespace.Validate()
}

func (ne *NamespaceEntry) View(barrier logical.Storage) BarrierView {
	if ne.Namespace.ID == namespace.RootNamespaceID {
		return NewBarrierView(barrier, "")
	}

	return NewBarrierView(barrier, path.Join(namespaceBarrierPrefix, ne.UUID)+"/")
}

// NewNamespaceStore creates a new NamespaceStore that is backed
// using a given view. It used used to durable store and manage named namespace.
func NewNamespaceStore(ctx context.Context, core *Core, logger hclog.Logger) (*NamespaceStore, error) {
	ns := &NamespaceStore{
		core:                 core,
		storage:              core.barrier,
		logger:               logger,
		namespacesByPath:     make(map[string]*NamespaceEntry),
		namespacesByUUID:     make(map[string]*NamespaceEntry),
		namespacesByAccessor: make(map[string]*NamespaceEntry),
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
	namespacesByPath := make(map[string]*NamespaceEntry, len(ns.namespacesByPath)+1)
	namespacesByUUID := make(map[string]*NamespaceEntry, len(ns.namespacesByUUID)+1)
	namespacesByAccessor := make(map[string]*NamespaceEntry, len(ns.namespacesByAccessor)+1)
	rootNs := &NamespaceEntry{Namespace: namespace.RootNamespace}
	namespacesByPath[rootNs.Namespace.Path] = rootNs
	namespacesByUUID[rootNs.UUID] = rootNs
	namespacesByAccessor[rootNs.Namespace.ID] = rootNs

	if err := logical.WithTransaction(ctx, ns.storage, func(s logical.Storage) error {
		// TODO(ascheel): We'll need to keep track of newly found namespaces
		// here and recurse to find child namespaces.
		if err := logical.HandleListPage(s, namespaceStoreRoot, 100, func(page int, index int, entry string) (bool, error) {
			path := path.Join(namespaceStoreRoot, entry)

			item, err := s.Get(ctx, path)
			if err != nil {
				return false, fmt.Errorf("failed to fetch namespace %v (page %v / index %v): %w", path, page, index, err)
			}

			if item == nil {
				return false, fmt.Errorf("%v has an empty namespace definition (page %v / index %v)", path, page, index)
			}

			var namespace NamespaceEntry
			if err := item.DecodeJSON(&namespace); err != nil {
				return false, fmt.Errorf("failed to decode namespace %v (page %v / index %v): %w", path, page, index, err)
			}

			namespacesByPath[namespace.Namespace.Path] = &namespace
			namespacesByUUID[namespace.UUID] = &namespace
			namespacesByAccessor[namespace.Namespace.ID] = &namespace

			return true, nil
		}, nil); err != nil {
			return err
		}

		return nil
	}); err != nil {
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
func (ns *NamespaceStore) SetNamespace(ctx context.Context, namespace *NamespaceEntry) error {
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
func (ns *NamespaceStore) setNamespaceLocked(ctx context.Context, nsEntry *NamespaceEntry) error {
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
		return fmt.Errorf("failed validating namespace: %w", err)
	}

	var exists bool
	if entry.UUID == "" {
		id, err := ns.assignIdentifier(entry.Namespace.Path)
		if err != nil {
			return err
		}

		entry.Namespace.ID = id
		entry.UUID, err = uuid.GenerateUUID()
		if err != nil {
			return err
		}
	} else {
		var existing *NamespaceEntry
		existing, exists = ns.namespacesByUUID[entry.UUID]
		if !exists {
			return errors.New("trying to update a non-existant namespace")
		}

		if existing.Namespace.ID != entry.Namespace.ID {
			return errors.New("accessor ID does not match")
		}

		if existing.Namespace.Path != entry.Namespace.Path {
			return errors.New("unable to remount namespace at new path")
		}
	}

	if err := ns.writeNamespace(ctx, entry); err != nil {
		return fmt.Errorf("failed to persist namespace: %w", err)
	}

	ns.namespacesByPath[entry.Namespace.Path] = entry
	ns.namespacesByUUID[entry.UUID] = entry
	ns.namespacesByAccessor[entry.Namespace.ID] = entry

	// Since the write succeeded, copy back any potentially changed values.
	nsEntry.UUID = entry.UUID
	nsEntry.Namespace.ID = entry.Namespace.ID
	nsEntry.Namespace.Path = entry.Namespace.Path

	if !exists {
		// unlock before initializeNamespace sice that will re-acqurie the lock
		ns.lock.Unlock()
		unlocked = true

		// Create sys/ and token/ mounts for the new namespace.
		if err := ns.initializeNamespace(ctx, entry); err != nil {
			return err
		}
	}

	return nil
}

func (ns *NamespaceStore) writeNamespace(ctx context.Context, entry *NamespaceEntry) error {
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
	if _, ok := ns.namespacesByPath[path]; ok {
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
func (ns *NamespaceStore) initializeNamespace(ctx context.Context, entry *NamespaceEntry) error {
	// ctx may have a namespace of the parent of our newly created namespace,
	// so create a new context with the newly created child namespace.
	nsCtx := namespace.ContextWithNamespace(ctx, entry.Clone().Namespace)

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
func (ns *NamespaceStore) GetNamespace(ctx context.Context, uuid string) (*NamespaceEntry, error) {
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
func (ns *NamespaceStore) GetNamespaceByAccessor(ctx context.Context, id string) (*NamespaceEntry, error) {
	defer metrics.MeasureSince([]string{"namespace", "get_namespace"}, time.Now())

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

// GetNamespaceByPath is used to fetch the namespace with the given full path.
func (ns *NamespaceStore) GetNamespaceByPath(ctx context.Context, path string) (*NamespaceEntry, error) {
	defer metrics.MeasureSince([]string{"namespace", "get_namespace_by_path"}, time.Now())

	if err := ns.checkInvalidation(ctx); err != nil {
		return nil, err
	}

	ns.lock.RLock()
	defer ns.lock.RUnlock()

	return ns.getNamespaceByPathLocked(ctx, path)
}

func (ns *NamespaceStore) getNamespaceByPathLocked(ctx context.Context, path string) (*NamespaceEntry, error) {
	parent, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, err
	}
	path = namespace.Canonicalize(parent.Path + path)
	item, ok := ns.namespacesByPath[path]
	if !ok {
		return nil, nil
	}

	return item.Clone(), nil
}

// ModifyNamespace is used to perform modifications to a namespace while
// holding a write lock to prevent other changes to namespaces from occurring
// at the same time.
func (ns *NamespaceStore) ModifyNamespaceByPath(ctx context.Context, path string, callback func(context.Context, *NamespaceEntry) (*NamespaceEntry, error)) (*NamespaceEntry, error) {
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
		return nil, errors.New("refusing to modify root namespace")
	}

	ns.lock.Lock()

	entry, ok := ns.namespacesByPath[path]
	if ok {
		entry = entry.Clone()
	} else {
		entry = &NamespaceEntry{Namespace: &namespace.Namespace{
			Path:           path,
			CustomMetadata: make(map[string]string),
		}}
	}

	entry, err = callback(ctx, entry)
	if err != nil {
		ns.lock.Unlock()
		return nil, err
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
	ctx = namespace.RootContext(ctx)
	return ns.ListNamespaces(ctx, includeRoot, true)
}

// ListNamespaces is used to list namespaces below a parent namespace.
// Optionally it can include the parent namespace itself and/or include all
// decendents of the child namespaces.
func (ns *NamespaceStore) ListNamespaces(ctx context.Context, includeParent bool, recursive bool) ([]*namespace.Namespace, error) {
	defer metrics.MeasureSince([]string{"namespace", "list_namespaces"}, time.Now())

	entries, err := ns.ListNamespaceEntries(ctx, includeParent, recursive)
	if err != nil {
		return nil, err
	}

	namespaces := make([]*namespace.Namespace, 0, len(entries))
	for _, item := range entries {
		namespaces = append(namespaces, item.Namespace)
	}

	return namespaces, nil
}

// ListAllNamespaceEntries lists all available NamespaceEntries, optionally
// including the root namespace.
func (ns *NamespaceStore) ListAllNamespaceEntries(ctx context.Context, includeRoot bool) ([]*NamespaceEntry, error) {
	ctx = namespace.RootContext(ctx)
	return ns.ListNamespaceEntries(ctx, includeRoot, true)
}

// ListNamespaceEntries is used to list NamespaceEntries below a parent namespace.
// Optionally it can include the parent namespace itself and/or include all
// decendents of the child namespaces.
func (ns *NamespaceStore) ListNamespaceEntries(ctx context.Context, includeParent bool, recursive bool) ([]*NamespaceEntry, error) {
	defer metrics.MeasureSince([]string{"namespace", "list_namespaces"}, time.Now())

	if err := ns.checkInvalidation(ctx); err != nil {
		return nil, err
	}

	parent, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	ns.lock.RLock()
	defer ns.lock.RUnlock()

	entries := make([]*NamespaceEntry, 0, len(ns.namespacesByUUID))
	for _, item := range ns.namespacesByUUID {
		if !includeParent && item.Namespace.ID == parent.ID {
			continue
		}
		if !recursive && !item.Namespace.HasDirectParent(parent) {
			continue
		}
		if !item.Namespace.HasParent(parent) {
			continue
		}

		entries = append(entries, item.Clone())
	}

	return entries, nil
}

// DeleteNamespace is used to delete the named namespace
func (ns *NamespaceStore) DeleteNamespace(ctx context.Context, uuid string) error {
	defer metrics.MeasureSince([]string{"namespace", "delete_namespace"}, time.Now())

	if err := ns.checkInvalidation(ctx); err != nil {
		return err
	}

	item, ok := ns.namespacesByUUID[uuid]
	if !ok {
		return nil
	}

	if item.Namespace.ID == namespace.RootNamespaceID {
		return errors.New("unable to delete root namespace")
	}

	// Now grab write lock so that we can write to storage.
	ns.lock.Lock()
	defer ns.lock.Unlock()

	delete(ns.namespacesByPath, item.Namespace.Path)
	delete(ns.namespacesByUUID, uuid)
	delete(ns.namespacesByAccessor, item.Namespace.ID)

	if err := logical.WithTransaction(ctx, ns.storage, func(s logical.Storage) error {
		storagePath := path.Join(namespaceStoreRoot, uuid)
		return s.Delete(ctx, storagePath)
	}); err != nil {
		return err
	}

	return nil
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

	intoCtx = namespace.ContextWithNamespace(intoCtx, entry.Namespace)
	return intoCtx, entry.Namespace, nil
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

	entries, err := ns.ListAllNamespaceEntries(newCtx, false)
	if err != nil {
		return newCtx, parentNs, reqPath, err
	}

	var longestPath string
	for _, entry := range entries {
		nsPath := entry.Namespace.Path
		if strings.HasPrefix(reqPath, nsPath) {
			// search for the longest namespace path prefix of reqPath
			// skip if nsPath does not have currently longest path as prefix
			if !strings.HasPrefix(nsPath, longestPath) {
				continue
			}
			longestPath = nsPath
		}
	}
	parentEntry, err := ns.GetNamespaceByPath(newCtx, longestPath)
	if err != nil {
		return newCtx, parentNs, reqPath, err
	}
	parentNs = parentEntry.Namespace
	reqPath = reqPath[len(longestPath):]

	// TODO(ascheel): Fix global uses of comparison by pointer.
	if parentNs.ID == namespace.RootNamespaceID {
		parentNs = namespace.RootNamespace
	}

	finalCtx := namespace.ContextWithNamespace(baseCtx, parentNs)
	return finalCtx, parentNs, reqPath, nil
}
