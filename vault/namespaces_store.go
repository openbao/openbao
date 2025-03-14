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

// Namespace storage location.
const namespaceStoreRoot = "core/namespaces/"

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
	namespaces []*NamespaceEntry

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

	return NewBarrierView(barrier, path.Join("namespaces", ne.UUID)+"/")
}

// NewNamespaceStore creates a new NamespaceStore that is backed
// using a given view. It used used to durable store and manage named namespace.
func NewNamespaceStore(ctx context.Context, core *Core, logger hclog.Logger) (*NamespaceStore, error) {
	ns := &NamespaceStore{
		core:    core,
		storage: core.barrier,
		logger:  logger,
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
	allNamespaces := make([]*NamespaceEntry, 0, len(ns.namespaces)+1)
	allNamespaces = append(allNamespaces, &NamespaceEntry{Namespace: namespace.RootNamespace})

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

			allNamespaces = append(allNamespaces, &namespace)

			return true, nil
		}, nil); err != nil {
			return err
		}

		return nil
	}); err != nil {
		return err
	}

	ns.namespaces = allNamespaces

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
func (ns *NamespaceStore) setNamespaceLocked(ctx context.Context, namespace *NamespaceEntry) error {
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
	entry := namespace.Clone()
	if err := entry.Validate(); err != nil {
		return fmt.Errorf("failed validating namespace: %w", err)
	}

	index := -1
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
		// Ensure we have no conflicts for paths.
		for idx, existing := range ns.namespaces {
			if existing.UUID == entry.UUID {
				index = idx
				break
			}

			if existing.Namespace.ID == entry.Namespace.ID {
				return errors.New("namespace with specified accessor already exists")
			}

			if existing.Namespace.Path == entry.Namespace.Path {
				return errors.New("namespace with specified path already exists")
			}
		}
	}

	if index != -1 && ns.namespaces[index].Namespace.Path != entry.Namespace.Path {
		return errors.New("unable to remount namespace at new path")
	}

	if err := ns.writeNamespace(ctx, entry); err != nil {
		return fmt.Errorf("failed to persist namespace: %w", err)
	}

	if index == -1 {
		ns.namespaces = append(ns.namespaces, entry)

		// Release the lock before creating new entries.
		ns.lock.Unlock()
		unlocked = true

		// Create sys/ and token/ mounts for the new namespace.
		if err := ns.initializeNamespace(ctx, entry); err != nil {
			return err
		}
	} else {
		ns.namespaces[index] = entry

		// No need to adjust mounts as they should already exist.
	}

	// Since the write succeeded, copy back any potentially changed values.
	namespace.UUID = entry.UUID
	namespace.Namespace.ID = entry.Namespace.ID
	namespace.Namespace.Path = entry.Namespace.Path

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
	for {
		id, err := base62.Random(namespaceIdLength)
		if err != nil {
			return "", fmt.Errorf("unable to generate namespace identifier: %w", err)
		}

		var found bool
		for _, existing := range ns.namespaces {
			if existing.Namespace.Path == path {
				return "", errors.New("unable to update when a namespace with this path already exists")
			}

			if existing.Namespace.ID == id {
				found = true
				break
			}
		}

		if found {
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

	for _, item := range ns.namespaces {
		if item.UUID == uuid {
			return item.Clone(), nil
		}
	}

	return nil, nil
}

// GetNamespaceByAccessor is used to fetch the namespace with the given accessor.
func (ns *NamespaceStore) GetNamespaceByAccessor(ctx context.Context, id string) (*NamespaceEntry, error) {
	defer metrics.MeasureSince([]string{"namespace", "get_namespace"}, time.Now())

	if err := ns.checkInvalidation(ctx); err != nil {
		return nil, err
	}

	ns.lock.RLock()
	defer ns.lock.RUnlock()

	for _, item := range ns.namespaces {
		if item.Namespace.ID == id {
			return item.Clone(), nil
		}
	}

	return nil, nil
}

// GetNamespaceByPath is used to fetch the namespace with the given path.
func (ns *NamespaceStore) GetNamespaceByPath(ctx context.Context, path string) (*NamespaceEntry, error) {
	defer metrics.MeasureSince([]string{"namespace", "get_namespace_by_path"}, time.Now())

	if err := ns.checkInvalidation(ctx); err != nil {
		return nil, err
	}

	ns.lock.RLock()
	defer ns.lock.RUnlock()

	path = namespace.Canonicalize(path)
	for _, item := range ns.namespaces {
		if item.Namespace.Path == path {
			return item.Clone(), nil
		}
	}

	return nil, nil
}

// ModifyNamespace is used to perform modifications to a namespace while
// holding a write lock to prevent other changes to namespaces from occurring
// at the same time.
func (ns *NamespaceStore) ModifyNamespaceByPath(ctx context.Context, path string, callback func(context.Context, *NamespaceEntry) (*NamespaceEntry, error)) (*NamespaceEntry, error) {
	defer metrics.MeasureSince([]string{"namespace", "modify_namespace"}, time.Now())

	if err := ns.checkInvalidation(ctx); err != nil {
		return nil, err
	}

	ns.lock.Lock()

	path = namespace.Canonicalize(path)
	if path == "" {
		return nil, errors.New("refusing to modify root namespace")
	}

	var entry *NamespaceEntry
	for _, item := range ns.namespaces {
		if item.Namespace.Path == path {
			entry = item.Clone()
			break
		}
	}

	if entry == nil {
		entry = &NamespaceEntry{Namespace: &namespace.Namespace{}}
	}

	var err error
	entry, err = callback(ctx, entry)
	if err != nil {
		return nil, err
	}

	if err := ns.setNamespaceLocked(ctx, entry); err != nil {
		return nil, err
	}

	return entry.Clone(), nil
}

// ListNamespaces is used to list all available namespaces
func (ns *NamespaceStore) ListNamespaces(ctx context.Context, includeRoot bool) ([]*namespace.Namespace, error) {
	defer metrics.MeasureSince([]string{"namespace", "list_namespaces"}, time.Now())

	if err := ns.checkInvalidation(ctx); err != nil {
		return nil, err
	}

	ns.lock.RLock()
	defer ns.lock.RUnlock()

	entries := make([]*namespace.Namespace, 0, len(ns.namespaces))
	for _, item := range ns.namespaces {
		if !includeRoot && item.Namespace.ID == namespace.RootNamespaceID {
			continue
		}

		entries = append(entries, item.Clone().Namespace)
	}

	return entries, nil
}

// ListNamespaceEntries is used to list all available namespace entries
func (ns *NamespaceStore) ListNamespaceEntries(ctx context.Context, includeRoot bool) ([]*NamespaceEntry, error) {
	defer metrics.MeasureSince([]string{"namespace", "list_namespaces"}, time.Now())

	if err := ns.checkInvalidation(ctx); err != nil {
		return nil, err
	}

	ns.lock.RLock()
	defer ns.lock.RUnlock()

	entries := make([]*NamespaceEntry, 0, len(ns.namespaces))
	for _, item := range ns.namespaces {
		if !includeRoot && item.Namespace.ID == namespace.RootNamespaceID {
			continue
		}

		entries = append(entries, item.Clone())
	}

	return entries, nil
}

// ListNamespaceUUIDs is used to list the uuids of available namespaces
func (ns *NamespaceStore) ListNamespaceUUIDs(ctx context.Context, includeRoot bool) ([]string, error) {
	defer metrics.MeasureSince([]string{"namespace", "list_namespace_uuids"}, time.Now())

	if err := ns.checkInvalidation(ctx); err != nil {
		return nil, err
	}

	ns.lock.RLock()
	defer ns.lock.RUnlock()

	entries := make([]string, 0, len(ns.namespaces))
	for _, item := range ns.namespaces {
		if !includeRoot && item.Namespace.ID == namespace.RootNamespaceID {
			continue
		}

		entries = append(entries, item.UUID)
	}

	return entries, nil
}

// ListNamespaceAccessors is used to list the identifiers of available namespaces
func (ns *NamespaceStore) ListNamespaceAccessors(ctx context.Context, includeRoot bool) ([]string, error) {
	defer metrics.MeasureSince([]string{"namespace", "list_namespace_accessors"}, time.Now())

	if err := ns.checkInvalidation(ctx); err != nil {
		return nil, err
	}

	ns.lock.RLock()
	defer ns.lock.RUnlock()

	entries := make([]string, 0, len(ns.namespaces))
	for _, item := range ns.namespaces {
		if !includeRoot && item.Namespace.ID == namespace.RootNamespaceID {
			continue
		}

		entries = append(entries, item.Namespace.ID)
	}

	return entries, nil
}

// ListNamespacePaths is used to list the paths of all available namespaces
func (ns *NamespaceStore) ListNamespacePaths(ctx context.Context, includeRoot bool) ([]string, error) {
	defer metrics.MeasureSince([]string{"namespace", "list_namespace_paths"}, time.Now())

	if err := ns.checkInvalidation(ctx); err != nil {
		return nil, err
	}

	ns.lock.RLock()
	defer ns.lock.RUnlock()

	entries := make([]string, 0, len(ns.namespaces))
	for _, item := range ns.namespaces {
		if !includeRoot && item.Namespace.ID == namespace.RootNamespaceID {
			continue
		}

		entries = append(entries, item.Namespace.Path)
	}

	return entries, nil
}

// DeleteNamespace is used to delete the named namespace
func (ns *NamespaceStore) DeleteNamespace(ctx context.Context, uuid string) error {
	defer metrics.MeasureSince([]string{"namespace", "delete_namespace"}, time.Now())

	if err := ns.checkInvalidation(ctx); err != nil {
		return err
	}

	// Now grab write lock so that we can write to storage.
	ns.lock.Lock()
	defer ns.lock.Unlock()

	index := -1
	for idx, item := range ns.namespaces {
		if item.UUID == uuid {
			if item.Namespace.ID == namespace.RootNamespaceID {
				return errors.New("unable to delete root namespace")
			}

			index = idx
			break
		}
	}

	if index == -1 {
		return nil
	}

	// We're guaranteed at least one item remaining since the root namespace
	// should always be present and not be removable.
	ns.namespaces = append(ns.namespaces[0:index], ns.namespaces[index+1:]...)

	if err := logical.WithTransaction(ctx, ns.storage, func(s logical.Storage) error {
		storagePath := path.Join(namespaceStoreRoot, uuid)
		return s.Delete(ctx, storagePath)
	}); err != nil {
		return err
	}

	return nil
}

// ResolveNamespaceFromRequestContext merges the given base context with
// the namespace from httpCtx.
func (ns *NamespaceStore) ResolveNamespaceFromRequestContext(baseCtx context.Context, httpCtx context.Context) (context.Context, *namespace.Namespace, error) {
	rawNs, err := namespace.FromContext(httpCtx)
	if err != nil {
		return baseCtx, nil, fmt.Errorf("could not parse namespace from http context: %w", err)
	}

	entry, err := ns.GetNamespaceByPath(baseCtx, rawNs.Path)
	if err != nil {
		return baseCtx, nil, fmt.Errorf("could not fetch namespace by path: %w", err)
	}

	if entry == nil {
		return baseCtx, nil, fmt.Errorf("requested namespace was not found")
	}

	newCtx := namespace.ContextWithNamespace(baseCtx, entry.Namespace)
	return newCtx, entry.Namespace, nil
}

// ResolveNamespaceFromRequest merges the given base context with the
// namespace from httpCtx, combining it with any namespaces within the
// request path itself. We remove the prefix from the path, if given,
// because logic elsewhere in vault/ combines the namespace with the
// path again.
func (ns *NamespaceStore) ResolveNamespaceFromRequest(baseCtx context.Context, httpCtx context.Context, reqPath string) (context.Context, *namespace.Namespace, string, error) {
	// We stack the namespace context ahead of any namespace in path.
	newCtx, parentNs, err := ns.ResolveNamespaceFromRequestContext(baseCtx, httpCtx)
	if err != nil {
		return newCtx, parentNs, reqPath, err
	}

	paths, err := ns.ListNamespacePaths(newCtx, false)
	if err != nil {
		return newCtx, parentNs, reqPath, err
	}

	// TODO(ascheel): handle child namespaces properly
	for _, nsPath := range paths {
		if strings.HasPrefix(reqPath, nsPath) {
			childNs, err := ns.GetNamespaceByPath(newCtx, nsPath)
			if err != nil {
				return newCtx, parentNs, reqPath, err
			}
			parentNs = childNs.Namespace
			reqPath = reqPath[len(nsPath):]
			break
		}
	}

	// TODO(ascheel): Fix global uses of comparison by pointer.
	if parentNs.ID == namespace.RootNamespaceID {
		parentNs = namespace.RootNamespace
	}

	finalCtx := namespace.ContextWithNamespace(baseCtx, parentNs)
	return finalCtx, parentNs, reqPath, nil
}
