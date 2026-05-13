// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"path"
	"slices"
	"strings"

	"github.com/hashicorp/go-uuid"
	"github.com/openbao/openbao/builtin/plugin"
	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/helper/versions"
	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/openbao/openbao/sdk/v2/helper/jsonutil"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/vault/barrier"
	"github.com/openbao/openbao/vault/routing"
)

const (
	// coreAuthConfigPath is used to store the auth configuration.
	// Auth configuration is protected within the Vault itself, which means it
	// can only be viewed or modified after an unseal.
	coreAuthConfigPath = "core/auth"

	// coreLocalAuthConfigPath is used to store credential configuration for
	// local (non-replicated) mounts
	coreLocalAuthConfigPath = "core/local-auth"
)

var (
	// errLoadAuthFailed if loadCredentials encounters an error
	errLoadAuthFailed = errors.New("failed to setup auth table")

	// credentialAliases maps old backend names to new backend names, allowing us
	// to move/rename backends but maintain backwards compatibility
	credentialAliases = map[string]string{"aws-ec2": "aws"}

	// protectedAuths marks auth mounts that are protected and cannot be remounted
	protectedAuths = []string{
		"auth/token",
	}
)

// enableCredential is used to enable a new credential backend
func (c *Core) enableCredential(ctx context.Context, entry *routing.MountEntry) error {
	// Ensure the token backend is a singleton
	if entry.Type == routing.MountTypeToken || entry.Type == routing.MountTypeNSToken {
		return errors.New("token credential backend cannot be instantiated")
	}

	// Enable credential internally
	if err := c.enableCredentialInternal(ctx, entry, true); err != nil {
		return err
	}

	return nil
}

// enableCredential is used to enable a new credential backend
func (c *Core) enableCredentialInternal(ctx context.Context, entry *routing.MountEntry, updateStorage bool) error {
	// Ensure we end the path in a slash
	if !strings.HasSuffix(entry.Path, "/") {
		entry.Path += "/"
	}

	// Ensure there is a name
	if entry.Path == "/" {
		return errors.New("backend path must be specified")
	}

	c.mountsLock.Lock()
	c.authLock.Lock()
	defer c.authLock.Unlock()
	defer c.mountsLock.Unlock()

	return c.enableCredentialInternalWithLock(ctx, entry, updateStorage)
}

func (c *Core) enableCredentialInternalWithLock(ctx context.Context, entry *routing.MountEntry, updateStorage bool) error {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return err
	}
	entry.NamespaceID = ns.ID
	entry.Namespace = ns

	// Basic check for matching names
	for _, ent := range c.auth.Entries {
		if ns.ID == ent.NamespaceID {
			switch {
			// Existing is oauth/github/ new is oauth/ or
			// existing is oauth/ and new is oauth/github/
			case strings.HasPrefix(ent.Path, entry.Path):
				fallthrough
			case strings.HasPrefix(entry.Path, ent.Path):
				return logical.CodedError(409, "path is already in use at %s", ent.Path)
			}
		}
	}

	// Check for conflicts according to the router
	if conflict := c.router.MountConflict(ctx, routing.CredentialRoutePrefix+entry.Path); conflict != "" {
		return logical.CodedError(409, "existing mount at %s", conflict)
	}

	// Generate a new UUID and view
	if entry.UUID == "" {
		entryUUID, err := uuid.GenerateUUID()
		if err != nil {
			return err
		}
		entry.UUID = entryUUID
	}
	if entry.BackendAwareUUID == "" {
		bUUID, err := uuid.GenerateUUID()
		if err != nil {
			return err
		}
		entry.BackendAwareUUID = bUUID
	}
	if entry.Accessor == "" {
		accessor, err := c.generateMountAccessor("auth_" + entry.Type)
		if err != nil {
			return err
		}
		entry.Accessor = accessor
	}
	// Sync values to the cache
	entry.SyncCache()

	view, err := c.mountEntryView(entry)
	if err != nil {
		return err
	}

	origViewReadOnlyErr := view.GetReadOnlyErr()

	// Mark the view as read-only until the mounting is complete and
	// ensure that it is reset after. This ensures that there will be no
	// writes during the construction of the backend.
	view.SetReadOnlyErr(logical.ErrSetupReadOnly)
	defer view.SetReadOnlyErr(origViewReadOnlyErr)

	var backend logical.Backend
	// Create the new backend
	sysView := c.mountEntrySysView(entry)
	backend, entry.RunningSha256, err = c.newCredentialBackend(ctx, entry, sysView, view)
	if err != nil {
		return err
	}

	// Discard the backend if any remaining steps below fail.
	var success bool
	defer func() {
		if !success {
			backend.Cleanup(ctx)
		}
	}()

	// Check for the correct backend type
	backendType := backend.Type()
	if backendType != logical.TypeCredential {
		return fmt.Errorf("cannot mount %q of type %q as an auth backend", entry.Type, backendType)
	}
	// update the entry running version with the configured version, which was verified during registration.
	entry.RunningVersion = entry.Version
	if entry.RunningVersion == "" {
		// don't set the running version to a builtin if it is running as an external plugin
		if entry.RunningSha256 == "" {
			entry.RunningVersion = versions.GetBuiltinVersion(consts.PluginTypeCredential, entry.Type)
		}
	}

	// Update the auth table
	newTable := c.auth.ShallowClone()
	newTable.Entries = append(newTable.Entries, entry)
	if updateStorage {
		if err := c.persistAuth(ctx, c.NamespaceView(ns), newTable, &entry.Local, entry.UUID); err != nil {
			c.logger.Error("failed to update auth table", "error", err)
			return fmt.Errorf("failed to update auth table: %w", err)
		}
	}

	c.auth = newTable

	if err := c.router.Mount(backend, routing.CredentialRoutePrefix+entry.Path, entry, view); err != nil {
		return err
	}

	// restore the original readOnlyErr, so we can write to the view in
	// Initialize() if necessary
	view.SetReadOnlyErr(origViewReadOnlyErr)
	// initialize, using the core's active context.
	err = backend.Initialize(c.activeContext.Load(), &logical.InitializationRequest{Storage: view})
	if err != nil {
		return err
	}

	success = true
	if c.logger.IsInfo() {
		c.logger.Info("enabled credential backend", "namespace", entry.Namespace.Path, "path", entry.Path, "type", entry.Type, "version", entry.Version)
	}

	return nil
}

// disableCredential is used to disable an existing credential backend
func (c *Core) disableCredential(ctx context.Context, path string) error {
	// Ensure we end the path in a slash
	if !strings.HasSuffix(path, "/") {
		path += "/"
	}

	// Ensure the token backend is not affected
	if path == "token/" {
		return errors.New("token credential backend cannot be disabled")
	}

	// Disable credential internally
	if err := c.disableCredentialInternal(ctx, path, true); err != nil {
		return err
	}

	return nil
}

func (c *Core) disableCredentialInternal(ctx context.Context, path string, updateStorage bool) error {
	path = routing.CredentialRoutePrefix + path

	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return err
	}

	// Verify exact match of the route
	match := c.router.MatchingMount(ctx, path)
	if match == "" || ns.Path+path != match {
		return errNoMatchingMount
	}

	// Get the view for this backend
	view := c.router.MatchingStorageByAPIPath(ctx, path)
	if view == nil {
		return fmt.Errorf("no matching storage %q", path)
	}

	// Get the backend/mount entry for this path, used to remove ignored
	// replication prefixes
	backend := c.router.MatchingBackend(ctx, path)

	// Mark the entry as tainted
	if err := c.taintCredEntry(ctx, ns.ID, path, updateStorage); err != nil {
		c.logger.Error("failed to taint credential entry for path being unmounted", "error", err, "namespace", ns.Path, "path", path)
		return err
	}

	// Taint the router path to prevent routing
	if err := c.router.Taint(ctx, path); err != nil {
		return err
	}

	revokeCtx := namespace.ContextWithNamespace(c.activeContext.Load(), ns)

	if backend != nil && c.expiration != nil && updateStorage {
		// Revoke credentials from this path
		if err := c.expiration.RevokePrefix(revokeCtx, path, true); err != nil {
			return err
		}
	}

	if backend != nil {
		// Call cleanup function if it exists
		backend.Cleanup(revokeCtx)
	}

	switch {
	case !updateStorage:
		// Don't attempt to clear data, replication will handle this
	default:
		// Have writable storage, remove the whole thing
		if err := logical.ClearViewWithLogging(revokeCtx, view, c.logger.Named("auth.deletion").With("namespace", ns.Path, "path", path)); err != nil {
			c.logger.Error("failed to clear view for path being unmounted", "error", err, "namespace", ns.Path, "path", path)
			return err
		}
	}

	// Remove the mount table entry
	if err := c.removeCredEntry(revokeCtx, strings.TrimPrefix(path, routing.CredentialRoutePrefix), updateStorage); err != nil {
		c.logger.Error("failed to remove credential entry for path being unmounted", "error", err, "namespace", ns.Path, "path", path)
		return err
	}

	// Unmount the backend
	if err := c.router.Unmount(revokeCtx, path); err != nil {
		return err
	}

	if c.quotaManager != nil {
		if err := c.quotaManager.HandleBackendDisabling(revokeCtx, ns.Path, path); err != nil {
			c.logger.Error("failed to update quotas after disabling auth", "error", err, "namespace", ns.Path, "path", path)
			return err
		}
	}

	if c.logger.IsInfo() {
		c.logger.Info("disabled credential backend", "namespace", ns.Path, "path", path)
	}

	return nil
}

// removeCredEntry is used to remove an entry in the auth table
func (c *Core) removeCredEntry(ctx context.Context, path string, updateStorage bool) error {
	c.authLock.Lock()
	defer c.authLock.Unlock()

	return c.removeCredEntryWithLock(ctx, path, updateStorage)
}

func (c *Core) removeCredEntryWithLock(ctx context.Context, path string, updateStorage bool) error {
	// Taint the entry from the auth table
	newTable := c.auth.ShallowClone()
	entry, err := newTable.Remove(ctx, path)
	if err != nil {
		return err
	}
	if entry == nil {
		c.logger.Error("nil entry found removing entry in auth table", "path", path)
		return logical.CodedError(500, "failed to remove entry in auth table")
	}

	if updateStorage {
		// Update the auth table
		if err := c.persistAuth(ctx, c.NamespaceView(entry.Namespace), newTable, &entry.Local, entry.UUID); err != nil {
			return fmt.Errorf("failed to update auth table: %w", err)
		}
	}

	c.auth = newTable

	return nil
}

func (c *Core) remountCredential(ctx context.Context, src, dst namespace.MountPathDetails, updateStorage bool) error {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return err
	}

	if !strings.HasPrefix(src.MountPath, routing.CredentialRoutePrefix) {
		return fmt.Errorf("cannot remount non-auth mount %q", src.MountPath)
	}

	if !strings.HasPrefix(dst.MountPath, routing.CredentialRoutePrefix) {
		return fmt.Errorf("cannot remount auth mount to non-auth mount %q", dst.MountPath)
	}

	for _, auth := range protectedAuths {
		if strings.HasPrefix(src.MountPath, auth) {
			return fmt.Errorf("cannot remount %q", src.MountPath)
		}
	}

	for _, auth := range protectedAuths {
		if strings.HasPrefix(dst.MountPath, auth) {
			return fmt.Errorf("cannot remount to %q", dst.MountPath)
		}
	}

	srcRelativePath := src.GetRelativePath(ns)
	dstRelativePath := dst.GetRelativePath(ns)

	// Verify exact match of the route
	mountEntry := c.router.MatchingMountEntry(ctx, srcRelativePath)
	if mountEntry == nil {
		return fmt.Errorf("no matching mount at %q", src.Namespace.Path+src.MountPath)
	}

	if match := c.router.MountConflict(ctx, dstRelativePath); match != dst.Namespace.Path && match != "" {
		return fmt.Errorf("path in use at %q", match)
	}

	// Mark the entry as tainted
	if err := c.taintCredEntry(ctx, src.Namespace.ID, src.MountPath, updateStorage); err != nil {
		return err
	}

	// Taint the router path to prevent routing
	if err := c.router.Taint(ctx, srcRelativePath); err != nil {
		return err
	}

	if c.expiration != nil {
		revokeCtx := namespace.ContextWithNamespace(ctx, src.Namespace)
		// Revoke all the dynamic keys
		if err := c.expiration.RevokePrefix(revokeCtx, src.MountPath, true); err != nil {
			return err
		}
	}

	c.authLock.Lock()
	if match := c.router.MountConflict(ctx, dstRelativePath); match != dst.Namespace.Path && match != "" {
		c.authLock.Unlock()
		return fmt.Errorf("path in use at %q", match)
	}

	mountEntry.Tainted = false
	mountEntry.NamespaceID = dst.Namespace.ID
	mountEntry.Namespace = dst.Namespace
	srcPath := mountEntry.Path
	mountEntry.Path = strings.TrimPrefix(dst.MountPath, routing.CredentialRoutePrefix)

	// Update the mount table
	if err := c.persistAuth(ctx, c.NamespaceView(mountEntry.Namespace), c.auth, &mountEntry.Local, mountEntry.UUID); err != nil {
		mountEntry.Namespace = src.Namespace
		mountEntry.NamespaceID = src.Namespace.ID
		mountEntry.Path = srcPath
		mountEntry.Tainted = true
		c.authLock.Unlock()
		return fmt.Errorf("failed to update auth table with error %w", err)
	}

	if src.Namespace.ID != dst.Namespace.ID {
		// Handle storage entries
		if err := c.moveAuthStorage(ctx, src, mountEntry); err != nil {
			c.authLock.Unlock()
			return err
		}
	}

	dstBarrierView, err := c.mountEntryView(mountEntry)
	if err != nil {
		c.authLock.Unlock()
		return err
	}

	// Remount the backend
	if err := c.router.Remount(ctx, srcRelativePath, dstRelativePath, func(re *routing.RouteEntry) error {
		re.StorageView = dstBarrierView
		re.StoragePrefix = dstBarrierView.Prefix()

		return nil
	}); err != nil {
		c.authLock.Unlock()
		return err
	}
	c.authLock.Unlock()

	// Un-taint the new path in the router
	if err := c.router.Untaint(ctx, dstRelativePath); err != nil {
		return err
	}

	return nil
}

// taintCredEntry is used to mark an entry in the auth table as tainted
func (c *Core) taintCredEntry(ctx context.Context, nsID, path string, updateStorage bool) error {
	c.authLock.Lock()
	defer c.authLock.Unlock()

	// Taint the entry from the auth table
	// We do this on the original since setting the taint operates
	// on the entries which a shallow clone shares anyways
	entry := c.auth.SetTaint(nsID, strings.TrimPrefix(path, routing.CredentialRoutePrefix))

	// Ensure there was a match
	if entry == nil {
		return fmt.Errorf("no matching backend for path %q namespaceID %q", path, nsID)
	}

	if updateStorage {
		// Update the auth table
		if err := c.persistAuth(ctx, c.NamespaceView(entry.Namespace), c.auth, &entry.Local, entry.UUID); err != nil {
			return fmt.Errorf("failed to update auth table: %w", err)
		}
	}

	return nil
}

// loadCredentials is invoked as part of postUnseal to load the auth table
func (c *Core) loadCredentials(ctx context.Context, standby bool) error {
	// Previously, this lock would be held after attempting to read the
	// storage entries. While we could never read corrupted entries,
	// we now need to ensure we can gracefully failover from legacy to
	// transactional auth mount table structure. This means holding the locks
	// for longer.
	//
	// Note that this lock is used for consistency with other code during
	// system operation (when mounting and unmounting auth engines), but
	// is not strictly necessary here as unseal(...) is serial and blocks
	// startup until finished.
	c.authLock.Lock()
	defer c.authLock.Unlock()

	// Start with an empty mount table.
	c.auth = nil

	// Migrating auth mounts from the previous single-entry to a transactional
	// variant requires careful surgery that should only be done in the
	// event the backend is transactionally aware. Otherwise, we'll continue
	// to use the legacy storage format indefinitely.
	//
	// This does mean that going backwards (from a transaction-aware storage
	// to not) is not possible without manual reconstruction.
	txnableBarrier, ok := c.barrier.(logical.TransactionalStorage)
	if !ok {
		_, err := c.loadLegacyCredentials(ctx, c.barrier, standby)
		return err
	}

	// Create a write transaction in case we need to persist the initial
	// table or migrate from the old format.
	txn, err := txnableBarrier.BeginTx(ctx)
	if err != nil {
		return err
	}

	// Defer rolling back: we may commit the transaction anyways, but we
	// need to ensure the transaction is cleaned up in the event of an
	// error.
	defer txn.Rollback(ctx) //nolint:errcheck

	legacy, err := c.loadLegacyCredentials(ctx, txn, standby)
	if err != nil {
		return fmt.Errorf("failed to load legacy auth mounts in transaction: %w", err)
	}

	// If we have legacy auth mounts, migration was handled by the above. Otherwise,
	// we need to fetch the new auth mount table.
	if !legacy {
		c.logger.Info("reading transactional auth mount table")
		if err := c.loadTransactionalCredentials(ctx, txn, standby); err != nil {
			return fmt.Errorf("failed to load transactional auth mount table: %w", err)
		}
	}

	// Finally, persist our changes.
	if err := txn.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit auth table changes: %w", err)
	}

	return nil
}

// loadCredentialsForNamespace is invoked as part of postNamespaceUnseal
// to load the auth mounts of a namespace.
func (c *Core) loadCredentialsForNamespace(ctx context.Context, ns *namespace.Namespace) error {
	c.authLock.Lock()
	defer c.authLock.Unlock()

	// Check if we're on a non-transactional storage
	if _, ok := c.barrier.(logical.TransactionalStorage); !ok {
		return c.loadLegacyCredentialsForNamespace(ctx, ns)
	}
	return c.loadTransactionalCredentialsForNamespace(ctx, ns)
}

// loadTransactionalCredentials reads the transactional split auth (credential)
// table, populates the storage if there are no existing entries.
func (c *Core) loadTransactionalCredentials(ctx context.Context, barrier logical.Storage, standby bool) error {
	allNamespaces, err := c.ListNamespaces(ctx)
	if err != nil {
		return fmt.Errorf("failed to list namespaces: %w", err)
	}

	for _, ns := range allNamespaces {
		if err = c.loadTransactionalCredentialsForNamespace(ctx, ns); err != nil {
			return err
		}
	}

	var needPersist bool
	// This happens only on the first initialization run of the Core.
	// If there's only root namespace, and there are no auth entries in storage.
	if len(allNamespaces) == 1 && len(c.auth.Entries) == 0 {
		c.logger.Info("no auth mounts in transactional auth mount table; adding default auth mount table")
		c.auth, err = c.defaultAuthTable(ctx)
		if err != nil {
			panic(err.Error())
		}
		needPersist = true
	}

	if err = c.runCredentialUpdates(ctx, barrier, needPersist, standby); err != nil {
		c.logger.Error("failed to run legacy auth mount table upgrades", "error", err)
		return err
	}

	return nil
}

// loadTransactionalCredentialsForNamespace loads the auth mounts of a single namespace.
func (c *Core) loadTransactionalCredentialsForNamespace(ctx context.Context, ns *namespace.Namespace) error {
	if c.NamespaceSealed(ns) {
		return barrier.ErrNamespaceSealed
	}

	if ns.Tainted {
		c.logger.Info("skipping loading auth mounts for tainted namespace", "ns", ns.ID)
		return nil
	}

	view := c.NamespaceView(ns)
	globalEntries, localEntries, err := listTransactionalCredentialsForNamespace(ctx, view)
	if err != nil {
		return fmt.Errorf("failed to list auth mounts for namespace: %w", err)
	}

	for index, uuid := range globalEntries {
		entry, err := c.fetchAndDecodeMountTableEntry(ctx, view, coreAuthConfigPath, uuid)
		if err != nil {
			return fmt.Errorf("error loading auth mount table entry ([%v] %v/%v): %w", ns.ID, index, uuid, err)
		}

		if entry != nil {
			c.auth.Entries = append(c.auth.Entries, entry)
		}
	}

	for index, uuid := range localEntries {
		entry, err := c.fetchAndDecodeMountTableEntry(ctx, view, coreLocalAuthConfigPath, uuid)
		if err != nil {
			return fmt.Errorf("error loading local auth mount table entry ([%v] %v/%v): %w", ns.ID, index, uuid, err)
		}

		if entry != nil {
			c.auth.Entries = append(c.auth.Entries, entry)
		}
	}

	return nil
}

// listTransactionalCredentialsForNamespace retrieves list of
// auth mount entries (global & local) using provided barrier.
func listTransactionalCredentialsForNamespace(ctx context.Context, barrier logical.Storage) ([]string, []string, error) {
	globalEntries, err := barrier.List(ctx, coreAuthConfigPath+"/")
	if err != nil {
		return nil, nil, fmt.Errorf("failed listing core auth mounts: %w", err)
	}

	localEntries, err := barrier.List(ctx, coreLocalAuthConfigPath+"/")
	if err != nil {
		return nil, nil, fmt.Errorf("failed listing core local auth mounts: %w", err)
	}

	return globalEntries, localEntries, nil
}

// loadLegacyCredentials reads the legacy, single-entry combined auth
// mount table, returning true if it was used. This will let us know
// (if we're inside a transaction) if we need to do an upgrade.
func (c *Core) loadLegacyCredentials(ctx context.Context, barrier logical.Storage, standby bool) (bool, error) {
	// Load the existing mount table per namespace
	allNamespaces, err := c.ListNamespaces(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to list namespaces: %w", err)
	}

	if c.auth == nil {
		// Create the auth mount table if it doesn't exist.
		c.auth = &routing.MountTable{
			Type: routing.CredentialTableType,
		}
	}

	for _, ns := range allNamespaces {
		if err = c.loadLegacyCredentialsForNamespace(ctx, ns); err != nil {
			return false, err
		}
	}

	var needPersist bool
	if len(c.auth.Entries) == 0 {
		// In the event we are inside a transaction, we do not yet know if
		// we have a transactional mount table; exit early and load the new format.
		if _, ok := barrier.(logical.Transaction); ok {
			return false, nil
		}
		c.logger.Info("no mounts in legacy auth table; adding default mount table")
		c.auth, err = c.defaultAuthTable(ctx)
		if err != nil {
			panic(err.Error())
		}
		needPersist = true
	} else {
		if _, ok := barrier.(logical.Transaction); ok {
			// We know we have legacy mount table entries, so force a migration.
			c.logger.Info("migrating legacy auth table to transactional layout")
			needPersist = true
		}
	}

	// Here, we must call runCredentialUpdates:
	//
	// 1. We may be without any auth mount table and need to create the legacy
	//    table format because we don't have a transaction aware storage
	//    backend.
	// 2. We may have had a legacy auth mount table and need to upgrade into the
	//    new format. runCredentialUpdates will handle this for us.
	if err = c.runCredentialUpdates(ctx, barrier, needPersist, standby); err != nil {
		c.logger.Error("failed to run legacy auth mount table upgrades", "error", err)
		return false, err
	}

	// We loaded a legacy auth mount table and successfully migrated it, if
	// necessary.
	return true, nil
}

// loadLegacyCredentialsForNamespace reads the legacy, single-entry combined
// auth mount table of a provided namespace and loads it to memory.
func (c *Core) loadLegacyCredentialsForNamespace(ctx context.Context, ns *namespace.Namespace) error {
	if c.NamespaceSealed(ns) {
		return barrier.ErrNamespaceSealed
	}

	if ns.Tainted {
		c.logger.Info("skipping loading auth mounts for tainted namespace", "ns", ns.ID)
		return nil
	}

	view := c.NamespaceView(ns)
	entry, localEntry, err := getLegacyCredentialsForNamespace(ctx, view)
	if err != nil {
		c.logger.Error("failed to get legacy auth mounts for namespace", "error", err, "namespace", ns.ID)
		return err
	}

	if entry != nil {
		mEntries, err := c.decodeMountEntries(ctx, entry)
		if err != nil {
			c.logger.Error("failed to decompress and/or decode the legacy auth table", "error", err)
			return err
		}
		c.auth.Entries = append(c.auth.Entries, mEntries...)
	}

	if localEntry != nil {
		mEntries, err := c.decodeMountEntries(ctx, localEntry)
		if err != nil {
			c.logger.Error("failed to decompress and/or decode the local legacy auth table", "error", err)
			return err
		}
		c.auth.Entries = append(c.auth.Entries, mEntries...)
	}

	return nil
}

// getLegacyCredentialsForNamespace retrieves the single-entry combined
// mount table entry (global & local) using provided barrier.
func getLegacyCredentialsForNamespace(ctx context.Context, barrier logical.Storage) (*logical.StorageEntry, *logical.StorageEntry, error) {
	globalEntry, err := barrier.Get(ctx, coreAuthConfigPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read legacy auth mounts: %w", err)
	}

	localEntry, err := barrier.Get(ctx, coreLocalAuthConfigPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read legacy local auth mounts: %w", err)
	}

	return globalEntry, localEntry, nil
}

// Note that this is only designed to work with singletons, as it checks by
// type only.
func (c *Core) runCredentialUpdates(ctx context.Context, barrier logical.Storage, needPersist, standby bool) error {
	// Upgrade to typed auth table
	if c.auth.Type == "" {
		c.auth.Type = routing.CredentialTableType
		needPersist = true
	}

	// Upgrade to table-scoped entries
	for _, entry := range c.auth.Entries {
		if entry.Table == "" {
			entry.Table = c.auth.Type
			needPersist = true
		}
		if entry.Accessor == "" {
			accessor, err := c.generateMountAccessor("auth_" + entry.Type)
			if err != nil {
				return err
			}
			entry.Accessor = accessor
			needPersist = true
		}
		if entry.BackendAwareUUID == "" {
			bUUID, err := uuid.GenerateUUID()
			if err != nil {
				return err
			}
			entry.BackendAwareUUID = bUUID
			needPersist = true
		}

		// Don't store built-in version in the auth mount table, to make upgrades smoother.
		if versions.IsBuiltinVersion(entry.Version) {
			entry.Version = ""
			needPersist = true
		}

		if entry.NamespaceID == "" {
			entry.NamespaceID = namespace.RootNamespaceID
			needPersist = true
		}
		ns, err := c.NamespaceByID(ctx, entry.NamespaceID)
		if err != nil {
			return err
		}
		if ns == nil {
			return namespace.ErrNoNamespace
		}
		entry.Namespace = ns

		// Sync values to the cache
		entry.SyncCache()
	}

	if !needPersist {
		return nil
	}

	// Ignore the intent to persist the mount table if this is a standby node;
	// this can happen when upgrading from a legacy mount table but the cluster
	// hasn't unsealed as primary yet.
	if standby {
		return nil
	}

	if err := c.persistAuth(ctx, barrier, c.auth, nil, ""); err != nil {
		c.logger.Error("failed to persist auth table", "error", err)
		return errLoadAuthFailed
	}

	return nil
}

// persistAuth is used to persist the auth table after modification
func (c *Core) persistAuth(ctx context.Context, barrier logical.Storage, table *routing.MountTable, local *bool, mount string) error {
	if barrier == nil {
		return errors.New("nil barrier encountered while persisting auth mount changes")
	}

	// Gracefully handle a transaction-aware backend, if a transaction
	// wasn't created for us. This is safe as we do not support nested
	// transactions.
	needTxnCommit := false
	if txnBarrier, ok := barrier.(logical.TransactionalStorage); ok {
		var err error
		barrier, err = txnBarrier.BeginTx(ctx)
		if err != nil {
			return fmt.Errorf("failed to begin transaction to persist auth mounts: %w", err)
		}

		needTxnCommit = true

		// In the event of an unexpected error, rollback this transaction.
		// A rollback of a committed transaction does not impact the commit.
		defer barrier.(logical.Transaction).Rollback(ctx) //nolint:errcheck
	}

	if table.Type != routing.CredentialTableType {
		c.logger.Error("given table to persist has wrong type", "actual_type", table.Type, "expected_type", routing.CredentialTableType)
		return errors.New("invalid table type given, not persisting")
	}

	nonLocalAuth := &routing.MountTable{
		Type: routing.CredentialTableType,
	}

	localAuth := &routing.MountTable{
		Type: routing.CredentialTableType,
	}

	for _, entry := range table.Entries {
		if entry.Table != table.Type {
			c.logger.Error("given entry to persist in auth table has wrong table value", "path", entry.Path, "entry_table_type", entry.Table, "actual_type", table.Type)
			return errors.New("invalid auth entry found, not persisting")
		}

		if entry.Local {
			localAuth.Entries = append(localAuth.Entries, entry)
		} else {
			nonLocalAuth.Entries = append(nonLocalAuth.Entries, entry)
		}

		// We potentially modified the auth mount table entry so update the
		// map accordingly.
		entry.SyncCache()
	}

	// Handle writing the legacy auth mount table by default.
	writeTable := func(mt *routing.MountTable, path string) (int, error) {
		allNamespaces, err := c.ListNamespaces(ctx)
		if err != nil {
			return -1, fmt.Errorf("failed to list namespaces: %w", err)
		}

		var size int
		for _, ns := range allNamespaces {
			mountCopy := mt.ShallowClone()
			mountCopy.Entries = slices.DeleteFunc(mountCopy.Entries, func(e *routing.MountEntry) bool {
				return e.NamespaceID != ns.ID
			})

			// Encode the auth mount table into JSON and compress it (Gzip).
			compressedBytes, err := jsonutil.EncodeJSONAndCompress(mountCopy, nil)
			if err != nil {
				c.logger.Error("failed to encode or compress auth mount table", "error", err)
				return -1, err
			}

			// Create an entry
			entry := &logical.StorageEntry{
				Key:   path,
				Value: compressedBytes,
			}

			if err := c.NamespaceView(ns).Put(ctx, entry); err != nil {
				c.logger.Error("failed to persist auth mount table", "error", err)
				return -1, err
			}
			size += len(compressedBytes)
		}

		return size, nil
	}

	if _, ok := barrier.(logical.Transaction); ok {
		// Write a transactional-aware mount table series instead.
		writeTable = func(mt *routing.MountTable, prefix string) (int, error) {
			var size int
			var found bool
			currentEntries := make(map[string]struct{}, len(mt.Entries))
			for index, mtEntry := range mt.Entries {
				if mount != "" && mtEntry.UUID != mount {
					continue
				}

				found = true
				currentEntries[mtEntry.UUID] = struct{}{}

				// Encode the mount table into JSON. There is little value in
				// compressing short entries.
				path := path.Join(prefix, mtEntry.UUID)
				encoded, err := jsonutil.EncodeJSON(mtEntry)
				if err != nil {
					c.logger.Error("failed to encode auth mount table entry", "index", index, "uuid", mtEntry.UUID, "error", err)
					return -1, err
				}

				// Create a storage entry.
				sEntry := &logical.StorageEntry{
					Key:   path,
					Value: encoded,
				}

				// Write to the backend.
				if err := barrier.Put(ctx, sEntry); err != nil {
					c.logger.Error("failed to persist auth mount table entry", "index", index, "uuid", mtEntry.UUID, "error", err)
					return -1, err
				}

				size += len(encoded)
			}

			if mount != "" && !found {
				// Remove this mount from storage if it is not in the mount
				// table passed to this function anymore.
				ns, err := namespace.FromContext(ctx)
				if err != nil {
					return -1, err
				}

				if err := barrier.Delete(ctx, path.Join(prefix, mount)); err != nil {
					c.logger.Error("failed to persist removal of auth mount table entry", "namespace", ns.Path, "uuid", mount, "error", err)
					return -1, fmt.Errorf("failed to remove auth mount from storage: %w", err)
				}
			}

			if mount == "" {
				allNamespaces, err := c.ListNamespaces(ctx)
				if err != nil {
					return -1, fmt.Errorf("failed to list namespaces: %w", err)
				}

				for nsIndex, ns := range allNamespaces {
					// List all entries and remove any deleted ones.
					presentEntries, err := barrier.List(ctx, prefix+"/")
					if err != nil {
						return -1, fmt.Errorf("failed to list entries in namespace %v (%v) for removal: %w", ns.ID, nsIndex, err)
					}

					for index, presentEntry := range presentEntries {
						if _, present := currentEntries[presentEntry]; present {
							continue
						}

						if err := barrier.Delete(ctx, prefix+"/"+presentEntry); err != nil {
							return -1, fmt.Errorf("failed to remove deleted mount %v (%d) in namespace %v (%v): %w", presentEntry, index, ns.ID, nsIndex, err)
						}
					}
				}
			}

			// Finally, delete the legacy entries, if any.
			if err := barrier.Delete(ctx, prefix); err != nil {
				return -1, err
			}

			return size, nil
		}
	}

	var err error
	var compressedBytesLen int
	switch {
	case local == nil:
		// Write non-local mounts
		compressedBytesLen, err = writeTable(nonLocalAuth, coreAuthConfigPath)
		if err != nil {
			return err
		}
		c.tableMetrics(routing.CredentialTableType, false, len(nonLocalAuth.Entries), compressedBytesLen)

		// Write local mounts
		compressedBytesLen, err = writeTable(localAuth, coreLocalAuthConfigPath)
		if err != nil {
			return err
		}
		c.tableMetrics(routing.CredentialTableType, true, len(localAuth.Entries), compressedBytesLen)
	case *local:
		compressedBytesLen, err = writeTable(localAuth, coreLocalAuthConfigPath)
		if err != nil {
			return err
		}
		c.tableMetrics(routing.CredentialTableType, true, len(localAuth.Entries), compressedBytesLen)
	default:
		compressedBytesLen, err = writeTable(nonLocalAuth, coreAuthConfigPath)
		if err != nil {
			return err
		}
		c.tableMetrics(routing.CredentialTableType, false, len(nonLocalAuth.Entries), compressedBytesLen)
	}

	if needTxnCommit {
		if err := barrier.(logical.Transaction).Commit(ctx); err != nil {
			return fmt.Errorf("failed to persist mounts inside transaction: %w", err)
		}
	}

	return nil
}

// setupCredentials is invoked after we've loaded the auth mount table
// to initialize the credential backends and setup the router.
func (c *Core) setupCredentials(ctx context.Context) error {
	c.authLock.Lock()
	defer c.authLock.Unlock()

	for _, entry := range c.auth.SortEntriesByPathDepth().Entries {
		postUnsealFunc, err := c.setupCredential(ctx, entry)
		if err != nil {
			return err
		}

		if postUnsealFunc != nil {
			c.postUnsealFuncs = append(c.postUnsealFuncs, postUnsealFunc)
		}
	}

	return nil
}

// setupCredentialsForNamespace is invoked after we've loaded auth mounts
// of a namespace to initialize the credential backends and update the router.
func (c *Core) setupCredentialsForNamespace(ctx context.Context, ns *namespace.Namespace) ([]func(), error) {
	c.authLock.Lock()
	defer c.authLock.Unlock()

	postUnsealFuncs := make([]func(), 0)
	for _, entry := range c.auth.SortEntriesByPath().Entries {
		// Only process entries with matching namespace ID
		if entry.NamespaceID != ns.ID {
			continue
		}

		postUnsealFunc, err := c.setupCredential(ctx, entry)
		if err != nil {
			return postUnsealFuncs, err
		}

		if postUnsealFunc != nil {
			postUnsealFuncs = append(postUnsealFuncs, postUnsealFunc)
		}
	}

	return postUnsealFuncs, nil
}

// setupCredential initializes the credential backend
// and updates the router for specific mount entry.
func (c *Core) setupCredential(ctx context.Context, entry *routing.MountEntry) (func(), error) {
	view, err := c.mountEntryView(entry)
	if err != nil {
		return nil, err
	}

	origViewReadOnlyErr := view.GetReadOnlyErr()

	// Mark the view as read-only until the mounting is complete and
	// ensure that it is reset after. This ensures that there will be no
	// writes during the construction of the backend.
	view.SetReadOnlyErr(logical.ErrSetupReadOnly)
	if slices.Contains(singletonMounts, entry.Type) {
		defer view.SetReadOnlyErr(origViewReadOnlyErr)
	}

	// Initialize the backend
	var backend logical.Backend
	sysView := c.mountEntrySysView(entry)
	backend, entry.RunningSha256, err = c.newCredentialBackend(ctx, entry, sysView, view)
	if err != nil {
		c.logger.Error("failed to create credential entry", "path", entry.Path, "error", err)
		if !c.isMountable(ctx, entry, consts.PluginTypeCredential) {
			return nil, errLoadAuthFailed
		}

		c.logger.Warn("skipping plugin-based auth entry", "path", entry.Path)
	} else {
		// update the entry running version with the configured
		// version, which was verified during registration.
		entry.RunningVersion = entry.Version
		if entry.RunningVersion == "" && entry.RunningSha256 == "" {
			// don't set the running version to a builtin if it is running as an external plugin
			entry.RunningVersion = versions.GetBuiltinVersion(consts.PluginTypeCredential, entry.Type)
		}

		// Do not start up deprecated builtin plugins. If this is a major
		// upgrade, stop unsealing and shutdown. If we've already mounted this
		// plugin, skip backend initialization and mount the data for posterity.
		if versions.IsBuiltinVersion(entry.RunningVersion) {
			_, err := c.handleDeprecatedMountEntry(ctx, entry, consts.PluginTypeCredential)
			if c.isMajorVersionFirstMount(ctx) && err != nil {
				go c.ShutdownCoreError(fmt.Errorf("could not mount %q: %w", entry.Type, err))
				return nil, errLoadAuthFailed
			} else if err != nil {
				c.logger.Error("skipping deprecated auth entry", "name", entry.Type, "path", entry.Path, "error", err)
				backend.Cleanup(ctx)
				backend = nil
			}
		}
	}

	if backend != nil {
		// Check for the correct backend type
		backendType := backend.Type()
		if backendType != logical.TypeCredential {
			return nil, fmt.Errorf("cannot mount %q of type %q as an auth backend", entry.Type, backendType)
		}
	}

	path := routing.CredentialRoutePrefix + entry.Path
	if err = c.router.Mount(backend, path, entry, view); err != nil {
		c.logger.Error("failed to mount auth entry", "path", entry.Path, "namespace", entry.Namespace, "error", err)
		return nil, errLoadAuthFailed
	}

	// Check if this is the token store
	if entry.Type == routing.MountTypeToken {
		c.tokenStore = backend.(*TokenStore)

		// At some point when this isn't beta we may persist this but for
		// now always set it on mount
		entry.Config.TokenType = logical.TokenTypeDefaultService

		// this is loaded *after* the normal mounts, including cubbyhole
		c.router.SetTokenStoreSaltFunc(c.tokenStore.Salt)
		c.tokenStore.cubbyholeBackend = c.router.MatchingBackend(ctx, routing.MountPathCubbyhole).(*CubbyholeBackend)
	}

	// Bind locally as mount entry might be mutated in-between.
	localEntry := entry
	postUnsealFunc := func() {
		postUnsealLogger := c.logger.With("type", localEntry.Type, "version", localEntry.RunningVersion, "path", localEntry.Path)
		if backend == nil {
			postUnsealLogger.Error("skipping initialization for nil auth backend")
			return
		}
		if !slices.Contains(singletonMounts, localEntry.Type) {
			view.SetReadOnlyErr(origViewReadOnlyErr)
		}

		err := backend.Initialize(ctx, &logical.InitializationRequest{Storage: view})
		if err != nil {
			postUnsealLogger.Error("failed to initialize auth backend", "error", err)
		}
	}

	if c.logger.IsInfo() {
		c.logger.Info("successfully mounted", "type", entry.Type, "version", entry.RunningVersion, "path", entry.Path, "namespace", entry.Namespace)
	}

	// Ensure the path is tainted if set in the auth table.
	if entry.Tainted {
		// Calculate any namespace prefixes here, because when Taint() is called, there won't be
		// a namespace to pull from the context. This is similar to what we do above in c.router.Mount().
		path = entry.Namespace.Path + path
		c.logger.Debug("tainting a mount due to it being marked as tainted in auth table", "entry.path", entry.Path, "entry.namespace.path", entry.Namespace.Path, "full_path", path)
		if err := c.router.Taint(ctx, path); err != nil {
			return nil, err
		}
	}

	return postUnsealFunc, nil
}

// teardownCredentials is used before we seal the vault to reset the credential
// backends to their unloaded state. This is reversed by loadCredentials.
func (c *Core) teardownCredentials(ctx context.Context) error {
	c.authLock.Lock()
	defer c.authLock.Unlock()

	if c.auth != nil {
		authTable := c.auth.ShallowClone()
		for _, e := range authTable.Entries {
			backend := c.router.MatchingBackend(namespace.ContextWithNamespace(ctx, e.Namespace), routing.CredentialRoutePrefix+e.Path)
			if backend != nil {
				backend.Cleanup(ctx)
			}
		}
	}

	c.auth = nil

	if c.tokenStore != nil {
		c.tokenStore.teardown()
		c.tokenStore = nil
	}

	return nil
}

// newCredentialBackend is used to create and configure a new credential backend by name.
// It also returns the SHA256 of the plugin, if available.
func (c *Core) newCredentialBackend(ctx context.Context, entry *routing.MountEntry, sysView logical.SystemView, view logical.Storage) (logical.Backend, string, error) {
	t := entry.Type
	if alias, ok := credentialAliases[t]; ok {
		t = alias
	}

	var runningSha string
	f, ok := c.credentialBackends[t]
	if !ok {
		plug, err := c.pluginCatalog.Get(ctx, t, consts.PluginTypeCredential, entry.Version)
		if err != nil {
			return nil, "", err
		}
		if plug == nil {
			errContext := t
			if entry.Version != "" {
				errContext += fmt.Sprintf(", version=%s", entry.Version)
			}
			return nil, "", fmt.Errorf("%w: %s", ErrPluginNotFound, errContext)
		}
		if len(plug.Sha256) > 0 {
			runningSha = hex.EncodeToString(plug.Sha256)
		}

		f = plugin.Factory
		if !plug.Builtin {
			f = wrapFactoryCheckPerms(c, plugin.Factory)
		}
	}
	// Set up conf to pass in plugin_name
	conf := make(map[string]string)
	maps.Copy(conf, entry.Options)

	switch entry.Type {
	case "plugin":
		conf["plugin_name"] = entry.Config.PluginName
	default:
		conf["plugin_name"] = t
	}

	conf["plugin_type"] = consts.PluginTypeCredential.String()
	conf["plugin_version"] = entry.Version

	authLogger := c.baseLogger.Named(fmt.Sprintf("auth.%s.%s", t, entry.Accessor))
	c.AddLogger(authLogger)

	config := &logical.BackendConfig{
		StorageView: view,
		Logger:      authLogger,
		Config:      conf,
		System:      sysView,
		BackendUUID: entry.BackendAwareUUID,
	}

	b, err := f(ctx, config)
	if err != nil {
		return nil, "", err
	}
	if b == nil {
		return nil, "", fmt.Errorf("nil backend of type %q returned from factory", t)
	}

	return b, runningSha, nil
}

// defaultAuthTable creates a default auth table
func (c *Core) defaultAuthTable(ctx context.Context) (*routing.MountTable, error) {
	ns, err := namespace.FromContext(ctx)
	if err != nil && !errors.Is(err, namespace.ErrNoNamespace) {
		return nil, err
	}
	if ns == nil {
		ns = namespace.RootNamespace
	}

	table := &routing.MountTable{
		Type: routing.CredentialTableType,
	}
	tokenUUID, err := uuid.GenerateUUID()
	if err != nil {
		return nil, fmt.Errorf("could not generate UUID for default auth table token entry: %w", err)
	}
	tokenAccessor, err := c.generateMountAccessor("auth_token")
	if err != nil {
		return nil, fmt.Errorf("could not generate accessor for default auth table token entry: %w", err)
	}
	tokenBackendUUID, err := uuid.GenerateUUID()
	if err != nil {
		return nil, fmt.Errorf("could not create identity backend UUID: %w", err)
	}
	tokenAuth := &routing.MountEntry{
		Table:            routing.CredentialTableType,
		Path:             "token/",
		Type:             routing.MountTypeToken,
		Description:      "token based credentials",
		UUID:             tokenUUID,
		Accessor:         tokenAccessor,
		BackendAwareUUID: tokenBackendUUID,
		NamespaceID:      ns.ID,
		Namespace:        ns,
	}

	if ns.ID != namespace.RootNamespaceID {
		tokenAuth.Type = routing.MountTypeNSToken
	}

	table.Entries = append(table.Entries, tokenAuth)
	return table, nil
}
