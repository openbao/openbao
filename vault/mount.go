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
	"reflect"
	"slices"
	"strings"

	metrics "github.com/hashicorp/go-metrics/compat"
	"github.com/hashicorp/go-uuid"
	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/builtin/plugin"
	"github.com/openbao/openbao/helper/metricsutil"
	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/helper/versions"
	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/openbao/openbao/sdk/v2/helper/jsonutil"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/vault/barrier"
	ident "github.com/openbao/openbao/vault/identity"
	"github.com/openbao/openbao/vault/routing"
)

const (
	// coreMountConfigPath is used to store the mount configuration.
	// Mounts are protected within the Vault itself, which means they
	// can only be viewed or modified after an unseal.
	coreMountConfigPath = "core/mounts"

	// coreLocalMountConfigPath is used to store mount configuration for local
	// (non-replicated) mounts
	coreLocalMountConfigPath = "core/local-mounts"

	// backendBarrierPrefix is the prefix to the UUID used in the
	// barrier view for the backends.
	backendBarrierPrefix = "logical/"
)

// DeprecationStatus errors
var (
	errMountDeprecated     = errors.New("mount entry associated with deprecated builtin")
	errMountPendingRemoval = errors.New("mount entry associated with pending removal builtin")
	errMountRemoved        = errors.New("mount entry associated with removed builtin")
)

var (
	// loadMountsFailed if loadMounts encounters an error
	errLoadMountsFailed = errors.New("failed to setup mount table")

	// protectedMounts cannot be remounted
	protectedMounts = []string{
		"audit/",
		"auth/",
		routing.MountPathSystem,
		routing.MountPathCubbyhole,
		routing.MountPathIdentity,
	}

	untunableMounts = []string{
		routing.MountPathCubbyhole,
		routing.MountPathSystem,
		"audit/",
		routing.MountPathIdentity,
	}

	// singletonMounts can only exist in one location and are
	// loaded by default. These are types, not paths.
	singletonMounts = []string{
		routing.MountTypeCubbyhole,
		routing.MountTypeNSCubbyhole,
		routing.MountTypeSystem,
		routing.MountTypeNSSystem,
		routing.MountTypeToken,
		routing.MountTypeNSToken,
		routing.MountTypeIdentity,
		routing.MountTypeNSIdentity,
	}

	// mountAliases maps old backend names to new backend names, allowing us
	// to move/rename backends but maintain backwards compatibility
	mountAliases = map[string]string{"generic": "kv"}
)

func knownMountType(entryType string) error {
	switch entryType {
	case routing.MountTypeKV, routing.MountTypeSystem, routing.MountTypeCubbyhole, routing.MountTypeNSSystem, routing.MountTypeNSCubbyhole:
	default:
		return fmt.Errorf(`unknown backend type: "%s"`, entryType)
	}

	return nil
}

func (c *Core) generateMountAccessor(entryType string) (string, error) {
	var accessor string
	for {
		randBytes, err := uuid.GenerateRandomBytes(4)
		if err != nil {
			return "", err
		}
		accessor = fmt.Sprintf("%s_%s", entryType, fmt.Sprintf("%08x", randBytes[0:4]))
		if entry := c.router.MatchingMountByAccessor(accessor); entry == nil {
			break
		}
	}

	return accessor, nil
}

func (c *Core) decodeMountEntries(ctx context.Context, entry *logical.StorageEntry) ([]*routing.MountEntry, error) {
	mountTable := new(routing.MountTable)
	if err := jsonutil.DecodeJSON(entry.Value, mountTable); err != nil {
		return nil, err
	}

	// Populate the namespace in memory
	for _, entry := range mountTable.Entries {
		if entry.NamespaceID == "" {
			entry.NamespaceID = namespace.RootNamespaceID
		}

		ns, err := c.NamespaceByID(ctx, entry.NamespaceID)
		if err != nil {
			return nil, err
		}

		if ns == nil {
			c.logger.Error("namespace on mount entry not found", "namespace_id", entry.NamespaceID, "mount_path", entry.Path, "mount_description", entry.Description)
			continue
		}
		entry.Namespace = ns
	}

	return mountTable.Entries, nil
}

func (c *Core) fetchAndDecodeMountTableEntry(ctx context.Context, barrier logical.Storage, prefix string, uuid string) (*routing.MountEntry, error) {
	path := path.Join(prefix, uuid)
	sEntry, err := barrier.Get(ctx, path)
	if err != nil {
		return nil, err
	}
	if sEntry == nil {
		return nil, errors.New("unexpected empty storage entry for mount")
	}

	entry := new(routing.MountEntry)
	if err := jsonutil.DecodeJSON(sEntry.Value, entry); err != nil {
		return nil, err
	}

	if entry.UUID == "" {
		entry.UUID = uuid
	} else if entry.UUID != uuid {
		return nil, fmt.Errorf("mismatch between mount entry uuid in path (%v) and value (%v)", uuid, entry.UUID)
	}

	if entry.NamespaceID == "" {
		entry.NamespaceID = namespace.RootNamespaceID
	}
	ns, err := c.NamespaceByID(ctx, entry.NamespaceID)
	if err != nil {
		return nil, err
	}
	if ns == nil {
		c.logger.Error("namespace on mount entry not found", "table", prefix, "uuid", uuid, "namespace_id", entry.NamespaceID, "mount_path", entry.Path, "mount_description", entry.Description)
		return nil, nil
	}

	entry.Namespace = ns

	return entry, nil
}

// Mount is used to mount a new backend to the mount table.
func (c *Core) mount(ctx context.Context, entry *routing.MountEntry) error {
	// Ensure we end the path in a slash
	if !strings.HasSuffix(entry.Path, "/") {
		entry.Path += "/"
	}

	// Prevent protected paths from being mounted
	for _, p := range protectedMounts {
		if strings.HasPrefix(entry.Path, p) && entry.Namespace == nil {
			return logical.CodedError(403, "cannot mount %q", entry.Path)
		}
	}

	// Do not allow more than one instance of a singleton mount
	if slices.Contains(singletonMounts, entry.Type) {
		return logical.CodedError(403, "mount type of %q is not mountable", entry.Type)
	}

	// Mount internally
	if err := c.mountInternal(ctx, entry, true); err != nil {
		return err
	}

	return nil
}

func (c *Core) mountInternal(ctx context.Context, entry *routing.MountEntry, updateStorage bool) error {
	c.mountsLock.Lock()
	c.authLock.Lock()
	defer c.authLock.Unlock()
	defer c.mountsLock.Unlock()

	return c.mountInternalWithLock(ctx, entry, updateStorage)
}

func (c *Core) mountInternalWithLock(ctx context.Context, entry *routing.MountEntry, updateStorage bool) error {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return err
	}

	entry.NamespaceID = ns.ID
	entry.Namespace = ns

	// Basic check for matching names
	for _, ent := range c.mounts.Entries {
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

	// Verify there are no conflicting mounts in the router
	if match := c.router.MountConflict(ctx, entry.Path); match != "" {
		return logical.CodedError(409, "existing mount at %s", match)
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
		accessor, err := c.generateMountAccessor(entry.Type)
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

	origReadOnlyErr := view.GetReadOnlyErr()

	// Mark the view as read-only until the mounting is complete and
	// ensure that it is reset after. This ensures that there will be no
	// writes during the construction of the backend.
	view.SetReadOnlyErr(logical.ErrSetupReadOnly)
	// We defer this because we're already up and running so we don't need to
	// time it for after postUnseal
	defer view.SetReadOnlyErr(origReadOnlyErr)

	var backend logical.Backend
	// Create the new backend
	sysView := c.mountEntrySysView(entry)
	backend, entry.RunningSha256, err = c.newLogicalBackend(ctx, entry, sysView, view)
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
	if backendType != logical.TypeLogical {
		if err := knownMountType(entry.Type); err != nil {
			return err
		}
	}

	// update the entry running version with the configured version, which was verified during registration.
	entry.RunningVersion = entry.Version
	if entry.RunningVersion == "" {
		// don't set the running version to a builtin if it is running as an external plugin
		if entry.RunningSha256 == "" {
			entry.RunningVersion = versions.GetBuiltinVersion(consts.PluginTypeSecrets, entry.Type)
		}
	}

	c.setCoreBackend(entry, backend, view)

	newTable := c.mounts.ShallowClone()
	newTable.Entries = append(newTable.Entries, entry)
	if updateStorage {
		if err := c.persistMounts(ctx, c.NamespaceView(ns), newTable, &entry.Local, entry.UUID); err != nil {
			if logical.ShouldForward(err) {
				return err
			}

			c.logger.Error("failed to update mount table", "error", err)
			return logical.CodedError(500, "failed to update mount table")
		}
	}
	c.mounts = newTable

	if err := c.router.Mount(backend, entry.Path, entry, view); err != nil {
		return err
	}

	// restore the original readOnlyErr, so we can write to the view in
	// Initialize() if necessary
	view.SetReadOnlyErr(origReadOnlyErr)
	// initialize, using the core's active context.
	err = backend.Initialize(c.activeContext, &logical.InitializationRequest{Storage: view})
	if err != nil {
		return err
	}

	success = true
	if c.logger.IsInfo() {
		c.logger.Info("successful mount", "namespace", entry.Namespace.Path, "path", entry.Path, "type", entry.Type, "version", entry.Version)
	}

	return nil
}

// builtinTypeFromMountEntry attempts to find a builtin PluginType associated
// with the specified MountEntry. Returns consts.PluginTypeUnknown if not found.
func (c *Core) builtinTypeFromMountEntry(ctx context.Context, entry *routing.MountEntry) consts.PluginType {
	if c.builtinRegistry == nil || entry == nil {
		return consts.PluginTypeUnknown
	}

	if !versions.IsBuiltinVersion(entry.RunningVersion) {
		return consts.PluginTypeUnknown
	}

	builtinPluginType := func(name string, pluginType consts.PluginType) (consts.PluginType, bool) {
		plugin, err := c.pluginCatalog.Get(ctx, name, pluginType, entry.RunningVersion)
		if err == nil && plugin != nil && plugin.Builtin {
			return plugin.Type, true
		}
		return consts.PluginTypeUnknown, false
	}

	// auth plugins have their own dedicated mount table
	if pluginType, err := consts.ParsePluginType(entry.Table); err == nil {
		if builtinType, ok := builtinPluginType(entry.Type, pluginType); ok {
			return builtinType
		}
	}

	// Check for possible matches
	var builtinTypes []consts.PluginType
	for _, pluginType := range [...]consts.PluginType{consts.PluginTypeSecrets, consts.PluginTypeDatabase} {
		if builtinType, ok := builtinPluginType(entry.Type, pluginType); ok {
			builtinTypes = append(builtinTypes, builtinType)
		}
	}

	if len(builtinTypes) == 1 {
		return builtinTypes[0]
	}

	return consts.PluginTypeUnknown
}

// Unmount is used to unmount a path. The boolean indicates whether the mount
// was found.
func (c *Core) unmount(ctx context.Context, path string) error {
	// Ensure we end the path in a slash
	if !strings.HasSuffix(path, "/") {
		path += "/"
	}

	// Prevent protected paths from being unmounted
	for _, p := range protectedMounts {
		if strings.HasPrefix(path, p) {
			return fmt.Errorf("cannot unmount %q", path)
		}
	}

	// Unmount mount internally
	if err := c.unmountInternal(ctx, path, true); err != nil {
		return err
	}

	return nil
}

func (c *Core) unmountInternal(ctx context.Context, path string, updateStorage bool) error {
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
	if err := c.taintMountEntry(ctx, ns.ID, path, updateStorage, true); err != nil {
		c.logger.Error("failed to taint mount entry for path being unmounted", "error", err, "namespace", ns.Path, "path", path)
		return err
	}

	// Taint the router path to prevent routing. Note that in-flight requests
	// are uncertain, right now.
	if err := c.router.Taint(ctx, path); err != nil {
		return err
	}

	revokeCtx := namespace.ContextWithNamespace(c.activeContext, ns)
	if backend != nil && c.rollback != nil {
		// Invoke the rollback manager a final time. This is not fatal as
		// various periodic funcs (e.g., PKI) can legitimately error; the
		// periodic rollback manager logs these errors rather than failing
		// replication like returning this error would do.
		if err := c.rollback.Rollback(revokeCtx, path); err != nil {
			c.logger.Error("ignoring rollback error during unmount", "error", err, "path", path)
			err = nil //nolint:ineffassign // this is done to be explicit about the fact that we ignore the error
		}
	}
	if backend != nil && c.expiration != nil && updateStorage {
		// Revoke all the dynamic keys
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
		if err := logical.ClearViewWithLogging(revokeCtx, view, c.logger.Named("secrets.deletion").With("namespace", ns.Path, "path", path)); err != nil {
			c.logger.Error("failed to clear view for path being unmounted", "error", err, "namespace", ns.Path, "path", path)
			return err
		}
	}

	// Remove the mount table entry
	if err := c.removeMountEntry(revokeCtx, path, updateStorage); err != nil {
		c.logger.Error("failed to remove mount entry for path being unmounted", "error", err, "namespace", ns.Path, "path", path)
		return err
	}

	// Unmount the backend entirely
	if err := c.router.Unmount(revokeCtx, path); err != nil {
		return err
	}

	if c.quotaManager != nil {
		if err := c.quotaManager.HandleBackendDisabling(revokeCtx, ns.Path, path); err != nil {
			c.logger.Error("failed to update quotas after disabling mount", "error", err, "namespace", ns.Path, "path", path)
			return err
		}
	}

	if c.logger.IsInfo() {
		c.logger.Info("successfully unmounted", "namespace", ns.Path, "path", path)
	}

	return nil
}

// removeMountEntry is used to remove an entry from the mount table
func (c *Core) removeMountEntry(ctx context.Context, path string, updateStorage bool) error {
	c.mountsLock.Lock()
	defer c.mountsLock.Unlock()

	return c.removeMountEntryWithLock(ctx, path, updateStorage)
}

func (c *Core) removeMountEntryWithLock(ctx context.Context, path string, updateStorage bool) error {
	// Remove the entry from the mount table
	newTable := c.mounts.ShallowClone()
	entry, err := newTable.Remove(ctx, path)
	if err != nil {
		return err
	}
	if entry == nil {
		c.logger.Error("nil entry found removing entry in mounts table", "path", path)
		return logical.CodedError(500, "failed to remove entry in mounts table")
	}

	// When unmounting all entries the JSON code will load back up from storage
	// as a nil slice, which kills tests...just set it nil explicitly
	if len(newTable.Entries) == 0 {
		newTable.Entries = nil
	}

	if updateStorage {
		// Update the mount table
		if err := c.persistMounts(ctx, c.NamespaceView(entry.Namespace), newTable, &entry.Local, entry.UUID); err != nil {
			c.logger.Error("failed to remove entry from mounts table", "error", err)
			return logical.CodedError(500, "failed to remove entry from mounts table")
		}
	}

	c.mounts = newTable
	return nil
}

// taintMountEntry is used to mark an entry in the mount table as tainted
func (c *Core) taintMountEntry(ctx context.Context, nsID, mountPath string, updateStorage, unmounting bool) error {
	c.mountsLock.Lock()
	defer c.mountsLock.Unlock()

	// As modifying the taint of an entry affects shallow clones,
	// we simply use the original
	entry := c.mounts.SetTaint(nsID, mountPath)
	if entry == nil {
		c.logger.Error("nil entry found tainting entry in mounts table", "path", mountPath)
		return logical.CodedError(500, "failed to taint entry in mounts table")
	}

	if updateStorage {
		// Update the mount table
		if err := c.persistMounts(ctx, c.NamespaceView(entry.Namespace), c.mounts, &entry.Local, entry.UUID); err != nil {
			c.logger.Error("failed to taint entry in mounts table", "error", err)
			return logical.CodedError(500, "failed to taint entry in mounts table: %v", err)
		}
	}

	return nil
}

// handleDeprecatedMountEntry handles the Deprecation Status of the specified
// mount entry's builtin engine. Warnings are appended to the returned response
// and logged. Errors are returned with a nil response to be processed by the
// caller.
func (c *Core) handleDeprecatedMountEntry(ctx context.Context, entry *routing.MountEntry, pluginType consts.PluginType) (*logical.Response, error) {
	resp := &logical.Response{}

	if c.builtinRegistry == nil || entry == nil {
		return nil, nil
	}

	// Allow type to be determined from mount entry when not otherwise specified
	if pluginType == consts.PluginTypeUnknown {
		pluginType = c.builtinTypeFromMountEntry(ctx, entry)
	}

	// Handle aliases
	t := entry.Type
	if alias, ok := mountAliases[t]; ok {
		t = alias
	}

	status, ok := c.builtinRegistry.DeprecationStatus(t, pluginType)
	if ok {
		switch status {
		case consts.Deprecated:
			c.logger.Warn("mounting deprecated builtin", "name", t, "type", pluginType, "path", entry.Path)
			resp.AddWarning(errMountDeprecated.Error())
			return resp, nil

		case consts.PendingRemoval:
			if c.pendingRemovalMountsAllowed {
				c.Logger().Info("mount allowed by environment variable", "env", consts.EnvVaultAllowPendingRemovalMounts)
				resp.AddWarning(errMountPendingRemoval.Error())
				return resp, nil
			}
			return nil, errMountPendingRemoval

		case consts.Removed:
			return nil, errMountRemoved
		}
	}
	return nil, nil
}

func (c *Core) remountSecretsEngineCurrentNamespace(ctx context.Context, src, dst string, updateStorage bool) error {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return err
	}

	srcPathDetails := c.splitNamespaceAndMountFromPath(ns.Path, src)
	dstPathDetails := c.splitNamespaceAndMountFromPath(ns.Path, dst)
	return c.remountSecretsEngine(ctx, srcPathDetails, dstPathDetails, updateStorage)
}

// remountSecretsEngine is used to remount a path at a new mount point.
func (c *Core) remountSecretsEngine(ctx context.Context, src, dst namespace.MountPathDetails, updateStorage bool) error {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return err
	}

	// Prevent protected paths from being remounted, or target mounts being in protected paths
	for _, p := range protectedMounts {
		if strings.HasPrefix(src.MountPath, p) {
			return fmt.Errorf("cannot remount %q", src.MountPath)
		}

		if strings.HasPrefix(dst.MountPath, p) {
			return fmt.Errorf("cannot remount to destination %+v", dst)
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
	if err := c.taintMountEntry(ctx, src.Namespace.ID, src.MountPath, updateStorage, false); err != nil {
		return err
	}

	// Taint the router path to prevent routing
	if err := c.router.Taint(ctx, srcRelativePath); err != nil {
		return err
	}

	// Invoke the rollback manager a final time. This is not fatal as
	// various periodic funcs (e.g., PKI) can legitimately error; the
	// periodic rollback manager logs these errors rather than failing
	// replication like returning this error would do.
	rCtx := namespace.ContextWithNamespace(c.activeContext, ns)
	if c.rollback != nil && c.router.MatchingBackend(ctx, srcRelativePath) != nil {
		if err := c.rollback.Rollback(rCtx, srcRelativePath); err != nil {
			c.logger.Error("ignoring rollback error during remount", "error", err, "path", src.Namespace.Path+src.MountPath)
			err = nil //nolint:ineffassign // we explicitly ignore the error
		}
	}

	revokeCtx := namespace.ContextWithNamespace(ctx, src.Namespace)
	// Revoke all the dynamic keys
	if err := c.expiration.RevokePrefix(revokeCtx, src.MountPath, true); err != nil {
		return err
	}

	c.mountsLock.Lock()
	if match := c.router.MountConflict(ctx, dstRelativePath); match != dst.Namespace.Path && match != "" {
		c.mountsLock.Unlock()
		return fmt.Errorf("path in use at %q", match)
	}

	mountEntry.Tainted = false
	mountEntry.NamespaceID = dst.Namespace.ID
	mountEntry.Namespace = dst.Namespace
	srcPath := mountEntry.Path
	mountEntry.Path = dst.MountPath

	dstBarrierView, err := c.mountEntryView(mountEntry)
	if err != nil {
		return err
	}

	// Update the mount table
	if err := c.persistMounts(ctx, c.NamespaceView(mountEntry.Namespace), c.mounts, &mountEntry.Local, mountEntry.UUID); err != nil {
		mountEntry.Namespace = src.Namespace
		mountEntry.NamespaceID = src.Namespace.ID
		mountEntry.Path = srcPath
		mountEntry.Tainted = true
		c.mountsLock.Unlock()
		return fmt.Errorf("failed to update mount table with error %+v", err)
	}

	if src.Namespace.ID != dst.Namespace.ID {
		// Handle storage entries
		if err := c.moveMountStorage(ctx, src, mountEntry); err != nil {
			c.mountsLock.Unlock()
			return err
		}
	}

	// Remount the backend
	if err := c.router.Remount(ctx, srcRelativePath, dstRelativePath, func(re *routing.RouteEntry) error {
		re.StorageView = dstBarrierView
		re.StoragePrefix = dstBarrierView.Prefix()

		return nil
	}); err != nil {
		c.mountsLock.Unlock()
		return err
	}
	c.mountsLock.Unlock()

	// Un-taint the path
	if err := c.router.Untaint(ctx, dstRelativePath); err != nil {
		return err
	}

	return nil
}

// moveMountStorage moves storage entries of a mount mountEntry to its new destination.
func (c *Core) moveMountStorage(ctx context.Context, src namespace.MountPathDetails, me *routing.MountEntry) error {
	return c.moveStorage(ctx, src, me, backendBarrierPrefix)
}

// moveAuthStorage moves storage entries of an auth mountEntry to its new destination.
func (c *Core) moveAuthStorage(ctx context.Context, src namespace.MountPathDetails, me *routing.MountEntry) error {
	return c.moveStorage(ctx, src, me, routing.CredentialRoutePrefix)
}

// moveStorage moves storage entries of a mountEntry to its new destination.
// It detects the mountEntry type.
func (c *Core) moveStorage(ctx context.Context, src namespace.MountPathDetails, me *routing.MountEntry, prefix string) error {
	srcBarrier := c.NamespaceView(src.Namespace)
	dstBarrier := c.NamespaceView(me.Namespace)

	var key string
	keys, err := srcBarrier.List(ctx, path.Join(prefix, me.UUID)+"/")
	if err != nil {
		return err
	}

	for len(keys) > 0 {
		key, keys = keys[0], keys[1:]
		entryKey := path.Join(prefix, me.UUID, key)
		if strings.HasSuffix(key, "/") {
			nestedKeys, err := srcBarrier.List(ctx, entryKey)
			if err != nil {
				return err
			}
			for k := range nestedKeys {
				nestedKeys[k] = key + nestedKeys[k]
			}

			keys = append(keys, nestedKeys...)
			continue
		}

		if err := logical.WithTransaction(ctx, srcBarrier, func(s logical.Storage) error {
			se, err := s.Get(ctx, entryKey)
			if err != nil || se == nil {
				return err
			}

			se.Key = entryKey
			if err := dstBarrier.Put(ctx, se); err != nil {
				return err
			}

			return s.Delete(ctx, entryKey)
		}); err != nil {
			return err
		}
	}

	var coreLocalPath, corePath string
	switch me.Table {
	case routing.MountTableType:
		coreLocalPath = coreLocalMountConfigPath
		corePath = coreMountConfigPath
	case routing.CredentialTableType:
		coreLocalPath = coreLocalAuthConfigPath
		corePath = coreAuthConfigPath
	default:
		return fmt.Errorf("unable to delete mount table type %q", me.Table)
	}

	if me.Local {
		return srcBarrier.Delete(ctx, path.Join(coreLocalPath, me.UUID))
	}

	return srcBarrier.Delete(ctx, path.Join(corePath, me.UUID))
}

// From an input path that has a relative namespace hierarchy followed by a mount point, return the full
// namespace of the mount point, along with the mount point without the namespace related prefix.
// For example, in a hierarchy ns1/ns2/ns3/secret-mount, when currNs is ns1 and path is ns2/ns3/secret-mount,
// this returns the namespace object for ns1/ns2/ns3/, and the string "secret-mount"
func (c *Core) splitNamespaceAndMountFromPath(currNs, path string) namespace.MountPathDetails {
	fullPath := currNs + path
	ns, mountPath := c.namespaceStore.GetNamespaceByLongestPrefix(namespace.RootContext(context.TODO()), fullPath)

	return namespace.MountPathDetails{
		Namespace: ns,
		MountPath: sanitizePath(mountPath),
	}
}

// loadMounts is invoked as part of postUnseal to load the mount table
func (c *Core) loadMounts(ctx context.Context, standby bool) error {
	// Previously, this lock would be held after attempting to read the
	// storage entries. While we could never read corrupted entries,
	// we now need to ensure we can gracefully failover from legacy to
	// transactional mount table structure. This means holding the locks
	// for longer.
	//
	// Note that this lock is used for consistency with other code during
	// system operation (when mounting and unmounting secret engines), but
	// is not strictly necessary here as unseal(...) is serial and blocks
	// startup until finished.
	c.mountsLock.Lock()
	defer c.mountsLock.Unlock()

	// Start with an empty mount table.
	c.mounts = nil

	// Migrating mounts from the previous single-entry to a transactional
	// variant requires careful surgery that should only be done in the
	// event the backend is transactionally aware. Otherwise, we'll continue
	// to use the legacy storage format indefinitely.
	//
	// This does mean that going backwards (from a transaction-aware storage
	// to not) is not possible without manual reconstruction.
	txnableBarrier, ok := c.barrier.(logical.TransactionalStorage)
	if !ok {
		_, err := c.loadLegacyMounts(ctx, c.barrier, standby)
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

	legacy, err := c.loadLegacyMounts(ctx, txn, standby)
	if err != nil {
		return fmt.Errorf("failed to load legacy mounts in transaction: %w", err)
	}

	// If we have legacy mounts, migration was handled by the above. Otherwise,
	// we need to fetch the new mount table.
	if !legacy {
		c.logger.Info("reading transactional mount table")
		if err := c.loadTransactionalMounts(ctx, txn, standby); err != nil {
			return fmt.Errorf("failed to load transactional mount table: %w", err)
		}
	}

	// Finally, persist our changes.
	if err := txn.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit mount table changes: %w", err)
	}

	return nil
}

// loadMountsForNamespace is invoked as part of postNamespaceUnseal to
// load the mounts of a namespace.
func (c *Core) loadMountsForNamespace(ctx context.Context, ns *namespace.Namespace) error {
	c.mountsLock.Lock()
	defer c.mountsLock.Unlock()

	// Check if we're on a non-transactional storage
	if _, ok := c.barrier.(logical.TransactionalStorage); !ok {
		return c.loadLegacyMountsForNamespace(ctx, ns)
	}
	return c.loadTransactionalMountsForNamespace(ctx, ns)
}

// loadTransactionalMounts reads the transactional split mount table
// populates the storage if there are no existing entries.
func (c *Core) loadTransactionalMounts(ctx context.Context, barrier logical.Storage, standby bool) error {
	allNamespaces, err := c.ListNamespaces(ctx)
	if err != nil {
		return fmt.Errorf("failed to list namespaces: %w", err)
	}

	for _, ns := range allNamespaces {
		if err = c.loadTransactionalMountsForNamespace(ctx, ns); err != nil {
			return err
		}
	}

	var needPersist bool
	// This happens only on the first initialization run of the Core.
	// If there's only root namespace, and there are no mount entries in storage.
	if len(allNamespaces) == 1 && len(c.mounts.Entries) == 0 {
		c.logger.Info("no mounts in transactional mount table; adding default mount table")
		c.mounts = c.defaultMountTable(ctx)
		needPersist = true
	}

	if err = c.runMountUpdates(ctx, barrier, needPersist, standby); err != nil {
		c.logger.Error("failed to run legacy mount table upgrades", "error", err)
		return err
	}

	return nil
}

// loadTransactionalMountsForNamespace loads the mounts of a single namespace.
func (c *Core) loadTransactionalMountsForNamespace(ctx context.Context, ns *namespace.Namespace) error {
	if c.NamespaceSealed(ns) {
		return barrier.ErrNamespaceSealed
	}

	if ns.Tainted {
		c.logger.Info("skipping loading mounts for tainted namespace", "ns", ns.ID)
		return nil
	}

	view := c.NamespaceView(ns)
	globalEntries, localEntries, err := listTransactionalMountsForNamespace(ctx, view)
	if err != nil {
		return fmt.Errorf("failed to list mounts for namespace: %w", err)
	}

	for index, uuid := range globalEntries {
		entry, err := c.fetchAndDecodeMountTableEntry(ctx, view, coreMountConfigPath, uuid)
		if err != nil {
			return fmt.Errorf("error loading mount table entry ([%v] %v/%v): %w", ns.ID, index, uuid, err)
		}

		if entry != nil {
			c.mounts.Entries = append(c.mounts.Entries, entry)
		}
	}

	for index, uuid := range localEntries {
		entry, err := c.fetchAndDecodeMountTableEntry(ctx, view, coreLocalMountConfigPath, uuid)
		if err != nil {
			return fmt.Errorf("error loading local mount table entry ([%v] %v/%v): %w", ns.ID, index, uuid, err)
		}

		if entry != nil {
			c.mounts.Entries = append(c.mounts.Entries, entry)
		}
	}

	return nil
}

// listTransactionalMountsForNamespace retrieves list of mount
// entries (global & local) using provided barrier.
func listTransactionalMountsForNamespace(ctx context.Context, barrier logical.Storage) ([]string, []string, error) {
	globalEntries, err := barrier.List(ctx, coreMountConfigPath+"/")
	if err != nil {
		return nil, nil, fmt.Errorf("failed listing core mounts: %w", err)
	}

	localEntries, err := barrier.List(ctx, coreLocalMountConfigPath+"/")
	if err != nil {
		return nil, nil, fmt.Errorf("failed listing core local mounts: %w", err)
	}

	return globalEntries, localEntries, nil
}

// loadLegacyMounts reads the legacy, single-entry combined mount table,
// returning true if it was used. This will let us know (if we're inside
// a transaction) if we need to do an upgrade.
func (c *Core) loadLegacyMounts(ctx context.Context, barrier logical.Storage, standby bool) (bool, error) {
	// Load the existing mount table per namespace
	allNamespaces, err := c.ListNamespaces(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to list namespaces: %w", err)
	}

	if c.mounts == nil {
		// Create the mount table if it doesn't exist.
		c.mounts = &routing.MountTable{
			Type: routing.MountTableType,
		}
	}

	for _, ns := range allNamespaces {
		if err = c.loadLegacyMountsForNamespace(ctx, ns); err != nil {
			return false, err
		}
	}

	var needPersist bool
	if len(c.mounts.Entries) == 0 {
		// In the event we are inside a transaction, we do not yet know if
		// we have a transactional mount table; exit early and load the new format.
		if _, ok := barrier.(logical.Transaction); ok {
			return false, nil
		}
		c.logger.Info("no mounts in legacy mount table; adding default mount table")
		c.mounts = c.defaultMountTable(ctx)
		needPersist = true
	} else {
		if _, ok := barrier.(logical.Transaction); ok {
			// We know we have legacy mount table entries, so force a migration.
			c.logger.Info("migrating legacy mount table to transactional layout")
			needPersist = true
		}
	}

	// Here, we must call runMountUpdates:
	//
	// 1. We may be without any mount table and need to create the legacy
	//    table format because we don't have a transaction aware storage
	//    backend.
	// 2. We may have had a legacy mount table and need to upgrade into the
	//    new format. runMountUpdates will handle this for us.
	if err = c.runMountUpdates(ctx, barrier, needPersist, standby); err != nil {
		c.logger.Error("failed to run legacy mount table upgrades", "error", err)
		return false, err
	}

	// We loaded a legacy mount table and successfully migrated it, if
	// necessary.
	return true, nil
}

// loadLegacyMountsForNamespace reads the legacy, single-entry combined
// mount table of a provided namespace and loads it to memory.
func (c *Core) loadLegacyMountsForNamespace(ctx context.Context, ns *namespace.Namespace) error {
	if c.NamespaceSealed(ns) {
		return barrier.ErrNamespaceSealed
	}

	if ns.Tainted {
		c.logger.Info("skipping loading mounts for tainted namespace", "ns", ns.ID)
		return nil
	}

	view := c.NamespaceView(ns)
	entry, localEntry, err := getLegacyMountsForNamespace(ctx, view)
	if err != nil {
		c.logger.Error("failed to get legacy mounts for namespace", "error", err, "namespace", ns.ID)
		return err
	}

	if entry != nil {
		mEntries, err := c.decodeMountEntries(ctx, entry)
		if err != nil {
			c.logger.Error("failed to decompress and/or decode the legacy mount table", "error", err)
			return err
		}
		c.mounts.Entries = append(c.mounts.Entries, mEntries...)
	}

	if localEntry != nil {
		mEntries, err := c.decodeMountEntries(ctx, localEntry)
		if err != nil {
			c.logger.Error("failed to decompress and/or decode the legacy local mount table", "error", err)
			return err
		}
		c.mounts.Entries = append(c.mounts.Entries, mEntries...)
	}

	return nil
}

// getLegacyMountsForNamespace retrieves the single-entry combined
// mount table entry (global & local) using provided barrier.
func getLegacyMountsForNamespace(ctx context.Context, barrier logical.Storage) (*logical.StorageEntry, *logical.StorageEntry, error) {
	globalEntry, err := barrier.Get(ctx, coreMountConfigPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read legacy mount table: %w", err)
	}

	localEntry, err := barrier.Get(ctx, coreLocalMountConfigPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read legacy local mount table: %w", err)
	}

	return globalEntry, localEntry, nil
}

// Note that this is only designed to work with singletons, as it checks by
// type only.
func (c *Core) runMountUpdates(ctx context.Context, barrier logical.Storage, needPersist, standby bool) error {
	// Upgrade to typed mount table
	if c.mounts.Type == "" {
		c.mounts.Type = routing.MountTableType
		needPersist = true
	}

	requiredMounts, err := c.requiredMountTable(ctx)
	if err != nil {
		panic(err.Error())
	}
	for _, requiredMount := range requiredMounts.Entries {
		foundRequired := false
		for _, coreMount := range c.mounts.Entries {
			if coreMount.Type == requiredMount.Type {
				foundRequired = true
				coreMount.Config = requiredMount.Config

				// Since we're potentially updating the config here, sync the
				// cache.
				coreMount.SyncCache()
				break
			}
		}

		// In a replication scenario we will let sync invalidation take
		// care of creating a new required mount that doesn't exist yet.
		// This should only happen in the upgrade case where a new one is
		// introduced on the primary; otherwise initial bootstrapping will
		// ensure this comes over. If we upgrade first, we simply don't
		// create the mount, so we won't conflict when we sync. If this is
		// local (e.g. cubbyhole) we do still add it.
		if !foundRequired {
			c.mounts.Entries = append(c.mounts.Entries, requiredMount)
			needPersist = true
		}
	}

	// Upgrade to table-scoped entries
	for _, entry := range c.mounts.Entries {
		if entry.Type == routing.MountTypeNSCubbyhole && !entry.Local {
			entry.Local = true
			needPersist = true
		}
		if entry.Type == routing.MountTypeCubbyhole && !entry.Local {
			entry.Local = true
			needPersist = true
		}
		if entry.Table == "" {
			entry.Table = c.mounts.Type
			needPersist = true
		}
		if entry.Accessor == "" {
			accessor, err := c.generateMountAccessor(entry.Type)
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

		// Don't store built-in version in the mount table, to make upgrades smoother.
		if versions.IsBuiltinVersion(entry.Version) {
			entry.Version = ""
			needPersist = true
		}

		// Sync values to the cache
		entry.SyncCache()
	}
	// Done if we have restored the mount table and we don't need
	// to persist
	if !needPersist {
		return nil
	}

	// Ignore the intent to persist the mount table if this is a standby node;
	// this can happen when upgrading from a legacy mount table but the cluster
	// hasn't unsealed as primary yet.
	if standby {
		return nil
	}

	// Persist both mount tables
	if err := c.persistMounts(ctx, barrier, c.mounts, nil, ""); err != nil {
		c.logger.Error("failed to persist mount table", "error", err)
		return errLoadMountsFailed
	}
	return nil
}

// persistMounts is used to persist the mount table after modification.
func (c *Core) persistMounts(ctx context.Context, barrier logical.Storage, table *routing.MountTable, local *bool, mount string) error {
	if barrier == nil {
		return errors.New("nil barrier encountered while persisting mount changes")
	}

	// Gracefully handle a transaction-aware backend, if a transaction
	// wasn't created for us. This is safe as we do not support nested
	// transactions.
	needTxnCommit := false
	if txnBarrier, ok := barrier.(logical.TransactionalStorage); ok {
		var err error
		barrier, err = txnBarrier.BeginTx(ctx)
		if err != nil {
			return fmt.Errorf("failed to begin transaction to persist mounts: %w", err)
		}

		needTxnCommit = true

		// In the event of an unexpected error, rollback this transaction.
		// A rollback of a committed transaction does not impact the commit.
		defer barrier.(logical.Transaction).Rollback(ctx) //nolint:errcheck
	}

	if table.Type != routing.MountTableType {
		c.logger.Error("given table to persist has wrong type", "actual_type", table.Type, "expected_type", routing.MountTableType)
		return errors.New("invalid table type given, not persisting")
	}

	nonLocalMounts := &routing.MountTable{
		Type: routing.MountTableType,
	}

	localMounts := &routing.MountTable{
		Type: routing.MountTableType,
	}

	for _, entry := range table.Entries {
		if entry.Table != table.Type {
			c.logger.Error("given entry to persist in mount table has wrong table value", "path", entry.Path, "entry_table_type", entry.Table, "actual_type", table.Type)
			return errors.New("invalid mount entry found, not persisting")
		}

		if entry.Local {
			localMounts.Entries = append(localMounts.Entries, entry)
		} else {
			nonLocalMounts.Entries = append(nonLocalMounts.Entries, entry)
		}

		// We potentially modified the mount table entry so update the map
		// accordingly.
		entry.SyncCache()
	}

	// Handle writing the legacy mount table by default.
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
					c.logger.Error("failed to encode mount table entry", "index", index, "uuid", mtEntry.UUID, "error", err)
					return -1, err
				}

				// Create a storage entry.
				sEntry := &logical.StorageEntry{
					Key:   path,
					Value: encoded,
				}

				// Write to the backend.
				if err := barrier.Put(ctx, sEntry); err != nil {
					c.logger.Error("failed to persist mount table entry", "index", index, "uuid", mtEntry.UUID, "error", err)
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
					c.logger.Error("failed to persist removal of secrets mount table entry", "namespace", ns.Path, "uuid", mount, "error", err)
					return -1, fmt.Errorf("failed to remove mount from storage: %w", err)
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
							return -1, fmt.Errorf("failed to remove deleted mount %v (%v) in namespace %v (%v): %w", presentEntry, index, ns.ID, nsIndex, err)
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
		compressedBytesLen, err = writeTable(nonLocalMounts, coreMountConfigPath)
		if err != nil {
			return err
		}
		c.tableMetrics(routing.MountTableType, false, len(nonLocalMounts.Entries), compressedBytesLen)

		// Write local mounts
		compressedBytesLen, err = writeTable(localMounts, coreLocalMountConfigPath)
		if err != nil {
			return err
		}
		c.tableMetrics(routing.MountTableType, true, len(localMounts.Entries), compressedBytesLen)

	case *local:
		// Write local mounts
		compressedBytesLen, err = writeTable(localMounts, coreLocalMountConfigPath)
		if err != nil {
			return err
		}
		c.tableMetrics(routing.MountTableType, true, len(localMounts.Entries), compressedBytesLen)
	default:
		// Write non-local mounts
		compressedBytesLen, err = writeTable(nonLocalMounts, coreMountConfigPath)
		if err != nil {
			return err
		}
		c.tableMetrics(routing.MountTableType, false, len(nonLocalMounts.Entries), compressedBytesLen)
	}

	if needTxnCommit {
		if err := barrier.(logical.Transaction).Commit(ctx); err != nil {
			return fmt.Errorf("failed to persist mounts inside transaction: %w", err)
		}
	}

	return nil
}

// setupMounts is invoked after we've loaded the mount table
// to initialize the logical backends and setup the router.
func (c *Core) setupMounts(ctx context.Context) error {
	c.mountsLock.Lock()
	defer c.mountsLock.Unlock()

	for _, entry := range c.mounts.SortEntriesByPathDepth().Entries {
		postUnsealFunc, err := c.setupMount(ctx, entry)
		if err != nil {
			return err
		}

		if postUnsealFunc != nil {
			c.postUnsealFuncs = append(c.postUnsealFuncs, postUnsealFunc)
		}
	}

	return nil
}

// setupMountsForNamespace is invoked after we've loaded mounts of a namespace
// to initialize the logical backends and update the router.
func (c *Core) setupMountsForNamespace(ctx context.Context, ns *namespace.Namespace) ([]func(), error) {
	c.mountsLock.Lock()
	defer c.mountsLock.Unlock()

	postUnsealFuncs := make([]func(), 0)
	for _, entry := range c.mounts.SortEntriesByPath().Entries {
		// Only process entries with matching namespace ID
		if entry.NamespaceID != ns.ID {
			continue
		}

		postUnsealFunc, err := c.setupMount(ctx, entry)
		if err != nil {
			return postUnsealFuncs, err
		}

		if postUnsealFunc != nil {
			postUnsealFuncs = append(postUnsealFuncs, postUnsealFunc)
		}
	}

	return postUnsealFuncs, nil
}

// setupMount initializes the logical backend
// and updates the router for specific mount entry.
func (c *Core) setupMount(ctx context.Context, entry *routing.MountEntry) (func(), error) {
	// Initialize the backend, special casing for system
	view, err := c.mountEntryView(entry)
	if err != nil {
		return nil, err
	}

	origReadOnlyErr := view.GetReadOnlyErr()

	// Mark the view as read-only until the mounting is complete and
	// ensure that it is reset after. This ensures that there will be no
	// writes during the construction of the backend.
	view.SetReadOnlyErr(logical.ErrSetupReadOnly)
	if slices.Contains(singletonMounts, entry.Type) {
		defer view.SetReadOnlyErr(origReadOnlyErr)
	}

	// Create the new backend
	var backend logical.Backend
	sysView := c.mountEntrySysView(entry)
	backend, entry.RunningSha256, err = c.newLogicalBackend(ctx, entry, sysView, view)
	if err != nil {
		c.logger.Error("failed to create mount entry", "path", entry.Path, "error", err)
		if !c.isMountable(ctx, entry, consts.PluginTypeSecrets) {
			return nil, errLoadMountsFailed
		}

		c.logger.Warn("skipping plugin-based mount entry", "path", entry.Path)
	} else {
		// update the entry running version with the configured
		// version, which was verified during registration.
		entry.RunningVersion = entry.Version
		if entry.RunningVersion == "" && entry.RunningSha256 == "" {
			// don't set the running version to a builtin if it is running as an external plugin
			entry.RunningVersion = versions.GetBuiltinVersion(consts.PluginTypeSecrets, entry.Type)
		}

		// Do not start up deprecated builtin plugins. If this is a major
		// upgrade, stop unsealing and shutdown. If we've already mounted this
		// plugin, proceed with unsealing and skip backend initialization.
		if versions.IsBuiltinVersion(entry.RunningVersion) {
			_, err := c.handleDeprecatedMountEntry(ctx, entry, consts.PluginTypeSecrets)
			if c.isMajorVersionFirstMount(ctx) && err != nil {
				go c.ShutdownCoreError(fmt.Errorf("could not mount %q: %w", entry.Type, err))
				return nil, errLoadMountsFailed
			} else if err != nil {
				c.logger.Error("skipping deprecated mount entry", "name", entry.Type, "path", entry.Path, "error", err)
				backend.Cleanup(ctx)
				backend = nil
			}
		}
	}

	if backend != nil {
		// Check for the correct backend type
		if backend.Type() != logical.TypeLogical {
			if err := knownMountType(entry.Type); err != nil {
				return nil, err
			}
		}

		c.setCoreBackend(entry, backend, view)
	}

	if err = c.router.Mount(backend, entry.Path, entry, view); err != nil {
		c.logger.Error("failed to mount entry", "path", entry.Path, "error", err)
		return nil, errLoadMountsFailed
	}

	// Bind locally as mount entry might be mutated in-between.
	localEntry := entry
	postUnsealFunc := func() {
		postUnsealLogger := c.logger.With("type", localEntry.Type, "version", localEntry.RunningVersion, "path", localEntry.Path)
		if backend == nil {
			postUnsealLogger.Error("skipping initialization for nil backend", "path", localEntry.Path)
			return
		}
		if !slices.Contains(singletonMounts, localEntry.Type) {
			view.SetReadOnlyErr(origReadOnlyErr)
		}

		err := backend.Initialize(ctx, &logical.InitializationRequest{Storage: view})
		if err != nil {
			postUnsealLogger.Error("failed to initialize mount backend", "error", err)
		}
	}

	if c.logger.IsInfo() {
		c.logger.Info("successfully mounted", "type", entry.Type, "version", entry.RunningVersion, "path", entry.Path, "namespace", entry.Namespace)
	}

	// Ensure the path is tainted if set in the mount table.
	if entry.Tainted {
		// Calculate any namespace prefixes here, because when Taint() is called, there won't be
		// a namespace to pull from the context. This is similar to what we do above in c.router.Mount().
		path := entry.Namespace.Path + entry.Path
		c.logger.Debug("tainting a mount due to it being marked as tainted in mount table", "entry.path", entry.Path, "entry.namespace.path", entry.Namespace.Path, "full_path", path)
		if err := c.router.Taint(ctx, path); err != nil {
			return nil, err
		}
	}

	return postUnsealFunc, nil
}

// unloadMounts is used before we seal the vault to reset the mounts to
// their unloaded state, calling Cleanup if defined. This is reversed by load and setup mounts.
func (c *Core) unloadMounts(ctx context.Context) error {
	c.mountsLock.Lock()
	defer c.mountsLock.Unlock()

	if c.mounts != nil {
		mountTable := c.mounts.ShallowClone()
		for _, e := range mountTable.Entries {
			backend := c.router.MatchingBackend(namespace.ContextWithNamespace(ctx, e.Namespace), e.Path)
			if backend != nil {
				backend.Cleanup(ctx)
			}
		}
	}

	c.mounts = nil
	c.router.Reset()
	c.systemBarrierView = nil
	return nil
}

// newLogicalBackend is used to create and configure a new logical backend by name.
// It also returns the SHA256 of the plugin, if available.
func (c *Core) newLogicalBackend(ctx context.Context, entry *routing.MountEntry, sysView logical.SystemView, view logical.Storage) (logical.Backend, string, error) {
	t := entry.Type
	if alias, ok := mountAliases[t]; ok {
		t = alias
	}

	var runningSha string
	f, ok := c.logicalBackends[t]
	if !ok {
		plug, err := c.pluginCatalog.Get(ctx, t, consts.PluginTypeSecrets, entry.Version)
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
	case routing.MountTypePlugin:
		conf["plugin_name"] = entry.Config.PluginName
	default:
		conf["plugin_name"] = t
	}

	conf["plugin_type"] = consts.PluginTypeSecrets.String()
	conf["plugin_version"] = entry.Version

	backendLogger := c.baseLogger.Named(fmt.Sprintf("secrets.%s.%s", t, entry.Accessor))
	c.AddLogger(backendLogger)

	config := &logical.BackendConfig{
		StorageView: view,
		Logger:      backendLogger,
		Config:      conf,
		System:      sysView,
		BackendUUID: entry.BackendAwareUUID,
	}

	ctx = namespace.ContextWithNamespace(ctx, entry.Namespace)
	ctx = context.WithValue(ctx, "core_number", c.coreNumber)
	b, err := f(ctx, config)
	if err != nil {
		return nil, "", err
	}
	if b == nil {
		return nil, "", fmt.Errorf("nil backend of type %q returned from factory", t)
	}

	return b, runningSha, nil
}

// defaultMountTable creates a default mount table
func (c *Core) defaultMountTable(ctx context.Context) *routing.MountTable {
	table := &routing.MountTable{
		Type: routing.MountTableType,
	}

	requiredMounts, err := c.requiredMountTable(ctx)
	if err != nil {
		panic(fmt.Sprintf("failed to create required mounts: %v", err))
	}
	table.Entries = append(table.Entries, requiredMounts.Entries...)

	if api.ReadBaoVariable("BAO_INTERACTIVE_DEMO_SERVER") != "" {
		mountUUID, err := uuid.GenerateUUID()
		if err != nil {
			panic(fmt.Sprintf("could not create default secret mount UUID: %v", err))
		}
		mountAccessor, err := c.generateMountAccessor(routing.MountTypeKV)
		if err != nil {
			panic(fmt.Sprintf("could not generate default secret mount accessor: %v", err))
		}
		bUUID, err := uuid.GenerateUUID()
		if err != nil {
			panic(fmt.Sprintf("could not create default secret mount backend UUID: %v", err))
		}

		kvMount := &routing.MountEntry{
			Table:            routing.MountTableType,
			Path:             "secret/",
			Type:             routing.MountTypeKV,
			Description:      "key/value secret storage",
			UUID:             mountUUID,
			Accessor:         mountAccessor,
			BackendAwareUUID: bUUID,
			Options: map[string]string{
				"version": "2",
			},
			RunningVersion: versions.GetBuiltinVersion(consts.PluginTypeSecrets, "kv"),
		}
		table.Entries = append(table.Entries, kvMount)
	}

	return table
}

// requiredMountTable() creates a mount table with entries required
// to be available
func (c *Core) requiredMountTable(ctx context.Context) (*routing.MountTable, error) {
	ns, err := namespace.FromContext(ctx)
	if err != nil && !errors.Is(err, namespace.ErrNoNamespace) {
		return nil, err
	}
	if ns == nil {
		ns = namespace.RootNamespace
	}

	table := &routing.MountTable{
		Type: routing.MountTableType,
	}
	cubbyholeUUID, err := uuid.GenerateUUID()
	if err != nil {
		return nil, fmt.Errorf("could not create cubbyhole UUID: %w", err)
	}
	cubbyholeAccessor, err := c.generateMountAccessor("cubbyhole")
	if err != nil {
		return nil, fmt.Errorf("could not generate cubbyhole accessor: %w", err)
	}
	cubbyholeBackendUUID, err := uuid.GenerateUUID()
	if err != nil {
		return nil, fmt.Errorf("could not create cubbyhole backend UUID: %w", err)
	}
	cubbyholeMount := &routing.MountEntry{
		Table:            routing.MountTableType,
		Path:             routing.MountPathCubbyhole,
		Type:             routing.MountTypeCubbyhole,
		Description:      "per-token private secret storage",
		UUID:             cubbyholeUUID,
		Accessor:         cubbyholeAccessor,
		Local:            true,
		BackendAwareUUID: cubbyholeBackendUUID,
		RunningVersion:   versions.GetBuiltinVersion(consts.PluginTypeSecrets, "cubbyhole"),

		NamespaceID: ns.ID,
		Namespace:   ns,
	}

	sysUUID, err := uuid.GenerateUUID()
	if err != nil {
		return nil, fmt.Errorf("could not create sys UUID: %w", err)
	}
	sysAccessor, err := c.generateMountAccessor("system")
	if err != nil {
		return nil, fmt.Errorf("could not generate sys accessor: %w", err)
	}
	sysBackendUUID, err := uuid.GenerateUUID()
	if err != nil {
		return nil, fmt.Errorf("could not create sys backend UUID: %w", err)
	}
	sysMount := &routing.MountEntry{
		Table:            routing.MountTableType,
		Path:             "sys/",
		Type:             routing.MountTypeSystem,
		Description:      "system endpoints used for control, policy and debugging",
		UUID:             sysUUID,
		Accessor:         sysAccessor,
		BackendAwareUUID: sysBackendUUID,
		SealWrap:         true, // Enable SealWrap since SystemBackend utilizes SealWrapStorage, see factory in addExtraLogicalBackends().
		Config: routing.MountConfig{
			PassthroughRequestHeaders: []string{"Accept"},
		},
		RunningVersion: versions.DefaultBuiltinVersion,

		NamespaceID: ns.ID,
		Namespace:   ns,
	}

	identityUUID, err := uuid.GenerateUUID()
	if err != nil {
		return nil, fmt.Errorf("could not create identity mount entry UUID: %w", err)
	}
	identityAccessor, err := c.generateMountAccessor("identity")
	if err != nil {
		return nil, fmt.Errorf("could not generate identity accessor: %w", err)
	}
	identityBackendUUID, err := uuid.GenerateUUID()
	if err != nil {
		return nil, fmt.Errorf("could not create identity backend UUID: %w", err)
	}
	identityMount := &routing.MountEntry{
		Table:            routing.MountTableType,
		Path:             "identity/",
		Type:             "identity",
		Description:      "identity store",
		UUID:             identityUUID,
		Accessor:         identityAccessor,
		BackendAwareUUID: identityBackendUUID,
		Config: routing.MountConfig{
			PassthroughRequestHeaders: []string{"Authorization"},
		},
		RunningVersion: versions.DefaultBuiltinVersion,
		NamespaceID:    ns.ID,
		Namespace:      ns,
	}

	if ns.ID != namespace.RootNamespaceID {
		cubbyholeMount.Type = routing.MountTypeNSCubbyhole
		identityMount.Type = routing.MountTypeNSIdentity
		sysMount.Type = routing.MountTypeNSSystem
	}

	table.Entries = append(table.Entries, cubbyholeMount)
	table.Entries = append(table.Entries, sysMount)
	table.Entries = append(table.Entries, identityMount)

	return table, nil
}

// This function returns tables that are singletons. The main usage of this is
// for replication, so we can send over mount info (especially, UUIDs of
// mounts, which are used for salts) for mounts that may not be able to be
// handled normally. After saving these values on the secondary, we let normal
// sync invalidation do its thing. Because of its use for replication, we
// exclude local mounts.
func (c *Core) singletonMountTables() (mounts, auth *routing.MountTable) {
	mounts = &routing.MountTable{}
	auth = &routing.MountTable{}

	c.mountsLock.RLock()
	for _, entry := range c.mounts.Entries {
		if slices.Contains(singletonMounts, entry.Type) && !entry.Local && entry.Namespace.ID == namespace.RootNamespaceID {
			mounts.Entries = append(mounts.Entries, entry)
		}
	}
	c.mountsLock.RUnlock()

	c.authLock.RLock()
	for _, entry := range c.auth.Entries {
		if slices.Contains(singletonMounts, entry.Type) && !entry.Local && entry.Namespace.ID == namespace.RootNamespaceID {
			auth.Entries = append(auth.Entries, entry)
		}
	}
	c.authLock.RUnlock()

	return mounts, auth
}

func (c *Core) setCoreBackend(entry *routing.MountEntry, backend logical.Backend, view barrier.View) {
	// bail for non-root namespace
	if entry.NamespaceID != namespace.RootNamespaceID {
		return
	}

	switch entry.Type {
	case routing.MountTypeSystem:
		c.systemBackend = backend.(*SystemBackend)
		c.systemBarrierView = view
	case routing.MountTypeCubbyhole:
		c.cubbyholeBackend = backend.(*CubbyholeBackend)
		c.cubbyholeBackend.saltUUID = entry.UUID
	case routing.MountTypeIdentity:
		c.identityStore = backend.(*ident.IdentityStore)
	}
}

func (c *Core) reloadNamespaceMounts(childCtx context.Context, uuid string, deleted bool) error {
	if _, ok := c.barrier.(logical.TransactionalStorage); !ok {
		return c.reloadLegacyMounts(childCtx)
	}

	keys := []string{}

	if deleted {
		c.mountsLock.RLock()
		for _, entry := range c.mounts.Entries {
			if entry.Namespace.UUID == uuid {
				key := path.Join(coreMountConfigPath, entry.UUID)
				if entry.Local {
					key = path.Join(coreLocalMountConfigPath, entry.UUID)
				}
				keys = append(keys, key)
			}
		}
		c.mountsLock.RUnlock()

		c.authLock.RLock()
		for _, entry := range c.auth.Entries {
			if entry.Namespace.UUID == uuid {
				key := path.Join(coreAuthConfigPath, entry.UUID)
				if entry.Local {
					key = path.Join(coreLocalAuthConfigPath, entry.UUID)
				}
				keys = append(keys, key)
			}
		}
		c.authLock.RUnlock()

		if len(keys) == 0 {
			return nil
		}
	} else {
		ns, err := namespace.FromContext(childCtx)
		if err != nil {
			return fmt.Errorf("failed to get namespace from context: %w", err)
		}

		barrier := NamespaceScopedView(c.barrier, ns)

		mountGlobal, mountLocal, err := listTransactionalMountsForNamespace(childCtx, barrier)
		if err != nil {
			return fmt.Errorf("unable to invalidate mounts for namespace %q: %w", uuid, err)
		}

		authGlobal, authLocal, err := listTransactionalCredentialsForNamespace(childCtx, barrier)
		if err != nil {
			return fmt.Errorf("unable to invalidate auths for namespace %q: %w", uuid, err)
		}

		for _, mount := range mountGlobal {
			keys = append(keys, path.Join(coreMountConfigPath, mount))
		}
		for _, mount := range mountLocal {
			keys = append(keys, path.Join(coreLocalMountConfigPath, mount))
		}
		for _, mount := range authGlobal {
			keys = append(keys, path.Join(coreAuthConfigPath, mount))
		}
		for _, mount := range authLocal {
			keys = append(keys, path.Join(coreLocalAuthConfigPath, mount))
		}
	}

	c.logger.Debug("invalidating namespace mounts", "ns", uuid, "keys", keys)
	for _, key := range keys {
		err := c.reloadMount(childCtx, key)
		if err != nil {
			return fmt.Errorf("unable to invalidate mount for key %q in namespace %q: %w", key, uuid, err)
		}
	}

	return nil
}

func (c *Core) reloadLegacyMounts(ctx context.Context, keys ...string) error {
	if len(keys) == 0 {
		keys = []string{coreMountConfigPath, coreLocalMountConfigPath, coreAuthConfigPath, coreLocalAuthConfigPath}
	}

	// If we have a transactional storage backend, assume the primary will
	// migrate us to a new storage layout and return early.
	if _, ok := c.barrier.(logical.TransactionalStorage); ok {
		return nil
	}

	ns, err := namespace.FromContext(ctx)
	if err != nil {
		if err != namespace.ErrNoNamespace {
			return fmt.Errorf("failed to extract namespace from context: %w", err)
		}
		ns = namespace.RootNamespace
	}

	type invalidation struct {
		Table             string
		DesiredMountEntry *routing.MountEntry
		Namespace         *namespace.Namespace
	}
	invalidations := map[string]invalidation{}

	for _, path := range keys {
		table := routing.MountTableType
		if path == coreAuthConfigPath && path != coreLocalAuthConfigPath {
			table = routing.CredentialTableType
		}

		view := c.NamespaceView(ns)
		raw, err := view.Get(ctx, path)
		if err != nil {
			return fmt.Errorf("failed to read legacy mount table: %w", err)
		}

		if raw != nil {
			entries, err := c.decodeMountEntries(ctx, raw)
			if err != nil {
				return fmt.Errorf("failed to decompress and/or decode the legacy mount table: %w", err)
			}

			for _, mount := range entries {
				if ns.ID != namespace.RootNamespaceID && ns.ID != mount.NamespaceID {
					continue
				}

				invalidations[mount.UUID] = invalidation{
					Table:             table,
					DesiredMountEntry: mount,
					Namespace:         mount.Namespace,
				}
			}
		}
	}

	// Loop over all mounts in memory, this is required to find mount deletions
	c.mountsLock.RLock()
	c.authLock.RLock()
	for _, table := range []*routing.MountTable{c.mounts, c.auth} {
		if table == nil {
			continue
		}
		for _, entry := range table.Entries {
			if ns.ID != namespace.RootNamespaceID && ns.ID != entry.NamespaceID {
				continue
			}

			storagePath := entry.Table
			if entry.Local {
				storagePath = "local-" + storagePath
			}
			storagePath = path.Join("core", storagePath)
			if !slices.Contains(keys, storagePath) {
				continue
			}

			if _, ok := invalidations[entry.UUID]; !ok {
				invalidations[entry.UUID] = invalidation{
					Table:             entry.Table,
					DesiredMountEntry: nil,
					Namespace:         entry.Namespace,
				}
			}
		}
	}
	c.authLock.RUnlock()
	c.mountsLock.RUnlock()

	for uuid, value := range invalidations {
		err := c.reloadMountInternal(namespace.ContextWithNamespace(ctx, value.Namespace), value.Table, uuid, value.DesiredMountEntry)
		if err != nil {
			return fmt.Errorf("unable to invalidate mount: %w", err)
		}
	}

	return nil
}

func (c *Core) reloadMount(ctx context.Context, key string) error {
	prefix, uuid := path.Split(key)
	prefix = path.Clean(prefix)

	table := routing.MountTableType
	if prefix != coreLocalMountConfigPath && prefix != coreMountConfigPath {
		if prefix != coreAuthConfigPath && prefix != coreLocalAuthConfigPath {
			return fmt.Errorf("invalid path prefix %q", prefix)
		}
		table = routing.CredentialTableType
	}

	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return err
	}

	desiredMountEntry, err := c.fetchAndDecodeMountTableEntry(ctx, c.NamespaceView(ns), prefix, uuid)
	if err != nil {
		if err.Error() != "unexpected empty storage entry for mount" {
			return err
		}
		desiredMountEntry = nil
	}

	if desiredMountEntry != nil && ns.Tainted {
		// The desired state of this mount is deleted, because we've tainted
		// this namespace. Because we're on a standby node, we don't actually
		// write to storage but let the active node handle deletion.
		c.logger.Debug("cache invalidation: marking mount as deleted due to tainted namespace", "mount_uuid", uuid, "ns_uuid", ns.UUID)
		desiredMountEntry = nil
	}

	return c.reloadMountInternalWithLock(ctx, table, uuid, desiredMountEntry)
}

func (c *Core) reloadMountInternal(ctx context.Context, table, uuid string, desiredMountEntry *routing.MountEntry) error {
	c.mountsLock.Lock()
	c.authLock.Lock()
	defer c.mountsLock.Unlock()
	defer c.authLock.Unlock()

	return c.reloadMountInternalWithLock(ctx, table, uuid, desiredMountEntry)
}

func (c *Core) reloadMountInternalWithLock(ctx context.Context, table, uuid string, desiredMountEntry *routing.MountEntry) error {
	switch table {
	case routing.CredentialTableType, routing.MountTableType:
	default:
		return fmt.Errorf("invalid mount table type passed: %q", table)
	}

	actualMountEntry := c.router.MatchingMountByUUID(uuid)

	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return err
	}

	switch {
	case desiredMountEntry == nil && actualMountEntry != nil: // mount was deleted
		c.logger.Debug("cache invalidation: mount was deleted", "type", table, "uuid", uuid)

		if table == routing.CredentialTableType {
			err = c.removeCredEntryWithLock(ctx, actualMountEntry.Path, false)
		} else {
			err = c.removeMountEntryWithLock(ctx, actualMountEntry.Path, false)
		}
		if err != nil {
			return err
		}

		routerPath := actualMountEntry.Path
		if table == routing.CredentialTableType {
			routerPath = path.Join(routing.CredentialRoutePrefix, routerPath) + "/"
		}
		if err := c.router.Unmount(ctx, routerPath); err != nil {
			return err
		}

		if c.quotaManager != nil {
			if err := c.quotaManager.HandleBackendDisabling(ctx, ns.Path, actualMountEntry.APIPathNoNamespace()); err != nil {
				c.logger.Error("failed to update quotas after disabling mount", "error", err, "namespace", ns.Path, "uuid", uuid)
				return err
			}
		}

	case desiredMountEntry != nil && actualMountEntry == nil: // mount was created
		c.logger.Debug("cache invalidation: mount was created", "type", table, "uuid", uuid)

		if table == routing.CredentialTableType {
			err = c.enableCredentialInternalWithLock(ctx, desiredMountEntry, false)
			if err != nil {
				return err
			}
		} else {
			c.logger.Info("calling mount internal", "path", desiredMountEntry.Path)
			err := c.mountInternalWithLock(ctx, desiredMountEntry, false)
			if err != nil {
				return err
			}
		}

	case desiredMountEntry != nil && actualMountEntry != nil: // mount was modified (e.g. tuned or tainted)
		c.logger.Debug("cache invalidation: mount was modified", "type", table, "uuid", uuid)
		routerPath := actualMountEntry.Path
		if table == routing.CredentialTableType {
			routerPath = path.Join(routing.CredentialRoutePrefix, routerPath) + "/"
		}

		if desiredMountEntry.Tainted != actualMountEntry.Tainted {
			if desiredMountEntry.Tainted {
				err = c.router.Taint(ctx, routerPath)
				if err != nil {
					return err
				}
				actualMountEntry.Tainted = true
			} else {
				err = c.router.Untaint(ctx, routerPath)
				if err != nil {
					return err
				}
				actualMountEntry.Tainted = false
			}
		}

		if !reflect.DeepEqual(desiredMountEntry.Config, actualMountEntry.Config) {
			actualMountEntry.Config = desiredMountEntry.Config
			actualMountEntry.SyncCache()
		}

		if desiredMountEntry.Options["version"] != actualMountEntry.Options["version"] {
			err = c.reloadBackendCommon(ctx, desiredMountEntry, table == routing.CredentialTableType)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

type FailedLoginUser struct {
	aliasName     string
	mountAccessor string
}

type FailedLoginInfo struct {
	count               uint
	lastFailedLoginTime int
}

// mountEntrySysView creates a logical.SystemView from global and
// mount-specific entries; because this should be called when setting
// up a mountEntry, it doesn't check to ensure that me is not nil
func (c *Core) mountEntrySysView(entry *routing.MountEntry) extendedSystemView {
	return extendedSystemViewImpl{
		dynamicSystemView{
			core:       c,
			mountEntry: entry,
		},
	}
}

// mountEntryView returns the barrier view object with prefix depending on the mount entry type, table and namespace.
func (c *Core) mountEntryView(me *routing.MountEntry) (barrier.View, error) {
	if me.Namespace != nil && me.Namespace.ID != me.NamespaceID {
		return nil, errors.New("invalid namespace")
	}

	switch me.Type {
	case routing.MountTypeSystem, routing.MountTypeNSSystem:
		return c.NamespaceView(me.Namespace).SubView(barrier.SystemBarrierPrefix), nil
	case routing.MountTypeToken:
		return c.NamespaceView(me.Namespace).SubView(barrier.SystemBarrierPrefix + tokenSubPath), nil
	}

	switch me.Table {
	case routing.MountTableType:
		return c.NamespaceView(me.Namespace).SubView(path.Join(backendBarrierPrefix, me.UUID) + "/"), nil
	case routing.CredentialTableType:
		return c.NamespaceView(me.Namespace).SubView(path.Join(barrier.CredentialBarrierPrefix, me.UUID) + "/"), nil
	case auditTableType, configAuditTableType:
		return NamespaceScopedView(c.barrier, me.Namespace).SubView(path.Join(auditBarrierPrefix, me.UUID) + "/"), nil
	}

	return nil, errors.New("invalid mount entry")
}

// tableMetrics is responsible for setting gauge metrics for
// mount table storage sizes (in bytes) and mount table num
// entries. It does this via setGaugeWithLabels. It then
// saves these metrics in a cache for regular reporting in
// a loop, via AddGaugeLoopMetric.

// Note that the reported storage sizes are pre-encryption
// sizes. Currently barrier uses aes-gcm for encryption, which
// preserves plaintext size, adding a constant of 30 bytes of
// padding, which is negligible and subject to change, and thus
// not accounted for.
func (c *Core) tableMetrics(tableType string, isLocal bool, entryCount, compressedTableLen int) {
	if c.metricsHelper == nil {
		// do nothing if metrics are not initialized
		return
	}

	mountTableTypeLabelMap := map[string]metrics.Label{
		routing.MountTableType:      {Name: "type", Value: "logical"},
		routing.CredentialTableType: {Name: "type", Value: "auth"},
		// we don't report number of audit mounts, but it is here for consistency
		auditTableType: {Name: "type", Value: "audit"},
	}

	localLabelMap := map[bool]metrics.Label{
		true:  {Name: "local", Value: "true"},
		false: {Name: "local", Value: "false"},
	}

	c.metricSink.SetGaugeWithLabels(metricsutil.LogicalTableSizeName,
		float32(entryCount), []metrics.Label{
			mountTableTypeLabelMap[tableType],
			localLabelMap[isLocal],
		})

	c.metricsHelper.AddGaugeLoopMetric(metricsutil.LogicalTableSizeName,
		float32(entryCount), []metrics.Label{
			mountTableTypeLabelMap[tableType],
			localLabelMap[isLocal],
		})

	c.metricSink.SetGaugeWithLabels(metricsutil.PhysicalTableSizeName,
		float32(compressedTableLen), []metrics.Label{
			mountTableTypeLabelMap[tableType],
			localLabelMap[isLocal],
		})

	c.metricsHelper.AddGaugeLoopMetric(metricsutil.PhysicalTableSizeName,
		float32(compressedTableLen), []metrics.Label{
			mountTableTypeLabelMap[tableType],
			localLabelMap[isLocal],
		})
}

func (c *Core) createMigrationStatus(from, to namespace.MountPathDetails) (string, error) {
	migrationID, err := uuid.GenerateUUID()
	if err != nil {
		return "", fmt.Errorf("error generating uuid for mount move invocation: %w", err)
	}
	migrationInfo := MountMigrationInfo{
		SourceMount:     from.Namespace.Path + from.MountPath,
		TargetMount:     to.Namespace.Path + to.MountPath,
		MigrationStatus: MigrationInProgressStatus.String(),
	}
	c.mountMigrationTracker.Store(migrationID, migrationInfo)
	return migrationID, nil
}

func (c *Core) setMigrationStatus(migrationID string, migrationStatus MountMigrationStatus) error {
	migrationInfoRaw, ok := c.mountMigrationTracker.Load(migrationID)
	if !ok {
		return fmt.Errorf("migration Tracker entry missing for ID %s", migrationID)
	}
	migrationInfo := migrationInfoRaw.(MountMigrationInfo)
	migrationInfo.MigrationStatus = migrationStatus.String()
	c.mountMigrationTracker.Store(migrationID, migrationInfo)
	return nil
}

func (c *Core) readMigrationStatus(migrationID string) *MountMigrationInfo {
	migrationInfoRaw, ok := c.mountMigrationTracker.Load(migrationID)
	if !ok {
		return nil
	}
	migrationInfo := migrationInfoRaw.(MountMigrationInfo)
	return &migrationInfo
}

type MountMigrationStatus int

const (
	MigrationInProgressStatus MountMigrationStatus = iota
	MigrationSuccessStatus
	MigrationFailureStatus
)

func (m MountMigrationStatus) String() string {
	switch m {
	case MigrationInProgressStatus:
		return "in-progress"
	case MigrationSuccessStatus:
		return "success"
	case MigrationFailureStatus:
		return "failure"
	}
	return "unknown"
}

type MountMigrationInfo struct {
	SourceMount     string `json:"source_mount"`
	TargetMount     string `json:"target_mount"`
	MigrationStatus string `json:"status"`
}
