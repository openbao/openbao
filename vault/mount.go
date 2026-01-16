// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"path"
	"reflect"
	"slices"

	"github.com/hashicorp/go-uuid"
	"github.com/openbao/openbao/builtin/plugin"
	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/helper/versions"
	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/openbao/openbao/sdk/v2/helper/jsonutil"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const (
	// coreMountConfigPath is used to store the mount configuration.
	// Mounts are protected within the Vault itself, which means they
	// can only be viewed or modified after an unseal.
	coreMountConfigPath = "core/mounts"

	// coreLocalMountConfigPath is used to store mount configuration
	// for local (non-replicated) mounts.
	coreLocalMountConfigPath = "core/local-mounts"

	// backendBarrierPrefix is the prefix to the UUID used in the
	// barrier view for the backends.
	backendBarrierPrefix = "logical/"

	// systemBarrierPrefix is the prefix used for the
	// system logical backend.
	systemBarrierPrefix = "sys/"

	// mountTableType is the value we expect to find for the mount
	// table and corresponding entries.
	mountTableType = "mounts"
)

// ListingVisibilityType represents the types for listing visibility
type ListingVisibilityType string

const (
	// ListingVisibilityDefault is the default value for listing visibility
	ListingVisibilityDefault ListingVisibilityType = ""
	// ListingVisibilityHidden is the hidden type for listing visibility
	ListingVisibilityHidden ListingVisibilityType = "hidden"
	// ListingVisibilityUnauth is the unauth type for listing visibility
	ListingVisibilityUnauth ListingVisibilityType = "unauth"

	mountPathSystem    = "sys/"
	mountPathIdentity  = "identity/"
	mountPathCubbyhole = "cubbyhole/"

	mountTypeSystem      = "system"
	mountTypeNSSystem    = "ns_system"
	mountTypeIdentity    = "identity"
	mountTypeNSIdentity  = "ns_identity"
	mountTypeCubbyhole   = "cubbyhole"
	mountTypePlugin      = "plugin"
	mountTypeKV          = "kv"
	mountTypeNSCubbyhole = "ns_cubbyhole"
	mountTypeToken       = "token"
	mountTypeNSToken     = "ns_token"
)

// DeprecationStatus errors
var (
	errMountDeprecated     = errors.New("mount entry associated with deprecated builtin")
	errMountPendingRemoval = errors.New("mount entry associated with pending removal builtin")
	errMountRemoved        = errors.New("mount entry associated with removed builtin")
)

var (
	// errLoadMountsFailed indicates we encountered an error
	// during mount table setup
	errLoadMountsFailed = errors.New("failed to setup mount table")

	// protectedMounts cannot be remounted
	protectedMounts = []string{
		"audit/",
		"auth/",
		mountPathSystem,
		mountPathCubbyhole,
		mountPathIdentity,
	}

	untunableMounts = []string{
		mountPathCubbyhole,
		mountPathSystem,
		"audit/",
		mountPathIdentity,
	}

	// singletonMounts can only exist in one location and are
	// loaded by default. These are types, not paths.
	singletonMounts = []string{
		mountTypeCubbyhole,
		mountTypeNSCubbyhole,
		mountTypeSystem,
		mountTypeNSSystem,
		mountTypeToken,
		mountTypeNSToken,
		mountTypeIdentity,
		mountTypeNSIdentity,
	}

	// mountAliases maps old backend names to new backend names, allowing us
	// to move/rename backends but maintain backwards compatibility
	mountAliases = map[string]string{"generic": "kv"}
)

func newSecretMountsTable(core *Core) *mountable {
	return &mountable{
		core:      core,
		tableType: mountTableType,
		path:      coreMountConfigPath,
		localPath: coreLocalMountConfigPath,
	}
}

func (c *Core) setupSecretMounts(ctx context.Context) error {
	c.secretMounts = newSecretMountsTable(c)

	if err := c.secretMounts.loadMounts(ctx); err != nil {
		return err
	}

	return c.secretMounts.setupMounts(ctx)
}

func knownMountType(entryType string) error {
	switch entryType {
	case mountTypeKV, mountTypeSystem, mountTypeCubbyhole, mountTypeNSSystem, mountTypeNSCubbyhole:
	default:
		return fmt.Errorf("unknown backend type: %q", entryType)
	}

	return nil
}

func (c *Core) generateMountAccessor(entryType string) (string, error) {
	for {
		randBytes, err := uuid.GenerateRandomBytes(4)
		if err != nil {
			return "", err
		}
		accessor := fmt.Sprintf("%s_%s", entryType, fmt.Sprintf("%08x", randBytes[0:4]))
		if entry := c.router.MatchingMountByAccessor(accessor); entry == nil {
			return accessor, nil
		}
	}
}

func (c *Core) decodeMountTable(ctx context.Context, raw []byte) (*MountTable, error) {
	// Decode into mount table
	mountTable := new(MountTable)
	if err := jsonutil.DecodeJSON(raw, mountTable); err != nil {
		return nil, err
	}

	// Populate the namespace in memory
	var mountEntries []*MountEntry
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

		entry.namespace = ns
		mountEntries = append(mountEntries, entry)
	}

	return &MountTable{
		Type:    mountTable.Type,
		Entries: mountEntries,
	}, nil
}

// builtinTypeFromMountEntry attempts to find a builtin PluginType associated
// with the specified MountEntry. Returns consts.PluginTypeUnknown if not found.
func (c *Core) builtinTypeFromMountEntry(ctx context.Context, entry *MountEntry) consts.PluginType {
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

// handleDeprecatedMountEntry handles the Deprecation Status of the specified
// mount entry's builtin engine. Warnings are appended to the returned response
// and logged. Errors are returned with a nil response to be processed by the
// caller.
func (c *Core) handleDeprecatedMountEntry(ctx context.Context, entry *MountEntry, pluginType consts.PluginType) (*logical.Response, error) {
	resp := &logical.Response{}

	if c.builtinRegistry == nil || entry == nil {
		return nil, nil //nolint:nilnil // nil response is a valid 204 status code body
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

	return nil, nil //nolint:nilnil // nil response is a valid 204 status code body
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

// newLogicalBackend is used to create and configure a new logical backend by name.
// It also returns the SHA256 of the plugin, if available.
func (c *Core) newLogicalBackend(ctx context.Context, entry *MountEntry, sysView logical.SystemView, view logical.Storage) (logical.Backend, string, error) {
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
	for k, v := range entry.Options {
		conf[k] = v
	}

	switch entry.Type {
	case mountTypePlugin:
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

	ctx = namespace.ContextWithNamespace(ctx, entry.namespace)
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

func (c *Core) setCoreBackend(entry *MountEntry, backend logical.Backend, view BarrierView) {
	if entry.NamespaceID != namespace.RootNamespaceID {
		return
	}

	switch entry.Type {
	case mountTypeSystem:
		c.systemBackend = backend.(*SystemBackend)
		c.systemBarrierView = view
	case mountTypeCubbyhole:
		c.cubbyholeBackend = backend.(*CubbyholeBackend)
		c.cubbyholeBackend.saltUUID = entry.UUID
	case mountTypeIdentity:
		c.identityStore = backend.(*IdentityStore)
	}
}

func (c *Core) reloadNamespaceMounts(childCtx context.Context, uuid string, deleted bool) error {
	if _, ok := c.barrier.(logical.TransactionalStorage); !ok {
		return c.reloadLegacyMounts(childCtx)
	}

	keys := []string{}

	if deleted {
		c.secretMounts.lock.RLock()
		for _, entry := range c.secretMounts.table.Entries {
			if entry.Namespace().UUID == uuid {
				key := path.Join(coreMountConfigPath, entry.UUID)
				if entry.Local {
					key = path.Join(coreLocalMountConfigPath, entry.UUID)
				}
				keys = append(keys, key)
			}
		}
		c.secretMounts.lock.RUnlock()

		c.authMounts.lock.RLock()
		for _, entry := range c.authMounts.table.Entries {
			if entry.Namespace().UUID == uuid {
				key := path.Join(coreAuthConfigPath, entry.UUID)
				if entry.Local {
					key = path.Join(coreLocalAuthConfigPath, entry.UUID)
				}
				keys = append(keys, key)
			}
		}
		c.authMounts.lock.RUnlock()

		if len(keys) == 0 {
			return nil
		}
	} else {
		ns, err := namespace.FromContext(childCtx)
		if err != nil {
			return fmt.Errorf("failed to get namespace from context: %w", err)
		}

		for _, path := range []string{c.secretMounts.path, c.secretMounts.localPath, c.authMounts.path, c.authMounts.localPath} {
			entries, err := NamespaceView(c.barrier, ns).List(childCtx, path+"/")
			if err != nil {
				return fmt.Errorf("unable to list mounts for invalidation for namespace %q: %w", uuid, err)
			}

			for _, entryKey := range entries {
				keys = append(keys, fmt.Sprintf("%s/%s", path, entryKey))
			}
		}
	}

	c.logger.Debug("invalidating namespace mount", "ns", uuid, "keys", keys)
	for _, key := range keys {
		err := c.reloadMount(childCtx, key)
		if err != nil {
			return fmt.Errorf("unable to invalidate mount for key %q in namespace %q: %w", key, uuid, err)
		}
	}

	return nil
}

// TODO: adjust
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
		Table             *mountable
		DesiredMountEntry *MountEntry
		Namespace         *namespace.Namespace
	}
	invalidations := map[string]invalidation{}

	for _, path := range keys {
		table := c.secretMounts
		if path == coreAuthConfigPath && path != coreLocalAuthConfigPath {
			table = c.authMounts
		}

		raw, err := c.barrier.Get(ctx, path)
		if err != nil {
			return fmt.Errorf("failed to read legacy mount table: %w", err)
		}

		if raw != nil {
			mountTable, err := c.decodeMountTable(ctx, raw.Value)
			if err != nil {
				return fmt.Errorf("failed to decompress and/or decode the legacy mount table: %w", err)
			}

			for _, entry := range mountTable.Entries {
				if ns.ID != namespace.RootNamespaceID && ns.ID != entry.NamespaceID {
					continue
				}

				invalidations[entry.UUID] = invalidation{
					Table:             table,
					DesiredMountEntry: entry,
					Namespace:         entry.Namespace(),
				}
			}
		}
	}

	// Loop over all mounts in memory, this is required to find mount deletions
	c.secretMounts.lock.RLock()
	c.authMounts.lock.RLock()
	for _, mounts := range []*mountable{c.secretMounts, c.authMounts} {
		if mounts.table == nil {
			continue
		}
		for _, entry := range mounts.table.Entries {
			if ns.ID != namespace.RootNamespaceID && ns.ID != entry.NamespaceID {
				continue
			}

			storagePath := mounts.path
			if entry.Local {
				storagePath = mounts.localPath
			}

			if !slices.Contains(keys, storagePath) {
				continue
			}

			if _, ok := invalidations[entry.UUID]; !ok {
				invalidations[entry.UUID] = invalidation{
					Table:             mounts,
					DesiredMountEntry: nil,
					Namespace:         entry.Namespace(),
				}
			}
		}
	}
	c.authMounts.lock.RUnlock()
	c.secretMounts.lock.RUnlock()

	for uuid, inv := range invalidations {
		err := c.reloadMountInternal(ctx, ns, inv.Table, uuid, inv.DesiredMountEntry)
		if err != nil {
			return fmt.Errorf("unable to invalidate mount: %w", err)
		}
	}

	return nil
}

func (c *Core) reloadMount(ctx context.Context, key string) error {
	prefix, uuid := path.Split(key)
	prefix = path.Clean(prefix)

	table := c.secretMounts
	local := false
	switch prefix {
	case c.secretMounts.path:
	case c.secretMounts.localPath:
		local = true
	case c.authMounts.path:
		table = c.authMounts
	case c.authMounts.localPath:
		table = c.authMounts
		local = true
	default:
		return fmt.Errorf("invalid path prefix %q", prefix)
	}

	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return err
	}
	barrier := NamespaceView(c.barrier, ns)

	desiredMountEntry, err := table.fetchAndDecodeMountTableEntry(ctx, barrier, local, uuid)
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

	return c.reloadMountInternal(ctx, ns, table, uuid, desiredMountEntry)
}

func (c *Core) reloadMountInternal(ctx context.Context, ns *namespace.Namespace, table *mountable, uuid string, desiredMountEntry *MountEntry) error {
	actualMountEntry := c.router.MatchingMountByUUID(uuid)

	switch {
	case desiredMountEntry == nil && actualMountEntry != nil: // mount was deleted
		c.logger.Debug("cache invalidation: mount was deleted", "type", actualMountEntry.Type, "uuid", uuid)

		if err := table.removeMountEntry(ctx, actualMountEntry.Path, false); err != nil {
			return err
		}

		if err := c.router.Unmount(ctx, actualMountEntry.APIPathNoNamespace()); err != nil {
			return err
		}

		if c.quotaManager != nil {
			if err := c.quotaManager.HandleBackendDisabling(ctx, ns.Path, actualMountEntry.APIPathNoNamespace()); err != nil {
				c.logger.Error("failed to update quotas after disabling mount", "error", err, "namespace", ns.Path, "uuid", uuid)
				return err
			}
		}

	case desiredMountEntry != nil && actualMountEntry == nil: // mount was created
		c.logger.Debug("cache invalidation: mount was created", "type", desiredMountEntry.Type, "uuid", uuid)

		if err := table.mountInternal(ctx, desiredMountEntry, false); err != nil {
			return err
		}

	case desiredMountEntry != nil && actualMountEntry != nil: // mount was modified (e.g. tuned or tainted)
		c.logger.Debug("cache invalidation: mount was modified", "type", desiredMountEntry.Type, "uuid", uuid)

		table.lock.Lock()
		defer table.lock.Unlock()

		if desiredMountEntry.Tainted != actualMountEntry.Tainted {
			if desiredMountEntry.Tainted {
				err := c.router.Taint(ctx, actualMountEntry.APIPathNoNamespace())
				if err != nil {
					return err
				}
				actualMountEntry.Tainted = true
			} else {
				err := c.router.Untaint(ctx, actualMountEntry.APIPathNoNamespace())
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
			if err := c.reloadBackendCommon(ctx, desiredMountEntry, table.table.Type == credentialTableType); err != nil {
				return err
			}
		}
	}

	return nil
}
