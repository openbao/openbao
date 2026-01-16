package vault

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path"
	"slices"
	"strings"

	uuid "github.com/hashicorp/go-uuid"
	"github.com/openbao/openbao/audit"
	"github.com/openbao/openbao/helper/locking"
	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/helper/versions"
	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/openbao/openbao/sdk/v2/helper/jsonutil"
	"github.com/openbao/openbao/sdk/v2/logical"
)

type mountable struct {
	core  *Core
	lock  locking.DeadlockRWMutex
	table *MountTable
	// tableType is used for upgrades to typed mount table (persisted)
	tableType string
	// path determines the storage path used for global [table.Entries] persistence
	path string
	// localPath determines the storage path used for local [table.Entries] persistence
	localPath string
}

// loadMounts is invoked as part of postUnseal to load the mount table
func (m *mountable) loadMounts(ctx context.Context) error {
	// Previously, this lock would be held after attempting to read the
	// storage entries. While we could never read corrupted entries,
	// we now need to ensure we can gracefully failover from legacy to
	// transactional mount table structure. This means holding the locks
	// for longer.
	//
	// Note that this lock is used for consistency with other code during
	// system operation (when mounting and unmounting secret/auth engines),
	// but is not strictly necessary here as unseal(...) is serial and blocks
	// startup until finished.
	m.lock.Lock()
	defer m.lock.Unlock()

	// Start with an empty table.
	m.table = nil

	// Migrating mounts from the previous single-entry to a transactional
	// variant requires careful surgery that should only be done in the
	// event the backend is transactionally aware. Otherwise, we'll continue
	// to use the legacy storage format indefinitely.
	//
	// This does mean that going backwards (from a transaction-aware storage
	// to not) is not possible without manual reconstruction.
	txnableBarrier, ok := m.core.barrier.(logical.TransactionalStorage)
	if !ok {
		_, err := m.loadLegacyMounts(ctx, m.core.barrier)
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

	legacy, err := m.loadLegacyMounts(ctx, txn)
	if err != nil {
		return fmt.Errorf("failed to load legacy mounts in transaction: %w", err)
	}

	// If we have legacy mounts, migration was handled by the above. Otherwise,
	// we need to fetch the new mount table.
	if !legacy {
		m.core.logger.Info("reading transactional mount table")
		if err := m.loadTransactionalMounts(ctx, txn); err != nil {
			return fmt.Errorf("failed to load transactional mount table: %w", err)
		}
	}

	// Finally, persist our changes.
	if err := txn.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit mount table changes: %w", err)
	}

	return nil
}

// This function reads the transactional split mount table.
func (m *mountable) loadTransactionalMounts(ctx context.Context, barrier logical.Storage) error {
	allNamespaces, err := m.core.ListNamespaces(ctx)
	if err != nil {
		return fmt.Errorf("failed to list namespaces: %w", err)
	}

	var needPersist bool
	globalEntries := make(map[string][]string, len(allNamespaces))
	localEntries := make(map[string][]string, len(allNamespaces))
	for _, ns := range allNamespaces {
		if ns.Tainted {
			m.core.logger.Info("skipping loading mounts for tainted namespace", "ns", ns.ID)
			continue
		}

		view := NamespaceView(barrier, ns)
		nsGlobal, err := view.List(ctx, m.path+"/")
		if err != nil {
			return fmt.Errorf("failed to list core mounts: %w", err)
		}

		nsLocal, err := view.List(ctx, m.localPath+"/")
		if err != nil {
			return fmt.Errorf("failed to list core local mounts: %w", err)
		}

		if len(nsGlobal) > 0 {
			globalEntries[ns.ID] = nsGlobal
		}

		if len(nsLocal) > 0 {
			localEntries[ns.ID] = nsLocal
		}
	}

	if len(globalEntries) == 0 {
		// TODO(ascheel) Assertion: globalEntries is empty if there is only
		// one namespace (the root namespace).
		m.core.logger.Info("no mounts in transactional mount table; adding default mount table")
		m.table, err = m.defaultMountTable(ctx)
		if err != nil {
			return err
		}
		needPersist = true
	} else {
		m.table = &MountTable{
			Type: m.tableType,
		}

		for nsIndex, ns := range allNamespaces {
			view := NamespaceView(barrier, ns)
			for index, uuid := range globalEntries[ns.ID] {
				entry, err := m.fetchAndDecodeMountTableEntry(ctx, view, false, uuid)
				if err != nil {
					return fmt.Errorf("error loading mount table entry (%v (%v)/%v - %v [%v]): %w", ns.ID, nsIndex, index, uuid, m.tableType, err)
				}

				if entry != nil {
					m.table.Entries = append(m.table.Entries, entry)
				}
			}
		}
	}

	if len(localEntries) > 0 {
		for nsIndex, ns := range allNamespaces {
			view := NamespaceView(barrier, ns)
			for index, uuid := range localEntries[ns.ID] {
				entry, err := m.fetchAndDecodeMountTableEntry(ctx, view, true, uuid)
				if err != nil {
					return fmt.Errorf("error loading local mount table entry (%v (%v)/%v - %v [%v]): %w", ns.ID, nsIndex, index, uuid, m.tableType, err)
				}

				if entry != nil {
					m.table.Entries = append(m.table.Entries, entry)
				}
			}
		}
	}

	if err = m.runMountUpdates(ctx, barrier, needPersist); err != nil {
		m.core.logger.Error("failed to run legacy mount table upgrades", "error", err)
		return err
	}

	return nil
}

// This function reads the legacy, single-entry combined mount table,
// returning true if it was used. This will let us know (if we're inside
// a transaction) if we need to do an upgrade.
func (m *mountable) loadLegacyMounts(ctx context.Context, barrier logical.Storage) (bool, error) {
	// Load the existing mount table
	raw, err := barrier.Get(ctx, m.path)
	if err != nil {
		m.core.logger.Error("failed to read legacy mount table", "error", err)
		return false, errLoadMountsFailed
	}

	rawLocal, err := barrier.Get(ctx, m.localPath)
	if err != nil {
		m.core.logger.Error("failed to read legacy local mount table", "error", err)
		return false, errLoadMountsFailed
	}

	if raw != nil {
		mountTable, err := m.decodeMountTable(ctx, raw.Value)
		if err != nil {
			m.core.logger.Error("failed to decompress and/or decode the legacy mount table", "error", err)
			return false, err
		}
		m.core.tableMetrics(m.tableType, false, len(mountTable.Entries), len(raw.Value))
		m.table = mountTable
	}

	var needPersist bool
	if m.table == nil {
		// In the event we are inside a transaction, we do not yet know if
		// we have a transactional mount table; exit early and load the new format.
		if _, ok := barrier.(logical.Transaction); ok {
			return false, nil
		}
		m.core.logger.Info("no mounts in legacy mount table; adding default mount table")
		m.table, err = m.defaultMountTable(ctx)
		if err != nil {
			return false, err
		}
		needPersist = true
	} else {
		if _, ok := barrier.(logical.Transaction); ok {
			// We know we have legacy mount table entries, so force a migration.
			m.core.logger.Info("migrating legacy mount table to transactional layout")
			needPersist = true
		}
		m.core.tableMetrics(m.tableType, false, len(m.table.Entries), len(raw.Value))
	}

	if rawLocal != nil {
		localMountTable, err := m.decodeMountTable(ctx, rawLocal.Value)
		if err != nil {
			m.core.logger.Error("failed to decompress and/or decode the legacy local mount table", "error", err)
			return false, err
		}
		if localMountTable != nil && len(localMountTable.Entries) > 0 {
			m.core.tableMetrics(m.tableType, true, len(localMountTable.Entries), len(rawLocal.Value))
			m.table.Entries = append(m.table.Entries, localMountTable.Entries...)
		}
	}

	// Here, we must call runMountUpdates:
	//
	// 1. We may be without any mount table and need to create the legacy
	//    table format because we don't have a transaction aware storage
	//    backend.
	// 2. We may have had a legacy mount table and need to upgrade into the
	//    new format. runMountUpdates will handle this for us.
	if err = m.runMountUpdates(ctx, barrier, needPersist); err != nil {
		m.core.logger.Error("failed to run legacy mount table upgrades", "error", err)
		return false, err
	}

	// We loaded a legacy mount table and successfully migrated it, if
	// necessary.
	return true, nil
}

// defaultMountTable creates a default mount table
func (m *mountable) defaultMountTable(ctx context.Context) (*MountTable, error) {
	// short-circuit the audit table
	switch m.tableType {
	case auditTableType:
		return &MountTable{Type: auditTableType}, nil
	case configAuditTableType:
		return &MountTable{Type: configAuditTableType}, nil
	}

	table := &MountTable{
		Type: m.tableType,
	}

	switch table.Type {
	case credentialTableType:
		tokenMount, err := m.createMountEntry(ctx, mountTypeToken)
		if err != nil {
			return nil, err
		}
		table.Entries = append(table.Entries, tokenMount)
	case mountTableType:
		for _, mountType := range []string{mountTypeCubbyhole, mountTypeSystem, mountTypeIdentity} {
			mount, err := m.createMountEntry(ctx, mountType)
			if err != nil {
				return nil, err
			}
			table.Entries = append(table.Entries, mount)
		}
	default:
		return nil, fmt.Errorf("couldn't create default mount table for invalid mount table type: %q", table.Type)
	}

	return table, nil
}

func (m *mountable) createMountEntry(ctx context.Context, mountType string) (*MountEntry, error) {
	ns, err := namespace.FromContext(ctx)
	if err != nil && !errors.Is(err, namespace.ErrNoNamespace) {
		return nil, err
	}
	if ns == nil {
		ns = namespace.RootNamespace
	}

	meUUID, err := uuid.GenerateUUID()
	if err != nil {
		return nil, fmt.Errorf("could not generate UUID for mount entry of type (%s): %w", mountType, err)
	}
	// question: can we change entry type from `auth_token` to `token`?
	accessor, err := m.core.generateMountAccessor(mountType)
	if err != nil {
		return nil, fmt.Errorf("could not generate accessor for mount entry of type (%s): %w", mountType, err)
	}
	backendUUID, err := uuid.GenerateUUID()
	if err != nil {
		return nil, fmt.Errorf("could not generate backend-aware UUID for mount entry of type (%s): %w", mountType, err)
	}
	me := &MountEntry{
		Table:            m.tableType,
		Type:             mountType,
		UUID:             meUUID,
		Accessor:         accessor,
		BackendAwareUUID: backendUUID,
		NamespaceID:      ns.ID,
		namespace:        ns,
	}

	switch mountType {
	case mountTypeToken:
		me.Path = "token/"
		me.Description = "token based credentials"
	case mountTypeCubbyhole:
		me.Path = mountPathCubbyhole
		me.Description = "per-token private secret storage"
		me.RunningVersion = versions.GetBuiltinVersion(consts.PluginTypeSecrets, "cubbyhole")
		me.Local = true
	case mountTypeSystem:
		me.Path = mountPathSystem
		me.Description = "system endpoints used for control, policy and debugging"
		me.RunningVersion = versions.DefaultBuiltinVersion
		me.Config = MountConfig{
			PassthroughRequestHeaders: []string{"Accept"},
		}
		me.SealWrap = true
	case mountTypeIdentity:
		me.Path = mountPathIdentity
		me.Description = "identity store"
		me.RunningVersion = versions.DefaultBuiltinVersion
		me.Config = MountConfig{
			PassthroughRequestHeaders: []string{"Authorization"},
		}
	}

	if ns.ID != namespace.RootNamespaceID {
		switch mountType {
		case mountTypeToken:
			me.Type = mountTypeNSToken
		case mountTypeCubbyhole:
			me.Type = mountTypeNSCubbyhole
		case mountTypeIdentity:
			me.Type = mountTypeNSIdentity
		case mountTypeNSSystem:
			me.Type = mountTypeNSSystem
		}
	}

	return me, nil
}

func (m *mountable) fetchAndDecodeMountTableEntry(ctx context.Context, barrier logical.Storage, local bool, uuid string) (*MountEntry, error) {
	entryPathPrefix := m.path
	if local {
		entryPathPrefix = m.localPath
	}

	entryPath := path.Join(entryPathPrefix, uuid)
	sEntry, err := barrier.Get(ctx, entryPath)
	if err != nil {
		return nil, err
	}
	if sEntry == nil {
		return nil, errors.New("unexpected empty storage entry for mount")
	}

	entry := new(MountEntry)
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

	ns, err := m.core.NamespaceByID(ctx, entry.NamespaceID)
	if err != nil {
		return nil, err
	}
	if ns == nil {
		m.core.logger.Error("namespace on mount entry not found", "entryPath", entryPath, "uuid", uuid, "namespace_id", entry.NamespaceID, "mount_path", entry.Path, "mount_description", entry.Description)
		return nil, nil //nolint:nilnil // callers handle both cases of an error and non-existent entry
	}

	entry.namespace = ns
	return entry, nil
}

func (m *mountable) decodeMountTable(ctx context.Context, raw []byte) (*MountTable, error) {
	mountTable := new(MountTable)
	if err := jsonutil.DecodeJSON(raw, mountTable); err != nil {
		return nil, err
	}

	// short-circuit audit
	if m.tableType == auditTableType || m.tableType == configAuditTableType {
		return &MountTable{
			Type:    mountTable.Type,
			Entries: mountTable.Entries,
		}, nil
	}

	// Populate the namespace in memory
	var mountEntries []*MountEntry
	for _, entry := range mountTable.Entries {
		if entry.NamespaceID == "" {
			entry.NamespaceID = namespace.RootNamespaceID
		}
		ns, err := m.core.NamespaceByID(ctx, entry.NamespaceID)
		if err != nil {
			return nil, err
		}
		if ns == nil {
			m.core.logger.Error("namespace on mount entry not found", "namespace_id", entry.NamespaceID, "mount_path", entry.Path, "mount_description", entry.Description)
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

// Mount is used to mount a new backend to the mount table.
func (m *mountable) mount(ctx context.Context, entry *MountEntry) error {
	if entry.Path == "/" {
		return errors.New("backend path must be specified")
	}

	// Ensure we end the path in a slash
	if !strings.HasSuffix(entry.Path, "/") {
		entry.Path += "/"
	}

	// For secret mounts prevent mounting on protected paths
	// due to possible conflicts with existing paths
	if m.tableType == mountTableType {
		for _, p := range protectedMounts {
			if strings.HasPrefix(entry.Path, p) && entry.namespace == nil {
				return logical.CodedError(http.StatusForbidden, "cannot mount %q", entry.Path)
			}
		}
	}

	// Do not allow more than one instance of a singleton mount
	if slices.Contains(singletonMounts, entry.Type) {
		return logical.CodedError(http.StatusForbidden, "mount type of %q is not mountable", entry.Type)
	}

	return m.mountInternal(ctx, entry, true)
}

func (m *mountable) mountInternal(ctx context.Context, entry *MountEntry, updateStorage bool) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return err
	}

	entry.NamespaceID = ns.ID
	entry.namespace = ns

	// Basic check for matching names
	for _, ent := range m.table.Entries {
		if ns.ID == ent.NamespaceID {
			switch {
			// examples:
			// 	Existing is oauth/github/ new is oauth/ or
			// 	existing is oauth/ and new is oauth/github/
			case strings.HasPrefix(ent.Path, entry.Path):
				fallthrough
			case strings.HasPrefix(entry.Path, ent.Path):
				return logical.CodedError(http.StatusConflict, "path is already in use at %s", ent.Path)
			}
		}
	}

	// TODO: audit does not have this check
	// Verify there are no conflicting mounts in the router
	if conflict := m.core.router.MountConflict(ctx, entry.APIPathNoNamespace()); conflict != "" {
		return logical.CodedError(http.StatusConflict, "existing mount at %s", conflict)
	}

	// Generate a new UUID and view
	if entry.UUID == "" {
		entryUUID, err := uuid.GenerateUUID()
		if err != nil {
			return err
		}
		entry.UUID = entryUUID
	}

	// TODO: not needed for audit
	if entry.BackendAwareUUID == "" {
		bUUID, err := uuid.GenerateUUID()
		if err != nil {
			return err
		}
		entry.BackendAwareUUID = bUUID
	}

	if entry.Accessor == "" {
		// TODO: entryType
		accessor, err := m.core.generateMountAccessor(entry.Type)
		if err != nil {
			return err
		}
		entry.Accessor = accessor
	}
	// Sync values to the cache - not synced when audit
	entry.SyncCache()

	view, err := m.core.mountEntryView(entry)
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
	var auditBackend audit.Backend
	sysView := m.core.mountEntrySysView(entry)

	switch m.tableType {
	case mountTableType:
		backend, entry.RunningSha256, err = m.core.newLogicalBackend(ctx, entry, sysView, view)
	case credentialTableType:
		backend, entry.RunningSha256, err = m.core.newCredentialBackend(ctx, entry, sysView, view)
	case auditTableType, configAuditTableType:
		auditBackend, err = m.core.newAuditBackend(ctx, entry, view, entry.Options)
	}

	if err != nil {
		return err
	}
	if backend == nil && auditBackend == nil {
		return fmt.Errorf("nil backend of type %q returned", entry.Type)
	}

	// Check for the correct backend type
	backendType := backend.Type()
	switch m.tableType {
	case mountTableType:
		if backendType != logical.TypeLogical {
			if err := knownMountType(entry.Type); err != nil {
				return err
			}
		}
		m.core.setCoreBackend(entry, backend, view)
	case credentialTableType:
		if backendType != logical.TypeCredential {
			return fmt.Errorf("cannot mount %q of type %q as an auth backend", entry.Type, backendType)
		}
	case auditTableType, configAuditTableType:
		// this is not a test for a backend type, just a probe for created audit
		if entry.Options["skip_test"] != "true" {
			testProbe, err := m.core.generateAuditTestProbe()
			if err != nil {
				return err
			}
			if err = auditBackend.LogTestMessage(ctx, testProbe, entry.Options); err != nil {
				m.core.logger.Error("new audit backend failed test", "path", entry.Path, "type", entry.Type, "error", err)
				return fmt.Errorf("audit backend failed test message: %w", err)
			}
		}
	default:
		return fmt.Errorf("cannot mount %q of type %q as an %s backend", entry.Type, backendType, m.tableType)
	}

	// for now audits are not plugable, so omit it
	if m.tableType != auditTableType && m.tableType != configAuditTableType {
		var pluginType consts.PluginType
		switch m.tableType {
		case mountTableType:
			pluginType = consts.PluginTypeSecrets
		case credentialTableType:
			pluginType = consts.PluginTypeCredential
		default:
			pluginType = consts.PluginTypeUnknown
		}

		// update the entry running version with the configured version,
		// which was verified during registration.
		entry.RunningVersion = entry.Version
		if entry.RunningVersion == "" && entry.RunningSha256 == "" {
			// don't set the running version to a builtin
			// if it is running as an external plugin
			entry.RunningVersion = versions.GetBuiltinVersion(pluginType, entry.Type)
		}
	}

	newTable := m.table.shallowClone()
	newTable.Entries = append(newTable.Entries, entry)

	if updateStorage {
		if err := m.persistMount(ctx, m.core.barrier, newTable, entry); err != nil {
			m.core.logger.Error("failed to update mount table", "error", err)
			return fmt.Errorf("failed to update mount table: %w", err)
		}
	}
	m.table = newTable

	if m.tableType == auditTableType || m.tableType == configAuditTableType {
		m.core.auditBroker.Register(entry.Path, auditBackend, view, entry.Local)
	} else {
		// secret or auth mount then
		if err := m.core.router.Mount(backend, entry.APIPathNoNamespace(), entry, view); err != nil {
			return err
		}

		// restore the original readOnlyErr, so we can write to the view in
		// Initialize if necessary
		view.SetReadOnlyErr(origReadOnlyErr)
		// initialize, using the core's active context.
		if err = backend.Initialize(m.core.activeContext, &logical.InitializationRequest{Storage: view}); err != nil {
			return err
		}
	}

	if m.core.logger.IsInfo() {
		m.core.logger.Info("successful mount", "namespace", entry.Namespace().Path, "path", entry.APIPathNoNamespace(), "type", entry.Type, "version", entry.Version)
	}
	return nil
}

func (m *mountable) runMountUpdates(ctx context.Context, barrier logical.Storage, needPersist bool) error {
	// Upgrade to typed mount table
	if m.table.Type == "" {
		m.table.Type = m.tableType
		needPersist = true
	}

	if m.table.Type == mountTableType {
		requiredMounts, err := m.defaultMountTable(ctx)
		if err != nil {
			return err
		}

		for _, requiredMount := range requiredMounts.Entries {
			foundRequired := false
			for _, coreMount := range m.table.Entries {
				if coreMount.Type == requiredMount.Type {
					foundRequired = true
					coreMount.Config = requiredMount.Config

					// Since we're potentially updating the config here,
					// sync the cache.
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
				m.table.Entries = append(m.table.Entries, requiredMount)
				needPersist = true
			}
		}
	}

	// Upgrade to table-scoped entries
	for _, entry := range m.table.Entries {
		if (entry.Type == mountTypeNSCubbyhole || entry.Type == mountTypeCubbyhole) && !entry.Local {
			entry.Local = true
			needPersist = true
		}
		if entry.Table == "" {
			entry.Table = m.table.Type
			needPersist = true
		}
		if entry.Accessor == "" {
			// TODO: entryType
			accessor, err := m.core.generateMountAccessor(entry.Type)
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

		// Don't store built-in version in the mount table, to make upgrades smoother.
		if versions.IsBuiltinVersion(entry.Version) {
			entry.Version = ""
			needPersist = true
		}

		if entry.NamespaceID == "" {
			entry.NamespaceID = namespace.RootNamespaceID
			needPersist = true
		}

		ns, err := m.core.NamespaceByID(ctx, entry.NamespaceID)
		if err != nil {
			return err
		}
		if ns == nil {
			return namespace.ErrNoNamespace
		}
		entry.namespace = ns

		// Sync values to the cache
		entry.SyncCache()
	}

	if !needPersist {
		return nil
	}

	// Persist mount tables
	if err := m.persistMounts(ctx, barrier, m.table); err != nil {
		m.core.logger.Error("failed to persist mount table", "error", err)
		return errLoadMountsFailed
	}
	return nil
}

// remount is used to remount a path at a new mount point.
func (m *mountable) remount(ctx context.Context, src, dst namespace.MountPathDetails, updateStorage bool) error {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return err
	}

	protected := protectedMounts
	if m.tableType == credentialTableType {
		if !strings.HasPrefix(src.MountPath, credentialRoutePrefix) ||
			!strings.HasPrefix(dst.MountPath, credentialRoutePrefix) {
			return fmt.Errorf("cannot remount cross-type mounts from %q to %q", src.MountPath, dst.MountPath)
		}
		protected = protectedAuths
	}

	for _, p := range protected {
		if strings.HasPrefix(src.MountPath, p) {
			return fmt.Errorf("cannot remount %q", src.MountPath)
		}

		if strings.HasPrefix(dst.MountPath, p) {
			return fmt.Errorf("cannot remount to %q", dst.MountPath)
		}
	}

	srcRelativePath := src.GetRelativePath(ns)
	dstRelativePath := dst.GetRelativePath(ns)

	// Verify exact match of the route
	mountEntry := m.core.router.MatchingMountEntry(ctx, srcRelativePath)
	if mountEntry == nil {
		return fmt.Errorf("no matching mount at %q", src.Namespace.Path+src.MountPath)
	}

	if conflict := m.core.router.MountConflict(ctx, dstRelativePath); conflict != dst.Namespace.Path && conflict != "" {
		return logical.CodedError(http.StatusConflict, "existing mount at %s", conflict)
	}

	srcBarrierView, err := m.core.mountEntryView(mountEntry)
	if err != nil {
		return err
	}

	// Mark the entry as tainted
	if err := m.taintMountEntry(ctx, src.Namespace.ID, src.MountPath, updateStorage); err != nil {
		return err
	}

	// Taint the router path to prevent routing
	if err := m.core.router.Taint(ctx, srcRelativePath); err != nil {
		return err
	}

	// Invoke the rollback manager a final time. This is not fatal as
	// various periodic funcs (e.g., PKI) can legitimately error; the
	// periodic rollback manager logs these errors rather than failing
	// replication like returning this error would do.
	if m.core.rollback != nil && m.core.router.MatchingBackend(ctx, srcRelativePath) != nil {
		rCtx := namespace.ContextWithNamespace(m.core.activeContext, ns)
		if err := m.core.rollback.Rollback(rCtx, srcRelativePath); err != nil {
			m.core.logger.Error("ignoring rollback error during remount", "error", err, "path", src.Namespace.Path+src.MountPath)
			err = nil //nolint:ineffassign // we explicitly ignore the error
		}
	}

	if m.core.expiration != nil {
		revokeCtx := namespace.ContextWithNamespace(ctx, src.Namespace)
		// Revoke all the dynamic keys
		if err := m.core.expiration.RevokePrefix(revokeCtx, src.MountPath, true); err != nil {
			return err
		}
	}

	m.lock.Lock()
	defer m.lock.Unlock()
	if conflict := m.core.router.MountConflict(ctx, dstRelativePath); conflict != dst.Namespace.Path && conflict != "" {
		return logical.CodedError(http.StatusConflict, "existing mount at %s", conflict)
	}

	mountEntry.Tainted = false
	mountEntry.NamespaceID = dst.Namespace.ID
	mountEntry.namespace = dst.Namespace
	srcPath := mountEntry.Path
	mountEntry.Path = strings.TrimPrefix(dst.MountPath, credentialRoutePrefix)

	dstBarrierView, err := m.core.mountEntryView(mountEntry)
	if err != nil {
		return err
	}

	// Update the mount table
	if err := m.persistMount(ctx, m.core.barrier, m.table, mountEntry); err != nil {
		mountEntry.namespace = src.Namespace
		mountEntry.NamespaceID = src.Namespace.ID
		mountEntry.Path = srcPath
		mountEntry.Tainted = true
		return fmt.Errorf("failed to update mount table with error %+v", err)
	}

	if src.Namespace.ID != dst.Namespace.ID {
		// Handle storage entries
		if err := m.moveStorage(ctx, src, mountEntry, srcBarrierView, dstBarrierView); err != nil {
			return err
		}
	}

	// Remount the backend
	if err := m.core.router.Remount(ctx, srcRelativePath, dstRelativePath, func(re *routeEntry) error {
		re.storageView = dstBarrierView
		re.storagePrefix = dstBarrierView.Prefix()
		return nil
	}); err != nil {
		return err
	}

	// Un-taint the path
	return m.core.router.Untaint(ctx, dstRelativePath)
}

// moveStorage moves storage entries of a mountEntry to its new destination
func (m *mountable) moveStorage(ctx context.Context, src namespace.MountPathDetails, me *MountEntry, srcBarrierView, dstBarrierView BarrierView) error {
	srcPrefix := srcBarrierView.Prefix()
	dstPrefix := dstBarrierView.Prefix()

	barrier := m.core.barrier

	var key string
	keys, err := barrier.List(ctx, srcPrefix)
	if err != nil {
		return err
	}

	for len(keys) > 0 {
		key, keys = keys[0], keys[1:]
		if strings.HasSuffix(key, "/") {
			nestedKeys, err := barrier.List(ctx, srcPrefix+key)
			if err != nil {
				return err
			}
			for k := range nestedKeys {
				nestedKeys[k] = key + nestedKeys[k]
			}

			keys = append(keys, nestedKeys...)
			continue
		}

		if err := logical.WithTransaction(ctx, barrier, func(s logical.Storage) error {
			se, err := s.Get(ctx, srcPrefix+key)
			if err != nil {
				return err
			}
			if se == nil {
				return nil
			}

			se.Key = dstPrefix + key
			if err = s.Put(ctx, se); err != nil {
				return err
			}
			return s.Delete(ctx, srcPrefix+key)
		}); err != nil {
			return err
		}
	}

	srcEntryView := NamespaceView(barrier, src.Namespace)
	if me.Local {
		srcEntryView = srcEntryView.SubView(m.localPath + "/")
	} else {
		srcEntryView = srcEntryView.SubView(m.path + "/")
	}

	return srcEntryView.Delete(ctx, me.UUID)
}

func (m *mountable) unmount(ctx context.Context, path string) error {
	// Ensure there is a name
	if path == "/" {
		return errors.New("backend path must be specified")
	}

	// Ensure we end the path in a slash
	if !strings.HasSuffix(path, "/") {
		path += "/"
	}

	if m.tableType == credentialTableType && path == "token/" {
		return errors.New("token credential backend cannot be disabled")
	}

	// Prevent protected paths (secrets) from being unmounted
	if slices.ContainsFunc(
		protectedMounts,
		func(protPath string) bool {
			return strings.HasPrefix(path, protPath)
		},
	) {
		return fmt.Errorf("cannot unmount %q", path)
	}

	return m.unmountInternal(ctx, path, true)
}

func (m *mountable) unmountInternal(ctx context.Context, path string, updateStorage bool) error {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return err
	}
	revokeCtx := namespace.ContextWithNamespace(m.core.activeContext, ns)

	// short-circuit the audit
	if m.tableType == auditTableType || m.tableType == configAuditTableType {
		if err := m.removeMountEntry(revokeCtx, path, updateStorage); err != nil {
			m.core.logger.Error("failed to remove mount entry for path being unmounted", "error", err, "namespace", ns.Path, "path", path)
			return err
		}
	}

	if m.tableType == credentialTableType {
		path = credentialRoutePrefix + path
	}

	// Verify exact match of the route
	match := m.core.router.MatchingMount(revokeCtx, path)
	if match == "" || ns.Path+path != match {
		return errNoMatchingMount
	}

	// Get the view for this backend
	view := m.core.router.MatchingStorageByAPIPath(revokeCtx, path)
	if view == nil {
		return fmt.Errorf("no matching storage %q", path)
	}

	// Get the backend/mount entry for this path, used to remove ignored
	// replication prefixes
	backend := m.core.router.MatchingBackend(revokeCtx, path)

	// Mark the entry as tainted
	if err := m.taintMountEntry(revokeCtx, ns.ID, path, updateStorage); err != nil {
		m.core.logger.Error("failed to taint mount entry for path being unmounted", "error", err, "namespace", ns.Path, "path", path)
		return err
	}

	// Taint the router path to prevent routing. Note that in-flight requests
	// are uncertain, right now.
	if err := m.core.router.Taint(revokeCtx, path); err != nil {
		return err
	}

	if backend != nil {
		if m.tableType == mountTableType && m.core.rollback != nil {
			// Invoke the rollback manager a final time. This is not fatal as
			// various periodic funcs (e.g., PKI) can legitimately error; the
			// periodic rollback manager logs these errors rather than failing
			// replication like returning this error would do.
			if err := m.core.rollback.Rollback(revokeCtx, path); err != nil {
				m.core.logger.Error("ignoring rollback error during unmount", "error", err, "path", path)
				err = nil //nolint:ineffassign // this is done to be explicit about the fact that we ignore the error
			}
		}

		if m.core.expiration != nil && updateStorage {
			// Revoke all the dynamic keys
			if err := m.core.expiration.RevokePrefix(revokeCtx, path, true); err != nil {
				return err
			}
		}

		// Call cleanup function if it exists
		backend.Cleanup(revokeCtx)
	}

	if updateStorage {
		if err := logical.ClearViewWithLogging(revokeCtx, view, m.core.logger.Named("mount.cleanup").With("namespace", ns.Path, "path", path)); err != nil {
			m.core.logger.Error("failed to clear view for path being unmounted", "error", err, "namespace", ns.Path, "path", path)
			return err
		}
	}

	if err := m.removeMountEntry(revokeCtx, path, updateStorage); err != nil {
		m.core.logger.Error("failed to remove mount entry for path being unmounted", "error", err, "namespace", ns.Path, "path", path)
		return err
	}

	// Unmount the backend entirely
	if err := m.core.router.Unmount(revokeCtx, path); err != nil {
		return err
	}

	if m.core.quotaManager != nil {
		if err := m.core.quotaManager.HandleBackendDisabling(revokeCtx, ns.Path, path); err != nil {
			m.core.logger.Error("failed to update quotas after disabling mount", "error", err, "namespace", ns.Path, "path", path)
			return err
		}
	}

	if m.core.logger.IsInfo() {
		m.core.logger.Info("successfully unmounted", "namespace", ns.Path, "path", path)
	}

	return nil
}

// removeMountEntry is used to remove an entry from the mount table
func (m *mountable) removeMountEntry(ctx context.Context, path string, updateStorage bool) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	// Remove the entry from the mount table
	newTable := m.table.shallowClone()
	entry, err := newTable.remove(ctx, strings.TrimPrefix(path, credentialRoutePrefix))
	if err != nil {
		return err
	}
	if entry == nil {
		m.core.logger.Error("nil entry found while removing entry in mounts table", "path", path)
		return logical.CodedError(http.StatusInternalServerError, "failed to remove entry in mounts table")
	}

	if m.tableType == auditTableType || m.tableType == configAuditTableType {
		m.core.removeAuditReloadFunc(entry)
	}

	// When unmounting all entries the JSON code will load back up from storage
	// as a nil slice, which kills tests...just set it nil explicitly
	if len(newTable.Entries) == 0 {
		newTable.Entries = nil
	}

	if updateStorage {
		if err := m.persistMount(ctx, m.core.barrier, newTable, entry); err != nil {
			m.core.logger.Error("failed to remove entry from mounts table", "error", err)
			return logical.CodedError(http.StatusInternalServerError, "failed to remove entry from mounts table")
		}
	}

	m.table = newTable
	if m.tableType == auditTableType || m.tableType == configAuditTableType {
		m.core.auditBroker.Deregister(path)
		if m.core.logger.IsInfo() {
			m.core.logger.Info("disabled audit backend", "path", path)
		}
	}

	return nil
}

// TODO: should it be on core?
// TODO: can it handle multiple transactions at once?
// persistMount is used to persist the mount table after
// modification of one mount entry.
func (m *mountable) persistMount(ctx context.Context, barrier logical.Storage, newTable *MountTable, me *MountEntry) error {
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

	if me.Table != newTable.Type {
		m.core.logger.Error("given entry to persist in mount table has wrong table value", "path", me.Path, "entry_table_type", me.Table, "actual_type", newTable.Type)
		return errors.New("invalid mount entry found, not persisting")
	}

	// Handle writing the legacy mount table by default.
	writeTable := func(mt *MountTable, path string) (int, error) {
		// Encode the mount table into JSON and compress it (Gzip).
		compressedBytes, err := jsonutil.EncodeJSONAndCompress(mt, nil)
		if err != nil {
			m.core.logger.Error("failed to encode or compress mount table", "error", err)
			return -1, err
		}

		// Create an entry
		entry := &logical.StorageEntry{
			Key:   path,
			Value: compressedBytes,
		}

		// Write to the physical backend
		if err := barrier.Put(ctx, entry); err != nil {
			m.core.logger.Error("failed to persist mount table", "error", err)
			return -1, err
		}
		return len(compressedBytes), nil
	}

	if _, ok := barrier.(logical.Transaction); ok {
		// Write a transactional-aware mount table series instead.
		writeTable = func(mt *MountTable, prefix string) (int, error) {
			var size int
			var found bool
			currentEntries := make(map[string]struct{}, len(mt.Entries))
			for index, mtEntry := range mt.Entries {
				if mtEntry.UUID != me.UUID {
					continue
				}

				view := NamespaceView(barrier, mtEntry.Namespace())

				found = true
				currentEntries[mtEntry.UUID] = struct{}{}

				// Encode the mount table into JSON. There is little value in
				// compressing short entries.
				encoded, err := jsonutil.EncodeJSON(mtEntry)
				if err != nil {
					m.core.logger.Error("failed to encode mount table entry", "index", index, "uuid", mtEntry.UUID, "error", err)
					return -1, err
				}

				// Create a storage entry.
				sEntry := &logical.StorageEntry{
					Key:   path.Join(prefix, mtEntry.UUID),
					Value: encoded,
				}

				// Write to the backend.
				if err := view.Put(ctx, sEntry); err != nil {
					m.core.logger.Error("failed to persist mount table entry", "index", index, "uuid", mtEntry.UUID, "error", err)
					return -1, err
				}

				size += len(encoded)
			}

			if !found {
				// Delete this component if it exists. This signifies that
				// we're removing this mount. We don't know which namespace
				// this entry could belong to, so remove it from all.
				allNamespaces, err := m.core.ListNamespaces(ctx)
				if err != nil {
					return -1, fmt.Errorf("failed to list namespaces: %w", err)
				}

				for nsIndex, ns := range allNamespaces {
					view := NamespaceView(barrier, ns)
					if err := view.Delete(ctx, path.Join(prefix, me.UUID)); err != nil {
						return -1, fmt.Errorf("requested removal of auth mount from namespace %v (%v) but failed: %w", ns.ID, nsIndex, err)
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
	localMounts, globalMounts := newTable.splitByLocal()
	if me.Local {
		compressedBytesLen, err = writeTable(localMounts, m.localPath)
		if err != nil {
			return err
		}
		m.core.tableMetrics(m.tableType, true, len(localMounts.Entries), compressedBytesLen)
	} else {
		compressedBytesLen, err = writeTable(globalMounts, m.path)
		if err != nil {
			return err
		}
		m.core.tableMetrics(m.tableType, false, len(globalMounts.Entries), compressedBytesLen)
	}

	if needTxnCommit {
		if err := barrier.(logical.Transaction).Commit(ctx); err != nil {
			return fmt.Errorf("failed to persist mounts inside transaction: %w", err)
		}
	}

	return nil
}

// persistMount is used to persist mount table.
func (m *mountable) persistMounts(ctx context.Context, barrier logical.Storage, newTable *MountTable) error {
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

	for _, entry := range newTable.Entries {
		if entry.Table != newTable.Type {
			m.core.logger.Error("given entry to persist in mount table has wrong table value", "path", entry.Path, "entry_table_type", entry.Table, "actual_type", newTable.Type)
			return errors.New("invalid mount entry found, not persisting")
		}

		// We potentially modified the mount table entry so update the map
		// accordingly.
		entry.SyncCache()
	}

	// Handle writing the legacy mount table by default.
	writeTable := func(mt *MountTable, path string) (int, error) {
		// Encode the mount table into JSON and compress it (Gzip).
		compressedBytes, err := jsonutil.EncodeJSONAndCompress(mt, nil)
		if err != nil {
			m.core.logger.Error("failed to encode or compress mount table", "error", err)
			return -1, err
		}

		// Create an entry
		entry := &logical.StorageEntry{
			Key:   path,
			Value: compressedBytes,
		}

		// Write to the physical backend
		if err := barrier.Put(ctx, entry); err != nil {
			m.core.logger.Error("failed to persist mount table", "error", err)
			return -1, err
		}
		return len(compressedBytes), nil
	}

	if _, ok := barrier.(logical.Transaction); ok {
		// Write a transactional-aware mount table series instead.
		writeTable = func(mt *MountTable, prefix string) (int, error) {
			var size int
			currentEntries := make(map[string]struct{}, len(mt.Entries))
			for index, mtEntry := range mt.Entries {
				view := NamespaceView(barrier, mtEntry.Namespace())
				currentEntries[mtEntry.UUID] = struct{}{}

				// Encode the mount table into JSON. There is little value in
				// compressing short entries.
				encoded, err := jsonutil.EncodeJSON(mtEntry)
				if err != nil {
					m.core.logger.Error("failed to encode mount table entry", "index", index, "uuid", mtEntry.UUID, "error", err)
					return -1, err
				}

				// Create a storage entry.
				sEntry := &logical.StorageEntry{
					Key:   path.Join(prefix, mtEntry.UUID),
					Value: encoded,
				}

				// Write to the backend.
				if err := view.Put(ctx, sEntry); err != nil {
					m.core.logger.Error("failed to persist mount table entry", "index", index, "uuid", mtEntry.UUID, "error", err)
					return -1, err
				}

				size += len(encoded)
			}

			allNamespaces, err := m.core.ListNamespaces(ctx)
			if err != nil {
				return -1, fmt.Errorf("failed to list namespaces: %w", err)
			}

			for nsIndex, ns := range allNamespaces {
				view := NamespaceView(barrier, ns)

				// List all entries and remove any deleted ones.
				presentEntries, err := view.List(ctx, prefix+"/")
				if err != nil {
					return -1, fmt.Errorf("failed to list entries in namespace %v (%v) for removal: %w", ns.ID, nsIndex, err)
				}

				for index, presentEntry := range presentEntries {
					if _, present := currentEntries[presentEntry]; present {
						continue
					}

					if err := view.Delete(ctx, path.Join(prefix, presentEntry)); err != nil {
						return -1, fmt.Errorf("failed to remove deleted mount %v (%v) in namespace %v (%v): %w", presentEntry, index, ns.ID, nsIndex, err)
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

	localMounts, globalMounts := newTable.splitByLocal()
	compressedBytesLen, err := writeTable(localMounts, m.localPath)
	if err != nil {
		return err
	}
	m.core.tableMetrics(m.tableType, true, len(localMounts.Entries), compressedBytesLen)

	compressedBytesLen, err = writeTable(globalMounts, m.path)
	if err != nil {
		return err
	}
	m.core.tableMetrics(m.tableType, false, len(globalMounts.Entries), compressedBytesLen)

	if needTxnCommit {
		if err := barrier.(logical.Transaction).Commit(ctx); err != nil {
			return fmt.Errorf("failed to persist mounts inside transaction: %w", err)
		}
	}

	return nil
}

// setupMounts is invoked after we've loaded the mount table to
// initialize the logical backends and setup the router
func (m *mountable) setupMounts(ctx context.Context) error {
	var broker *AuditBroker
	if m.tableType == auditTableType || m.tableType == configAuditTableType {
		brokerLogger := m.core.baseLogger.Named("audit")
		m.core.AddLogger(brokerLogger)
		broker = NewAuditBroker(brokerLogger)
	}

	m.lock.Lock()
	defer m.lock.Unlock()

	// TODO: look into possible removal
	var successCount int

	for _, entry := range m.table.sortEntriesByPathDepth().Entries {
		// Initialize the backend, special casing for system
		view, err := m.core.mountEntryView(entry)
		if err != nil {
			return err
		}

		origReadOnlyErr := view.GetReadOnlyErr()

		// Mark the view as read-only until the mounting is complete and
		// ensure that it is reset after. This ensures that there will be no
		// writes during the construction of the backend.
		view.SetReadOnlyErr(logical.ErrSetupReadOnly)
		// TODO: look into this
		if slices.Contains(singletonMounts, entry.Type) {
			defer view.SetReadOnlyErr(origReadOnlyErr)
		}

		// Create the new backend
		var backend logical.Backend
		sysView := m.core.mountEntrySysView(entry)

		switch m.tableType {
		case mountTableType:
			backend, entry.RunningSha256, err = m.core.newLogicalBackend(ctx, entry, sysView, view)
		case credentialTableType:
			backend, entry.RunningSha256, err = m.core.newCredentialBackend(ctx, entry, sysView, view)
		case auditTableType, configAuditTableType:
			auditBackend, err := m.core.newAuditBackend(ctx, entry, view, entry.Options)
			if err != nil {
				m.core.logger.Error("failed to create audit entry", "path", entry.Path, "error", err)
				continue
			}
			if backend == nil {
				m.core.logger.Error("created audit entry was nil", "path", entry.Path, "type", entry.Type)
				continue
			}
			broker.Register(entry.Path, auditBackend, view, entry.Local)
			successCount++
		}

		if m.tableType == auditTableType || m.tableType == configAuditTableType {
			if len(m.table.Entries) > 0 && successCount == 0 {
				return errLoadAuditFailed
			}

			m.core.auditBroker = broker
			return nil
		}

		var pluginType consts.PluginType
		switch m.tableType {
		case mountTableType:
			pluginType = consts.PluginTypeSecrets
		case credentialTableType:
			pluginType = consts.PluginTypeCredential
		default:
			pluginType = consts.PluginTypeUnknown
		}

		if err != nil {
			m.core.logger.Error("failed to create mount entry", "path", entry.Path, "error", err)
			if m.core.isMountable(ctx, entry, pluginType) {
				m.core.logger.Warn("skipping plugin-based mount entry", "path", entry.Path)
				goto ROUTER_MOUNT
			}
			return errLoadMountsFailed
		}

		if backend == nil {
			return fmt.Errorf("created mount entry of type %q is nil", entry.Type)
		}

		// update the entry running version with the configured version,
		// which was verified during registration.
		entry.RunningVersion = entry.Version
		if entry.RunningVersion == "" {
			// don't set the running version to a builtin if it
			// is running as an external plugin
			if entry.RunningSha256 == "" {
				entry.RunningVersion = versions.GetBuiltinVersion(pluginType, entry.Type)
			}
		}

		// Do not start up deprecated builtin plugins. If this is a major
		// upgrade, stop unsealing and shutdown. If we've already mounted this
		// plugin, proceed with unsealing and skip backend initialization.
		if versions.IsBuiltinVersion(entry.RunningVersion) {
			_, err := m.core.handleDeprecatedMountEntry(ctx, entry, pluginType)
			if m.core.isMajorVersionFirstMount(ctx) && err != nil {
				go m.core.ShutdownCoreError(fmt.Errorf("could not mount %q: %w", entry.Type, err))
				return errLoadMountsFailed
			} else if err != nil {
				m.core.logger.Error("skipping deprecated mount entry", "name", entry.Type, "path", entry.Path, "error", err)
				backend.Cleanup(ctx)
				backend = nil
				goto ROUTER_MOUNT
			}
		}

		{
			backendType := backend.Type()
			switch m.tableType {
			case mountTableType:
				if backendType != logical.TypeLogical {
					if err := knownMountType(entry.Type); err != nil {
						return err
					}
				}
				m.core.setCoreBackend(entry, backend, view)
			case credentialTableType:
				if backendType != logical.TypeCredential {
					return fmt.Errorf("cannot mount %q of type %q as an auth backend", entry.Type, backendType)
				}
			default:
				return fmt.Errorf("cannot mount %q of type %q as an %s backend", entry.Type, backendType, m.tableType)
			}
		}

	ROUTER_MOUNT:
		// Mount the backend
		if err = m.core.router.Mount(backend, entry.APIPathNoNamespace(), entry, view); err != nil {
			m.core.logger.Error("failed to mount entry", "path", entry.APIPathNoNamespace(), "error", err)
			return errLoadMountsFailed
		}

		if m.core.logger.IsInfo() {
			m.core.logger.Info("successfully mounted", "type", entry.Type, "version", entry.RunningVersion, "path", entry.APIPathNoNamespace(), "namespace", entry.Namespace())
		}

		// Ensure the path is tainted if set in the mount table
		if entry.Tainted {
			m.core.logger.Debug("tainting a mount due to it being marked as tainted in mount table", "path", entry.APIPathNoNamespace(), "namespace_path", entry.Namespace().Path, "full_path", entry.APIPath())
			if err := m.core.router.Taint(ctx, entry.APIPath()); err != nil {
				return err
			}
		}

		// Check if this is the token store
		if entry.Type == mountTypeToken {
			m.core.tokenStore = backend.(*TokenStore)

			// At some point when this isn't beta we may persist this but for
			// now always set it on mount
			entry.Config.TokenType = logical.TokenTypeDefaultService

			// this is loaded *after* the normal mounts, including cubbyhole
			m.core.router.tokenStoreSaltFunc = m.core.tokenStore.Salt
			m.core.tokenStore.cubbyholeBackend = m.core.router.MatchingBackend(ctx, mountPathCubbyhole).(*CubbyholeBackend)
		}

		// Bind locally
		localEntry := entry
		m.core.postUnsealFuncs = append(m.core.postUnsealFuncs, func() {
			postUnsealLogger := m.core.logger.With("type", localEntry.Type, "version", localEntry.RunningVersion, "path", entry.APIPathNoNamespace())
			if backend == nil {
				postUnsealLogger.Error("skipping initialization for nil backend", "path", entry.APIPathNoNamespace())
				return
			}
			if !slices.Contains(singletonMounts, localEntry.Type) {
				view.SetReadOnlyErr(origReadOnlyErr)
			}

			if err := backend.Initialize(ctx, &logical.InitializationRequest{Storage: view}); err != nil {
				postUnsealLogger.Error("failed to initialize mount backend", "error", err)
			}
		})
	}

	return nil
}

// taintMountEntry is used to mark an entry in the mount table as tainted
func (m *mountable) taintMountEntry(ctx context.Context, nsID, mountPath string, updateStorage bool) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	// Taint the entry on original slice since setting the taint
	// operates on the entries which a shallow clone shares anyways
	entry := m.table.setTaint(nsID, strings.TrimPrefix(mountPath, credentialRoutePrefix))
	// Ensure there was a match
	if entry == nil {
		return fmt.Errorf("no matching backend for path %q namespaceID %q", mountPath, nsID)
	}

	if updateStorage {
		// Update the mount table
		if err := m.persistMount(ctx, m.core.barrier, m.table, entry); err != nil {
			return fmt.Errorf("failed to update mount table: %w", err)
		}
	}

	return nil
}
