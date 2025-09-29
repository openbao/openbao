// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"

	"github.com/hashicorp/go-multierror"
	uuid "github.com/hashicorp/go-uuid"
	"github.com/openbao/openbao/audit"
	"github.com/openbao/openbao/command/server"
	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/openbao/openbao/sdk/v2/helper/jsonutil"
	"github.com/openbao/openbao/sdk/v2/helper/salt"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const (
	// coreAuditConfigPath is used to store the audit configuration.
	// Audit configuration is protected within the Vault itself, which means it
	// can only be viewed or modified after an unseal.
	coreAuditConfigPath = "core/audit"

	// coreLocalAuditConfigPath is used to store audit information for local
	// (non-replicated) mounts
	coreLocalAuditConfigPath = "core/local-audit"

	// auditBarrierPrefix is the prefix to the UUID used in the
	// barrier view for the audit backends.
	auditBarrierPrefix = "audit/"

	// auditTableType is the value we expect to find for the audit table and
	// corresponding entries. These can only be created by the deprecated
	// sys/audit API; config-created audit entries are created with a
	// different type.
	auditTableType = "audit"

	// configAuditTableType is the value we expect to find for audit table
	// entries created by configuration and not just in-storage. While the
	// in-storage takes precedence and is loaded, having a mismatched
	// configuration entry means that audit devices will be removed and/or
	// server startup will fail if the audit device configuration changes.
	configAuditTableType = "audit-config"
)

// loadAuditFailed if loading audit tables encounters an error
var errLoadAuditFailed = errors.New("failed to setup audit table")

func (c *Core) generateAuditTestProbe() (*logical.LogInput, error) {
	requestId, err := uuid.GenerateUUID()
	if err != nil {
		return nil, err
	}
	return &logical.LogInput{
		Type: "request",
		Auth: nil,
		Request: &logical.Request{
			ID:        requestId,
			Operation: "update",
			Path:      "sys/audit/test",
		},
		Response: nil,
		OuterErr: nil,
	}, nil
}

// enableAudit is used to enable a new audit backend
func (c *Core) enableAudit(ctx context.Context, entry *MountEntry, updateStorage bool) error {
	// Ensure we end the path in a slash
	if !strings.HasSuffix(entry.Path, "/") {
		entry.Path += "/"
	}

	// Ensure there is a name
	if entry.Path == "/" {
		return errors.New("backend path must be specified")
	}

	// Update the audit table
	c.auditLock.Lock()
	defer c.auditLock.Unlock()

	// Look for matching name
	for _, ent := range c.audit.Entries {
		switch {
		// Existing is sql/mysql/ new is sql/ or
		// existing is sql/ and new is sql/mysql/
		case strings.HasPrefix(ent.Path, entry.Path):
			fallthrough
		case strings.HasPrefix(entry.Path, ent.Path):
			return errors.New("path already in use")
		}
	}

	// Generate a new UUID and view
	if entry.UUID == "" {
		entryUUID, err := uuid.GenerateUUID()
		if err != nil {
			return err
		}
		entry.UUID = entryUUID
	}
	if entry.Accessor == "" {
		accessor, err := c.generateMountAccessor("audit_" + entry.Type)
		if err != nil {
			return err
		}
		entry.Accessor = accessor
	}

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

	// Lookup the new backend
	backend, err := c.newAuditBackend(ctx, entry, view, entry.Options)
	if err != nil {
		return err
	}
	if backend == nil {
		return fmt.Errorf("nil audit backend of type %q returned from factory", entry.Type)
	}

	if entry.Options["skip_test"] != "true" {
		// Test the new audit device and report failure if it doesn't work.
		testProbe, err := c.generateAuditTestProbe()
		if err != nil {
			return err
		}
		err = backend.LogTestMessage(ctx, testProbe, entry.Options)
		if err != nil {
			c.logger.Error("new audit backend failed test", "path", entry.Path, "type", entry.Type, "error", err)
			return fmt.Errorf("audit backend failed test message: %w", err)

		}
	}

	newTable := c.audit.shallowClone()
	newTable.Entries = append(newTable.Entries, entry)

	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return err
	}
	entry.NamespaceID = ns.ID
	entry.namespace = ns

	if updateStorage {
		if err := c.persistAudit(ctx, newTable, entry.Local); err != nil {
			return errors.New("failed to update audit table")
		}
	}

	c.audit = newTable

	// Register the backend
	c.auditBroker.Register(entry.Path, backend, view, entry.Local)
	if c.logger.IsInfo() {
		c.logger.Info("enabled audit backend", "path", entry.Path, "type", entry.Type)
	}

	return nil
}

// disableAudit is used to disable an existing audit backend
func (c *Core) disableAudit(ctx context.Context, path string, updateStorage bool) (bool, error) {
	// Ensure we end the path in a slash
	if !strings.HasSuffix(path, "/") {
		path += "/"
	}

	// Ensure there is a name
	if path == "/" {
		return false, errors.New("backend path must be specified")
	}

	// Remove the entry from the mount table
	c.auditLock.Lock()
	defer c.auditLock.Unlock()

	newTable := c.audit.shallowClone()
	entry, err := newTable.remove(ctx, path)
	if err != nil {
		return false, err
	}

	// Ensure there was a match
	if entry == nil {
		return false, errors.New("no matching backend")
	}

	c.removeAuditReloadFunc(entry)

	// When unmounting all entries the JSON code will load back up from storage
	// as a nil slice, which kills tests...just set it nil explicitly
	if len(newTable.Entries) == 0 {
		newTable.Entries = nil
	}

	if updateStorage {
		// Update the audit table
		if err := c.persistAudit(ctx, newTable, entry.Local); err != nil {
			return true, errors.New("failed to update audit table")
		}
	}

	c.audit = newTable

	// Unmount the backend
	c.auditBroker.Deregister(path)
	if c.logger.IsInfo() {
		c.logger.Info("disabled audit backend", "path", path)
	}

	return true, nil
}

// loadAudits is invoked as part of reconcileAudits (which holds the lock) to load the audit table
func (c *Core) loadAudits(ctx context.Context, readonly bool) error {
	auditTable := &MountTable{}
	localAuditTable := &MountTable{}

	// Load the existing audit table
	raw, err := c.barrier.Get(ctx, coreAuditConfigPath)
	if err != nil {
		c.logger.Error("failed to read audit table", "error", err)
		return errLoadAuditFailed
	}
	rawLocal, err := c.barrier.Get(ctx, coreLocalAuditConfigPath)
	if err != nil {
		c.logger.Error("failed to read local audit table", "error", err)
		return errLoadAuditFailed
	}

	if raw != nil {
		if err := jsonutil.DecodeJSON(raw.Value, auditTable); err != nil {
			c.logger.Error("failed to decode audit table", "error", err)
			return errLoadAuditFailed
		}
		c.audit = auditTable
	}

	var needPersist bool
	if c.audit == nil {
		c.audit = defaultAuditTable()
		needPersist = true
	}

	if rawLocal != nil {
		if err := jsonutil.DecodeJSON(rawLocal.Value, localAuditTable); err != nil {
			c.logger.Error("failed to decode local audit table", "error", err)
			return errLoadAuditFailed
		}
		if len(localAuditTable.Entries) > 0 {
			c.audit.Entries = append(c.audit.Entries, localAuditTable.Entries...)
		}
	}

	// Upgrade to typed auth table
	if c.audit.Type == "" {
		c.audit.Type = auditTableType
		needPersist = true
	}

	// Upgrade to table-scoped entries
	for _, entry := range c.audit.Entries {
		if entry.Table == "" {
			entry.Table = c.audit.Type
			needPersist = true
		}
		if entry.Accessor == "" {
			accessor, err := c.generateMountAccessor("audit_" + entry.Type)
			if err != nil {
				return err
			}
			entry.Accessor = accessor
			needPersist = true
		}

		if entry.NamespaceID == "" {
			entry.NamespaceID = namespace.RootNamespaceID
			needPersist = true
		}
		// Get the namespace from the namespace ID and load it in memory
		ns, err := c.NamespaceByID(ctx, entry.NamespaceID)
		if err != nil {
			return err
		}
		if ns == nil {
			return namespace.ErrNoNamespace
		}
		entry.namespace = ns
	}

	if !needPersist {
		return nil
	}

	if readonly {
		c.logger.Warn("audit table needs update")
		return nil
	}

	if err := c.persistAudit(ctx, c.audit, false); err != nil {
		return errLoadAuditFailed
	}
	return nil
}

// persistAudit is used to persist the audit table after modification
func (c *Core) persistAudit(ctx context.Context, table *MountTable, localOnly bool) error {
	if table.Type != auditTableType {
		c.logger.Error("given table to persist has wrong type", "actual_type", table.Type, "expected_type", auditTableType)
		return errors.New("invalid table type given, not persisting")
	}

	nonLocalAudit := &MountTable{
		Type: auditTableType,
	}

	localAudit := &MountTable{
		Type: auditTableType,
	}

	for _, entry := range table.Entries {
		if entry.Table != table.Type && entry.Table != configAuditTableType {
			c.logger.Error("given entry to persist in audit table has wrong table value", "path", entry.Path, "entry_table_type", entry.Table, "actual_type", table.Type)
			return errors.New("invalid audit entry found, not persisting")
		}

		if entry.Local {
			localAudit.Entries = append(localAudit.Entries, entry)
		} else {
			nonLocalAudit.Entries = append(nonLocalAudit.Entries, entry)
		}
	}

	if !localOnly {
		// Marshal the table
		compressedBytes, err := jsonutil.EncodeJSONAndCompress(nonLocalAudit, nil)
		if err != nil {
			c.logger.Error("failed to encode and/or compress audit table", "error", err)
			return err
		}

		// Create an entry
		entry := &logical.StorageEntry{
			Key:   coreAuditConfigPath,
			Value: compressedBytes,
		}

		// Write to the physical backend
		if err := c.barrier.Put(ctx, entry); err != nil {
			c.logger.Error("failed to persist audit table", "error", err)
			return err
		}
	}

	// Repeat with local audit
	compressedBytes, err := jsonutil.EncodeJSONAndCompress(localAudit, nil)
	if err != nil {
		c.logger.Error("failed to encode and/or compress local audit table", "error", err)
		return err
	}

	entry := &logical.StorageEntry{
		Key:   coreLocalAuditConfigPath,
		Value: compressedBytes,
	}

	if err := c.barrier.Put(ctx, entry); err != nil {
		c.logger.Error("failed to persist local audit table", "error", err)
		return err
	}

	return nil
}

// setupAudit is invoked after we've loaded the audit able to
// initialize the audit backends
func (c *Core) setupAudits(ctx context.Context) error {
	brokerLogger := c.baseLogger.Named("audit")
	c.AddLogger(brokerLogger)
	c.auditBroker = NewAuditBroker(brokerLogger)

	err := c.reconcileAudits(reconcileAuditsRequests{
		ctx:       ctx,
		readonly:  false,
		isInitial: true,
	})
	if err != nil {
		if multiErr, ok := err.(*multierror.Error); ok {
			for _, err := range multiErr.Errors {
				c.logger.Error(err.Error())
			}
		} else {
			return err
		}
	}

	if len(c.audit.Entries) > 0 && c.auditBroker.Count() == 0 {
		return errLoadAuditFailed
	}

	return nil
}

func (c *Core) invalidateAudits() {
	go func() {
		err := c.reconcileAudits(reconcileAuditsRequests{
			ctx:       c.activeContext,
			readonly:  true,
			isInitial: false,
		})
		if err != nil {
			c.logger.Error("unable to invalidate audits, restarting core", "error", err.Error())
			c.restart()
		}
	}()
}

type reconcileAuditsRequests struct {
	ctx       context.Context
	readonly  bool
	isInitial bool
}

func (c *Core) reconcileAudits(req reconcileAuditsRequests) error {
	c.auditLock.Lock()
	defer c.auditLock.Unlock()

	var oldTable *MountTable
	if c.audit != nil {
		oldTable = c.audit.shallowClone()
	}

	if err := c.loadAudits(req.ctx, req.readonly); err != nil {
		c.audit = oldTable
		return err
	}

	additions, deletions := oldTable.delta(c.audit)

	var multiErr *multierror.Error

	for _, entry := range deletions {
		c.removeAuditReloadFunc(entry)

		c.auditBroker.Deregister(entry.Path)
		if c.logger.IsInfo() {
			c.logger.Info("disabled audit backend", "path", entry.Path)
		}
	}

	for _, entry := range additions {
		view, err := c.mountEntryView(entry)
		if err != nil {
			return err
		}

		origViewReadOnlyErr := view.GetReadOnlyErr()

		// Mark the view as read-only until the mounting is complete and
		// ensure that it is reset after. This ensures that there will be no
		// writes during the construction of the backend.
		view.SetReadOnlyErr(logical.ErrSetupReadOnly)
		if req.isInitial {
			c.postUnsealFuncs = append(c.postUnsealFuncs, func() {
				view.SetReadOnlyErr(origViewReadOnlyErr)
			})
		} else {
			defer view.SetReadOnlyErr(origViewReadOnlyErr)
		}

		// Initialize the backend
		backend, err := c.newAuditBackend(req.ctx, entry, view, entry.Options)
		if err != nil {
			multiErr = multierror.Append(multiErr, err)
			continue
		}
		if backend == nil {
			multiErr = multierror.Append(multiErr, fmt.Errorf("nil audit backend of type %q returned from factory at path %q", entry.Type, entry.Path))
			continue
		}

		// Register the backend
		c.auditBroker.Register(entry.Path, backend, view, entry.Local)
		if c.logger.IsInfo() {
			c.logger.Info("enabled audit backend", "path", entry.Path, "type", entry.Type)
		}
	}

	return multiErr.ErrorOrNil()
}

// teardownAudit is used before we seal the vault to reset the audit
// backends to their unloaded state. This is reversed by loadAudits.
func (c *Core) teardownAudits() error {
	c.auditLock.Lock()
	defer c.auditLock.Unlock()

	if c.audit != nil {
		for _, entry := range c.audit.Entries {
			c.removeAuditReloadFunc(entry)
		}
	}

	c.audit = nil
	c.auditBroker = nil
	return nil
}

// removeAuditReloadFunc removes the reload func from the working set. The
// audit lock needs to be held before calling this.
func (c *Core) removeAuditReloadFunc(entry *MountEntry) {
	switch entry.Type {
	case "file":
		key := "audit_file|" + entry.Path
		c.reloadFuncsLock.Lock()

		if c.logger.IsDebug() {
			c.baseLogger.Named("audit").Debug("removing reload function", "path", entry.Path)
		}

		delete(c.reloadFuncs, key)

		c.reloadFuncsLock.Unlock()
	}
}

// newAuditBackend is used to create and configure a new audit backend by name
func (c *Core) newAuditBackend(ctx context.Context, entry *MountEntry, view logical.Storage, conf map[string]string) (audit.Backend, error) {
	f, ok := c.auditBackends[entry.Type]
	if !ok {
		return nil, fmt.Errorf("unknown backend type: %q", entry.Type)
	}
	saltConfig := &salt.Config{
		HMAC:     sha256.New,
		HMACType: "hmac-sha256",
		Location: salt.DefaultLocation,
	}

	be, err := f(ctx, &audit.BackendConfig{
		SaltView:   view,
		SaltConfig: saltConfig,
		Config:     conf,
	})
	if err != nil {
		return nil, err
	}
	if be == nil {
		return nil, fmt.Errorf("nil backend returned from %q factory function", entry.Type)
	}

	auditLogger := c.baseLogger.Named("audit")
	c.AddLogger(auditLogger)

	switch entry.Type {
	case "file":
		key := "audit_file|" + entry.Path

		c.reloadFuncsLock.Lock()

		if auditLogger.IsDebug() {
			auditLogger.Debug("adding reload function", "path", entry.Path)
			if entry.Options != nil {
				auditLogger.Debug("file backend options", "path", entry.Path, "file_path", entry.Options["file_path"])
			}
		}

		c.reloadFuncs[key] = append(c.reloadFuncs[key], func() error {
			if auditLogger.IsInfo() {
				auditLogger.Info("reloading file audit backend", "path", entry.Path)
			}
			return be.Reload(ctx)
		})

		c.reloadFuncsLock.Unlock()
	case "socket":
		if auditLogger.IsDebug() {
			if entry.Options != nil {
				auditLogger.Debug("socket backend options", "path", entry.Path, "address", entry.Options["address"], "socket type", entry.Options["socket_type"])
			}
		}
	case "syslog":
		if auditLogger.IsDebug() {
			if entry.Options != nil {
				auditLogger.Debug("syslog backend options", "path", entry.Path, "facility", entry.Options["facility"], "tag", entry.Options["tag"])
			}
		}
	}

	return be, err
}

// defaultAuditTable creates a default audit table
func defaultAuditTable() *MountTable {
	table := &MountTable{
		Type: auditTableType,
	}
	return table
}

type AuditLogger interface {
	AuditRequest(ctx context.Context, input *logical.LogInput) error
	AuditResponse(ctx context.Context, input *logical.LogInput) error
}

type basicAuditor struct {
	c *Core
}

func (b *basicAuditor) AuditRequest(ctx context.Context, input *logical.LogInput) error {
	if b.c.auditBroker == nil {
		return consts.ErrSealed
	}
	return b.c.auditBroker.LogRequest(ctx, input, b.c.auditedHeaders)
}

func (b *basicAuditor) AuditResponse(ctx context.Context, input *logical.LogInput) error {
	if b.c.auditBroker == nil {
		return consts.ErrSealed
	}
	return b.c.auditBroker.LogResponse(ctx, input, b.c.auditedHeaders)
}

type genericAuditor struct {
	c         *Core
	mountType string
	namespace *namespace.Namespace
}

func (g genericAuditor) AuditRequest(ctx context.Context, input *logical.LogInput) error {
	ctx = namespace.ContextWithNamespace(ctx, g.namespace)
	logInput := *input
	logInput.Type = g.mountType + "-request"
	return g.c.auditBroker.LogRequest(ctx, &logInput, g.c.auditedHeaders)
}

func (g genericAuditor) AuditResponse(ctx context.Context, input *logical.LogInput) error {
	ctx = namespace.ContextWithNamespace(ctx, g.namespace)
	logInput := *input
	logInput.Type = g.mountType + "-response"
	return g.c.auditBroker.LogResponse(ctx, &logInput, g.c.auditedHeaders)
}

func (c *Core) ReloadAuditLogs() {
	// Ensure we are already unsealed
	c.stateLock.RLock()
	defer c.stateLock.RUnlock()

	if c.Sealed() {
		return
	}

	if err := c.handleAuditLogSetup(c.activeContext); err != nil {
		c.logger.Error("failed to set up audit logs on reload", "error", err)
	}
}

func (c *Core) handleAuditLogSetup(ctx context.Context) error {
	conf := c.rawConfig.Load().(*server.Config)

	c.auditLock.RLock()
	table := c.audit.shallowClone()
	c.auditLock.RUnlock()

	auditDevicePaths := make(map[string]struct{}, len(conf.Audits))
	for index, auditConfig := range conf.Audits {
		if !strings.HasSuffix(auditConfig.Path, "/") {
			auditConfig.Path += "/"
		}

		if auditConfig.Path == "/" {
			return fmt.Errorf("audit config %v is missing a path", index)
		}

		// Ensure it is unique w.r.t. other configs.
		if _, present := auditDevicePaths[auditConfig.Path]; present {
			return fmt.Errorf("two audit devices with same path (%v) exist in config", auditConfig.Path)
		}

		// Ensure we don't have a prefix.
		if _, hasPrefix := auditConfig.Options["prefix"]; hasPrefix && !conf.AllowAuditLogPrefixing {
			return fmt.Errorf("audit log prefixing is not allowed")
		}

		// If the device exists in our table, validate it.
		auditDevicePaths[auditConfig.Path] = struct{}{}

		entry, err := table.findByPath(ctx, auditConfig.Path)
		if err != nil {
			return fmt.Errorf("while processing audit %v: %w", auditConfig.Path, err)
		}

		if entry == nil {
			if err := c.addAuditFromConfig(ctx, auditConfig); err != nil {
				return fmt.Errorf("failed to create new audit device %v: %w", auditConfig.Path, err)
			}
		} else {
			// We have created a duplicate entry.
			if entry.Table != configAuditTableType {
				return fmt.Errorf("audit device in configuration (path: %v) was already created by API; remove the API audit device before attempting to create a duplicate configuration-based version", entry.Path)
			}

			if err := c.validateAuditFromConfig(ctx, auditConfig, entry); err != nil {
				return fmt.Errorf("failed to validate audit device config %v: modifications to audit devices are not allowed: %w", auditConfig.Path, err)
			}
		}
	}

	for _, auditMount := range table.Entries {
		if _, present := auditDevicePaths[auditMount.Path]; present {
			continue
		}

		// If we have an API-based audit device, prevent deletion of it.
		if auditMount.Table != configAuditTableType {
			continue
		}

		if c.standby {
			c.logger.Warn("audit device present in storage but not standby node configuration", "path", auditMount.Path)
			continue
		}

		c.logger.Info("disabling removed audit device", "path", auditMount.Path)
		if existed, err := c.disableAudit(ctx, auditMount.Path, true); existed && err != nil {
			return fmt.Errorf("failed to disable removed audit %v: %w", auditMount.Path, err)
		}
	}

	return nil
}

func (c *Core) addAuditFromConfig(ctx context.Context, auditConfig *server.AuditDevice) error {
	if c.standby {
		c.logger.Warn("audit device present in local configuration but not in the configuration of the active node", "path", auditConfig.Path)
		return nil
	}

	c.logger.Info("adding new audit device", "path", auditConfig.Path)

	me := &MountEntry{
		// Config created
		Table:       configAuditTableType,
		Path:        auditConfig.Path,
		Type:        auditConfig.Type,
		Description: auditConfig.Description,
		Options:     auditConfig.Options,
		Local:       auditConfig.Local,
	}

	return c.enableAudit(ctx, me, true)
}

func (c *Core) validateAuditFromConfig(ctx context.Context, auditConfig *server.AuditDevice, auditEntry *MountEntry) error {
	if auditEntry.Type != auditConfig.Type {
		return fmt.Errorf("audit device %v has different types: %v (table) vs %v (config)", auditConfig.Path, auditEntry.Type, auditConfig.Type)
	}

	if auditEntry.Description != auditConfig.Description {
		return fmt.Errorf("audit device %v has different descriptions: %v (table) vs %v (config)", auditConfig.Path, auditEntry.Description, auditConfig.Description)
	}

	if auditEntry.Local != auditConfig.Local {
		return fmt.Errorf("audit device %v has different values for local: %v (table) vs %v (config)", auditConfig.Path, auditEntry.Local, auditConfig.Local)
	}

	for key, valueConfig := range auditConfig.Options {
		valueEntry, present := auditEntry.Options[key]
		if !present {
			return fmt.Errorf("audit device %v is missing option %v in the audit table but is present in the config", auditConfig.Path, key)
		}
		if valueEntry != valueConfig {
			return fmt.Errorf("audit device %v is missing option %v differs: %v (table) vs %v (config)", auditConfig.Path, key, valueEntry, valueConfig)
		}
	}

	for key := range auditEntry.Options {
		if _, present := auditConfig.Options[key]; !present {
			return fmt.Errorf("audit device %v is missing option %v in the audit table but is present in the config", auditConfig.Path, key)
		}
	}

	return nil
}
