// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package audit

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-multierror"
	uuid "github.com/hashicorp/go-uuid"
	au "github.com/openbao/openbao/audit"
	"github.com/openbao/openbao/command/server"
	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/sdk/v2/helper/jsonutil"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/vault/barrier"
	"github.com/openbao/openbao/vault/routing"
)

const (
	// ConfigPath is used to store the audit configuration.
	// Audit configuration is protected within the Vault itself, which means it
	// can only be viewed or modified after an unseal.
	ConfigPath = "core/audit"

	// LocalConfigPath is used to store audit information for local
	// (non-replicated) mounts
	LocalConfigPath = "core/local-audit"

	// BarrierPrefix is the prefix to the UUID used in the
	// barrier view for the audit backends.
	BarrierPrefix = "audit/"

	// TableType is the value we expect to find for the audit table and
	// corresponding entries. These can only be created by the deprecated
	// sys/audit API; config-created audit entries are created with a
	// different type.
	TableType = "audit"

	// ConfigTableType is the value we expect to find for audit table
	// entries created by configuration and not just in-storage. While the
	// in-storage takes precedence and is loaded, having a mismatched
	// configuration entry means that audit devices will be removed and/or
	// server startup will fail if the audit device configuration changes.
	ConfigTableType = "audit-config"
)

// ErrLoadAuditFailed returns an error if loading audit tables encounters an error.
var ErrLoadAuditFailed = errors.New("failed to setup audit table")

func generateAuditTestProbe() (*logical.LogInput, error) {
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

type core interface {
	MountEntryView(me *routing.MountEntry) (barrier.View, error)
	NewAuditBackend(ctx context.Context, entry *routing.MountEntry, view logical.Storage, conf map[string]string) (au.Backend, error)
	RemoveAuditReloadFunc(entry *routing.MountEntry)
	NamespaceView(ns *namespace.Namespace) barrier.View
	NamespaceByID(ctx context.Context, nsID string) (*namespace.Namespace, error)
}

type Table struct {
	// Broker is used to ingest the audit events and fan
	// out into the configured audit backends
	Broker *Broker
	c      core
	r      *routing.Router

	Mt *routing.MountTable
	// lock is used to ensure that the audit table does not
	// change underneath a calling function.
	sync.RWMutex

	logger log.Logger
}

// defaultAuditTable creates a default audit table.
func defaultAuditTable() *routing.MountTable {
	return &routing.MountTable{
		Type: TableType,
	}
}

func NewAuditTable(ctx context.Context, c core, r *routing.Router, view barrier.View, logger log.Logger) (*Table, []func(), error) {
	var err error
	at := &Table{c: c, r: r, logger: logger}
	at.Broker, err = NewAuditBroker(ctx, view, logger)
	if err != nil {
		return nil, nil, err
	}

	postUnsealFuncs, err := at.ReconcileAudits(ctx, false, true)
	if err != nil {
		if multiErr, ok := err.(*multierror.Error); ok {
			for _, err := range multiErr.Errors {
				logger.Error(err.Error())
			}
		} else {
			return nil, nil, err
		}
	}

	if len(at.Mt.Entries) > 0 && at.Broker.Count() == 0 {
		return nil, nil, ErrLoadAuditFailed
	}

	return at, postUnsealFuncs, nil
}

// EnableAudit is used to enable a new audit backend
func (at *Table) EnableAudit(ctx context.Context, entry *routing.MountEntry, updateStorage bool) error {
	// Ensure we end the path in a slash
	if !strings.HasSuffix(entry.Path, "/") {
		entry.Path += "/"
	}

	// Ensure there is a name
	if entry.Path == "/" {
		return errors.New("backend path must be specified")
	}

	// Update the audit table
	at.Lock()
	defer at.Unlock()

	// Look for matching name
	for _, ent := range at.Mt.Entries {
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
		accessor, err := at.r.GenerateMountAccessor("audit_" + entry.Type)
		if err != nil {
			return err
		}
		entry.Accessor = accessor
	}

	view, err := at.c.MountEntryView(entry)
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
	backend, err := at.c.NewAuditBackend(ctx, entry, view, entry.Options)
	if err != nil {
		return err
	}
	if backend == nil {
		return fmt.Errorf("nil audit backend of type %q returned from factory", entry.Type)
	}

	if entry.Options["skip_test"] != "true" {
		// Test the new audit device and report failure if it doesn't work.
		testProbe, err := generateAuditTestProbe()
		if err != nil {
			return err
		}
		err = backend.LogTestMessage(ctx, testProbe, entry.Options)
		if err != nil {
			at.logger.Error("new audit backend failed test", "path", entry.Path, "type", entry.Type, "error", err)
			return fmt.Errorf("audit backend failed test message: %w", err)
		}
	}

	newTable := at.Mt.ShallowClone()
	newTable.Entries = append(newTable.Entries, entry)

	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return err
	}
	entry.NamespaceID = ns.ID
	entry.Namespace = ns

	if updateStorage {
		if err := at.persistAudit(ctx, at.c.NamespaceView(ns), newTable, entry.Local); err != nil {
			return errors.New("failed to update audit table")
		}
	}

	at.Mt = newTable

	// Register the backend
	at.Broker.Register(entry.Path, backend, view, entry.Local)
	if at.logger.IsInfo() {
		at.logger.Info("enabled audit backend", "path", entry.Path, "type", entry.Type)
	}

	return nil
}

// DisableAudit is used to disable an existing audit backend
func (at *Table) DisableAudit(ctx context.Context, path string, updateStorage bool) (bool, error) {
	// Ensure we end the path in a slash
	if !strings.HasSuffix(path, "/") {
		path += "/"
	}

	// Ensure there is a name
	if path == "/" {
		return false, errors.New("backend path must be specified")
	}

	// Remove the entry from the mount table
	at.Lock()
	defer at.Unlock()

	newTable := at.Mt.ShallowClone()
	entry, err := newTable.Remove(ctx, path)
	if err != nil {
		return false, err
	}

	// Ensure there was a match
	if entry == nil {
		return false, errors.New("no matching backend")
	}

	at.c.RemoveAuditReloadFunc(entry)

	// When unmounting all entries the JSON code will load back up from storage
	// as a nil slice, which kills tests...just set it nil explicitly
	if len(newTable.Entries) == 0 {
		newTable.Entries = nil
	}

	if updateStorage {
		// Update the audit table
		if err := at.persistAudit(ctx, at.c.NamespaceView(namespace.RootNamespace), newTable, entry.Local); err != nil {
			return true, errors.New("failed to update audit table")
		}
	}

	at.Mt = newTable

	// Unmount the backend
	at.Broker.Deregister(path)
	if at.logger.IsInfo() {
		at.logger.Info("disabled audit backend", "path", path)
	}

	return true, nil
}

// loadAudits is invoked as part of reconcileAudits (which holds the lock) to load the audit table.
func (at *Table) loadAudits(ctx context.Context, b barrier.View, readonly bool) error {
	auditTable := &routing.MountTable{}
	localAuditTable := &routing.MountTable{}

	// Load the existing audit table
	raw, err := b.Get(ctx, ConfigPath)
	if err != nil {
		at.logger.Error("failed to read audit table", "error", err)
		return ErrLoadAuditFailed
	}
	rawLocal, err := b.Get(ctx, LocalConfigPath)
	if err != nil {
		at.logger.Error("failed to read local audit table", "error", err)
		return ErrLoadAuditFailed
	}

	if raw != nil {
		if err := jsonutil.DecodeJSON(raw.Value, auditTable); err != nil {
			at.logger.Error("failed to decode audit table", "error", err)
			return ErrLoadAuditFailed
		}
		at.Mt = auditTable
	}

	var needPersist bool
	if at.Mt == nil {
		at.Mt = defaultAuditTable()
		needPersist = true
	}

	if rawLocal != nil {
		if err := jsonutil.DecodeJSON(rawLocal.Value, localAuditTable); err != nil {
			at.logger.Error("failed to decode local audit table", "error", err)
			return ErrLoadAuditFailed
		}
		if len(localAuditTable.Entries) > 0 {
			at.Mt.Entries = append(at.Mt.Entries, localAuditTable.Entries...)
		}
	}

	// Upgrade to typed auth table
	if at.Mt.Type == "" {
		at.Mt.Type = TableType
		needPersist = true
	}

	// Upgrade to table-scoped entries
	for _, entry := range at.Mt.Entries {
		if entry.Table == "" {
			entry.Table = at.Mt.Type
			needPersist = true
		}
		if entry.Accessor == "" {
			accessor, err := at.r.GenerateMountAccessor("audit_" + entry.Type)
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
		ns, err := at.c.NamespaceByID(ctx, entry.NamespaceID)
		if err != nil {
			return err
		}
		if ns == nil {
			return namespace.ErrNoNamespace
		}
		entry.Namespace = ns
	}

	if !needPersist {
		return nil
	}

	if readonly {
		at.logger.Warn("audit table needs update")
		return nil
	}

	if err := at.persistAudit(ctx, at.c.NamespaceView(namespace.RootNamespace), at.Mt, false); err != nil {
		return ErrLoadAuditFailed
	}
	return nil
}

// persistAudit is used to persist the audit table after modification.
func (at *Table) persistAudit(ctx context.Context, b barrier.View, table *routing.MountTable, localOnly bool) error {
	if table.Type != TableType {
		at.logger.Error("given table to persist has wrong type", "actual_type", table.Type, "expected_type", TableType)
		return errors.New("invalid table type given, not persisting")
	}

	nonLocalAudit := &routing.MountTable{
		Type: TableType,
	}

	localAudit := &routing.MountTable{
		Type: TableType,
	}

	for _, entry := range table.Entries {
		if entry.Table != table.Type && entry.Table != ConfigTableType {
			at.logger.Error("given entry to persist in audit table has wrong table value", "path", entry.Path, "entry_table_type", entry.Table, "actual_type", table.Type)
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
			at.logger.Error("failed to encode and/or compress audit table", "error", err)
			return err
		}

		// Create an entry
		entry := &logical.StorageEntry{
			Key:   ConfigPath,
			Value: compressedBytes,
		}

		// Write to the physical backend
		if err := b.Put(ctx, entry); err != nil {
			at.logger.Error("failed to persist audit table", "error", err)
			return err
		}
	}

	// Repeat with local audit
	compressedBytes, err := jsonutil.EncodeJSONAndCompress(localAudit, nil)
	if err != nil {
		at.logger.Error("failed to encode and/or compress local audit table", "error", err)
		return err
	}

	entry := &logical.StorageEntry{
		Key:   LocalConfigPath,
		Value: compressedBytes,
	}

	if err := b.Put(ctx, entry); err != nil {
		at.logger.Error("failed to persist local audit table", "error", err)
		return err
	}

	return nil
}

func (at *Table) InvalidateAudits(ctx context.Context) error {
	_, err := at.ReconcileAudits(ctx, true, false)
	return err
}

func (at *Table) ReconcileAudits(ctx context.Context, readonly, initial bool) ([]func(), error) {
	at.Lock()
	defer at.Unlock()

	var oldTable *routing.MountTable
	if at.Mt != nil {
		oldTable = at.Mt.ShallowClone()
	}

	if err := at.loadAudits(ctx, at.c.NamespaceView(namespace.RootNamespace), readonly); err != nil {
		at.Mt = oldTable
		return nil, err
	}

	additions, deletions := oldTable.Delta(at.Mt)

	var multiErr *multierror.Error

	for _, entry := range deletions {
		at.c.RemoveAuditReloadFunc(entry)
		at.Broker.Deregister(entry.Path)
		if at.logger.IsInfo() {
			at.logger.Info("disabled audit backend", "path", entry.Path)
		}
	}

	postUnsealFuncs := make([]func(), 0)
	for _, entry := range additions {
		view, err := at.c.MountEntryView(entry)
		if err != nil {
			return nil, err
		}

		origViewReadOnlyErr := view.GetReadOnlyErr()

		// Mark the view as read-only until the mounting is complete and
		// ensure that it is reset after. This ensures that there will be no
		// writes during the construction of the backend.
		view.SetReadOnlyErr(logical.ErrSetupReadOnly)
		if initial {
			postUnsealFuncs = append(postUnsealFuncs, func() {
				view.SetReadOnlyErr(origViewReadOnlyErr)
			})
		} else {
			defer view.SetReadOnlyErr(origViewReadOnlyErr)
		}

		// Initialize the backend
		backend, err := at.c.NewAuditBackend(ctx, entry, view, entry.Options)
		if err != nil {
			multiErr = multierror.Append(multiErr, err)
			continue
		}
		if backend == nil {
			multiErr = multierror.Append(multiErr, fmt.Errorf("nil audit backend of type %q returned from factory at path %q", entry.Type, entry.Path))
			continue
		}

		// Register the backend
		at.Broker.Register(entry.Path, backend, view, entry.Local)
		if at.logger.IsInfo() {
			at.logger.Info("enabled audit backend", "path", entry.Path, "type", entry.Type)
		}
	}

	return postUnsealFuncs, multiErr.ErrorOrNil()
}

func (at *Table) HandleAuditLogSetup(ctx context.Context, conf *server.Config, standby bool) error {
	if conf == nil {
		return errors.New("empty config encountered")
	}

	at.RLock()
	table := at.Mt.ShallowClone()
	at.RUnlock()

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

		entry, err := table.FindByPath(ctx, auditConfig.Path)
		if err != nil {
			return fmt.Errorf("while processing audit %v: %w", auditConfig.Path, err)
		}

		if entry == nil {
			if err := at.AddAuditFromConfig(ctx, auditConfig, standby); err != nil {
				return fmt.Errorf("failed to create new audit device %v: %w", auditConfig.Path, err)
			}
		} else {
			// We have created a duplicate entry.
			if entry.Table != ConfigTableType {
				return fmt.Errorf("audit device in configuration (path: %v) was already created by API; remove the API audit device before attempting to create a duplicate configuration-based version", entry.Path)
			}

			if err := validateAuditFromConfig(auditConfig, entry); err != nil {
				return fmt.Errorf("failed to validate audit device config %v: modifications to audit devices are not allowed: %w", auditConfig.Path, err)
			}
		}
	}

	for _, auditMount := range table.Entries {
		if _, present := auditDevicePaths[auditMount.Path]; present {
			continue
		}

		// If we have an API-based audit device, prevent deletion of it.
		if auditMount.Table != ConfigTableType {
			continue
		}

		if standby {
			at.logger.Warn("audit device present in storage but not standby node configuration; this may be a false-positive depending on data replication state", "path", auditMount.Path)
			continue
		}

		at.logger.Info("disabling removed audit device", "path", auditMount.Path)
		if existed, err := at.DisableAudit(ctx, auditMount.Path, true); existed && err != nil {
			return fmt.Errorf("failed to disable removed audit %v: %w", auditMount.Path, err)
		}
	}

	return nil
}

func (at *Table) AddAuditFromConfig(ctx context.Context, auditConfig *server.AuditDevice, standby bool) error {
	if standby {
		at.logger.Warn("audit device present in local configuration but not in the configuration of the active node; this may be a false-positive depending on data replication state", "path", auditConfig.Path)
		return nil
	}

	at.logger.Info("adding new audit device", "path", auditConfig.Path)

	me := &routing.MountEntry{
		Table:       ConfigTableType,
		Path:        auditConfig.Path,
		Type:        auditConfig.Type,
		Description: auditConfig.Description,
		Options:     auditConfig.Options,
		Local:       auditConfig.Local,
	}

	return at.EnableAudit(ctx, me, true)
}

func validateAuditFromConfig(auditConfig *server.AuditDevice, auditEntry *routing.MountEntry) error {
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
