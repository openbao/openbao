// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"path"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/armon/go-metrics"
	"github.com/hashicorp/go-uuid"
	"github.com/mitchellh/copystructure"
	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/builtin/plugin"
	"github.com/openbao/openbao/helper/metricsutil"
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

	// coreLocalMountConfigPath is used to store mount configuration for local
	// (non-replicated) mounts
	coreLocalMountConfigPath = "core/local-mounts"

	// backendBarrierPrefix is the prefix to the UUID used in the
	// barrier view for the backends.
	backendBarrierPrefix = "logical/"

	// systemBarrierPrefix is the prefix used for the
	// system logical backend.
	systemBarrierPrefix = "sys/"

	// mountTableType is the value we expect to find for the mount table and
	// corresponding entries
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

	MountTableUpdateStorage   = true
	MountTableNoUpdateStorage = false
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

func knownMountType(entryType string) error {
	switch entryType {
	case mountTypeKV, mountTypeSystem, mountTypeCubbyhole, mountTypeNSSystem, mountTypeNSCubbyhole:
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

// MountTable is used to represent the internal mount table
type MountTable struct {
	Type    string        `json:"type"`
	Entries []*MountEntry `json:"entries"`
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
func (c *Core) tableMetrics(entryCount int, isLocal bool, isAuth bool, compressedTableLen int) {
	if c.metricsHelper == nil {
		// do nothing if metrics are not initialized
		return
	}
	typeAuthLabelMap := map[bool]metrics.Label{
		true:  {Name: "type", Value: "auth"},
		false: {Name: "type", Value: "logical"},
	}

	typeLocalLabelMap := map[bool]metrics.Label{
		true:  {Name: "local", Value: "true"},
		false: {Name: "local", Value: "false"},
	}

	c.metricSink.SetGaugeWithLabels(metricsutil.LogicalTableSizeName,
		float32(entryCount), []metrics.Label{
			typeAuthLabelMap[isAuth],
			typeLocalLabelMap[isLocal],
		})

	c.metricsHelper.AddGaugeLoopMetric(metricsutil.LogicalTableSizeName,
		float32(entryCount), []metrics.Label{
			typeAuthLabelMap[isAuth],
			typeLocalLabelMap[isLocal],
		})

	c.metricSink.SetGaugeWithLabels(metricsutil.PhysicalTableSizeName,
		float32(compressedTableLen), []metrics.Label{
			typeAuthLabelMap[isAuth],
			typeLocalLabelMap[isLocal],
		})

	c.metricsHelper.AddGaugeLoopMetric(metricsutil.PhysicalTableSizeName,
		float32(compressedTableLen), []metrics.Label{
			typeAuthLabelMap[isAuth],
			typeLocalLabelMap[isLocal],
		})
}

// shallowClone returns a copy of the mount table that
// keeps the MountEntry locations, so as not to invalidate
// other locations holding pointers. Care needs to be taken
// if modifying entries rather than modifying the table itself
func (t *MountTable) shallowClone() *MountTable {
	return &MountTable{
		Type:    t.Type,
		Entries: slices.Clone(t.Entries),
	}
}

func (old *MountTable) delta(new *MountTable) (additions []*MountEntry, deletions []*MountEntry) {
	if old == nil {
		additions = new.Entries
		return
	}

	additions = slices.Clone(new.Entries)
	deletions = slices.Clone(old.Entries)

	slices.SortFunc(additions, func(a, b *MountEntry) int {
		return strings.Compare(a.Accessor, b.Accessor)
	})

	slices.SortFunc(deletions, func(a, b *MountEntry) int {
		return strings.Compare(a.Accessor, b.Accessor)
	})

	idxOld := 0
	idxNew := 0

	for idxNew < len(additions) && idxOld < len(deletions) {
		diff := strings.Compare(additions[idxNew].Accessor, deletions[idxOld].Accessor)
		switch {
		case diff == 0:
			additions = slices.Delete(additions, idxNew, idxNew+1)
			deletions = slices.Delete(deletions, idxOld, idxOld+1)
		case diff < 0:
			idxNew += 1
		case diff > 0:
			idxOld += 1
		}
	}

	return
}

// setTaint is used to set the taint on given entry Accepts either the mount
// entry's path or namespace + path, i.e. <ns-path>/secret/ or <ns-path>/token/
func (t *MountTable) setTaint(nsID, path string, tainted bool, mountState string) (*MountEntry, error) {
	n := len(t.Entries)
	for i := 0; i < n; i++ {
		if entry := t.Entries[i]; entry.Path == path && entry.Namespace().ID == nsID {
			t.Entries[i].Tainted = tainted
			t.Entries[i].MountState = mountState
			return t.Entries[i], nil
		}
	}
	return nil, nil
}

// remove is used to remove a given path entry; returns the entry that was
// removed
func (t *MountTable) remove(ctx context.Context, path string) (*MountEntry, error) {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	var mountEntryToDelete *MountEntry
	t.Entries = slices.DeleteFunc(t.Entries, func(me *MountEntry) bool {
		if me.Path == path && me.Namespace().ID == ns.ID {
			mountEntryToDelete = me
			return true
		}
		return false
	})

	return mountEntryToDelete, nil
}

func (t *MountTable) findByPath(ctx context.Context, path string) (*MountEntry, error) {
	return t.find(ctx, func(me *MountEntry) bool { return me.Path == path })
}

func (t *MountTable) findByBackendUUID(ctx context.Context, backendUUID string) (*MountEntry, error) {
	return t.find(ctx, func(me *MountEntry) bool { return me.BackendAwareUUID == backendUUID })
}

func (t *MountTable) findAllNamespaceMounts(ctx context.Context) ([]*MountEntry, error) {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	var mounts []*MountEntry
	for _, entry := range t.Entries {
		if entry.Namespace().ID == ns.ID {
			mounts = append(mounts, entry)
		}
	}

	return mounts, nil
}

func (t *MountTable) find(ctx context.Context, predicate func(*MountEntry) bool) (*MountEntry, error) {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	for _, entry := range t.Entries {
		if predicate(entry) && entry.Namespace().ID == ns.ID {
			return entry, nil
		}
	}

	return nil, nil
}

// sortEntriesByPath sorts the entries in the table by path and returns the
// table; this is useful for tests
func (t *MountTable) sortEntriesByPath() *MountTable {
	sort.Slice(t.Entries, func(i, j int) bool {
		return t.Entries[i].Path < t.Entries[j].Path
	})
	return t
}

// sortEntriesByPath sorts the entries in the table by path and returns the
// table; this is useful for tests
func (t *MountTable) sortEntriesByPathDepth() *MountTable {
	sort.Slice(t.Entries, func(i, j int) bool {
		return len(strings.Split(t.Entries[i].Namespace().Path+t.Entries[i].Path, "/")) < len(strings.Split(t.Entries[j].Namespace().Path+t.Entries[j].Path, "/"))
	})
	return t
}

const mountStateUnmounting = "unmounting"

// MountEntry is used to represent a mount table entry
type MountEntry struct {
	Table                 string            `json:"table"`                             // The table it belongs to
	Path                  string            `json:"path"`                              // Mount Path
	Type                  string            `json:"type"`                              // Logical backend Type. NB: This is the plugin name, e.g. my-vault-plugin, NOT plugin type (e.g. auth).
	Description           string            `json:"description"`                       // User-provided description
	UUID                  string            `json:"uuid"`                              // Barrier view UUID
	BackendAwareUUID      string            `json:"backend_aware_uuid"`                // UUID that can be used by the backend as a helper when a consistent value is needed outside of storage.
	Accessor              string            `json:"accessor"`                          // Unique but more human-friendly ID. Does not change, not used for any sensitive things (like as a salt, which the UUID sometimes is).
	Config                MountConfig       `json:"config"`                            // Configuration related to this mount (but not backend-derived)
	Options               map[string]string `json:"options"`                           // Backend options
	Local                 bool              `json:"local"`                             // Local mounts are not replicated or affected by replication
	SealWrap              bool              `json:"seal_wrap"`                         // Whether to wrap CSPs
	ExternalEntropyAccess bool              `json:"external_entropy_access,omitempty"` // Whether to allow external entropy source access
	Tainted               bool              `json:"tainted,omitempty"`                 // Set as a Write-Ahead flag for unmount/remount
	MountState            string            `json:"mount_state,omitempty"`             // The current mount state.  The only non-empty mount state right now is "unmounting"
	NamespaceID           string            `json:"namespace_id"`

	// namespace contains the populated namespace
	namespace *namespace.Namespace

	// synthesizedConfigCache is used to cache configuration values. These
	// particular values are cached since we want to get them at a point-in-time
	// without separately managing their locks individually. See SyncCache() for
	// the specific values that are being cached.
	synthesizedConfigCache sync.Map

	// version info
	Version        string `json:"plugin_version,omitempty"`         // The semantic version of the mounted plugin, e.g. v1.2.3.
	RunningVersion string `json:"running_plugin_version,omitempty"` // The semantic version of the mounted plugin as reported by the plugin.
	RunningSha256  string `json:"running_sha256,omitempty"`
}

// MountConfig is used to hold settable options
type MountConfig struct {
	DefaultLeaseTTL           time.Duration         `json:"default_lease_ttl,omitempty" mapstructure:"default_lease_ttl"` // Override for global default
	MaxLeaseTTL               time.Duration         `json:"max_lease_ttl,omitempty" mapstructure:"max_lease_ttl"`         // Override for global default
	ForceNoCache              bool                  `json:"force_no_cache,omitempty" mapstructure:"force_no_cache"`       // Override for global default
	AuditNonHMACRequestKeys   []string              `json:"audit_non_hmac_request_keys,omitempty" mapstructure:"audit_non_hmac_request_keys"`
	AuditNonHMACResponseKeys  []string              `json:"audit_non_hmac_response_keys,omitempty" mapstructure:"audit_non_hmac_response_keys"`
	ListingVisibility         ListingVisibilityType `json:"listing_visibility,omitempty" mapstructure:"listing_visibility"`
	PassthroughRequestHeaders []string              `json:"passthrough_request_headers,omitempty" mapstructure:"passthrough_request_headers"`
	AllowedResponseHeaders    []string              `json:"allowed_response_headers,omitempty" mapstructure:"allowed_response_headers"`
	TokenType                 logical.TokenType     `json:"token_type,omitempty" mapstructure:"token_type"`
	AllowedManagedKeys        []string              `json:"allowed_managed_keys,omitempty" mapstructure:"allowed_managed_keys"`
	UserLockoutConfig         *UserLockoutConfig    `json:"user_lockout_config,omitempty" mapstructure:"user_lockout_config"`

	// PluginName is the name of the plugin registered in the catalog.
	//
	// Deprecated: MountEntry.Type should be used instead for Vault 1.0.0 and beyond.
	PluginName string `json:"plugin_name,omitempty" mapstructure:"plugin_name"`
}

type UserLockoutConfig struct {
	LockoutThreshold    uint64        `json:"lockout_threshold,omitempty" mapstructure:"lockout_threshold"`
	LockoutDuration     time.Duration `json:"lockout_duration,omitempty" mapstructure:"lockout_duration"`
	LockoutCounterReset time.Duration `json:"lockout_counter_reset,omitempty" mapstructure:"lockout_counter_reset"`
	DisableLockout      bool          `json:"disable_lockout,omitempty" mapstructure:"disable_lockout"`
}

type APIUserLockoutConfig struct {
	LockoutThreshold            string `json:"lockout_threshold,omitempty" mapstructure:"lockout_threshold"`
	LockoutDuration             string `json:"lockout_duration,omitempty" mapstructure:"lockout_duration"`
	LockoutCounterResetDuration string `json:"lockout_counter_reset_duration,omitempty" mapstructure:"lockout_counter_reset_duration"`
	DisableLockout              *bool  `json:"lockout_disable,omitempty" mapstructure:"lockout_disable"`
}

// APIMountConfig is an embedded struct of api.MountConfigInput
type APIMountConfig struct {
	DefaultLeaseTTL           string                `json:"default_lease_ttl" mapstructure:"default_lease_ttl"`
	MaxLeaseTTL               string                `json:"max_lease_ttl" mapstructure:"max_lease_ttl"`
	ForceNoCache              bool                  `json:"force_no_cache" mapstructure:"force_no_cache"`
	AuditNonHMACRequestKeys   []string              `json:"audit_non_hmac_request_keys,omitempty" mapstructure:"audit_non_hmac_request_keys"`
	AuditNonHMACResponseKeys  []string              `json:"audit_non_hmac_response_keys,omitempty" mapstructure:"audit_non_hmac_response_keys"`
	ListingVisibility         ListingVisibilityType `json:"listing_visibility,omitempty" mapstructure:"listing_visibility"`
	PassthroughRequestHeaders []string              `json:"passthrough_request_headers,omitempty" mapstructure:"passthrough_request_headers"`
	AllowedResponseHeaders    []string              `json:"allowed_response_headers,omitempty" mapstructure:"allowed_response_headers"`
	TokenType                 string                `json:"token_type" mapstructure:"token_type"`
	AllowedManagedKeys        []string              `json:"allowed_managed_keys,omitempty" mapstructure:"allowed_managed_keys"`
	UserLockoutConfig         *UserLockoutConfig    `json:"user_lockout_config,omitempty" mapstructure:"user_lockout_config"`
	PluginVersion             string                `json:"plugin_version,omitempty" mapstructure:"plugin_version"`

	// PluginName is the name of the plugin registered in the catalog.
	//
	// Deprecated: MountEntry.Type should be used instead for Vault 1.0.0 and beyond.
	PluginName string `json:"plugin_name,omitempty" mapstructure:"plugin_name"`
}

type FailedLoginUser struct {
	aliasName     string
	mountAccessor string
}

type FailedLoginInfo struct {
	count               uint
	lastFailedLoginTime int
}

// Clone returns a deep copy of the mount entry
func (e *MountEntry) Clone() (*MountEntry, error) {
	cp, err := copystructure.Copy(e)
	if err != nil {
		return nil, err
	}
	return cp.(*MountEntry), nil
}

// IsExternalPlugin returns whether the plugin is running externally
// if the RunningSha256 is non-empty, the builtin is external. Otherwise, it's builtin
func (e *MountEntry) IsExternalPlugin() bool {
	return e.RunningSha256 != ""
}

// MountClass returns the mount class based on Accessor and Path
func (e *MountEntry) MountClass() string {
	if e.Accessor == "" || strings.HasPrefix(e.Path, fmt.Sprintf("%s/", mountPathSystem)) {
		return ""
	}

	if e.Table == credentialTableType {
		return consts.PluginTypeCredential.String()
	}

	return consts.PluginTypeSecrets.String()
}

// Namespace returns the namespace for the mount entry
func (e *MountEntry) Namespace() *namespace.Namespace {
	return e.namespace
}

// APIPath returns the full API Path for the given mount entry
func (e *MountEntry) APIPath() string {
	path := e.Path
	if e.Table == credentialTableType {
		path = credentialRoutePrefix + path
	}
	return e.namespace.Path + path
}

// APIPathNoNamespace returns the API Path without the namespace for the given mount entry
func (e *MountEntry) APIPathNoNamespace() string {
	path := e.Path
	if e.Table == credentialTableType {
		path = credentialRoutePrefix + path
	}
	return path
}

// SyncCache syncs tunable configuration values to the cache. In the case of
// cached values, they should be retrieved via synthesizedConfigCache.Load()
// instead of accessing them directly through MountConfig.
func (e *MountEntry) SyncCache() {
	if len(e.Config.AuditNonHMACRequestKeys) == 0 {
		e.synthesizedConfigCache.Delete("audit_non_hmac_request_keys")
	} else {
		e.synthesizedConfigCache.Store("audit_non_hmac_request_keys", e.Config.AuditNonHMACRequestKeys)
	}

	if len(e.Config.AuditNonHMACResponseKeys) == 0 {
		e.synthesizedConfigCache.Delete("audit_non_hmac_response_keys")
	} else {
		e.synthesizedConfigCache.Store("audit_non_hmac_response_keys", e.Config.AuditNonHMACResponseKeys)
	}

	if len(e.Config.PassthroughRequestHeaders) == 0 {
		e.synthesizedConfigCache.Delete("passthrough_request_headers")
	} else {
		e.synthesizedConfigCache.Store("passthrough_request_headers", e.Config.PassthroughRequestHeaders)
	}

	if len(e.Config.AllowedResponseHeaders) == 0 {
		e.synthesizedConfigCache.Delete("allowed_response_headers")
	} else {
		e.synthesizedConfigCache.Store("allowed_response_headers", e.Config.AllowedResponseHeaders)
	}

	if len(e.Config.AllowedManagedKeys) == 0 {
		e.synthesizedConfigCache.Delete("allowed_managed_keys")
	} else {
		e.synthesizedConfigCache.Store("allowed_managed_keys", e.Config.AllowedManagedKeys)
	}
}

func (entry *MountEntry) Deserialize() map[string]interface{} {
	return map[string]interface{}{
		"mount_path":      entry.Path,
		"mount_namespace": entry.Namespace().Path,
		"uuid":            entry.UUID,
		"accessor":        entry.Accessor,
		"mount_type":      entry.Type,
	}
}

// DecodeMountTable is used for testing
func (c *Core) DecodeMountTable(ctx context.Context, raw []byte) (*MountTable, error) {
	return c.decodeMountTable(ctx, raw)
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

func (c *Core) fetchAndDecodeMountTableEntry(ctx context.Context, barrier logical.Storage, prefix string, uuid string) (*MountEntry, error) {
	path := path.Join(prefix, uuid)
	sEntry, err := barrier.Get(ctx, path)
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
	ns, err := c.NamespaceByID(ctx, entry.NamespaceID)
	if err != nil {
		return nil, err
	}
	if ns == nil {
		c.logger.Error("namespace on mount entry not found", "table", prefix, "uuid", uuid, "namespace_id", entry.NamespaceID, "mount_path", entry.Path, "mount_description", entry.Description)
		return nil, nil
	}

	entry.namespace = ns

	return entry, nil
}

// Mount is used to mount a new backend to the mount table.
func (c *Core) mount(ctx context.Context, entry *MountEntry) error {
	// Ensure we end the path in a slash
	if !strings.HasSuffix(entry.Path, "/") {
		entry.Path += "/"
	}

	// Prevent protected paths from being mounted
	for _, p := range protectedMounts {
		if strings.HasPrefix(entry.Path, p) && entry.namespace == nil {
			return logical.CodedError(403, "cannot mount %q", entry.Path)
		}
	}

	// Do not allow more than one instance of a singleton mount
	for _, p := range singletonMounts {
		if entry.Type == p {
			return logical.CodedError(403, "mount type of %q is not mountable", entry.Type)
		}
	}

	// Mount internally
	if err := c.mountInternal(ctx, entry, MountTableUpdateStorage); err != nil {
		return err
	}

	return nil
}

func (c *Core) mountInternal(ctx context.Context, entry *MountEntry, updateStorage bool) error {
	c.mountsLock.Lock()
	c.authLock.Lock()
	locked := true
	unlock := func() {
		if locked {
			c.authLock.Unlock()
			c.mountsLock.Unlock()
			locked = false
		}
	}
	defer unlock()

	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return err
	}

	entry.NamespaceID = ns.ID
	entry.namespace = ns

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
	sysView := c.mountEntrySysView(entry)

	backend, entry.RunningSha256, err = c.newLogicalBackend(ctx, entry, sysView, view)
	if err != nil {
		return err
	}
	if backend == nil {
		return fmt.Errorf("nil backend of type %q returned from creation function", entry.Type)
	}

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

	newTable := c.mounts.shallowClone()
	newTable.Entries = append(newTable.Entries, entry)
	if updateStorage {
		if err := c.persistMounts(ctx, nil, newTable, &entry.Local, entry.UUID); err != nil {
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

	if c.logger.IsInfo() {
		c.logger.Info("successful mount", "namespace", entry.Namespace().Path, "path", entry.Path, "type", entry.Type, "version", entry.Version)
	}
	return nil
}

// mountEntrySysView creates a logical.SystemView from global and
// mount-specific entries; because this should be called when setting
// up a mountEntry, it doesn't check to ensure that me is not nil
func (c *Core) mountEntrySysView(entry *MountEntry) extendedSystemView {
	esi := extendedSystemViewImpl{
		dynamicSystemView{
			core:       c,
			mountEntry: entry,
		},
	}

	// Due to complexity in the ACME interface, only return it when we
	// are a PKI plugin that needs it.
	if entry.Type != "pki" {
		return esi
	}

	return esi
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
	if err := c.unmountInternal(ctx, path, MountTableUpdateStorage); err != nil {
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

	// Remove the entry from the mount table
	newTable := c.mounts.shallowClone()
	entry, err := newTable.remove(ctx, path)
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
		if err := c.persistMounts(ctx, nil, newTable, &entry.Local, entry.UUID); err != nil {
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

	mountState := ""
	if unmounting {
		mountState = mountStateUnmounting
	}

	// As modifying the taint of an entry affects shallow clones,
	// we simply use the original
	entry, err := c.mounts.setTaint(nsID, mountPath, true, mountState)
	if err != nil {
		return err
	}
	if entry == nil {
		c.logger.Error("nil entry found tainting entry in mounts table", "path", mountPath)
		return logical.CodedError(500, "failed to taint entry in mounts table")
	}

	if updateStorage {
		// Update the mount table
		if err := c.persistMounts(ctx, nil, c.mounts, &entry.Local, entry.UUID); err != nil {
			c.logger.Error("failed to taint entry in mounts table", "error", err)
			return logical.CodedError(500, "failed to taint entry in mounts table")
		}
	}

	return nil
}

// handleDeprecatedMountEntry handles the Deprecation Status of the specified
// mount entry's builtin engine. Warnings are appended to the returned response
// and logged. Errors are returned with a nil response to be processed by the
// caller.
func (c *Core) handleDeprecatedMountEntry(ctx context.Context, entry *MountEntry, pluginType consts.PluginType) (*logical.Response, error) {
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

	srcBarrierView, err := c.mountEntryView(mountEntry)
	if err != nil {
		return err
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
	mountEntry.namespace = dst.Namespace
	srcPath := mountEntry.Path
	mountEntry.Path = dst.MountPath

	dstBarrierView, err := c.mountEntryView(mountEntry)
	if err != nil {
		return err
	}

	// Update the mount table
	if err := c.persistMounts(ctx, nil, c.mounts, &mountEntry.Local, mountEntry.UUID); err != nil {
		mountEntry.namespace = src.Namespace
		mountEntry.NamespaceID = src.Namespace.ID
		mountEntry.Path = srcPath
		mountEntry.Tainted = true
		c.mountsLock.Unlock()
		return fmt.Errorf("failed to update mount table with error %+v", err)
	}

	if src.Namespace.ID != dst.Namespace.ID {
		// Handle storage entries
		if err := c.moveMountStorage(ctx, src, mountEntry, srcBarrierView, dstBarrierView); err != nil {
			c.mountsLock.Unlock()
			return err
		}
	}

	// Remount the backend
	if err := c.router.Remount(ctx, srcRelativePath, dstRelativePath, func(re *routeEntry) error {
		re.storageView = dstBarrierView
		re.storagePrefix = dstBarrierView.Prefix()

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

// moveMountStorage moves storage entries of a mount mountEntry to its new destination
func (c *Core) moveMountStorage(ctx context.Context, src namespace.MountPathDetails, me *MountEntry, srcBarrierView, dstBarrierView BarrierView) error {
	return c.moveStorage(ctx, src, me, srcBarrierView, dstBarrierView)
}

// moveAuthStorage moves storage entries of an auth mountEntry to its new destination
func (c *Core) moveAuthStorage(ctx context.Context, src namespace.MountPathDetails, me *MountEntry, srcBarrierView, dstBarrierView BarrierView) error {
	return c.moveStorage(ctx, src, me, srcBarrierView, dstBarrierView)
}

// moveStorage moves storage entries of a mountEntry to its new destination
// It detects the mountEntry type
func (c *Core) moveStorage(ctx context.Context, src namespace.MountPathDetails, me *MountEntry, srcBarrierView, dstBarrierView BarrierView) error {
	srcPrefix := srcBarrierView.Prefix()
	dstPrefix := dstBarrierView.Prefix()

	barrier := c.barrier

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
			err = s.Put(ctx, se)
			if err != nil {
				return err
			}
			err = s.Delete(ctx, srcPrefix+key)
			if err != nil {
				return err
			}
			return nil
		}); err != nil {
			return err
		}
	}

	srcEntryView := NamespaceView(barrier, src.Namespace)
	var coreLocalPath, corePath string

	switch me.Table {
	case mountTableType:
		coreLocalPath = coreLocalMountConfigPath
		corePath = coreMountConfigPath
	case credentialTableType:
		coreLocalPath = coreLocalAuthConfigPath
		corePath = coreAuthConfigPath
	default:
		return fmt.Errorf("unable to delete mount table type %q", me.Table)
	}

	if me.Local {
		srcEntryView = srcEntryView.SubView(coreLocalPath + "/")
	} else {
		srcEntryView = srcEntryView.SubView(corePath + "/")
	}
	err = srcEntryView.Delete(ctx, me.UUID)
	if err != nil {
		return err
	}

	return nil
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
func (c *Core) loadMounts(ctx context.Context) error {
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
		_, err := c.loadLegacyMounts(ctx, c.barrier)
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
	defer txn.Rollback(ctx)

	legacy, err := c.loadLegacyMounts(ctx, txn)
	if err != nil {
		return fmt.Errorf("failed to load legacy mounts in transaction: %w", err)
	}

	// If we have legacy mounts, migration was handled by the above. Otherwise,
	// we need to fetch the new mount table.
	if !legacy {
		c.logger.Info("reading transactional mount table")
		if err := c.loadTransactionalMounts(ctx, txn); err != nil {
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
func (c *Core) loadTransactionalMounts(ctx context.Context, barrier logical.Storage) error {
	allNamespaces, err := c.ListNamespaces(ctx)
	if err != nil {
		return fmt.Errorf("failed to list namespaces: %w", err)
	}

	var needPersist bool
	globalEntries := make(map[string][]string, len(allNamespaces))
	localEntries := make(map[string][]string, len(allNamespaces))
	for index, ns := range allNamespaces {
		view := NamespaceView(barrier, ns)
		nsGlobal, nsLocal, err := listTransactionalMountsForNamespace(ctx, view)
		if err != nil {
			c.logger.Error("failed to list transactional mounts for namespace", "error", err, "ns_index", index, "namespace", ns.ID)
			return err
		}

		if len(nsGlobal) > 0 {
			globalEntries[ns.ID] = nsGlobal
		}

		if len(nsLocal) > 0 {
			localEntries[ns.ID] = nsLocal
		}
	}

	if len(globalEntries) == 0 {
		// TODO(ascheel) Assertion: globalEntries is empty iff there is only
		// one namespace (the root namespace).
		c.logger.Info("no mounts in transactional mount table; adding default mount table")
		c.mounts = c.defaultMountTable(ctx)
		needPersist = true
	} else {
		c.mounts = &MountTable{
			Type: mountTableType,
		}

		for nsIndex, ns := range allNamespaces {
			view := NamespaceView(barrier, ns)
			for index, uuid := range globalEntries[ns.ID] {
				entry, err := c.fetchAndDecodeMountTableEntry(ctx, view, coreMountConfigPath, uuid)
				if err != nil {
					return fmt.Errorf("error loading mount table entry (%v (%v)/%v/%v): %w", ns.ID, nsIndex, index, uuid, err)
				}

				if entry != nil {
					c.mounts.Entries = append(c.mounts.Entries, entry)
				}
			}
		}
	}

	if len(localEntries) > 0 {
		for nsIndex, ns := range allNamespaces {
			view := NamespaceView(barrier, ns)
			for index, uuid := range localEntries[ns.ID] {
				entry, err := c.fetchAndDecodeMountTableEntry(ctx, view, coreLocalMountConfigPath, uuid)
				if err != nil {
					return fmt.Errorf("error loading local mount table entry (%v (%v)/%v/%v): %w", ns.ID, nsIndex, index, uuid, err)
				}

				if entry != nil {
					c.mounts.Entries = append(c.mounts.Entries, entry)
				}
			}
		}
	}

	err = c.runMountUpdates(ctx, barrier, needPersist)
	if err != nil {
		c.logger.Error("failed to run legacy mount table upgrades", "error", err)
		return err
	}

	return nil
}

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

// This function reads the legacy, single-entry combined mount table,
// returning true if it was used. This will let us know (if we're inside
// a transaction) if we need to do an upgrade.
func (c *Core) loadLegacyMounts(ctx context.Context, barrier logical.Storage) (bool, error) {
	// Load the existing mount table
	raw, err := barrier.Get(ctx, coreMountConfigPath)
	if err != nil {
		c.logger.Error("failed to read legacy mount table", "error", err)
		return false, errLoadMountsFailed
	}
	rawLocal, err := barrier.Get(ctx, coreLocalMountConfigPath)
	if err != nil {
		c.logger.Error("failed to read legacy local mount table", "error", err)
		return false, errLoadMountsFailed
	}

	if raw != nil {
		mountTable, err := c.decodeMountTable(ctx, raw.Value)
		if err != nil {
			c.logger.Error("failed to decompress and/or decode the legacy mount table", "error", err)
			return false, err
		}
		c.tableMetrics(len(mountTable.Entries), false, false, len(raw.Value))
		c.mounts = mountTable
	}

	var needPersist bool
	if c.mounts == nil {
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
		c.tableMetrics(len(c.mounts.Entries), false, false, len(raw.Value))
	}

	if rawLocal != nil {
		localMountTable, err := c.decodeMountTable(ctx, rawLocal.Value)
		if err != nil {
			c.logger.Error("failed to decompress and/or decode the legacy local mount table", "error", err)
			return false, err
		}
		if localMountTable != nil && len(localMountTable.Entries) > 0 {
			c.tableMetrics(len(localMountTable.Entries), true, false, len(rawLocal.Value))
			c.mounts.Entries = append(c.mounts.Entries, localMountTable.Entries...)
		}
	}

	// Here, we must call runMountUpdates:
	//
	// 1. We may be without any mount table and need to create the legacy
	//    table format because we don't have a transaction aware storage
	//    backend.
	// 2. We may have had a legacy mount table and need to upgrade into the
	//    new format. runMountUpdates will handle this for us.
	err = c.runMountUpdates(ctx, barrier, needPersist)
	if err != nil {
		c.logger.Error("failed to run legacy mount table upgrades", "error", err)
		return false, err
	}

	// We loaded a legacy mount table and successfully migrated it, if
	// necessary.
	return true, nil
}

// Note that this is only designed to work with singletons, as it checks by
// type only.
func (c *Core) runMountUpdates(ctx context.Context, barrier logical.Storage, needPersist bool) error {
	// Upgrade to typed mount table
	if c.mounts.Type == "" {
		c.mounts.Type = mountTableType
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
		if entry.Type == mountTypeNSCubbyhole && !entry.Local {
			entry.Local = true
			needPersist = true
		}
		if entry.Type == mountTypeCubbyhole && !entry.Local {
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
		entry.namespace = ns

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

	// Persist both mount tables
	if err := c.persistMounts(ctx, barrier, c.mounts, nil, ""); err != nil {
		c.logger.Error("failed to persist mount table", "error", err)
		return errLoadMountsFailed
	}
	return nil
}

// persistMounts is used to persist the mount table after modification.
func (c *Core) persistMounts(ctx context.Context, barrier logical.Storage, table *MountTable, local *bool, mount string) error {
	// Sometimes we may not want to explicitly pass barrier; fetch it if
	// necessary.
	if barrier == nil {
		barrier = c.barrier
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
		defer barrier.(logical.Transaction).Rollback(ctx)
	}

	if table.Type != mountTableType {
		c.logger.Error("given table to persist has wrong type", "actual_type", table.Type, "expected_type", mountTableType)
		return errors.New("invalid table type given, not persisting")
	}

	nonLocalMounts := &MountTable{
		Type: mountTableType,
	}

	localMounts := &MountTable{
		Type: mountTableType,
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
	writeTable := func(mt *MountTable, path string) (int, error) {
		// Encode the mount table into JSON and compress it (Gzip).
		compressedBytes, err := jsonutil.EncodeJSONAndCompress(mt, nil)
		if err != nil {
			c.logger.Error("failed to encode or compress mount table", "error", err)
			return -1, err
		}

		// Create an entry
		entry := &logical.StorageEntry{
			Key:   path,
			Value: compressedBytes,
		}

		// Write to the physical backend
		if err := barrier.Put(ctx, entry); err != nil {
			c.logger.Error("failed to persist mount table", "error", err)
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
				if mount != "" && mtEntry.UUID != mount {
					continue
				}

				view := NamespaceView(barrier, mtEntry.Namespace())

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
				if err := view.Put(ctx, sEntry); err != nil {
					c.logger.Error("failed to persist mount table entry", "index", index, "uuid", mtEntry.UUID, "error", err)
					return -1, err
				}

				size += len(encoded)
			}

			if mount != "" && !found {
				// Delete this component if it exists. This signifies that
				// we're removing this mount. We don't know which namespace
				// this entry could belong to, so remove it from all.
				allNamespaces, err := c.ListNamespaces(ctx)
				if err != nil {
					return -1, fmt.Errorf("failed to list namespaces: %w", err)
				}

				for nsIndex, ns := range allNamespaces {
					view := NamespaceView(barrier, ns)
					path := path.Join(prefix, mount)
					if err := view.Delete(ctx, path); err != nil {
						return -1, fmt.Errorf("requested removal of auth mount from namespace %v (%v) but failed: %w", ns.ID, nsIndex, err)
					}
				}
			}

			if mount == "" {
				allNamespaces, err := c.ListNamespaces(ctx)
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

						if err := view.Delete(ctx, prefix+"/"+presentEntry); err != nil {
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
		c.tableMetrics(len(nonLocalMounts.Entries), false, false, compressedBytesLen)

		// Write local mounts
		compressedBytesLen, err = writeTable(localMounts, coreLocalMountConfigPath)
		if err != nil {
			return err
		}
		c.tableMetrics(len(localMounts.Entries), true, false, compressedBytesLen)

	case *local:
		// Write local mounts
		compressedBytesLen, err = writeTable(localMounts, coreLocalMountConfigPath)
		if err != nil {
			return err
		}
		c.tableMetrics(len(localMounts.Entries), true, false, compressedBytesLen)
	default:
		// Write non-local mounts
		compressedBytesLen, err = writeTable(nonLocalMounts, coreMountConfigPath)
		if err != nil {
			return err
		}
		c.tableMetrics(len(nonLocalMounts.Entries), false, false, compressedBytesLen)
	}

	if needTxnCommit {
		if err := barrier.(logical.Transaction).Commit(ctx); err != nil {
			return fmt.Errorf("failed to persist mounts inside transaction: %w", err)
		}
	}

	return nil
}

// setupMounts is invoked after we've loaded the mount table to
// initialize the logical backends and setup the router
func (c *Core) setupMounts(ctx context.Context) error {
	c.mountsLock.Lock()
	defer c.mountsLock.Unlock()

	for _, entry := range c.mounts.sortEntriesByPathDepth().Entries {
		// Initialize the backend, special casing for system
		view, err := c.mountEntryView(entry)
		if err != nil {
			return err
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

			if c.isMountable(ctx, entry, consts.PluginTypeSecrets) {
				c.logger.Warn("skipping plugin-based mount entry", "path", entry.Path)
				goto ROUTER_MOUNT
			}
			return errLoadMountsFailed
		}
		if backend == nil {
			return fmt.Errorf("created mount entry of type %q is nil", entry.Type)
		}

		// update the entry running version with the configured version, which was verified during registration.
		entry.RunningVersion = entry.Version
		if entry.RunningVersion == "" {
			// don't set the running version to a builtin if it is running as an external plugin
			if entry.RunningSha256 == "" {
				entry.RunningVersion = versions.GetBuiltinVersion(consts.PluginTypeSecrets, entry.Type)
			}
		}

		// Do not start up deprecated builtin plugins. If this is a major
		// upgrade, stop unsealing and shutdown. If we've already mounted this
		// plugin, proceed with unsealing and skip backend initialization.
		if versions.IsBuiltinVersion(entry.RunningVersion) {
			_, err := c.handleDeprecatedMountEntry(ctx, entry, consts.PluginTypeSecrets)
			if c.isMajorVersionFirstMount(ctx) && err != nil {
				go c.ShutdownCoreError(fmt.Errorf("could not mount %q: %w", entry.Type, err))
				return errLoadMountsFailed
			} else if err != nil {
				c.logger.Error("skipping deprecated mount entry", "name", entry.Type, "path", entry.Path, "error", err)
				backend.Cleanup(ctx)
				backend = nil
				goto ROUTER_MOUNT
			}
		}

		{
			// Check for the correct backend type
			backendType := backend.Type()

			if backendType != logical.TypeLogical {
				if err := knownMountType(entry.Type); err != nil {
					return err
				}
			}

			c.setCoreBackend(entry, backend, view)
		}

	ROUTER_MOUNT:
		// Mount the backend
		err = c.router.Mount(backend, entry.Path, entry, view)
		if err != nil {
			c.logger.Error("failed to mount entry", "path", entry.Path, "error", err)
			return errLoadMountsFailed
		}

		// Bind locally
		localEntry := entry
		c.postUnsealFuncs = append(c.postUnsealFuncs, func() {
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
		})

		if c.logger.IsInfo() {
			c.logger.Info("successfully mounted", "type", entry.Type, "version", entry.RunningVersion, "path", entry.Path, "namespace", entry.Namespace())
		}

		// Ensure the path is tainted if set in the mount table
		if entry.Tainted {
			// Calculate any namespace prefixes here, because when Taint() is called, there won't be
			// a namespace to pull from the context. This is similar to what we do above in c.router.Mount().
			path := entry.Namespace().Path + entry.Path
			c.logger.Debug("tainting a mount due to it being marked as tainted in mount table", "entry.path", entry.Path, "entry.namespace.path", entry.Namespace().Path, "full_path", path)
			c.router.Taint(ctx, path)
		}
	}
	return nil
}

// unloadMounts is used before we seal the vault to reset the mounts to
// their unloaded state, calling Cleanup if defined. This is reversed by load and setup mounts.
func (c *Core) unloadMounts(ctx context.Context) error {
	c.mountsLock.Lock()
	defer c.mountsLock.Unlock()

	if c.mounts != nil {
		mountTable := c.mounts.shallowClone()
		for _, e := range mountTable.Entries {
			backend := c.router.MatchingBackend(namespace.ContextWithNamespace(ctx, e.namespace), e.Path)
			if backend != nil {
				backend.Cleanup(ctx)
			}
		}
	}

	c.mounts = nil
	c.router.reset()
	c.systemBarrierView = nil
	return nil
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

// defaultMountTable creates a default mount table
func (c *Core) defaultMountTable(ctx context.Context) *MountTable {
	table := &MountTable{
		Type: mountTableType,
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
		mountAccessor, err := c.generateMountAccessor(mountTypeKV)
		if err != nil {
			panic(fmt.Sprintf("could not generate default secret mount accessor: %v", err))
		}
		bUUID, err := uuid.GenerateUUID()
		if err != nil {
			panic(fmt.Sprintf("could not create default secret mount backend UUID: %v", err))
		}

		kvMount := &MountEntry{
			Table:            mountTableType,
			Path:             "secret/",
			Type:             mountTypeKV,
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
func (c *Core) requiredMountTable(ctx context.Context) (*MountTable, error) {
	ns, err := namespace.FromContext(ctx)
	if err != nil && !errors.Is(err, namespace.ErrNoNamespace) {
		return nil, err
	}
	if ns == nil {
		ns = namespace.RootNamespace
	}

	table := &MountTable{
		Type: mountTableType,
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
	cubbyholeMount := &MountEntry{
		Table:            mountTableType,
		Path:             mountPathCubbyhole,
		Type:             mountTypeCubbyhole,
		Description:      "per-token private secret storage",
		UUID:             cubbyholeUUID,
		Accessor:         cubbyholeAccessor,
		Local:            true,
		BackendAwareUUID: cubbyholeBackendUUID,
		RunningVersion:   versions.GetBuiltinVersion(consts.PluginTypeSecrets, "cubbyhole"),

		NamespaceID: ns.ID,
		namespace:   ns,
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
	sysMount := &MountEntry{
		Table:            mountTableType,
		Path:             "sys/",
		Type:             mountTypeSystem,
		Description:      "system endpoints used for control, policy and debugging",
		UUID:             sysUUID,
		Accessor:         sysAccessor,
		BackendAwareUUID: sysBackendUUID,
		SealWrap:         true, // Enable SealWrap since SystemBackend utilizes SealWrapStorage, see factory in addExtraLogicalBackends().
		Config: MountConfig{
			PassthroughRequestHeaders: []string{"Accept"},
		},
		RunningVersion: versions.DefaultBuiltinVersion,

		NamespaceID: ns.ID,
		namespace:   ns,
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
	identityMount := &MountEntry{
		Table:            mountTableType,
		Path:             "identity/",
		Type:             "identity",
		Description:      "identity store",
		UUID:             identityUUID,
		Accessor:         identityAccessor,
		BackendAwareUUID: identityBackendUUID,
		Config: MountConfig{
			PassthroughRequestHeaders: []string{"Authorization"},
		},
		RunningVersion: versions.DefaultBuiltinVersion,
		NamespaceID:    ns.ID,
		namespace:      ns,
	}

	if ns.ID != namespace.RootNamespaceID {
		cubbyholeMount.Type = mountTypeNSCubbyhole
		identityMount.Type = mountTypeNSIdentity
		sysMount.Type = mountTypeNSSystem
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
func (c *Core) singletonMountTables() (mounts, auth *MountTable) {
	mounts = &MountTable{}
	auth = &MountTable{}

	c.mountsLock.RLock()
	for _, entry := range c.mounts.Entries {
		if slices.Contains(singletonMounts, entry.Type) && !entry.Local && entry.Namespace().ID == namespace.RootNamespaceID {
			mounts.Entries = append(mounts.Entries, entry)
		}
	}
	c.mountsLock.RUnlock()

	c.authLock.RLock()
	for _, entry := range c.auth.Entries {
		if slices.Contains(singletonMounts, entry.Type) && !entry.Local && entry.Namespace().ID == namespace.RootNamespaceID {
			auth.Entries = append(auth.Entries, entry)
		}
	}
	c.authLock.RUnlock()

	return mounts, auth
}

func (c *Core) setCoreBackend(entry *MountEntry, backend logical.Backend, view BarrierView) {
	switch entry.Type {
	case mountTypeSystem:
		c.systemBackend = backend.(*SystemBackend)
		c.systemBarrierView = view
	case mountTypeCubbyhole:
		ch := backend.(*CubbyholeBackend)
		ch.saltUUID = entry.UUID
		c.cubbyholeBackend = ch
	case mountTypeIdentity:
		c.identityStore = backend.(*IdentityStore)
	}
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
		return fmt.Errorf("Migration Tracker entry missing for ID %s", migrationID)
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

func (c *Core) namespaceMountEntryView(namespace *namespace.Namespace, prefix string) BarrierView {
	return NamespaceView(c.barrier, namespace).SubView(prefix)
}

// mountEntryView returns the barrier view object with prefix depending on the mount entry type, table and namespace
func (c *Core) mountEntryView(me *MountEntry) (BarrierView, error) {
	if me.Namespace() != nil && me.Namespace().ID != me.NamespaceID {
		return nil, errors.New("invalid namespace")
	}

	switch me.Type {
	case mountTypeSystem, mountTypeNSSystem:
		if me.Namespace() != nil && me.NamespaceID != namespace.RootNamespaceID {
			return c.namespaceMountEntryView(me.Namespace(), systemBarrierPrefix), nil
		}
		return NewBarrierView(c.barrier, systemBarrierPrefix), nil
	case mountTypeToken:
		return NewBarrierView(c.barrier, systemBarrierPrefix+tokenSubPath), nil
	}

	switch me.Table {
	case mountTableType:
		if me.Namespace() != nil && me.NamespaceID != namespace.RootNamespaceID {
			return c.namespaceMountEntryView(me.Namespace(), backendBarrierPrefix+me.UUID+"/"), nil
		}
		return NewBarrierView(c.barrier, backendBarrierPrefix+me.UUID+"/"), nil
	case credentialTableType:
		if me.Namespace() != nil && me.NamespaceID != namespace.RootNamespaceID {
			return c.namespaceMountEntryView(me.Namespace(), credentialBarrierPrefix+me.UUID+"/"), nil
		}
		return NewBarrierView(c.barrier, credentialBarrierPrefix+me.UUID+"/"), nil
	case auditTableType, configAuditTableType:
		return NewBarrierView(c.barrier, auditBarrierPrefix+me.UUID+"/"), nil
	}

	return nil, errors.New("invalid mount entry")
}
