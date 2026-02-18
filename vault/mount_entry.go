// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"errors"
	"fmt"
	"path"
	"strings"
	"sync"

	"github.com/mitchellh/copystructure"
	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/openbao/openbao/vault/barrier"
	"github.com/openbao/openbao/vault/routing"
)

// MountEntry is used to represent a mount table entry
type MountEntry struct {
	Table                 string              `json:"table"`                             // The table it belongs to
	Path                  string              `json:"path"`                              // Mount Path
	Type                  string              `json:"type"`                              // Logical backend Type. NB: This is the plugin name, e.g. my-vault-plugin, NOT plugin type (e.g. auth).
	Description           string              `json:"description"`                       // User-provided description
	UUID                  string              `json:"uuid"`                              // Barrier view UUID
	BackendAwareUUID      string              `json:"backend_aware_uuid"`                // UUID that can be used by the backend as a helper when a consistent value is needed outside of storage.
	Accessor              string              `json:"accessor"`                          // Unique but more human-friendly ID. Does not change, not used for any sensitive things (like as a salt, which the UUID sometimes is).
	Config                routing.MountConfig `json:"config"`                            // Configuration related to this mount (but not backend-derived)
	Options               map[string]string   `json:"options"`                           // Backend options
	Local                 bool                `json:"local"`                             // Local mounts are not replicated or affected by replication
	SealWrap              bool                `json:"seal_wrap"`                         // Whether to wrap CSPs
	ExternalEntropyAccess bool                `json:"external_entropy_access,omitempty"` // Whether to allow external entropy source access
	Tainted               bool                `json:"tainted,omitempty"`                 // Set as a Write-Ahead flag for unmount/remount
	NamespaceID           string              `json:"namespace_id"`

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

type FailedLoginUser struct {
	aliasName     string
	mountAccessor string
}

type FailedLoginInfo struct {
	count               uint
	lastFailedLoginTime int
}

type APIUserLockoutConfig struct {
	LockoutThreshold            string `json:"lockout_threshold,omitempty" structs:"lockout_threshold" mapstructure:"lockout_threshold"`
	LockoutDuration             string `json:"lockout_duration,omitempty" structs:"lockout_duration" mapstructure:"lockout_duration"`
	LockoutCounterResetDuration string `json:"lockout_counter_reset_duration,omitempty" structs:"lockout_counter_reset_duration" mapstructure:"lockout_counter_reset_duration"`
	DisableLockout              *bool  `json:"lockout_disable,omitempty" structs:"lockout_disable" mapstructure:"lockout_disable"`
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
	if e.Accessor == "" || strings.HasPrefix(e.Path, fmt.Sprintf("%s/", routing.MountPathSystem)) {
		return ""
	}

	if e.Table == routing.CredentialTableType {
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
	if e.Table == routing.CredentialTableType {
		path = routing.CredentialRoutePrefix + path
	}
	return e.namespace.Path + path
}

// APIPathNoNamespace returns the API Path without the namespace for the given mount entry
func (e *MountEntry) APIPathNoNamespace() string {
	path := e.Path
	if e.Table == routing.CredentialTableType {
		path = routing.CredentialRoutePrefix + path
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

// mountEntrySysView creates a logical.SystemView from global and
// mount-specific entries; because this should be called when setting
// up a mountEntry, it doesn't check to ensure that me is not nil
func (c *Core) mountEntrySysView(entry *MountEntry) extendedSystemView {
	return extendedSystemViewImpl{
		dynamicSystemView{
			core:       c,
			mountEntry: entry,
		},
	}
}

// mountEntryView returns the barrier view object with prefix depending on the mount entry type, table and namespace
func (c *Core) mountEntryView(me *MountEntry) (barrier.View, error) {
	if me.Namespace() != nil && me.Namespace().ID != me.NamespaceID {
		return nil, errors.New("invalid namespace")
	}

	switch me.Type {
	case routing.MountTypeSystem, routing.MountTypeNSSystem:
		return NamespaceView(c.barrier, me.Namespace()).SubView(systemBarrierPrefix), nil
	case routing.MountTypeToken:
		return NamespaceView(c.barrier, me.Namespace()).SubView(systemBarrierPrefix + tokenSubPath), nil
	}

	switch me.Table {
	case routing.MountTableType:
		return NamespaceView(c.barrier, me.Namespace()).SubView(path.Join(backendBarrierPrefix, me.UUID) + "/"), nil
	case routing.CredentialTableType:
		return NamespaceView(c.barrier, me.Namespace()).SubView(path.Join(credentialBarrierPrefix, me.UUID) + "/"), nil
	case auditTableType, configAuditTableType:
		return NamespaceView(c.barrier, me.Namespace()).SubView(path.Join(auditBarrierPrefix, me.UUID) + "/"), nil
	}

	return nil, errors.New("invalid mount entry")
}
