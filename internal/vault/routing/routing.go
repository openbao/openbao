package routing

import (
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"
)

const (
	// mountTableType is the value we expect to find for the mount table and
	// corresponding entries
	MountTableType = "mounts"

	// CredentialTableType is the value we expect to find for the credential
	// table and corresponding entries
	CredentialTableType = "auth"
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

	// CredentialRoutePrefix is the mount prefix used for the router
	CredentialRoutePrefix = "auth/"

	MountPathSystem    = "sys/"
	MountPathIdentity  = "identity/"
	MountPathCubbyhole = "cubbyhole/"

	MountTypeSystem      = "system"
	MountTypeNSSystem    = "ns_system"
	MountTypeIdentity    = "identity"
	MountTypeNSIdentity  = "ns_identity"
	MountTypeCubbyhole   = "cubbyhole"
	MountTypePlugin      = "plugin"
	MountTypeKV          = "kv"
	MountTypeNSCubbyhole = "ns_cubbyhole"
	MountTypeToken       = "token"
	MountTypeNSToken     = "ns_token"
)

// MountConfig is used to hold settable options
type MountConfig struct {
	DefaultLeaseTTL           time.Duration         `json:"default_lease_ttl,omitempty" structs:"default_lease_ttl" mapstructure:"default_lease_ttl"` // Override for global default
	MaxLeaseTTL               time.Duration         `json:"max_lease_ttl,omitempty" structs:"max_lease_ttl" mapstructure:"max_lease_ttl"`             // Override for global default
	ForceNoCache              bool                  `json:"force_no_cache,omitempty" structs:"force_no_cache" mapstructure:"force_no_cache"`          // Override for global default
	AuditNonHMACRequestKeys   []string              `json:"audit_non_hmac_request_keys,omitempty" structs:"audit_non_hmac_request_keys" mapstructure:"audit_non_hmac_request_keys"`
	AuditNonHMACResponseKeys  []string              `json:"audit_non_hmac_response_keys,omitempty" structs:"audit_non_hmac_response_keys" mapstructure:"audit_non_hmac_response_keys"`
	ListingVisibility         ListingVisibilityType `json:"listing_visibility,omitempty" structs:"listing_visibility" mapstructure:"listing_visibility"`
	PassthroughRequestHeaders []string              `json:"passthrough_request_headers,omitempty" structs:"passthrough_request_headers" mapstructure:"passthrough_request_headers"`
	AllowedResponseHeaders    []string              `json:"allowed_response_headers,omitempty" structs:"allowed_response_headers" mapstructure:"allowed_response_headers"`
	TokenType                 logical.TokenType     `json:"token_type,omitempty" structs:"token_type" mapstructure:"token_type"`
	UserLockoutConfig         *UserLockoutConfig    `json:"user_lockout_config,omitempty" mapstructure:"user_lockout_config"`

	// PluginName is the name of the plugin registered in the catalog.
	//
	// Deprecated: MountEntry.Type should be used instead for Vault 1.0.0 and beyond.
	PluginName string `json:"plugin_name,omitempty" structs:"plugin_name,omitempty" mapstructure:"plugin_name"`
}

// APIMountConfig is an embedded struct of api.MountConfigInput
type APIMountConfig struct {
	DefaultLeaseTTL           string                `json:"default_lease_ttl" structs:"default_lease_ttl" mapstructure:"default_lease_ttl"`
	MaxLeaseTTL               string                `json:"max_lease_ttl" structs:"max_lease_ttl" mapstructure:"max_lease_ttl"`
	ForceNoCache              bool                  `json:"force_no_cache" structs:"force_no_cache" mapstructure:"force_no_cache"`
	AuditNonHMACRequestKeys   []string              `json:"audit_non_hmac_request_keys,omitempty" structs:"audit_non_hmac_request_keys" mapstructure:"audit_non_hmac_request_keys"`
	AuditNonHMACResponseKeys  []string              `json:"audit_non_hmac_response_keys,omitempty" structs:"audit_non_hmac_response_keys" mapstructure:"audit_non_hmac_response_keys"`
	ListingVisibility         ListingVisibilityType `json:"listing_visibility,omitempty" structs:"listing_visibility" mapstructure:"listing_visibility"`
	PassthroughRequestHeaders []string              `json:"passthrough_request_headers,omitempty" structs:"passthrough_request_headers" mapstructure:"passthrough_request_headers"`
	AllowedResponseHeaders    []string              `json:"allowed_response_headers,omitempty" structs:"allowed_response_headers" mapstructure:"allowed_response_headers"`
	TokenType                 string                `json:"token_type" structs:"token_type" mapstructure:"token_type"`
	UserLockoutConfig         *UserLockoutConfig    `json:"user_lockout_config,omitempty" mapstructure:"user_lockout_config"`
	PluginVersion             string                `json:"plugin_version,omitempty" mapstructure:"plugin_version"`

	// PluginName is the name of the plugin registered in the catalog.
	//
	// Deprecated: MountEntry.Type should be used instead for Vault 1.0.0 and beyond.
	PluginName string `json:"plugin_name,omitempty" structs:"plugin_name,omitempty" mapstructure:"plugin_name"`
}

type UserLockoutConfig struct {
	LockoutThreshold    uint64        `json:"lockout_threshold,omitempty" structs:"lockout_threshold" mapstructure:"lockout_threshold"`
	LockoutDuration     time.Duration `json:"lockout_duration,omitempty" structs:"lockout_duration" mapstructure:"lockout_duration"`
	LockoutCounterReset time.Duration `json:"lockout_counter_reset,omitempty" structs:"lockout_counter_reset" mapstructure:"lockout_counter_reset"`
	DisableLockout      bool          `json:"disable_lockout,omitempty" structs:"disable_lockout" mapstructure:"disable_lockout"`
}
