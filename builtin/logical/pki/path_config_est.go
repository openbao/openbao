// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package pki

import (
	"context"
	"fmt"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/helper/errutil"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const (
	storageEstConfig      = "config/est"
	pathConfigEstHelpSyn  = "Configuration of EST Endpoints"
	pathConfigEstHelpDesc = `
This endpoint allows configuration of EST (Enrollment over Secure Transport) protocol support.

Configuration options:
- enabled: Whether EST is enabled (default: false)
- default_mount: Register the default .well-known/est URL path (only one mount can enable this)
- default_path_policy: Behavior for default EST label requests ("sign-verbatim" or "role:<role_name>")
- label_to_path_policy: Map of EST labels to path policies
- authenticators: Authentication mount configurations (userpass or cert)
  - REQUIRED for HTTP Basic Auth to work - no default fallback
  - Each authenticator requires an "accessor" field
  - cert authenticator supports optional "cert_role" field
  - Multiple authenticators can be configured; they will be tried in order
- enable_sentinel_parsing: Parse CSR fields for Sentinel policies (default: false)
- audit_fields: Fields from CSR to include in audit logs

Security Note: Following OpenBao's principle of explicit configuration, HTTP Basic Auth
will NOT work unless authenticators are explicitly configured. There is no automatic
fallback to any auth backend.

Example authenticators configuration:
{
  "userpass": {
    "accessor": "auth_userpass_abc123"
  },
  "cert": {
    "accessor": "auth_cert_def456"
  }
}
`
)

// AuthenticatorConfig holds configuration for an EST authenticator
type AuthenticatorConfig struct {
	Accessor string `json:"accessor"`
	CertRole string `json:"cert_role,omitempty"` // Only for cert auth
}

// estConfigEntry represents the EST configuration
type estConfigEntry struct {
	Enabled               bool                           `json:"enabled"`
	DefaultMount          bool                           `json:"default_mount"`
	DefaultPathPolicy     string                         `json:"default_path_policy"`
	LabelToPathPolicy     map[string]string              `json:"label_to_path_policy"`
	Authenticators        map[string]AuthenticatorConfig `json:"authenticators"`
	EnableSentinelParsing bool                           `json:"enable_sentinel_parsing"`
	AuditFields           []string                       `json:"audit_fields"`
	LastUpdated           time.Time                      `json:"last_updated"`
}

var defaultEstConfig = estConfigEntry{
	Enabled:               false,
	DefaultMount:          false,
	DefaultPathPolicy:     "",
	LabelToPathPolicy:     make(map[string]string),
	Authenticators:        make(map[string]AuthenticatorConfig),
	EnableSentinelParsing: false,
	AuditFields:           []string{"common_name", "alt_names", "ip_sans", "uri_sans"},
	LastUpdated:           time.Time{},
}

func (sc *storageContext) getEstConfig() (*estConfigEntry, error) {
	entry, err := sc.Storage.Get(sc.Context, storageEstConfig)
	if err != nil {
		return nil, err
	}

	var mapping estConfigEntry
	if entry == nil {
		mapping = defaultEstConfig
		return &mapping, nil
	}

	if err := entry.DecodeJSON(&mapping); err != nil {
		return nil, errutil.InternalError{Err: fmt.Sprintf("unable to decode EST configuration: %v", err)}
	}

	return &mapping, nil
}

func (sc *storageContext) setEstConfig(entry *estConfigEntry) error {
	entry.LastUpdated = time.Now()

	json, err := logical.StorageEntryJSON(storageEstConfig, entry)
	if err != nil {
		return fmt.Errorf("failed creating storage entry: %w", err)
	}

	if err := sc.Storage.Put(sc.Context, json); err != nil {
		return fmt.Errorf("failed writing storage entry: %w", err)
	}

	return nil
}

func pathEstConfig(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "config/est",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixPKI,
		},

		Fields: map[string]*framework.FieldSchema{
			"enabled": {
				Type:        framework.TypeBool,
				Description: `Whether EST is enabled. When disabled, all EST requests will return 404.`,
				Default:     false,
			},
			"default_mount": {
				Type:        framework.TypeBool,
				Description: `Should this mount register the default .well-known/est URL path. Only a single mount can enable this across a cluster.`,
				Default:     false,
			},
			"default_path_policy": {
				Type:        framework.TypeString,
				Description: `Required if default_mount is enabled. Specifies behavior for default EST label. Can be "sign-verbatim" or "role:<role_name>".`,
				Default:     "",
			},
			"label_to_path_policy": {
				Type:        framework.TypeKVPairs,
				Description: `Map of EST label to path policy. Labels must be unique across the cluster. Path policy can be "sign-verbatim" or "role:<role_name>".`,
				Default:     map[string]string{},
			},
			"authenticators": {
				Type:        framework.TypeMap,
				Description: `Map of authenticator types (userpass or cert) to their configurations. Each config must have an "accessor" field. The "cert" authenticator optionally supports "cert_role". REQUIRED for HTTP Basic Auth - no default fallback. Multiple authenticators can be configured and will be tried in order during HTTP Basic Auth.`,
				Default:     map[string]interface{}{},
			},
			"enable_sentinel_parsing": {
				Type:        framework.TypeBool,
				Description: `Parse CSR fields making them available for Sentinel policies.`,
				Default:     false,
			},
			"audit_fields": {
				Type:        framework.TypeCommaStringSlice,
				Description: `Fields parsed from the CSR that appear in audit logs. Allowed values: csr, common_name, alt_names, ip_sans, uri_sans, other_sans, signature_bits, exclude_cn_from_sans, ou, organization, country, locality, province, street_address, postal_code, serial_number, use_pss, key_type, key_bits, add_basic_constraints`,
				Default:     []string{"common_name", "alt_names", "ip_sans", "uri_sans"},
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				DisplayAttrs: &framework.DisplayAttributes{
					OperationSuffix: "est-configuration",
				},
				Callback: b.pathEstRead,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathEstWrite,
				DisplayAttrs: &framework.DisplayAttributes{
					OperationVerb:   "configure",
					OperationSuffix: "est",
				},
				ForwardPerformanceStandby:   true,
				ForwardPerformanceSecondary: true,
			},
		},

		HelpSynopsis:    pathConfigEstHelpSyn,
		HelpDescription: pathConfigEstHelpDesc,
	}
}

func (b *backend) pathEstRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	sc := b.makeStorageContext(ctx, req.Storage)
	config, err := sc.getEstConfig()
	if err != nil {
		return nil, err
	}

	return genResponseFromEstConfig(config), nil
}

func genResponseFromEstConfig(config *estConfigEntry) *logical.Response {
	response := &logical.Response{
		Data: map[string]interface{}{
			"enabled":                 config.Enabled,
			"default_mount":           config.DefaultMount,
			"default_path_policy":     config.DefaultPathPolicy,
			"label_to_path_policy":    config.LabelToPathPolicy,
			"authenticators":          config.Authenticators,
			"enable_sentinel_parsing": config.EnableSentinelParsing,
			"audit_fields":            config.AuditFields,
		},
	}

	if !config.LastUpdated.IsZero() {
		response.Data["last_updated"] = config.LastUpdated.Format(time.RFC3339)
	}

	return response
}

func (b *backend) pathEstWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	sc := b.makeStorageContext(ctx, req.Storage)

	config, err := sc.getEstConfig()
	if err != nil {
		return nil, err
	}

	if enabledRaw, ok := d.GetOk("enabled"); ok {
		config.Enabled = enabledRaw.(bool)
	}

	if defaultMountRaw, ok := d.GetOk("default_mount"); ok {
		config.DefaultMount = defaultMountRaw.(bool)
	}

	if defaultPathPolicyRaw, ok := d.GetOk("default_path_policy"); ok {
		config.DefaultPathPolicy = defaultPathPolicyRaw.(string)
	}

	// Validate default_path_policy if default_mount is enabled
	if config.DefaultMount && config.DefaultPathPolicy == "" {
		return logical.ErrorResponse("default_path_policy is required when default_mount is enabled"), nil
	}

	if labelToPolicyRaw, ok := d.GetOk("label_to_path_policy"); ok {
		config.LabelToPathPolicy = labelToPolicyRaw.(map[string]string)
	}

	if authenticatorsRaw, ok := d.GetOk("authenticators"); ok {
		authenticatorsMap := authenticatorsRaw.(map[string]interface{})
		config.Authenticators = make(map[string]AuthenticatorConfig)

		// Supported authenticator types for EST HTTP Basic Auth
		validAuthTypes := map[string]bool{
			"cert":     true, // TLS client certificate authentication
			"userpass": true, // Username/password authentication
		}

		for authType, authConfigRaw := range authenticatorsMap {
			// Validate auth type
			if !validAuthTypes[authType] {
				return logical.ErrorResponse("authenticator type must be one of: cert, userpass; got: %s", authType), nil
			}

			authConfigMap, ok := authConfigRaw.(map[string]interface{})
			if !ok {
				return logical.ErrorResponse("authenticator config for %s must be a map", authType), nil
			}

			accessor, ok := authConfigMap["accessor"].(string)
			if !ok || accessor == "" {
				return logical.ErrorResponse("authenticator %s must have an 'accessor' field", authType), nil
			}

			authConfig := AuthenticatorConfig{
				Accessor: accessor,
			}

			// cert_role is only valid for cert auth
			if certRole, ok := authConfigMap["cert_role"].(string); ok {
				if authType != "cert" {
					return logical.ErrorResponse("cert_role is only valid for cert authenticator"), nil
				}
				authConfig.CertRole = certRole
			}

			config.Authenticators[authType] = authConfig
		}
	}

	if enableSentinelRaw, ok := d.GetOk("enable_sentinel_parsing"); ok {
		config.EnableSentinelParsing = enableSentinelRaw.(bool)
	}

	if auditFieldsRaw, ok := d.GetOk("audit_fields"); ok {
		auditFields := auditFieldsRaw.([]string)
		// Validate audit fields
		validAuditFields := map[string]bool{
			"csr": true, "common_name": true, "alt_names": true, "ip_sans": true,
			"uri_sans": true, "other_sans": true, "signature_bits": true,
			"exclude_cn_from_sans": true, "ou": true, "organization": true,
			"country": true, "locality": true, "province": true,
			"street_address": true, "postal_code": true, "serial_number": true,
			"use_pss": true, "key_type": true, "key_bits": true,
			"add_basic_constraints": true,
		}

		for _, field := range auditFields {
			if !validAuditFields[field] {
				return logical.ErrorResponse("invalid audit field: %s", field), nil
			}
		}

		config.AuditFields = auditFields
	}

	// Validate path policies (both default and labels)
	policies := []string{config.DefaultPathPolicy}
	for _, policy := range config.LabelToPathPolicy {
		policies = append(policies, policy)
	}

	for _, policy := range policies {
		if policy == "" {
			continue
		}
		if err := validateEstPathPolicy(policy); err != nil {
			return logical.ErrorResponse(err.Error()), nil
		}
	}

	if err := sc.setEstConfig(config); err != nil {
		return nil, err
	}

	return genResponseFromEstConfig(config), nil
}

func validateEstPathPolicy(policy string) error {
	if policy == "sign-verbatim" {
		return nil
	}

	if len(policy) > 5 && policy[:5] == "role:" {
		roleName := policy[5:]
		if roleName == "" {
			return fmt.Errorf("role name cannot be empty in path policy")
		}
		return nil
	}

	return fmt.Errorf("path policy must be 'sign-verbatim' or 'role:<role_name>', got: %s", policy)
}
