// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func (b *SystemBackend) namespaceSealPaths() []*framework.Path {
	namespaceFieldsSchema := map[string]*framework.FieldSchema{
		"name": {
			Type:        framework.TypeString,
			Required:    true,
			Description: "Name of the namespace.",
		},
		"key": {
			Type:        framework.TypeString,
			Description: "Specifies a single namespace unseal key share.",
		},
	}

	sealStatusSchema := map[string]*framework.FieldSchema{
		"type": {
			Type:     framework.TypeString,
			Required: true,
		},
		"initialized": {
			Type:     framework.TypeBool,
			Required: true,
		},
		"sealed": {
			Type:     framework.TypeBool,
			Required: true,
		},
		"t": {
			Type:     framework.TypeInt,
			Required: true,
		},
		"n": {
			Type:     framework.TypeInt,
			Required: true,
		},
		"progress": {
			Type:     framework.TypeInt,
			Required: true,
		},
		"nonce": {
			Type:     framework.TypeString,
			Required: true,
		},
		"version": {
			Type:     framework.TypeString,
			Required: true,
		},
		"build_date": {
			Type:     framework.TypeString,
			Required: true,
		},
		"migration": {
			Type: framework.TypeBool,
		},
		"cluster_name": {
			Type: framework.TypeString,
		},
		"cluster_id": {
			Type: framework.TypeString,
		},
		"recovery_seal": {
			Type: framework.TypeBool,
		},
		"storage_type": {
			Type: framework.TypeString,
		},
	}

	rotationConfigSchema := map[string]*framework.FieldSchema{
		"max_operations": {
			Type:     framework.TypeInt64,
			Default:  absoluteOperationMaximum,
			Required: false,
		},
		"enabled": {
			Type:     framework.TypeBool,
			Default:  true,
			Required: false,
		},
		"interval": {
			Type:     framework.TypeString,
			Required: false,
		},
	}

	return []*framework.Path{
		{
			Pattern: "namespaces/(?P<name>.+)/key-status",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "namespaces",
				OperationVerb:   "status",
				OperationSuffix: "encryption-key",
			},
			Fields: map[string]*framework.FieldSchema{
				"name": namespaceFieldsSchema["name"],
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Summary:  "Provides information about the namespace backend encryption key.",
					Callback: b.handleNamespaceKeyStatus,
					Responses: map[int][]framework.Response{
						http.StatusOK: {{
							Fields: map[string]*framework.FieldSchema{
								"term": {
									Type:     framework.TypeInt,
									Required: true,
								},
								"install_time": {
									Type:     framework.TypeTime,
									Required: true,
								},
								"encryptions": {
									Type:     framework.TypeInt64,
									Required: true,
								},
							},
						}},
					},
				},
			},

			HelpSynopsis:    strings.TrimSpace(sysNamespacesSealsHelp["namespaces-seal"][0]),
			HelpDescription: strings.TrimSpace(sysNamespacesSealsHelp["namespaces-seal"][1]),
		},
		{
			Pattern: "namespaces/(?P<name>.+)/seal-status",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "namespaces",
				OperationVerb:   "status",
				OperationSuffix: "seal",
			},
			Fields: map[string]*framework.FieldSchema{
				"name": namespaceFieldsSchema["name"],
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Summary:  "Check the seal status of an OpenBao namespace.",
					Callback: b.handleNamespaceSealStatus(),
					Responses: map[int][]framework.Response{
						http.StatusOK: {{
							Description: http.StatusText(http.StatusOK),
							Fields:      sealStatusSchema,
						}},
					},
				},
			},

			HelpSynopsis:    strings.TrimSpace(sysNamespacesSealsHelp["namespaces-seal"][0]),
			HelpDescription: strings.TrimSpace(sysNamespacesSealsHelp["namespaces-seal"][1]),
		},

		{
			Pattern: "namespaces/(?P<name>.+)/seal",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "namespaces",
			},
			Fields: map[string]*framework.FieldSchema{
				"name": namespaceFieldsSchema["name"],
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Summary:  "Seal a namespace.",
					Callback: b.handleNamespacesSeal(),
					Responses: map[int][]framework.Response{
						http.StatusNoContent: {{Description: http.StatusText(http.StatusNoContent)}},
					},
				},
			},

			HelpSynopsis:    strings.TrimSpace(sysNamespacesSealsHelp["namespaces-seal"][0]),
			HelpDescription: strings.TrimSpace(sysNamespacesSealsHelp["namespaces-seal"][1]),
		},
		{
			Pattern: "namespaces/(?P<name>.+)/unseal",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "namespaces",
			},
			Fields: namespaceFieldsSchema,

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Summary:  "Unseal a namespace.",
					Callback: b.handleNamespacesUnseal(),
					Responses: map[int][]framework.Response{
						http.StatusOK: {{
							Description: http.StatusText(http.StatusOK),
							Fields:      sealStatusSchema,
						}},
					},
				},
			},

			HelpSynopsis:    strings.TrimSpace(sysNamespacesSealsHelp["namespaces-seal"][0]),
			HelpDescription: strings.TrimSpace(sysNamespacesSealsHelp["namespaces-seal"][1]),
		},
		{
			Pattern: "namespaces/(?P<name>.+)/rotate/config",

			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "namespaces",
			},

			Fields: map[string]*framework.FieldSchema{
				"name":           namespaceFieldsSchema["name"],
				"max_operations": rotationConfigSchema["max_operations"],
				"interval":       rotationConfigSchema["interval"],
				"enabled":        rotationConfigSchema["enabled"],
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Summary:  "Configure automatic key rotation.",
					Callback: b.handleNamespacesUpdateRotateConfig(),
					Responses: map[int][]framework.Response{
						http.StatusNoContent: {{Description: http.StatusText(http.StatusNoContent)}},
					},
				},
				logical.ReadOperation: &framework.PathOperation{
					Summary:  "Get the automatic key rotation config.",
					Callback: b.handleNamespacesGetRotateConfig(),
					Responses: map[int][]framework.Response{
						http.StatusOK: {{
							Description: http.StatusText(http.StatusOK),
							Fields:      rotationConfigSchema,
						}},
					},
				},
			},

			HelpSynopsis:    strings.TrimSpace(sysNamespacesSealsHelp["namespaces-rotate-config"][0]),
			HelpDescription: strings.TrimSpace(sysNamespacesSealsHelp["namespaces-rotate-config"][1]),
		},

		{
			Pattern: "namespaces/(?P<name>.+)/rotate",

			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "namespaces",
			},

			Fields: map[string]*framework.FieldSchema{
				"name": namespaceFieldsSchema["name"],
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Summary:  "Rotate the namespace key.",
					Callback: b.handleNamespacesRotate(),
					Responses: map[int][]framework.Response{
						http.StatusNoContent: {{Description: http.StatusText(http.StatusNoContent)}},
					},
				},
			},

			HelpSynopsis:    strings.TrimSpace(sysNamespacesSealsHelp["namespaces-rotate"][0]),
			HelpDescription: strings.TrimSpace(sysNamespacesSealsHelp["namespaces-rotate"][1]),
		},
	}
}

// handleNamespaceKeyStatus handles the "/sys/namespaces/<name>/key-status" endpoint
// to return status information about the namespace-owned backend key.
func (b *SystemBackend) handleNamespaceKeyStatus(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := namespace.Canonicalize(data.Get("name").(string))
	if len(name) > 0 && strings.Contains(name[:len(name)-1], "/") {
		return nil, errors.New("name must not contain /")
	}

	ns, err := b.Core.namespaceStore.GetNamespaceByPath(ctx, name)
	if err != nil {
		return handleError(err)
	}

	if ns == nil {
		return nil, fmt.Errorf("namespace %q doesn't exist", name)
	}

	barrier := b.Core.sealManager.NamespaceBarrier(ns.Path)
	if barrier == nil {
		return handleError(ErrBarrierNotFound)
	}

	info, err := barrier.ActiveKeyInfo()
	if err != nil {
		return handleError(err)
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"term":         info.Term,
			"install_time": info.InstallTime.Format(time.RFC3339Nano),
			"encryptions":  info.Encryptions,
		},
	}, nil
}

// handleNamespaceSealStatus handles the "/sys/namespaces/<name>/seal-status" endpoint
// to retrieve a seal status of the namespace.
func (b *SystemBackend) handleNamespaceSealStatus() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		name := namespace.Canonicalize(data.Get("name").(string))
		if len(name) > 0 && strings.Contains(name[:len(name)-1], "/") {
			return nil, errors.New("name must not contain /")
		}

		ns, err := b.Core.namespaceStore.GetNamespaceByPath(ctx, name)
		if err != nil {
			return handleError(err)
		}

		if ns == nil {
			return nil, fmt.Errorf("namespace %q doesn't exist", name)
		}

		status, err := b.Core.sealManager.GetSealStatus(ctx, ns)
		if err != nil {
			return handleError(err)
		}

		return &logical.Response{
			Data: map[string]interface{}{"seal_status": status},
		}, nil
	}
}

// handleNamespacesSeal handles the "/sys/namespaces/<name>/seal" endpoint to seal the namespace.
func (b *SystemBackend) handleNamespacesSeal() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		name := namespace.Canonicalize(data.Get("name").(string))

		if len(name) > 0 && strings.Contains(name[:len(name)-1], "/") {
			return nil, errors.New("name must not contain /")
		}

		err := b.Core.namespaceStore.SealNamespace(ctx, name)
		if err != nil {
			return handleError(err)
		}

		return nil, nil
	}
}

// handleNamespacesRotate handles the "/sys/namespaces/<name>/rotate" endpoint to rotate the namespace encryption key.
func (b *SystemBackend) handleNamespacesRotate() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		name := namespace.Canonicalize(data.Get("name").(string))

		if len(name) > 0 && strings.Contains(name[:len(name)-1], "/") {
			return nil, errors.New("name must not contain /")
		}

		ns, err := b.Core.namespaceStore.GetNamespaceByPath(ctx, name)
		if err != nil {
			return handleError(err)
		}

		if ns == nil {
			return nil, fmt.Errorf("namespace %q doesn't exist", name)
		}

		err = b.Core.sealManager.RotateNamespaceBarrierKey(ctx, ns)
		if err != nil {
			return nil, err
		}

		return nil, nil
	}
}

// handleNamespacesUnseal handles the "/sys/namespaces/<name>/unseal" endpoint to unseal the namespace.
func (b *SystemBackend) handleNamespacesUnseal() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		name := namespace.Canonicalize(data.Get("name").(string))
		key := data.Get("key").(string)

		if len(name) > 0 && strings.Contains(name[:len(name)-1], "/") {
			return nil, errors.New("name must not contain /")
		}

		if key == "" {
			return nil, errors.New("provided key is empty")
		}

		var decodedKey []byte
		decodedKey, err := hex.DecodeString(key)
		if err != nil {
			decodedKey, err = base64.StdEncoding.DecodeString(key)
			if err != nil {
				return handleError(err)
			}
		}

		ns, err := b.Core.namespaceStore.GetNamespaceByPath(ctx, name)
		if err != nil {
			return handleError(err)
		}

		if ns == nil {
			return nil, fmt.Errorf("namespace %q doesn't exist", name)
		}

		err = b.Core.namespaceStore.UnsealNamespace(ctx, name, decodedKey)
		if err != nil {
			invalidKeyErr := &ErrInvalidKey{}
			switch {
			case errors.As(err, &invalidKeyErr):
			case errors.Is(err, ErrBarrierInvalidKey):
			case errors.Is(err, ErrBarrierNotInit):
			case errors.Is(err, ErrBarrierSealed):
			default:
				return handleError(logical.CodedError(http.StatusInternalServerError, err.Error()))
			}
			return handleError(err)
		}

		status, err := b.Core.sealManager.GetSealStatus(ctx, ns)
		if err != nil {
			return handleError(err)
		}

		return &logical.Response{
			Data: map[string]interface{}{"seal_status": status},
		}, nil
	}
}

// handleNamespacesGetRotateConfig handles the GET "/sys/namespaces/<name>/rotate/config" endpoint to read the automatic key rotation config.
func (b *SystemBackend) handleNamespacesGetRotateConfig() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		name := namespace.Canonicalize(data.Get("name").(string))

		if len(name) > 0 && strings.Contains(name[:len(name)-1], "/") {
			return nil, errors.New("name must not contain /")
		}

		ns, err := b.Core.namespaceStore.GetNamespaceByPath(ctx, name)
		if err != nil {
			return handleError(err)
		}

		if ns == nil {
			return nil, fmt.Errorf("namespace %q doesn't exist", name)
		}

		barrier := b.Core.sealManager.NamespaceBarrier(ns.Path)
		if barrier == nil {
			return nil, ErrBarrierNotFound
		}

		rotConfig, err := barrier.RotationConfig()
		if err != nil {
			return nil, err
		}

		resp := &logical.Response{
			Data: map[string]any{
				"max_operations": rotConfig.MaxOperations,
				"enabled":        !rotConfig.Disabled,
			},
		}
		if rotConfig.Interval > 0 {
			resp.Data["interval"] = rotConfig.Interval.String()
		}
		return resp, nil
	}
}

// handleNamespacesUpdateRotateConfig handles the POST "/sys/namespaces/<name>/rotate/config" endpoint to update the automatic key rotation config.
func (b *SystemBackend) handleNamespacesUpdateRotateConfig() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		name := namespace.Canonicalize(data.Get("name").(string))

		if len(name) > 0 && strings.Contains(name[:len(name)-1], "/") {
			return nil, errors.New("name must not contain /")
		}

		ns, err := b.Core.namespaceStore.GetNamespaceByPath(ctx, name)
		if err != nil {
			return handleError(err)
		}

		if ns == nil {
			return nil, fmt.Errorf("namespace %q doesn't exist", name)
		}

		barrier := b.Core.sealManager.NamespaceBarrier(ns.Path)
		if barrier == nil {
			return nil, ErrBarrierNotFound
		}

		rotConfig, err := barrier.RotationConfig()
		if err != nil {
			return nil, err
		}
		maxOps, ok, err := data.GetOkErr("max_operations")
		if err != nil {
			return nil, err
		}
		if ok {
			rotConfig.MaxOperations = maxOps.(int64)
		}
		interval, ok, err := data.GetOkErr("interval")
		if err != nil {
			return nil, err
		}
		if ok {
			rotConfig.Interval, err = parseutil.ParseDurationSecond(interval)
			if err != nil {
				return nil, err
			}
		}

		enabled, ok, err := data.GetOkErr("enabled")
		if err != nil {
			return nil, err
		}
		if ok {
			rotConfig.Disabled = !enabled.(bool)
		}

		// Reject out of range settings
		if rotConfig.Interval < minimumRotationInterval && rotConfig.Interval != 0 {
			return logical.ErrorResponse("interval must be greater or equal to %s", minimumRotationInterval.String()), logical.ErrInvalidRequest
		}

		if rotConfig.MaxOperations < absoluteOperationMinimum || rotConfig.MaxOperations > absoluteOperationMaximum {
			return logical.ErrorResponse("max_operations must be in the range [%d,%d]", absoluteOperationMinimum, absoluteOperationMaximum), logical.ErrInvalidRequest
		}

		// Store the rotation config
		err = barrier.SetRotationConfig(ctx, rotConfig)
		if err != nil {
			return nil, err
		}

		return nil, nil
	}
}

var sysNamespacesSealsHelp = map[string][2]string{
	"namespaces-seal": {
		"Seal, unseal and check seal status of a namespace.",
		`
This path responds to the following HTTP methods.

	POST /<name>/seal
		Seal a namespace.

	POST /<name>/unseal
		Unseal a namespace.

	GET /<name>/seal-status
		Returns the seal status of the namespace.

	GET /<name>/key-status
		Provides the namespace current backend encryption key term and installation time.
		`,
	},

	"namespaces-rotate": {
		"Rotates the backend encryption key used to persist data for this namespace.",
		`
		Rotate generates a new encryption key which is used to encrypt all data
		of this namespace going to the storage backend. The old encryption keys
		are kept so that data encrypted using those keys can still be decrypted.
		`,
	},

	"namespaces-rotate-config": {
		"Configures settings related to the namespace encryption key management.",
		`
		Configures settings related to the automatic rotation of the namespace encryption key.
		`,
	},
}
