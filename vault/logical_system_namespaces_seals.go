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

	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func (b *SystemBackend) namespaceSealPaths() []*framework.Path {
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
				"name": namespaceNameSchema,
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
				"name": namespaceNameSchema,
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
				"name": namespaceNameSchema,
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
			Fields: map[string]*framework.FieldSchema{
				"name": namespaceNameSchema,
				"key": {
					Type:        framework.TypeString,
					Description: "Specifies a single namespace unseal key share.",
				},
				"reset": {
					Type:        framework.TypeBool,
					Description: "Specifies whether to reset an unseal process progress.",
				},
			},

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
		return handleError(ErrNotSealable)
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
			Data: map[string]interface{}{
				"type":        status.Type,
				"initialized": status.Initialized,
				"sealed":      status.Sealed,
				"t":           status.T,
				"n":           status.N,
				"progress":    status.Progress,
				"nonce":       status.Nonce,
			},
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

		if err := b.Core.namespaceStore.SealNamespace(ctx, name); err != nil {
			return handleError(err)
		}

		return nil, nil
	}
}

// handleNamespacesUnseal handles the "/sys/namespaces/<name>/unseal" endpoint to unseal the namespace.
func (b *SystemBackend) handleNamespacesUnseal() framework.OperationFunc {
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

		resetFlag := data.Get("reset").(bool)
		if resetFlag {
			b.Core.sealManager.ResetUnsealProcess(ns.UUID)
		} else {
			key := data.Get("key").(string)
			if key == "" {
				return nil, errors.New("provided key is empty")
			}

			var decodedKey []byte
			decodedKey, err = hex.DecodeString(key)
			if err != nil {
				decodedKey, err = base64.StdEncoding.DecodeString(key)
				if err != nil {
					return handleError(err)
				}
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
		}

		status, err := b.Core.sealManager.GetSealStatus(ctx, ns)
		if err != nil {
			return handleError(err)
		}

		return &logical.Response{
			Data: map[string]interface{}{
				"type":        status.Type,
				"initialized": status.Initialized,
				"sealed":      status.Sealed,
				"t":           status.T,
				"n":           status.N,
				"progress":    status.Progress,
				"nonce":       status.Nonce,
			},
		}, nil
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
}
