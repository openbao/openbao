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

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/v2/internal/helper/namespace"
	"github.com/openbao/openbao/v2/internal/vault/barrier"
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
			Pattern: "namespaces/(?P<path>.+)/seal-status",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "namespaces",
				OperationSuffix: "seal",
			},
			Fields: map[string]*framework.FieldSchema{
				"path": namespacePathSchema,
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
			Pattern: "namespaces/(?P<path>.+)/seal",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "namespaces",
				OperationVerb:   "seal",
			},
			Fields: map[string]*framework.FieldSchema{
				"path": namespacePathSchema,
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Summary:  "Seal a namespace.",
					Callback: b.handleNamespacesSeal(),
					Responses: map[int][]framework.Response{
						http.StatusNoContent: {{
							Description: http.StatusText(http.StatusNoContent),
						}},
					},
					ForwardPerformanceStandby: true,
				},
			},

			HelpSynopsis:    strings.TrimSpace(sysNamespacesSealsHelp["namespaces-seal"][0]),
			HelpDescription: strings.TrimSpace(sysNamespacesSealsHelp["namespaces-seal"][1]),
		},

		{
			Pattern: "namespaces/(?P<path>.+)/unseal",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "namespaces",
				OperationVerb:   "unseal",
			},
			Fields: map[string]*framework.FieldSchema{
				"path": namespacePathSchema,
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
					ForwardPerformanceStandby: true,
				},
			},

			HelpSynopsis:    strings.TrimSpace(sysNamespacesSealsHelp["namespaces-seal"][0]),
			HelpDescription: strings.TrimSpace(sysNamespacesSealsHelp["namespaces-seal"][1]),
		},

		{
			Pattern: "namespaces/(?P<path>.+)/delete-sealed",

			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "namespaces",
			},

			Fields: map[string]*framework.FieldSchema{
				"path": namespacePathSchema,
				"force": {
					Type:        framework.TypeBool,
					Description: "If true, recursively deletes all child namespaces of the sealed namespace.",
				},
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.handleNamespacesDeleteSealed(),
					Responses: map[int][]framework.Response{
						http.StatusOK: {
							{
								Description: "OK",
								Fields: map[string]*framework.FieldSchema{
									"status": {
										Type:        framework.TypeString,
										Description: "Status of the deletion operation.",
									},
								},
							},
						},
					},
					Summary: "Delete a sealed namespace by wiping its physical storage.",
				},
			},

			HelpSynopsis:    "Delete a sealed namespace.",
			HelpDescription: "Physically deletes a sealed namespace by wiping its storage. Requires sudo privilege. Pass force=true to also delete child namespaces.",
		},
	}
}

// handleNamespaceSealStatus handles the "/sys/namespaces/<path>/seal-status"
// endpoint to retrieve a seal status of the namespace.
func (b *SystemBackend) handleNamespaceSealStatus() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		path, err := namespace.ParseName(data.Get("path").(string))
		if err != nil {
			return handleError(err)
		}

		ns, err := b.Core.namespaceStore.GetNamespaceByPath(ctx, path)
		if err != nil {
			return handleError(err)
		}

		if ns == nil {
			return nil, fmt.Errorf("namespace %q doesn't exist", path)
		}

		status, err := b.Core.sealManager.SealStatus(ctx, ns)
		if err != nil {
			return handleError(err)
		}

		return &logical.Response{
			Data: map[string]any{
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

// handleNamespacesSeal handles the "/sys/namespaces/<path>/seal" endpoint to
// seal the namespace.
func (b *SystemBackend) handleNamespacesSeal() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		path, err := namespace.ParseName(data.Get("path").(string))
		if err != nil {
			return handleError(err)
		}

		if err := b.Core.namespaceStore.SealNamespace(ctx, path); err != nil {
			return handleError(err)
		}

		return nil, nil
	}
}

// handleNamespacesUnseal handles the "/sys/namespaces/<path>/unseal" endpoint
// to unseal the namespace.
func (b *SystemBackend) handleNamespacesUnseal() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		path, err := namespace.ParseName(data.Get("path").(string))
		if err != nil {
			return handleError(err)
		}

		ns, err := b.Core.namespaceStore.GetNamespaceByPath(ctx, path)
		if err != nil {
			return handleError(err)
		}

		if ns == nil {
			return nil, fmt.Errorf("namespace %q doesn't exist", path)
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

			if _, err = b.Core.namespaceStore.UnsealNamespace(ctx, path, decodedKey); err != nil {
				invalidKeyErr := &ErrInvalidKey{}
				switch {
				case errors.As(err, &invalidKeyErr):
				case errors.Is(err, barrier.ErrBarrierInvalidKey):
				case errors.Is(err, barrier.ErrBarrierNotInit):
				case errors.Is(err, barrier.ErrBarrierSealed):
				default:
					return handleError(logical.CodedError(http.StatusInternalServerError, err.Error()))
				}
				return handleError(err)
			}
		}

		status, err := b.Core.sealManager.SealStatus(ctx, ns)
		if err != nil {
			return handleError(err)
		}

		return &logical.Response{
			Data: map[string]any{
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

// handleNamespacesDeleteSealed handles the "/sys/namespaces/<path>/delete-sealed"
// endpoint to delete a sealed namespace.
func (b *SystemBackend) handleNamespacesDeleteSealed() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		path, err := namespace.ParseName(data.Get("path").(string))
		if err != nil {
			return handleError(err)
		}

		if !b.System().(extendedSystemView).SudoPrivilege(ctx, req.MountPoint+req.Path, req.ClientToken) {
			return nil, logical.ErrPermissionDenied
		}

		force := data.Get("force").(bool)
		status, err := b.Core.namespaceStore.DeleteSealedNamespace(ctx, path, force)
		if err != nil {
			return handleError(err)
		}

		if status == "" {
			resp := &logical.Response{}
			resp.AddWarning("requested namespace does not exist")
			return resp, nil
		}

		return &logical.Response{
			Data: map[string]any{"status": status},
		}, nil
	}
}

var sysNamespacesSealsHelp = map[string][2]string{
	"namespaces-seal": {
		"Seal, unseal and delete sealable namespaces and check their seal status.",
		`
This path responds to the following HTTP methods.

	POST /<path>/seal
		Seal a namespace.

	POST /<path>/unseal
		Unseal a namespace.

	GET /<path>/seal-status
		Returns the seal status of the namespace.

	DELETE /<path>/delete-sealed
		Delete a sealed namespace by wiping its storage.
		`,
	},
}
