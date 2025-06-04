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

	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func (b *SystemBackend) namespaceSealPaths() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "namespaces/(?P<name>.+)/seal-status",

			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "namespaces",
				OperationVerb:   "status",
			},

			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Required:    true,
					Description: "Name of the namespace.",
				},
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Summary:  "Check the seal status of an OpenBao namespace.",
					Callback: b.handleNamespaceSealStatus(),
					Responses: map[int][]framework.Response{
						http.StatusOK: {{
							Fields: map[string]*framework.FieldSchema{
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
									Type:     framework.TypeBool,
									Required: true,
								},
								"cluster_name": {
									Type:     framework.TypeString,
									Required: false,
								},
								"cluster_id": {
									Type:     framework.TypeString,
									Required: false,
								},
								"recovery_seal": {
									Type:     framework.TypeBool,
									Required: true,
								},
								"storage_type": {
									Type:     framework.TypeString,
									Required: false,
								},
							},
						}},
					},
				},
			},

			HelpSynopsis:    strings.TrimSpace(sysHelp["namespaces-seal"][0]),
			HelpDescription: strings.TrimSpace(sysHelp["namespaces-seal"][1]),
		},

		{
			Pattern: "namespaces/(?P<name>.+)/seal",

			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "namespaces",
			},

			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Required:    true,
					Description: "Name of the namespace.",
				},
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

			HelpSynopsis:    strings.TrimSpace(sysHelp["namespaces-seal"][0]),
			HelpDescription: strings.TrimSpace(sysHelp["namespaces-seal"][1]),
		},
		{
			Pattern: "namespaces/(?P<name>.+)/unseal",

			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "namespaces",
			},

			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Required:    true,
					Description: "Name of the namespace.",
				},
				"key": {
					Type:        framework.TypeString,
					Description: "Specifies a single namespace unseal key share.",
				},
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Summary:  "Unseal a namespace.",
					Callback: b.handleNamespacesUnseal(),
					Responses: map[int][]framework.Response{
						http.StatusNoContent: {{Description: http.StatusText(http.StatusNoContent)}},
					},
				},
			},

			HelpSynopsis:    strings.TrimSpace(sysHelp["namespaces-seal"][0]),
			HelpDescription: strings.TrimSpace(sysHelp["namespaces-seal"][1]),
		},
	}
}

// TODO: adjust comment when known what it does
// handleNamespaceSealStatus handles the "/sys/namespaces/<name>/seal-status" endpoint to .
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

		status, err := b.Core.sealManager.GetSealStatus(ctx, ns, false)
		if err != nil {
			return handleError(err)
		}

		if status == nil {
			return nil, nil
		}

		return &logical.Response{Data: map[string]interface{}{"seal_status": status}}, nil
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

		err = b.Core.sealManager.UnsealNamespace(ctx, ns, decodedKey)
		if err != nil {
			invalidKeyErr := &ErrInvalidKey{}
			switch {
			case errors.As(err, &invalidKeyErr):
			case errors.Is(err, ErrBarrierInvalidKey):
			case errors.Is(err, ErrBarrierNotInit):
			case errors.Is(err, ErrBarrierSealed):
			default:
				return logical.RespondWithStatusCode(logical.ErrorResponse(err.Error()), req, http.StatusInternalServerError)
			}
			return handleError(err)
		}

		status, err := b.Core.sealManager.GetSealStatus(ctx, ns, true)
		if err != nil {
			return nil, err
		}

		return &logical.Response{Data: map[string]interface{}{
			"seal_status": status,
		}}, nil
	}
}
