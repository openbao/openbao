// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func (b *SystemBackend) namespacePaths() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "namespaces/?$",

			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "namespaces",
				OperationVerb:   "list",
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.handleNamespacesList(),
					Responses: map[int][]framework.Response{
						http.StatusOK: {{
							Description: "OK",
							Fields: map[string]*framework.FieldSchema{
								"keys": {
									Type:     framework.TypeStringSlice,
									Required: true,
								},
								"namespaces": {
									Type: framework.TypeStringSlice,
								},
							},
						}},
					},
				},
				logical.ListOperation: &framework.PathOperation{
					Callback: b.handleNamespacesList(),
					Responses: map[int][]framework.Response{
						http.StatusOK: {{
							Description: "OK",
							Fields: map[string]*framework.FieldSchema{
								"keys": {
									Type:     framework.TypeStringSlice,
									Required: true,
								},
								"namespaces": {
									Type: framework.TypeStringSlice,
								},
							},
						}},
					},
				},
			},

			HelpSynopsis:    strings.TrimSpace(sysHelp["namespace-list"][0]),
			HelpDescription: strings.TrimSpace(sysHelp["namespace-list"][1]),
		},

		{
			Pattern: "namespaces/(?P<path>.+)",

			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "namespaces",
				// OperationSuffix: "api-namespace2", // ??? this endpoint duplicates /sys/namespaces/api-lock
			},

			Fields: map[string]*framework.FieldSchema{
				"id": {
					Type:        framework.TypeString,
					Description: strings.TrimSpace(sysHelp["namespace-id"][0]),
				},
				"path": {
					Type:        framework.TypeString,
					Description: strings.TrimSpace(sysHelp["namespace-path"][0]),
				},
				"custom_metadata": {
					Type:        framework.TypeMap,
					Description: strings.TrimSpace(sysHelp["namespace-custom_metadata"][0]),
				},
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.handleNamespacesRead(),
					Responses: map[int][]framework.Response{
						http.StatusOK: {{
							Description: "OK",
							Fields: map[string]*framework.FieldSchema{
								"id": {
									Type:     framework.TypeString,
									Required: false,
								},
								"path": {
									Type:     framework.TypeString,
									Required: true,
								},
								"custom_metadata": {
									Type:     framework.TypeMap,
									Required: false,
								},
							},
						}},
					},
					Summary: "Retrieve the namespace body for the named path.",
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.handleNamespacesSet(),
					Responses: map[int][]framework.Response{
						http.StatusNoContent: {{
							Description: "OK",
							Fields:      map[string]*framework.FieldSchema{},
						}},
					},
					Summary: "Add a new namespace.",
				},
				logical.PatchOperation: &framework.PathOperation{
					Callback: b.handleNamespacesPatch(),
					Responses: map[int][]framework.Response{
						http.StatusNoContent: {{
							Description: "OK",
							Fields:      map[string]*framework.FieldSchema{},
						}},
					},
					Summary: "Update an existing namespace.",
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.handleNamespacesDelete(),
					Responses: map[int][]framework.Response{
						http.StatusNoContent: {{
							Description: "OK",
							Fields:      map[string]*framework.FieldSchema{},
						}},
					},
					Summary: "Delete the namespace with the given name.",
				},
			},

			HelpSynopsis:    strings.TrimSpace(sysHelp["namespace"][0]),
			HelpDescription: strings.TrimSpace(sysHelp["namespace"][1]),
		},
	}
}

// handleNamespacesList handles /sys/namespaces/ endpoints to provide the enabled namespaces
func (b *SystemBackend) handleNamespacesList() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		namespaces, err := b.Core.namespaceStore.ListNamespacePaths(ctx, false /* includeRoot */)
		if err != nil {
			return nil, err
		}

		return logical.ListResponse(namespaces), nil
	}
}

// handleNamespacesRead handles the "/sys/namespaces/<path>" endpoints to read a namespace
func (b *SystemBackend) handleNamespacesRead() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		path := data.Get("path").(string)

		ns, err := b.Core.namespaceStore.GetNamespaceByPath(ctx, path)
		if err != nil {
			return handleError(err)
		}

		if ns == nil {
			return nil, nil
		}

		resp := &logical.Response{
			Data: map[string]interface{}{
				"uuid":            ns.UUID,
				"id":              ns.Namespace.ID,
				"path":            ns.Namespace.Path,
				"custom_metadata": ns.Namespace.CustomMetadata,
			},
		}

		return resp, nil
	}
}

// handleNamespaceSet handles the "/sys/namespaces/<path>" endpoint to set a namespace
func (b *SystemBackend) handleNamespacesSet() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		path := data.Get("path").(string)
		imetadata, ok := data.GetOk("custom_metadata")
		var metadata map[string]string
		if ok {
			metadata = make(map[string]string)
			for k, v := range imetadata.(map[string]interface{}) {
				if metadata[k], ok = v.(string); !ok {
					return nil, fmt.Errorf("custom_metadata values must be strings")
				}
			}
		}

		if err := b.Core.namespaceStore.ModifyNamespaceByPath(ctx, path, func(ctx context.Context, ns *NamespaceEntry) (*NamespaceEntry, error) {
			ns.Namespace.Path = path
			ns.Namespace.CustomMetadata = metadata
			return ns, nil
		}); err != nil {
			return nil, fmt.Errorf("failed to modify namespace: %w", err)
		}

		return nil, nil
	}
}

// customMetadataPatchPreprocessor is passed to framework.HandlePatchOperation within the handleNamespacesPatch handler.
func customMetadataPatchPreprocessor(input map[string]interface{}) (map[string]interface{}, error) {
	imetadata, ok := input["custom_metadata"]
	var metadata map[string]interface{}
	if ok {
		metadata = imetadata.(map[string]interface{})
		for _, v := range metadata {
			// Allow nil values in addition to strings so keys can be removed.
			if _, ok = v.(string); !ok && v != nil {
				return nil, fmt.Errorf("custom_metadata values must be strings")
			}
		}
	}
	return metadata, nil
}

// handleNamespacesPatch handles the "/sys/namespace/<path>" endpoints to update a namespace
func (b *SystemBackend) handleNamespacesPatch() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		path := data.Get("path").(string)
		if err := b.Core.namespaceStore.ModifyNamespaceByPath(ctx, path, func(ctx context.Context, ns *NamespaceEntry) (*NamespaceEntry, error) {
			current := make(map[string]interface{})
			for k, v := range ns.Namespace.CustomMetadata {
				current[k] = v
			}

			patchedBytes, err := framework.HandlePatchOperation(data, current, customMetadataPatchPreprocessor)
			if err != nil {
				return nil, err
			}

			var patched map[string]string
			if err = json.Unmarshal(patchedBytes, &patched); err != nil {
				return nil, err
			}

			ns.Namespace.CustomMetadata = patched
			return ns, nil
		}); err != nil {
			return nil, fmt.Errorf("failed to modify namespace: %w", err)
		}

		return nil, nil
	}
}

func (b *SystemBackend) handleNamespacesDelete() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		path := data.Get("path").(string)

		ns, err := b.Core.namespaceStore.GetNamespaceByPath(ctx, path)
		if err != nil {
			return nil, fmt.Errorf("failed to load namespace: %w", err)
		}

		if ns == nil {
			resp := &logical.Response{}
			resp.AddWarning("requested namespace does not exist")
			return resp, nil
		}

		if err := b.Core.namespaceStore.DeleteNamespace(ctx, ns.UUID); err != nil {
			return handleError(err)
		}

		return nil, nil
	}
}
