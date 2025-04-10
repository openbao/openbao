// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func (b *SystemBackend) namespacePaths() []*framework.Path {
	namespaceListSchema := map[string]*framework.FieldSchema{
		"keys": {
			Type:        framework.TypeStringSlice,
			Description: "List of namespace paths.",
		},
		"key_info": {
			Type:        framework.TypeMap,
			Description: "Map of namespace details by path.",
		},
	}

	namespaceSchema := map[string]*framework.FieldSchema{
		"uuid": {
			Type:        framework.TypeString,
			Required:    true,
			Description: "Internal UUID of the namespace.",
		},
		"id": {
			Type:        framework.TypeString,
			Required:    true,
			Description: "Accessor ID of the namespace.",
		},
		"path": {
			Type:        framework.TypeString,
			Required:    true,
			Description: "Path of the namespace.",
		},
		"custom_metadata": {
			Type:        framework.TypeMap,
			Required:    true,
			Description: "User provided key-value pairs.",
		},
	}

	return []*framework.Path{
		{
			Pattern: "namespaces/?$",

			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "namespaces",
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.handleNamespacesList(),
					Responses: map[int][]framework.Response{
						http.StatusOK: {{Description: "OK", Fields: namespaceListSchema}},
					},
					Summary: "List namespaces.",
				},
				logical.ScanOperation: &framework.PathOperation{
					Callback: b.handleNamespacesScan(),
					Responses: map[int][]framework.Response{
						http.StatusOK: {{Description: "OK", Fields: namespaceListSchema}},
					},
					Summary: "Scan (recursively list) namespaces.",
				},
			},

			HelpSynopsis:    strings.TrimSpace(sysHelp["list-namespaces"][0]),
			HelpDescription: strings.TrimSpace(sysHelp["list-namespaces"][1]),
		},

		{
			Pattern: "namespaces/(?P<path>.+)",

			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "namespaces",
			},

			Fields: map[string]*framework.FieldSchema{
				"path": {
					Type:        framework.TypeString,
					Required:    true,
					Description: "Path of the namespace.",
				},
				"custom_metadata": {
					Type:        framework.TypeMap,
					Description: "User provided key-value pairs.",
				},
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.handleNamespacesRead(),
					Responses: map[int][]framework.Response{
						http.StatusOK: {{Description: "OK", Fields: namespaceSchema}},
					},
					Summary: "Retrieve a namespace.",
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.handleNamespacesSet(),
					Responses: map[int][]framework.Response{
						http.StatusOK: {{Description: "OK", Fields: namespaceSchema}},
					},
					Summary: "Create or update a namespace.",
				},
				logical.PatchOperation: &framework.PathOperation{
					Callback: b.handleNamespacesPatch(),
					Responses: map[int][]framework.Response{
						http.StatusOK: {{Description: "OK", Fields: namespaceSchema}},
					},
					Summary: "Update a namespace's custom metadata.",
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.handleNamespacesDelete(),
					Responses: map[int][]framework.Response{
						http.StatusNoContent: {{Description: "OK"}},
					},
					Summary: "Delete a namespace.",
				},
			},

			HelpSynopsis:    strings.TrimSpace(sysHelp["namespaces"][0]),
			HelpDescription: strings.TrimSpace(sysHelp["namespaces"][1]),
		},
	}
}

// createNamespaceDataResponse is the standard response object
// for any operations concerning a namespace
func createNamespaceDataResponse(ns *namespace.Namespace) map[string]any {
	return map[string]any{
		"uuid":            ns.UUID,
		"path":            ns.Path,
		"id":              ns.ID,
		"tainted":         ns.Tainted,
		"custom_metadata": ns.CustomMetadata,
	}
}

// handleNamespacesList handles "/sys/namespaces" endpoint to list the enabled namespaces.
func (b *SystemBackend) handleNamespacesList() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		parent, err := namespace.FromContext(ctx)
		if err != nil {
			return nil, err
		}
		entries, err := b.Core.namespaceStore.ListNamespaces(ctx, false, false)
		if err != nil {
			return nil, err
		}

		var keys []string
		keyInfo := make(map[string]interface{})
		for _, entry := range entries {
			p := parent.TrimmedPath(entry.Path)
			keys = append(keys, p)
			keyInfo[p] = createNamespaceDataResponse(entry)
		}

		return logical.ListResponseWithInfo(keys, keyInfo), nil
	}
}

// handleNamespacesScan handles "/sys/namespaces" endpoint to scan the enabled namespaces.
func (b *SystemBackend) handleNamespacesScan() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		parent, err := namespace.FromContext(ctx)
		if err != nil {
			return nil, err
		}
		entries, err := b.Core.namespaceStore.ListNamespaces(ctx, false, true)
		if err != nil {
			return nil, err
		}

		var keys []string
		keyInfo := make(map[string]interface{})
		for _, entry := range entries {
			p := parent.TrimmedPath(entry.Path)
			keys = append(keys, p)
			keyInfo[p] = createNamespaceDataResponse(entry)
		}

		return logical.ListResponseWithInfo(keys, keyInfo), nil
	}
}

// handleNamespacesRead handles the "/sys/namespaces/<path>" endpoints to read a namespace.
func (b *SystemBackend) handleNamespacesRead() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		path := namespace.Canonicalize(data.Get("path").(string))

		if len(path) > 0 && strings.Contains(path[:len(path)-1], "/") {
			return nil, errors.New("path must not contain /")
		}

		ns, err := b.Core.namespaceStore.GetNamespaceByPath(ctx, path)
		if err != nil {
			return nil, err
		}

		if ns == nil {
			return nil, nil
		}

		return &logical.Response{Data: createNamespaceDataResponse(ns)}, nil
	}
}

// handleNamespaceSet handles the "/sys/namespaces/<path>" endpoint to set a namespace.
func (b *SystemBackend) handleNamespacesSet() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		path := namespace.Canonicalize(data.Get("path").(string))

		if len(path) > 0 && strings.Contains(path[:len(path)-1], "/") {
			return logical.ErrorResponse("path must not contain /"), logical.ErrInvalidRequest
		}

		imetadata, ok := data.GetOk("custom_metadata")
		var metadata map[string]string
		if ok {
			metadata = make(map[string]string)
			for k, v := range imetadata.(map[string]interface{}) {
				if metadata[k], ok = v.(string); !ok {
					return logical.ErrorResponse("custom_metadata values must be strings"), logical.ErrInvalidRequest
				}
			}
		}

		entry, err := b.Core.namespaceStore.ModifyNamespaceByPath(ctx, path, func(ctx context.Context, ns *namespace.Namespace) (*namespace.Namespace, error) {
			ns.CustomMetadata = metadata
			return ns, nil
		})
		if err != nil {
			return handleError(err)
		}

		return &logical.Response{Data: createNamespaceDataResponse(entry)}, nil
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

// handleNamespacesPatch handles the "/sys/namespace/<path>" endpoints to update a namespace's custom metadata.
func (b *SystemBackend) handleNamespacesPatch() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		path := namespace.Canonicalize(data.Get("path").(string))

		if len(path) > 0 && strings.Contains(path[:len(path)-1], "/") {
			return nil, errors.New("path must not contain /")
		}

		ns, err := b.Core.namespaceStore.ModifyNamespaceByPath(ctx, path, func(ctx context.Context, ns *namespace.Namespace) (*namespace.Namespace, error) {
			if ns.UUID == "" {
				return nil, fmt.Errorf("requested namespace does not exist")
			}

			current := make(map[string]interface{})
			for k, v := range ns.CustomMetadata {
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

			ns.CustomMetadata = patched
			return ns, nil
		})
		if err != nil {
			return nil, fmt.Errorf("failed to modify namespace: %w", err)
		}

		return &logical.Response{Data: createNamespaceDataResponse(ns)}, nil
	}
}

// handleNamespacesDelete handles the "/sys/namespace/<path>" endpoint to delete a namespace.
func (b *SystemBackend) handleNamespacesDelete() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		path := namespace.Canonicalize(data.Get("path").(string))

		if len(path) > 0 && strings.Contains(path[:len(path)-1], "/") {
			return nil, errors.New("path must not contain /")
		}

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
