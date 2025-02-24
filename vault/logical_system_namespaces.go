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
	listOperation := &framework.PathOperation{
		Callback: b.handleNamespacesList(),
		Responses: map[int][]framework.Response{
			http.StatusOK: {{
				Description: "OK",
				Fields: map[string]*framework.FieldSchema{
					"keys":     {Type: framework.TypeStringSlice},
					"key_info": {Type: framework.TypeMap},
				},
			}},
		},
		Summary: "List namespaces.",
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
				OperationVerb:   "list",
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: listOperation,
				logical.ListOperation: listOperation,
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

// handleNamespacesList handles "/sys/namespaces" endpoint to list the enabled namespaces.
func (b *SystemBackend) handleNamespacesList() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		namespaces, err := b.Core.namespaceStore.ListNamespaces(ctx, false /* includeRoot */)
		if err != nil {
			return nil, err
		}

		var keys []string
		keyInfo := make(map[string]interface{})
		for _, ns := range namespaces {
			keys = append(keys, ns.Path)
			keyInfo[ns.Path] = ns
		}

		return logical.ListResponseWithInfo(keys, keyInfo), nil
	}
}

// handleNamespacesRead handles the "/sys/namespaces/<path>" endpoints to read a namespace.
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

// handleNamespaceSet handles the "/sys/namespaces/<path>" endpoint to set a namespace.
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

		ns, err := b.Core.namespaceStore.ModifyNamespaceByPath(ctx, path, func(ctx context.Context, ns *NamespaceEntry) (*NamespaceEntry, error) {
			ns.Namespace.Path = path
			ns.Namespace.CustomMetadata = metadata
			return ns, nil
		})
		if err != nil {
			return nil, fmt.Errorf("failed to modify namespace: %w", err)
		}

		resp := &logical.Response{Data: map[string]interface{}{
			"uuid":            ns.UUID,
			"path":            ns.Namespace.Path,
			"id":              ns.Namespace.ID,
			"custom_metadata": ns.Namespace.CustomMetadata,
		}}
		return resp, nil
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
		path := data.Get("path").(string)
		ns, err := b.Core.namespaceStore.ModifyNamespaceByPath(ctx, path, func(ctx context.Context, ns *NamespaceEntry) (*NamespaceEntry, error) {
			if ns.UUID == "" {
				return nil, fmt.Errorf("requested namespace does not exist")
			}

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
		})
		if err != nil {
			return nil, fmt.Errorf("failed to modify namespace: %w", err)
		}

		resp := &logical.Response{Data: map[string]interface{}{
			"uuid":            ns.UUID,
			"path":            ns.Namespace.Path,
			"id":              ns.Namespace.ID,
			"custom_metadata": ns.Namespace.CustomMetadata,
		}}
		return resp, nil
	}
}

// handleNamespacesDelete handles the "/sys/namespace/<path>" endpoints to delete a namespace.
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
