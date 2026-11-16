// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"slices"
	"strings"

	jsonpatch "github.com/evanphx/json-patch/v5"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
	ek "github.com/openbao/openbao/v2/internal/vault/external_keys"
)

func (b *SystemBackend) externalKeysPaths() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "external-keys/configs/?",

			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "external-keys",
				OperationSuffix: "configs",
			},

			Fields: map[string]*framework.FieldSchema{
				"after": {
					Type:        framework.TypeString,
					Description: "Optional entry to begin listing after; not required to exist.",
				},
				"limit": {
					Type:        framework.TypeInt,
					Description: "Optional number of entries to return; defaults to all entries.",
				},
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.handleExternalKeyConfigList,
					Responses: map[int][]framework.Response{
						http.StatusOK: {{
							Description: http.StatusText(http.StatusOK),
							Fields: map[string]*framework.FieldSchema{
								"keys": {
									Type:        framework.TypeStringSlice,
									Description: "List of configuration names",
								},
							},
						}},
					},
					Summary: "List configs.",
				},
			},

			HelpSynopsis: "List configs.",
			HelpDescription: `This path responds to the following HTTP methods.

	LIST /configs
		List configs.`,
		},

		{
			Pattern: "external-keys/configs/" + framework.GenericNameRegex("config"),

			Fields: map[string]*framework.FieldSchema{
				"config": {
					Type:        framework.TypeString,
					Required:    true,
					Description: "Name of the config.",
				},
				"plugin": {
					Type:        framework.TypeString,
					Required:    true,
					Description: "Name of the KMS plugin.",
				},
				"verify": {
					Type:        framework.TypeBool,
					Default:     true,
					Description: "Verify the config against the KMS backend (default true).",
				},
			},

			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "external-keys",
				OperationSuffix: "configs",
			},

			TakesArbitraryInput: true,

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.handleExternalKeyConfigRead,
					Responses: map[int][]framework.Response{
						http.StatusOK: {{Description: http.StatusText(http.StatusOK)}},
					},
					Summary: "Read a config.",
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.handleExternalKeyConfigUpsert,
					Responses: map[int][]framework.Response{
						http.StatusNoContent: {{Description: http.StatusText(http.StatusNoContent)}},
					},
					Summary: "Create or update a config.",
				},
				logical.PatchOperation: &framework.PathOperation{
					Callback: b.handleExternalKeyConfigPatch,
					Responses: map[int][]framework.Response{
						http.StatusNoContent: {{Description: http.StatusText(http.StatusNoContent)}},
					},
					Summary: "Patch a config.",
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.handleExternalKeyConfigDelete,
					Responses: map[int][]framework.Response{
						http.StatusNoContent: {{Description: http.StatusText(http.StatusNoContent)}},
					},
					Summary: "Remove a config.",
				},
			},

			HelpSynopsis: "Manage configs.",
			HelpDescription: `This path responds to the following HTTP methods.

	GET /configs/<config>
		Read a config.

	PUT /configs/<config>
		Create or update a config.

	PATCH /configs/<config>
		Patch a config.

	DELETE /configs/<config>
		Remove a config.`,
		},

		{
			Pattern: "external-keys/configs/" + framework.GenericNameRegex("config") + "/keys/?",

			Fields: map[string]*framework.FieldSchema{
				"config": {
					Type:        framework.TypeString,
					Required:    true,
					Description: "Name of the config.",
				},
				"after": {
					Type:        framework.TypeString,
					Description: "Optional entry to begin listing after; not required to exist.",
				},
				"limit": {
					Type:        framework.TypeInt,
					Description: "Optional number of entries to return; defaults to all entries.",
				},
			},

			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "external-keys",
				OperationSuffix: "keys",
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.handleExternalKeyList,
					Responses: map[int][]framework.Response{
						http.StatusOK: {{
							Description: http.StatusText(http.StatusOK),
							Fields: map[string]*framework.FieldSchema{
								"keys": {
									Type:        framework.TypeStringSlice,
									Description: "List of key names",
								},
							},
						}},
					},
					Summary: "List keys.",
				},
			},

			HelpSynopsis: "List keys.",
			HelpDescription: `This path responds to the following HTTP methods.

	LIST /configs/<config>/keys
		List keys.`,
		},

		{
			Pattern: "external-keys/configs/" + framework.GenericNameRegex("config") + "/keys/" + framework.GenericNameRegex("key"),

			Fields: map[string]*framework.FieldSchema{
				"config": {
					Type:        framework.TypeString,
					Required:    true,
					Description: "Name of the config.",
				},
				"key": {
					Type:        framework.TypeString,
					Required:    true,
					Description: "Name of the key.",
				},
				"verify": {
					Type:        framework.TypeBool,
					Default:     true,
					Description: "Verify the key against the KMS backend (default true).",
				},
			},

			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "external-keys",
				OperationSuffix: "keys",
			},

			TakesArbitraryInput: true,

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.handleExternalKeyRead,
					Responses: map[int][]framework.Response{
						http.StatusOK: {{Description: http.StatusText(http.StatusOK)}},
					},
					Summary: "Read a key.",
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.handleExternalKeyUpsert,
					Responses: map[int][]framework.Response{
						http.StatusNoContent: {{Description: http.StatusText(http.StatusNoContent)}},
					},
					Summary: "Create or update a key.",
				},
				logical.PatchOperation: &framework.PathOperation{
					Callback: b.handleExternalKeyPatch,
					Responses: map[int][]framework.Response{
						http.StatusNoContent: {{Description: http.StatusText(http.StatusNoContent)}},
					},
					Summary: "Patch a key.",
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.handleExternalKeyDelete,
					Responses: map[int][]framework.Response{
						http.StatusNoContent: {{Description: http.StatusText(http.StatusNoContent)}},
					},
					Summary: "Remove a key.",
				},
			},

			HelpSynopsis: "Manage keys.",
			HelpDescription: `This path responds to the following HTTP methods.

	GET /configs/<config>/keys/<key>
		Read a key.

	PUT /configs/<config>/keys/<key>
		Create or update a key.

	PATCH /configs/<config>/keys/<key>
		Patch a key.

	DELETE /configs/<config>/keys/<key>
		Remove a key.`,
		},

		{
			Pattern: "external-keys/configs/" + framework.GenericNameRegex("config") + "/keys/" + framework.GenericNameRegex("key") + "/grants/?",

			Fields: map[string]*framework.FieldSchema{
				"config": {
					Type:        framework.TypeString,
					Required:    true,
					Description: "Name of the config.",
				},
				"key": {
					Type:        framework.TypeString,
					Required:    true,
					Description: "Name of the key.",
				},
			},

			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "external-keys",
				OperationSuffix: "grants",
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.handleExternalKeyGrantList,
					Responses: map[int][]framework.Response{
						http.StatusOK: {{
							Description: http.StatusText(http.StatusOK),
							Fields: map[string]*framework.FieldSchema{
								"keys": {
									Type:        framework.TypeStringSlice,
									Description: "List of grant paths",
								},
							},
						}},
					},
					Summary: "List grants.",
				},
			},

			HelpSynopsis: "List grants.",
			HelpDescription: `This path responds to the following HTTP methods.

	LIST /configs/<config>/keys/<key>/grants
		List grants.`,
		},

		{
			Pattern: "external-keys/configs/" + framework.GenericNameRegex("config") + "/keys/" + framework.GenericNameRegex("key") + "/grants/(?P<mount>.+)",

			Fields: map[string]*framework.FieldSchema{
				"config": {
					Type:        framework.TypeString,
					Required:    true,
					Description: "Name of the config.",
				},
				"key": {
					Type:        framework.TypeString,
					Required:    true,
					Description: "Name of the key.",
				},
				"mount": {
					Type:        framework.TypeString,
					Required:    true,
					Description: "Path of the mount.",
				},
			},

			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "external-keys",
				OperationSuffix: "grants",
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.handleExternalKeyGrantAdd,
					Responses: map[int][]framework.Response{
						http.StatusNoContent: {{Description: http.StatusText(http.StatusNoContent)}},
					},
					Summary: "Create a grant.",
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.handleExternalKeyGrantDelete,
					Responses: map[int][]framework.Response{
						http.StatusNoContent: {{Description: http.StatusText(http.StatusNoContent)}},
					},
					Summary: "Remove a grant.",
				},
			},

			HelpSynopsis: "Manage grants.",
			HelpDescription: `This path responds to the following HTTP methods.

	PUT /configs/<config>/keys/<key>/grants/<mount>
		Create a grant.

	DELETE /configs/<config>/keys/<key>/grants/<mount>
		Remove a grant.`,
		},
	}
}

func (b *SystemBackend) handleExternalKeyConfigList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	names, err := b.Core.externalKeys.ListConfigs(ctx, req.Storage, d.Get("after").(string), d.Get("limit").(int))
	if err != nil {
		return handleError(err)
	}
	return logical.ListResponse(names), nil
}

func (b *SystemBackend) handleExternalKeyConfigRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("config").(string)
	ce, err := b.Core.externalKeys.ReadRedactedConfig(ctx, req.Storage, name)
	switch {
	case err != nil:
		return handleError(err)
	case ce == nil:
		return handleError(logical.CodedError(http.StatusNotFound, "config %q not found", name))
	}

	resp := &logical.Response{Data: ce.Values}
	resp.Data["plugin"] = ce.Plugin

	return resp, nil
}

func (b *SystemBackend) handleExternalKeyConfigUpsert(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// This must validate manually because TakesArbitraryInput breaks required
	// fields in framework.
	plugin := d.Get("plugin").(string)
	if plugin == "" {
		return handleError(errors.New(`missing required field "plugin"`))
	}

	if err := b.Core.externalKeys.ModifyConfig(
		ctx,
		req.Storage,
		d.Get("config").(string),
		d.Get("verify").(bool),
		func(ce *ek.ConfigEntry, exists bool) error {
			// Clone req.Data into values, excluding any parameters we don't
			// want to copy.
			ce.Values = make(map[string]any, max(len(req.Data)-2, 0))
			for k, v := range req.Data {
				switch k {
				case "plugin", "verify":
				default:
					ce.Values[k] = v
				}
			}

			ce.Plugin = d.Get("plugin").(string)

			return nil
		},
	); err != nil {
		return handleError(err)
	}

	return nil, nil
}

func (b *SystemBackend) handleExternalKeyConfigPatch(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// Clone req.Data into input, excluding any parameters we don't want to
	// consider for the direct merge patch.
	input := make(map[string]any, max(len(req.Data)-2, 0))
	for k, v := range req.Data {
		switch k {
		case "plugin", "verify":
		default:
			input[k] = v
		}
	}

	patch, err := json.Marshal(input)
	if err != nil {
		return handleError(err)
	}

	name := d.Get("config").(string)

	if err := b.Core.externalKeys.ModifyConfig(
		ctx,
		req.Storage,
		name,
		d.Get("verify").(bool),
		func(ce *ek.ConfigEntry, exists bool) error {
			if !exists {
				return logical.CodedError(http.StatusNotFound, "config %q not found", name)
			}

			source, err := json.Marshal(ce.Values)
			if err != nil {
				return err
			}
			result, err := jsonpatch.MergePatch(source, patch)
			if err != nil {
				return err
			}

			// Clear these out so json.Unmarshal doesn't add on top of previous
			// data but replaces fully.
			ce.Values = nil

			if err := json.Unmarshal(result, &ce.Values); err != nil {
				return err
			}

			// Update the actual plugin field separately.
			if plugin := d.Get("plugin").(string); plugin != "" && plugin != ce.Plugin {
				ce.Plugin = plugin
			}

			return nil
		},
	); err != nil {
		return handleError(err)
	}

	return nil, nil
}

func (b *SystemBackend) handleExternalKeyConfigDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if err := b.Core.externalKeys.DeleteConfig(ctx, req.Storage, d.Get("config").(string)); err != nil {
		return handleError(err)
	}
	return nil, nil
}

func (b *SystemBackend) handleExternalKeyList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	names, err := b.Core.externalKeys.ListKeys(ctx, req.Storage, d.Get("config").(string), d.Get("after").(string), d.Get("limit").(int))
	if err != nil {
		return handleError(err)
	}
	return logical.ListResponse(names), nil
}

func (b *SystemBackend) handleExternalKeyRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("key").(string)
	ke, err := b.Core.externalKeys.ReadRedactedKey(ctx, req.Storage, d.Get("config").(string), name)
	switch {
	case err != nil:
		return handleError(err)
	case ke == nil:
		return handleError(logical.CodedError(http.StatusNotFound, "key %q not found", name))
	}

	return &logical.Response{Data: ke.Values}, nil
}

func (b *SystemBackend) handleExternalKeyUpsert(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if err := b.Core.externalKeys.ModifyKey(
		ctx,
		req.Storage,
		d.Get("config").(string), d.Get("key").(string),
		d.Get("verify").(bool),
		func(ke *ek.KeyEntry, exists bool) error {
			// Clone req.Data into values, excluding any parameters we don't
			// want to copy.
			ke.Values = make(map[string]any, max(len(req.Data)-1, 0))
			for k, v := range req.Data {
				switch k {
				case "verify":
				default:
					ke.Values[k] = v
				}
			}

			return nil
		},
	); err != nil {
		return handleError(err)
	}

	return nil, nil
}

func (b *SystemBackend) handleExternalKeyPatch(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// Clone req.Data into input, excluding any parameters we don't want to
	// consider for the direct merge patch.
	input := make(map[string]any, max(len(req.Data)-1, 0))
	for k, v := range req.Data {
		switch k {
		case "verify":
		default:
			input[k] = v
		}
	}

	patch, err := json.Marshal(input)
	if err != nil {
		return handleError(err)
	}

	name := d.Get("key").(string)

	if err := b.Core.externalKeys.ModifyKey(
		ctx,
		req.Storage,
		d.Get("config").(string), name,
		d.Get("verify").(bool),
		func(ke *ek.KeyEntry, exists bool) error {
			if !exists {
				return logical.CodedError(http.StatusNotFound, "key %q not found", name)
			}

			source, err := json.Marshal(ke.Values)
			if err != nil {
				return err
			}
			result, err := jsonpatch.MergePatch(source, patch)
			if err != nil {
				return err
			}

			// Clear these out so json.Unmarshal doesn't add on top of previous
			// data but replaces fully.
			ke.Values = nil

			return json.Unmarshal(result, &ke.Values)
		},
	); err != nil {
		return handleError(err)
	}

	return nil, nil
}

func (b *SystemBackend) handleExternalKeyDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if err := b.Core.externalKeys.DeleteKey(ctx, req.Storage, d.Get("config").(string), d.Get("key").(string)); err != nil {
		return handleError(err)
	}
	return nil, nil
}

func (b *SystemBackend) handleExternalKeyGrantList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("key").(string)
	ke, err := b.Core.externalKeys.ReadKey(ctx, req.Storage, d.Get("config").(string), name)
	switch {
	case err != nil:
		return handleError(err)
	case ke == nil:
		return handleError(logical.CodedError(http.StatusNotFound, "key %q not found", name))
	}

	keys := slices.Collect(maps.Keys(ke.Grants))
	// It's worth sorting the slice since it was derived from a map which has
	// random key ordering.
	slices.Sort(keys)

	return logical.ListResponse(keys), nil
}

func (b *SystemBackend) handleExternalKeyGrantAdd(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("key").(string)

	if err := b.Core.externalKeys.ModifyKey(
		ctx,
		req.Storage,
		d.Get("config").(string), name,
		false, // No need to verify on grant changes.
		func(ke *ek.KeyEntry, exists bool) error {
			if !exists {
				return logical.CodedError(http.StatusNotFound, "key %q not found", name)
			}

			// Normalize the mount path.
			mount := d.Get("mount").(string)
			if !strings.HasSuffix(mount, "/") {
				mount += "/"
			}

			if ke.Grants == nil {
				ke.Grants = make(map[string]struct{}, 1)
			}

			// Add the grant, no matter if it already existed.
			ke.Grants[mount] = struct{}{}

			return nil
		},
	); err != nil {
		return handleError(err)
	}

	return nil, nil
}

func (b *SystemBackend) handleExternalKeyGrantDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("key").(string)

	if err := b.Core.externalKeys.ModifyKey(
		ctx,
		req.Storage,
		d.Get("config").(string), name,
		false, // No need to verify on grant changes.
		func(ke *ek.KeyEntry, exists bool) error {
			if !exists {
				return logical.CodedError(http.StatusNotFound, "key %q not found", name)
			}

			// Normalize the mount path.
			mount := d.Get("mount").(string)
			if !strings.HasSuffix(mount, "/") {
				mount += "/"
			}

			// Remove the grant, no matter if it existed.
			delete(ke.Grants, mount)

			return nil
		},
	); err != nil {
		return handleError(err)
	}

	return nil, nil
}
