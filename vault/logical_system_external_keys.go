// Copyright The OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"net/http"
	"strings"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func (b *SystemBackend) externalKeyPaths() []*framework.Path {
	fieldConfig := &framework.FieldSchema{
		Type:        framework.TypeString,
		Required:    true,
		Description: "Name of the config.",
	}

	fieldKey := &framework.FieldSchema{
		Type:        framework.TypeString,
		Required:    true,
		Description: "Name of the key.",
	}

	fieldMount := &framework.FieldSchema{
		Type:        framework.TypeString,
		Required:    true,
		Description: "Path of the mount.",
	}

	return []*framework.Path{
		{
			Pattern: "external-keys/configs/?",

			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "external-keys",
				OperationSuffix: "configs",
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.Core.externalKeys.ListConfigs,
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

			HelpSynopsis:    "List configs.",
			HelpDescription: strings.TrimSpace(sysExternalKeysHelp["list-configs"]),
		},

		{
			Pattern: "external-keys/configs/" + framework.GenericNameRegex("config"),

			Fields: map[string]*framework.FieldSchema{
				"config": fieldConfig,
			},

			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "external-keys",
				OperationSuffix: "configs",
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.Core.externalKeys.GetConfig,
					Responses: map[int][]framework.Response{
						http.StatusOK: {{Description: http.StatusText(http.StatusOK)}},
					},
					Summary: "Read a config.",
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.Core.externalKeys.PutConfig,
					Responses: map[int][]framework.Response{
						http.StatusNoContent: {{Description: http.StatusText(http.StatusNoContent)}},
					},
					Summary: "Create or overwrite a config.",
				},
				logical.PatchOperation: &framework.PathOperation{
					Callback: b.Core.externalKeys.PatchConfig,
					Responses: map[int][]framework.Response{
						http.StatusNoContent: {{Description: http.StatusText(http.StatusNoContent)}},
					},
					Summary: "Patch a config.",
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.Core.externalKeys.DeleteConfig,
					Responses: map[int][]framework.Response{
						http.StatusNoContent: {{Description: http.StatusText(http.StatusNoContent)}},
					},
					Summary: "Remove a config.",
				},
			},

			HelpSynopsis:    "Manage configs.",
			HelpDescription: strings.TrimSpace(sysExternalKeysHelp["manage-configs"]),
		},

		{
			Pattern: "external-keys/configs/" + framework.GenericNameRegex("config") + "/keys/?",

			Fields: map[string]*framework.FieldSchema{
				"config": fieldConfig,
			},

			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "external-keys",
				OperationSuffix: "keys",
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.Core.externalKeys.ListKeys,
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

			HelpSynopsis:    "List keys.",
			HelpDescription: strings.TrimSpace(sysExternalKeysHelp["list-keys"]),
		},

		{
			Pattern: "external-keys/configs/" + framework.GenericNameRegex("config") +
				"/keys/" + framework.GenericNameRegex("key"),

			Fields: map[string]*framework.FieldSchema{
				"config": fieldConfig, "key": fieldKey,
			},

			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "external-keys",
				OperationSuffix: "keys",
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.Core.externalKeys.GetKey,
					Responses: map[int][]framework.Response{
						http.StatusOK: {{Description: http.StatusText(http.StatusOK)}},
					},
					Summary: "Read a key.",
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.Core.externalKeys.PutKey,
					Responses: map[int][]framework.Response{
						http.StatusNoContent: {{Description: http.StatusText(http.StatusNoContent)}},
					},
					Summary: "Create or overwrite a key.",
				},
				logical.PatchOperation: &framework.PathOperation{
					Callback: b.Core.externalKeys.PatchKey,
					Responses: map[int][]framework.Response{
						http.StatusNoContent: {{Description: http.StatusText(http.StatusNoContent)}},
					},
					Summary: "Update a key.",
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.Core.externalKeys.DeleteKey,
					Responses: map[int][]framework.Response{
						http.StatusNoContent: {{Description: http.StatusText(http.StatusNoContent)}},
					},
					Summary: "Remove a key.",
				},
			},

			HelpSynopsis:    "Manage keys.",
			HelpDescription: strings.TrimSpace(sysExternalKeysHelp["manage-keys"]),
		},

		{
			Pattern: "external-keys/configs/" + framework.GenericNameRegex("config") +
				"/keys/" + framework.GenericNameRegex("key") + "/grants/?",

			Fields: map[string]*framework.FieldSchema{
				"config": fieldConfig, "key": fieldKey,
			},

			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "external-keys",
				OperationSuffix: "grants",
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.Core.externalKeys.ListGrants,
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

			HelpSynopsis:    "List grants.",
			HelpDescription: strings.TrimSpace(sysExternalKeysHelp["list-grants"]),
		},

		{
			Pattern: "external-keys/configs/" + framework.GenericNameRegex("config") +
				"/keys/" + framework.GenericNameRegex("key") + "/grants/(?P<mount>.+)",

			Fields: map[string]*framework.FieldSchema{
				"config": fieldConfig, "key": fieldKey, "mount": fieldMount,
			},

			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "external-keys",
				OperationSuffix: "grants",
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.Core.externalKeys.PutGrant,
					Responses: map[int][]framework.Response{
						http.StatusNoContent: {{Description: http.StatusText(http.StatusNoContent)}},
					},
					Summary: "Create a grant.",
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.Core.externalKeys.DeleteGrant,
					Responses: map[int][]framework.Response{
						http.StatusNoContent: {{Description: http.StatusText(http.StatusNoContent)}},
					},
					Summary: "Remove a grant.",
				},
			},

			HelpSynopsis:    "Manage grants.",
			HelpDescription: strings.TrimSpace(sysExternalKeysHelp["manage-grants"]),
		},
	}
}

var sysExternalKeysHelp = map[string]string{
	"list-configs": `
This path responds to the following HTTP methods.

	LIST /configs
		List configs.
`,
	"manage-configs": `
This path responds to the following HTTP methods.

	GET /configs/<config>
		Read a config.

	PUT /configs/<config>
		Create or overwrite a config.

	PATCH /configs/<config>
		Patch a config.

	DELETE /configs/<config>
		Remove a config.
`,
	"list-keys": `
This path responds to the following HTTP methods.

	LIST /configs/<config>/keys
		List keys.
`,
	"manage-keys": `
This path responds to the following HTTP methods.

	GET /configs/<config>/keys/<key>
		Read a key.

	PUT /configs/<config>/keys/<key>
		Create or overwrite a key.

	PATCH /configs/<config>/keys/<key>
		Patch a key.

	DELETE /configs/<config>/keys/<key>
		Remove a key.
`,
	"list-grants": `
This path responds to the following HTTP methods.

	LIST /configs/<config>/keys/<key>/grants
		List grants.
`,
	"manage-grants": `
This path responds to the following HTTP methods.

	PUT /configs/<config>/keys/<key>/grants/<mount>
		Create a grant.

	DELETE /configs/<config>/keys/<key>/grants/<mount>
		Remove a grant.
`,
}
