// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

type namespaceExtractor func(ctx context.Context, data *framework.FieldData) (*namespace.Namespace, error)

var namespaceFieldSchema = framework.FieldSchema{
	Type:        framework.TypeString,
	Required:    true,
	Description: "Name of the namespace.",
}

func (b *SystemBackend) namespaceRotatePaths() []*framework.Path {
	return []*framework.Path{
		{
			// "/rotate" equivalent to "/rotate/keyring"
			Pattern: "namespaces/(?P<namespace>.+)/rotate(/keyring)?",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "namespaces",
				OperationVerb:   "rotate",
				OperationSuffix: "encryption-key",
			},
			Fields: map[string]*framework.FieldSchema{
				"namespace": &namespaceFieldSchema,
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.handleNamespacesRotate(),
					Summary:  "Rotate the namespace encryption key.",
					Responses: map[int][]framework.Response{
						http.StatusNoContent: {{
							Description: http.StatusText(http.StatusNoContent),
						}},
					},
				},
			},

			HelpSynopsis:    strings.TrimSpace(sysNamespacesRotateHelp["namespaces-rotate-keyring"][0]),
			HelpDescription: strings.TrimSpace(sysNamespacesRotateHelp["namespaces-rotate-keyring"][1]),
		},
		{
			// "/rotate/config" equivalent to "/rotate/keyring/config"
			Pattern: "namespaces/(?P<namespace>.+)/rotate/(keyring/)?config",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "namespaces",
				OperationSuffix: "encryption-key",
			},
			Fields: rotateConfigSchema,

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.handleRotationConfigRead(b.parseNamespaceFromRequest),
					Summary:  "Get the namespace automatic key rotation config.",
					DisplayAttrs: &framework.DisplayAttributes{
						OperationPrefix: "namespaces",
						OperationVerb:   "read",
						OperationSuffix: "rotation-config",
					},
					Responses: map[int][]framework.Response{
						http.StatusOK: {{
							Description: http.StatusText(http.StatusOK),
							Fields:      rotateConfigSchema,
						}},
					},
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.handleRotationConfigUpdate(b.parseNamespaceFromRequest),
					Summary:  "Configure the namespace automatic key rotation.",
					DisplayAttrs: &framework.DisplayAttributes{
						OperationPrefix: "namespaces",
						OperationVerb:   "configure",
						OperationSuffix: "rotation-config",
					},
					Responses: map[int][]framework.Response{
						http.StatusNoContent: {{
							Description: http.StatusText(http.StatusNoContent),
						}},
					},
				},
			},

			HelpSynopsis:    strings.TrimSpace(sysNamespacesRotateHelp["namespaces-rotate-keyring-config"][0]),
			HelpDescription: strings.TrimSpace(sysNamespacesRotateHelp["namespaces-rotate-keyring-config"][1]),
		},
		{
			Pattern: "namespaces/(?P<namespace>.+)/rotate/(root|recovery)/init",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "namespaces",
				OperationVerb:   "initialize",
				OperationSuffix: "rotate-attempt",
			},
			Fields: map[string]*framework.FieldSchema{
				"namespace":            &namespaceFieldSchema,
				"secret_shares":        rotateInitRequestSchema["secret_shares"],
				"secret_threshold":     rotateInitRequestSchema["secret_threshold"],
				"pgp_keys":             rotateInitRequestSchema["pgp_keys"],
				"backup":               rotateInitRequestSchema["backup"],
				"require_verification": rotateInitRequestSchema["require_verification"],
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.handleRotateInitGet(b.parseNamespaceFromRequest),
					DisplayAttrs: &framework.DisplayAttributes{
						OperationPrefix: "namespaces",
						OperationVerb:   "read",
						OperationSuffix: "progress",
					},
					Responses: map[int][]framework.Response{
						http.StatusOK: {{
							Description: http.StatusText(http.StatusOK),
							Fields:      rotateInitGetResponseSchema,
						}},
					},
					Summary: "Reads the configuration and progress of the current root or recovery rotate attempt for a namespace.",
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.handleRotateInitPut(b.parseNamespaceFromRequest),
					DisplayAttrs: &framework.DisplayAttributes{
						OperationPrefix: "namespaces",
						OperationVerb:   "initialize",
						OperationSuffix: "rotate-attempt",
					},
					Responses: map[int][]framework.Response{
						http.StatusOK: {{
							Description: http.StatusText(http.StatusOK),
							Fields:      rotateInitPutResponseSchema,
						}},
					},
					Summary:     "Initializes a new root or recovery rotate attempt for a namespace.",
					Description: "Only a single rotate attempt can take place at a time, and changing the parameters of a rotation requires canceling and starting a new rotation, which will also provide a new nonce.",
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.handleRotateInitDelete(b.parseNamespaceFromRequest),
					DisplayAttrs: &framework.DisplayAttributes{
						OperationVerb:   "cancel",
						OperationSuffix: "rotate-attempt",
					},
					Responses: map[int][]framework.Response{
						http.StatusNoContent: {{
							Description: http.StatusText(http.StatusNoContent),
						}},
					},
					Summary:     "Cancel any in-progress rotate root or recovery operation for a namespace.",
					Description: "This clears the rotate settings as well as any progress made. This must be called to change the parameters of the rotate. Note: verification is still a part of a rotate. If rotating is canceled during the verification flow, the current unseal keys remain valid.",
				},
			},

			HelpSynopsis:    strings.TrimSpace(sysHelp["namespaces-rotate-init"][0]),
			HelpDescription: strings.TrimSpace(sysHelp["namespaces-rotate-init"][1]),
		},
		{
			Pattern: "namespaces/(?P<namespace>.+)/rotate/(root|recovery)/update",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "namespaces",
				OperationVerb:   "update",
				OperationSuffix: "rotate-attempt",
			},
			Fields: map[string]*framework.FieldSchema{
				"namespace": &namespaceFieldSchema,
				"key": {
					Type:        framework.TypeString,
					Required:    true,
					Description: "Specifies a single unseal key share.",
				},
				"nonce": {
					Type:        framework.TypeString,
					Required:    true,
					Description: "Specifies the nonce of the rotation attempt.",
				},
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.handleRotateUpdate(b.parseNamespaceFromRequest),
					DisplayAttrs: &framework.DisplayAttributes{
						OperationPrefix: "namespaces",
						OperationVerb:   "update",
						OperationSuffix: "rotate-attempt",
					},
					Responses: map[int][]framework.Response{
						http.StatusOK: {{
							Description: http.StatusText(http.StatusOK),
							Fields:      rotateUpdateResponseSchema,
						}},
					},
					Summary: "Enter a single unseal key share to progress the rotation of the namespace key.",
				},
			},

			HelpSynopsis:    strings.TrimSpace(sysHelp["namespaces-rotate-update"][0]),
			HelpDescription: strings.TrimSpace(sysHelp["namespaces-rotate-update"][1]),
		},
		{
			Pattern: "namespaces/(?P<namespace>.+)/rotate/(root|recovery)/verify",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "namespace",
				OperationVerb:   "verify",
				OperationSuffix: "rotation-attempt",
			},

			Fields: map[string]*framework.FieldSchema{
				"namespace": &namespaceFieldSchema,
				"key": {
					Type:        framework.TypeString,
					Description: "Specifies a single unseal share key from the new set of shares.",
				},
				"nonce": {
					Type:        framework.TypeString,
					Description: "Specifies the nonce of the rotation verification operation.",
				},
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					DisplayAttrs: &framework.DisplayAttributes{
						OperationPrefix: "namespaces",
						OperationVerb:   "read",
						OperationSuffix: "verification-attempt",
					},
					Callback: b.handleRotateVerifyGet(b.parseNamespaceFromRequest),
					Responses: map[int][]framework.Response{
						http.StatusOK: {{
							Description: http.StatusText(http.StatusOK),
							Fields:      rotateVerifyResponseSchema,
						}},
					},
					Summary: "Read the configuration and progress of the current rotate verification attempt for a namespace.",
				},
				logical.UpdateOperation: &framework.PathOperation{
					DisplayAttrs: &framework.DisplayAttributes{
						OperationPrefix: "namespace",
						OperationVerb:   "update",
						OperationSuffix: "verification-attempt",
					},
					Callback: b.handleRotateVerifyPut(b.parseNamespaceFromRequest),
					Responses: map[int][]framework.Response{
						http.StatusOK: {{
							Description: http.StatusText(http.StatusOK),
							Fields:      rotateVerifyResponseSchema,
						}},
					},
					Summary: "Enter a single new key share to progress the rotation verification operation for a namespace.",
				},
				logical.DeleteOperation: &framework.PathOperation{
					DisplayAttrs: &framework.DisplayAttributes{
						OperationPrefix: "namespace",
						OperationVerb:   "cancel",
						OperationSuffix: "verification-attempt",
					},
					Callback: b.handleRotateVerifyDelete(b.parseNamespaceFromRequest),
					Responses: map[int][]framework.Response{
						http.StatusOK: {{
							Description: http.StatusText(http.StatusOK),
							Fields:      rotateVerifyResponseSchema,
						}},
					},
					Summary:     "Cancel any in-progress rotate verification operation for a namespace.",
					Description: "This clears any progress made and resets the nonce. Unlike a `DELETE` against `sys/rotate/(root/recovery)/init`, this only resets the current verification operation, not the entire rotate atttempt.",
				},
			},

			HelpSynopsis:    strings.TrimSpace(sysRotateHelp["namespaces-rotate-verify"][0]),
			HelpDescription: strings.TrimSpace(sysRotateHelp["namespaces-rotate-verify"][0]),
		},
		{
			Pattern: "namespaces/(?P<namespace>.+)/rotate/(root|recovery)/backup",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "namespaces",
				OperationVerb:   "backup",
				OperationSuffix: "unseal-keys",
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.handleRotateBackupRetrieve(b.parseNamespaceFromRequest),
					DisplayAttrs: &framework.DisplayAttributes{
						OperationPrefix: "namespaces",
						OperationVerb:   "read",
						OperationSuffix: "backup-key",
					},
					Responses: map[int][]framework.Response{
						http.StatusOK: {{
							Description: http.StatusText(http.StatusOK),
							Fields:      rotateBackupResponseSchema,
						}},
					},
					Summary: "Return the backup copy of PGP-encrypted unseal keys for a namespace.",
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.handleRotateBackupDelete(b.parseNamespaceFromRequest),
					DisplayAttrs: &framework.DisplayAttributes{
						OperationPrefix: "namespaces",
						OperationVerb:   "delete",
						OperationSuffix: "backup-key",
					},
					Responses: map[int][]framework.Response{
						http.StatusNoContent: {{
							Description: http.StatusText(http.StatusNoContent),
						}},
					},
					Summary: "Delete the backup copy of PGP-encrypted unseal keys for a namespace.",
				},
			},

			HelpSynopsis:    strings.TrimSpace(sysRotateHelp["namespaces-rotate-backup"][0]),
			HelpDescription: strings.TrimSpace(sysRotateHelp["namespaces-rotate-backup"][0]),
		},
	}
}

// parseNamespaceFromRequest satisfies namespaceExtractor signature, parsing
// `namespace` from path, verifing if it exists and returning.
func (b *SystemBackend) parseNamespaceFromRequest(ctx context.Context, data *framework.FieldData) (*namespace.Namespace, error) {
	nsName := namespace.Canonicalize(data.Get("namespace").(string))
	if len(nsName) > 0 && strings.Contains(nsName[:len(nsName)-1], "/") {
		return nil, errors.New("namespace name must not contain /")
	}

	ns, err := b.Core.namespaceStore.GetNamespaceByPath(ctx, nsName)
	if err != nil {
		return nil, err
	}

	if ns == nil {
		return nil, fmt.Errorf("namespace %q doesn't exist", nsName)
	}

	return ns, nil
}

// handleNamespacesRotate handles the `/sys/namespaces/<namespace>/rotate` and
// `/sys/namespaces/<namespace>/rotate/keyring` endpoints to rotate the namespace
// encryption key.
func (b *SystemBackend) handleNamespacesRotate() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		ns, err := b.parseNamespaceFromRequest(ctx, data)
		if err != nil {
			return handleError(err)
		}

		if err := b.Core.sealManager.RotateNamespaceBarrierKey(ctx, ns); err != nil {
			return handleError(err)
		}

		return nil, nil
	}
}

var sysNamespacesRotateHelp = map[string][2]string{
	"namespaces-rotate-keyring": {
		`Rotates the backend encryption key used to persist data for this
		namespace.
		`,
		`
		Rotate generates a new encryption key which is used to encrypt all
		data of this namespace going to the storage backend. The old
		encryption keys are kept so that data encrypted using those keys
		can still be decrypted.
		`,
	},

	"namespaces-rotate-keyring-config": {
		`Configures settings related to the namespace encryption key 
		management.
		`,
		`
		Configures settings related to the automatic rotation of the 
		namespace encryption key.
		`,
	},

	"namespaces-rotate-init": {
		`Initialize, read status or cancel the process of the rotation of
		the root or recovery key of a namespace.
		`,
		"",
	},

	"namespaces-rotate-update": {
		`Progress the rotation process of a namespace by providing a single
		key share.
		`,
		`This endpoint is used to enter a single key share to progress the
		rotation of the recovery or root key. If the threshold number of key
		shares is reached, rotation will be completed. Otherwise, this API
		must be called multiple times until that threshold is met.
		The rotation nonce operation must be provided with each call.
		On the final call, any new key shares will be returned immediately.
		`,
	},

	"rotate-verify": {
		`Read status of, progress or cancel the verification process of the
		rotation attempt of a namespace.
		`,
		"",
	},

	"rotate-backup": {
		`Allows fetching or deleting the backup of the rotated unseal keys 
		for a namespace.
		`,
		"",
	},
}
