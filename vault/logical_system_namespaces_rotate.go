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

	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/helper/pgpkeys"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/helper/shamir"
	"github.com/openbao/openbao/sdk/v2/logical"
)

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
				"namespace": {
					Type:        framework.TypeString,
					Required:    true,
					Description: "Name of the namespace.",
				},
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

			HelpSynopsis:    strings.TrimSpace(sysNamespacesRotateHelp["namespaces-rotate"][0]),
			HelpDescription: strings.TrimSpace(sysNamespacesRotateHelp["namespaces-rotate"][1]),
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
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.handleNamespacesUpdateRotateConfig(),
					Summary:  "Configure automatic key rotation.",
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
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.handleNamespacesGetRotateConfig(),
					Summary:  "Get the automatic key rotation config.",
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
			},

			HelpSynopsis:    strings.TrimSpace(sysNamespacesRotateHelp["namespaces-rotate-config"][0]),
			HelpDescription: strings.TrimSpace(sysNamespacesRotateHelp["namespaces-rotate-config"][1]),
		},
		{
			Pattern: "namespaces/(?P<namespace>.+)/rotate/(root|recovery)/init",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "namespaces",
				OperationVerb:   "rotate-attempt",
			},
			Fields: rotateInitRequestSchema,

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.handleNamespacesRotateInitGet(),
					DisplayAttrs: &framework.DisplayAttributes{
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
					Callback: b.handleNamespacesRotateInitPut(),
					DisplayAttrs: &framework.DisplayAttributes{
						OperationVerb: "initialize",
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
					Callback: b.handleNamespacesRotateInitDelete(),
					DisplayAttrs: &framework.DisplayAttributes{
						OperationVerb: "cancel",
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

			// TODO:
			HelpSynopsis:    strings.TrimSpace(sysHelp["namespaces-rotate-attempt"][0]),
			HelpDescription: strings.TrimSpace(sysHelp["namespaces-rotate-attempt"][1]),
		},
		{
			Pattern: "namespaces/(?P<namespace>.+)/rotate/(root|recovery)/update",
			Fields: map[string]*framework.FieldSchema{
				"namespace": {
					Type:        framework.TypeString,
					Required:    true,
					Description: "Name of the namespace.",
				},
				"key": {
					Type:        framework.TypeString,
					Description: "Specifies a single unseal key share.",
					Required:    true,
				},
				"nonce": {
					Type:        framework.TypeString,
					Description: "Specifies the nonce of the rotation attempt.",
					Required:    true,
				},
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.handleNamespacesRotateUpdate(),
					DisplayAttrs: &framework.DisplayAttributes{
						OperationPrefix: "rotate-attempt",
						OperationVerb:   "update",
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

			// todo:
			HelpSynopsis:    strings.TrimSpace(sysHelp["namespaces-rotate-update"][0]),
			HelpDescription: strings.TrimSpace(sysHelp["namespaces-rotate-update"][1]),
		},
	}
}

// parseNamespaceFromRequest parses `namespace` from path, verifies if a namespace
// with that path exists and returns it.
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

// handleNamespacesGetRotateConfig handles the GET `/sys/namespaces/<namespace>/rotate/config`,
// and `/sys/namespaces/<namespace>/rotate/keyring/config` endpoints to read the
// automatic key rotation config.
func (b *SystemBackend) handleNamespacesGetRotateConfig() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		ns, err := b.parseNamespaceFromRequest(ctx, data)
		if err != nil {
			return handleError(err)
		}

		barrier := b.Core.sealManager.NamespaceBarrier(ns.Path)
		if barrier == nil {
			return handleError(ErrNotSealable)
		}

		rotConfig, err := barrier.RotationConfig()
		if err != nil {
			return handleError(err)
		}

		nsPath := ns.Path
		if ns.ID == namespace.RootNamespaceID {
			nsPath = "root"
		}

		resp := &logical.Response{
			Data: map[string]any{
				"namespace":      nsPath,
				"max_operations": rotConfig.MaxOperations,
				"enabled":        !rotConfig.Disabled,
			},
		}

		if rotConfig.Interval > 0 {
			resp.Data["interval"] = rotConfig.Interval.String()
		} else {
			resp.Data["interval"] = 0
		}
		return resp, nil
	}
}

// handleNamespacesUpdateRotateConfig handles the POST `/sys/namespaces/<namespace>/rotate/config` and
// `/sys/namespaces/<namespace>/rotate/keyring/config` endpoints to update the automatic key rotation config.
func (b *SystemBackend) handleNamespacesUpdateRotateConfig() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		ns, err := b.parseNamespaceFromRequest(ctx, data)
		if err != nil {
			return handleError(err)
		}

		barrier := b.Core.sealManager.NamespaceBarrier(ns.Path)
		if barrier == nil {
			return handleError(ErrNotSealable)
		}

		rotConfig, err := barrier.RotationConfig()
		if err != nil {
			return handleError(err)
		}

		maxOps, ok, err := data.GetOkErr("max_operations")
		if err != nil {
			return handleError(err)
		}
		if ok {
			rotConfig.MaxOperations = maxOps.(int64)
		}

		interval, ok, err := data.GetOkErr("interval")
		if err != nil {
			return handleError(err)
		}
		if ok {
			rotConfig.Interval, err = parseutil.ParseDurationSecond(interval)
			if err != nil {
				return handleError(err)
			}
		}

		enabled, ok, err := data.GetOkErr("enabled")
		if err != nil {
			return handleError(err)
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
		if err = barrier.SetRotationConfig(ctx, rotConfig); err != nil {
			return handleError(err)
		}

		return nil, nil
	}
}

// handleNamespacesRotateInitGet handles the GET `/sys/namespaces/<namespace>/rotate/root/init`
// and `/sys/namespaces/<namespace>/rotate/recovery/init` endpoints to read rotation attempt status
// for a namespace.
func (b *SystemBackend) handleNamespacesRotateInitGet() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		ns, err := b.parseNamespaceFromRequest(ctx, data)
		if err != nil {
			return handleError(err)
		}

		recovery := strings.Contains(req.Path, "recovery")
		sealThreshold, err := b.Core.sealManager.RotationThreshold(ctx, ns, recovery)
		if err != nil {
			return handleError(err)
		}

		resp := &logical.Response{
			Data: map[string]interface{}{
				"namespace":      ns.Path,
				"started":        false,
				"t":              0,
				"n":              0,
				"seal_threshold": sealThreshold,
			},
		}

		rotationConfig := b.Core.sealManager.RotationConfig(ns, recovery)
		if rotationConfig != nil {
			config := rotationConfig.Clone()
			started, progress, err := b.Core.sealManager.RotationProgress(ns, recovery, false)
			if err != nil {
				return handleError(err)
			}

			resp.Data["nonce"] = config.Nonce
			resp.Data["started"] = started
			resp.Data["t"] = config.SecretThreshold
			resp.Data["n"] = config.SecretShares
			resp.Data["progress"] = progress
			resp.Data["verification_required"] = config.VerificationRequired
			resp.Data["verification_nonce"] = config.VerificationNonce
			if len(config.PGPKeys) != 0 {
				pgpFingerprints, err := pgpkeys.GetFingerprints(config.PGPKeys, nil)
				if err != nil {
					return handleError(err)
				}
				resp.Data["pgp_fingerprints"] = pgpFingerprints
				resp.Data["backup"] = config.Backup
			}
		}
		return resp, nil
	}
}

// handleNamespacesRotateInitPut handles the POST "/sys/namespaces/<namespace>/root/init" and
// "/sys/namespaces/<namespace>/recovery/init" endpoints to initialize root or recovery rotation
// attempt of a namespace.
func (b *SystemBackend) handleNamespacesRotateInitPut() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		ns, err := b.parseNamespaceFromRequest(ctx, data)
		if err != nil {
			return handleError(err)
		}

		rotateConf := &SealConfig{}
		secretShares, ok, err := data.GetOkErr("secret_shares")
		if err != nil {
			return handleError(err)
		}
		if ok {
			rotateConf.SecretShares = secretShares.(int)
		}

		secretThreshold, ok, err := data.GetOkErr("secret_threshold")
		if err != nil {
			return handleError(err)
		}
		if ok {
			rotateConf.SecretThreshold = secretThreshold.(int)
		}

		pgpKeys, ok, err := data.GetOkErr("pgp_keys")
		if err != nil {
			return handleError(err)
		}
		if ok {
			rotateConf.PGPKeys = pgpKeys.([]string)
		}

		backup, ok, err := data.GetOkErr("backup")
		if err != nil {
			return handleError(err)
		}
		if ok {
			rotateConf.Backup = backup.(bool)
		}

		verificationReq, ok, err := data.GetOkErr("require_verification")
		if err != nil {
			return handleError(err)
		}
		if ok {
			rotateConf.VerificationRequired = verificationReq.(bool)
		}

		recovery := strings.Contains(req.Path, "recovery")
		result, err := b.Core.sealManager.InitRotation(ctx, ns, rotateConf, recovery)
		if err != nil {
			return handleError(err)
		}

		// this can only happen in case of autoseal recovery rotation
		// due to keys not existing before, as the instance was initialized
		// with recovery config secret shares set to 0
		if result != nil {
			keys := make([]string, 0, len(result.SecretShares))
			keysB64 := make([]string, 0, len(result.SecretShares))
			for _, k := range result.SecretShares {
				keys = append(keys, hex.EncodeToString(k))
				keysB64 = append(keysB64, base64.StdEncoding.EncodeToString(k))
			}
			return &logical.Response{
				Data: map[string]interface{}{
					"namespace":             ns.Path,
					"complete":              true,
					"backup":                result.Backup,
					"pgp_fingerprints":      result.PGPFingerprints,
					"verification_required": result.VerificationRequired,
					"verification_nonce":    result.VerificationNonce,
					"keys":                  keys,
					"keys_base64":           keysB64,
				},
			}, nil
		}

		return b.handleNamespacesRotateInitGet()(ctx, req, data)
	}
}

// handleNamespacesRotateInitDelete handles the DELETE `/sys/namespaces/rotate/root/init` and
// `/sys/namespaces/rotate/recovery/init` endpoints cancelling any in-progress rotation
// operations for a namespace.
func (b *SystemBackend) handleNamespacesRotateInitDelete() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		ns, err := b.parseNamespaceFromRequest(ctx, data)
		if err != nil {
			return handleError(err)
		}

		recovery := strings.Contains(req.Path, "recovery")
		if err := b.Core.sealManager.CancelRotation(ns, recovery); err != nil {
			return handleError(err)
		}
		return nil, nil
	}
}

// handleNamespacesRotateUpdate handles the POST `/sys/rotate/root/update` and
// `/sys/rotate/recovery/update` endpoints used for providing a single key share
// progressing the rotation of the root or recovery key of a namespace.
func (b *SystemBackend) handleNamespacesRotateUpdate() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		ns, err := b.parseNamespaceFromRequest(ctx, data)
		if err != nil {
			return handleError(err)
		}

		ikey, ok, err := data.GetOkErr("key")
		if err != nil {
			return handleError(err)
		}
		if !ok || ikey.(string) == "" {
			return handleError(errors.New("missing required field 'key'"))
		}
		reqKey := ikey.(string)

		inonce, ok, err := data.GetOkErr("nonce")
		if err != nil {
			return handleError(err)
		}
		if !ok || inonce.(string) == "" {
			return handleError(errors.New("missing required field 'nonce'"))
		}
		reqNonce := inonce.(string)

		// We check min and max here to ensure that a string that is base64 encoded
		// but also valid hex will not be valid and we instead base64 decode it
		min, max := b.Core.BarrierKeyLength()
		max += shamir.ShareOverhead
		key, err := hex.DecodeString(reqKey)
		if err != nil || len(key) < min || len(key) > max {
			key, err = base64.StdEncoding.DecodeString(reqKey)
			if err != nil {
				return handleError(errors.New("'key' must be a valid hex or base64 string"))
			}
		}

		// Use the key to make progress on rotation
		recovery := strings.Contains(req.Path, "recovery")
		result, err := b.Core.sealManager.UpdateRotation(ctx, ns, key, reqNonce, recovery)
		if err != nil {
			return handleError(err)
		}

		if result != nil {
			keys := make([]string, 0, len(result.SecretShares))
			keysB64 := make([]string, 0, len(result.SecretShares))
			for _, k := range result.SecretShares {
				keys = append(keys, hex.EncodeToString(k))
				keysB64 = append(keysB64, base64.StdEncoding.EncodeToString(k))
			}
			return &logical.Response{
				Data: map[string]interface{}{
					"namespace":             ns.Path,
					"complete":              true,
					"nonce":                 reqNonce,
					"backup":                result.Backup,
					"pgp_fingerprints":      result.PGPFingerprints,
					"verification_required": result.VerificationRequired,
					"verification_nonce":    result.VerificationNonce,
					"keys":                  keys,
					"keys_base64":           keysB64,
				},
			}, nil
		} else {
			return b.handleNamespacesRotateInitGet()(ctx, req, data)
		}
	}
}

var sysNamespacesRotateHelp = map[string][2]string{
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
