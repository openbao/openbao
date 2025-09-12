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
	"github.com/openbao/openbao/helper/pgpkeys"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/helper/shamir"
	"github.com/openbao/openbao/sdk/v2/logical"
)

var (
	rotateInitRequestSchema = map[string]*framework.FieldSchema{
		"secret_shares": {
			Type:        framework.TypeInt,
			Required:    true,
			Description: "Specifies the number of shares to split the root key into.",
		},
		"secret_threshold": {
			Type:        framework.TypeInt,
			Required:    true,
			Description: "Specifies the number of shares required to reconstruct the root key.",
		},
		"pgp_keys": {
			Type:        framework.TypeStringSlice,
			Description: "Specifies an array of PGP public keys used to encrypt the output unseal keys.",
		},
		"backup": {
			Type:        framework.TypeBool,
			Description: "Specifies if using PGP-encrypted keys, whether OpenBao should also store a plaintext backup of the said keys.",
		},
		"require_verification": {
			Type:        framework.TypeBool,
			Description: "Enables verification which after successful authorization with the current unseal keys, ensures the new unseal keys are returned but the root key is not actually rotated.",
		},
	}

	rotateInitGetResponseSchema = map[string]*framework.FieldSchema{
		"namespace": &namespaceFieldSchema,
		"started": {
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
		"seal_threshold": {
			Type:     framework.TypeInt,
			Required: true,
		},
		"nonce": {
			Type: framework.TypeString,
		},
		"progress": {
			Type: framework.TypeInt,
		},
		"verification_required": {
			Type: framework.TypeBool,
		},
		"verification_nonce": {
			Type: framework.TypeString,
		},
		"pgp_fingerprints": {
			Type: framework.TypeCommaStringSlice,
		},
		"backup": {
			Type: framework.TypeBool,
		},
	}

	rotateInitPutResponseSchema = map[string]*framework.FieldSchema{
		"namespace": &namespaceFieldSchema,
		"complete": {
			Type: framework.TypeBool,
		},
		"pgp_fingerprints": {
			Type: framework.TypeCommaStringSlice,
		},
		"backup": {
			Type: framework.TypeBool,
		},
		"verification_required": {
			Type: framework.TypeBool,
		},
		"verification_nonce": {
			Type: framework.TypeString,
		},
		"keys": {
			Type: framework.TypeCommaStringSlice,
		},
		"keys_base64": {
			Type: framework.TypeCommaStringSlice,
		},
	}

	rotateUpdateResponseSchema = map[string]*framework.FieldSchema{
		"namespace": &namespaceFieldSchema,
		"complete": {
			Type: framework.TypeBool,
		},
		"nonce": {
			Type:     framework.TypeString,
			Required: true,
		},
		"backup": {
			Type: framework.TypeBool,
		},
		"pgp_fingerprints": {
			Type: framework.TypeCommaStringSlice,
		},
		"verification_required": {
			Type: framework.TypeBool,
		},
		"verification_nonce": {
			Type: framework.TypeString,
		},
		"keys": {
			Type: framework.TypeCommaStringSlice,
		},
		"keys_base64": {
			Type: framework.TypeCommaStringSlice,
		},
	}

	rotateConfigSchema = map[string]*framework.FieldSchema{
		"namespace": &namespaceFieldSchema,
		"enabled": {
			Type:        framework.TypeBool,
			Description: strings.TrimSpace(sysRotateHelp["rotation-enabled"][0]),
		},
		"max_operations": {
			Type:        framework.TypeInt64,
			Description: strings.TrimSpace(sysRotateHelp["rotation-max-operations"][0]),
		},
		"interval": {
			Type:        framework.TypeDurationSecond,
			Description: strings.TrimSpace(sysRotateHelp["rotation-interval"][0]),
		},
	}

	rotateVerifyResponseSchema = map[string]*framework.FieldSchema{
		"namespace": &namespaceFieldSchema,
		"started": {
			Type:     framework.TypeBool,
			Required: true,
		},
		"nonce": {
			Type: framework.TypeString,
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
			Type: framework.TypeInt,
		},
		"complete": {
			Type: framework.TypeBool,
		},
	}

	rotateBackupResponseSchema = map[string]*framework.FieldSchema{
		"namespace": &namespaceFieldSchema,
		"nonce": {
			Type: framework.TypeString,
		},
		"keys": {
			Type: framework.TypeCommaStringSlice,
		},
		"keys_base64": {
			Type: framework.TypeCommaStringSlice,
		},
	}
)

func (b *SystemBackend) rotatePaths() []*framework.Path {
	return []*framework.Path{
		{
			// "/rotate" equivalent to "/rotate/keyring"
			Pattern: "rotate(/keyring)?",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationVerb:   "rotate",
				OperationSuffix: "encryption-key",
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.handleRotate(b.rootNamespaceExtractor),
					Summary:  "Rotate the encryption key.",
					Responses: map[int][]framework.Response{
						http.StatusNoContent: {{
							Description: http.StatusText(http.StatusNoContent),
						}},
					},
				},
			},

			HelpSynopsis:    strings.TrimSpace(sysRotateHelp["rotate-keyring"][0]),
			HelpDescription: strings.TrimSpace(sysRotateHelp["rotate-keyring"][1]),
		},
		{
			// "/rotate/config" equivalent to "/rotate/keyring/config"
			Pattern: "rotate/(keyring/)?config",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationSuffix: "encryption-key",
			},
			Fields: map[string]*framework.FieldSchema{
				"enabled":        rotateConfigSchema["enabled"],
				"max_operations": rotateConfigSchema["max_operations"],
				"interval":       rotateConfigSchema["interval"],
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.handleRotationConfigRead(b.rootNamespaceExtractor),
					Summary:  "Get the automatic key rotation config.",
					DisplayAttrs: &framework.DisplayAttributes{
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
					Callback: b.handleRotationConfigUpdate(b.rootNamespaceExtractor),
					Summary:  "Configure automatic key rotation.",
					DisplayAttrs: &framework.DisplayAttributes{
						OperationVerb:   "configure",
						OperationSuffix: "rotation-config",
					},
					Responses: map[int][]framework.Response{
						http.StatusNoContent: {{
							Description: http.StatusText(http.StatusNoContent),
						}},
					},
					ForwardPerformanceSecondary: true,
					ForwardPerformanceStandby:   true,
				},
			},

			HelpSynopsis:    strings.TrimSpace(sysRotateHelp["rotate-keyring-config"][0]),
			HelpDescription: strings.TrimSpace(sysRotateHelp["rotate-keyring-config"][1]),
		},
		// The bare `sys/rotate/root` is a `sudo`-protected endpoint to directly
		// perform a root key rotation without requiring existing key shares be provided.
		{
			Pattern: "rotate/root",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "root-key",
				OperationVerb:   "rotate",
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.handleRotateRoot(),
					Responses: map[int][]framework.Response{
						http.StatusNoContent: {{
							Description: http.StatusText(http.StatusNoContent),
						}},
					},
				},
			},

			HelpSynopsis:    strings.TrimSpace(sysRotateHelp["rotate-root"][0]),
			HelpDescription: strings.TrimSpace(sysRotateHelp["rotate-root"][1]),
		},
		{
			Pattern: "rotate/(root|recovery)/init",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationVerb:   "initialize",
				OperationSuffix: "rotate-attempt",
			},
			Fields: rotateInitRequestSchema,

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.handleRotateInitGet(b.rootNamespaceExtractor),
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
					Summary: "Reads the configuration and progress of the current root or recovery rotate attempt.",
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.handleRotateInitPut(b.rootNamespaceExtractor),
					DisplayAttrs: &framework.DisplayAttributes{
						OperationVerb:   "initialize",
						OperationSuffix: "rotate-attempt",
					},
					Responses: map[int][]framework.Response{
						http.StatusOK: {{
							Description: http.StatusText(http.StatusOK),
							Fields:      rotateInitPutResponseSchema,
						}},
					},
					Summary:     "Initializes a new root or recovery rotate attempt.",
					Description: "Only a single rotate attempt can take place at a time, and changing the parameters of a rotation requires canceling and starting a new rotation, which will also provide a new nonce.",
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.handleRotateInitDelete(b.rootNamespaceExtractor),
					DisplayAttrs: &framework.DisplayAttributes{
						OperationVerb:   "cancel",
						OperationSuffix: "rotate-attempt",
					},
					Responses: map[int][]framework.Response{
						http.StatusNoContent: {{
							Description: http.StatusText(http.StatusNoContent),
						}},
					},
					Summary:     "Cancels any in-progress rotate root or recovery operation.",
					Description: "This clears the rotate settings as well as any progress made. This must be called to change the parameters of the rotate. Note: verification is still a part of a rotate. If rotating is canceled during the verification flow, the current unseal keys remain valid.",
				},
			},

			HelpSynopsis:    strings.TrimSpace(sysRotateHelp["rotate-init"][0]),
			HelpDescription: strings.TrimSpace(sysRotateHelp["rotate-init"][0]),
		},
		{
			Pattern: "rotate/(root|recovery)/update",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationVerb:   "update",
				OperationSuffix: "rotate-attempt",
			},
			Fields: map[string]*framework.FieldSchema{
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
					Callback: b.handleRotateUpdate(b.rootNamespaceExtractor),
					DisplayAttrs: &framework.DisplayAttributes{
						OperationVerb:   "update",
						OperationSuffix: "rotate-attempt",
					},
					Responses: map[int][]framework.Response{
						http.StatusOK: {{
							Description: http.StatusText(http.StatusOK),
							Fields:      rotateUpdateResponseSchema,
						}},
					},
					Summary: "Enter a single unseal key share to progress the rotation of the root key of OpenBao.",
				},
			},

			HelpSynopsis:    strings.TrimSpace(sysRotateHelp["rotate-update"][0]),
			HelpDescription: strings.TrimSpace(sysRotateHelp["rotate-update"][0]),
		},
		{
			Pattern: "rotate/(root|recovery)/verify",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationVerb:   "verify",
				OperationSuffix: "rotation-attempt",
			},

			Fields: map[string]*framework.FieldSchema{
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
						OperationVerb:   "read",
						OperationSuffix: "verification-attempt",
					},
					Callback: b.handleRotateVerifyGet(b.rootNamespaceExtractor),
					Responses: map[int][]framework.Response{
						http.StatusOK: {{
							Description: http.StatusText(http.StatusOK),
							Fields:      rotateVerifyResponseSchema,
						}},
					},
					Summary: "Read the configuration and progress of the current rotate verification attempt.",
				},
				logical.UpdateOperation: &framework.PathOperation{
					DisplayAttrs: &framework.DisplayAttributes{
						OperationVerb:   "update",
						OperationSuffix: "verification-attempt",
					},
					Callback: b.handleRotateVerifyPut(b.rootNamespaceExtractor),
					Responses: map[int][]framework.Response{
						http.StatusOK: {{
							Description: http.StatusText(http.StatusOK),
							Fields:      rotateVerifyResponseSchema,
						}},
					},
					Summary: "Enter a single new key share to progress the rotation verification operation.",
				},
				logical.DeleteOperation: &framework.PathOperation{
					DisplayAttrs: &framework.DisplayAttributes{
						OperationVerb:   "cancel",
						OperationSuffix: "verification-attempt",
					},
					Callback: b.handleRotateVerifyDelete(b.rootNamespaceExtractor),
					Responses: map[int][]framework.Response{
						http.StatusOK: {{
							Description: http.StatusText(http.StatusOK),
							Fields:      rotateVerifyResponseSchema,
						}},
					},
					Summary:     "Cancel any in-progress rotate verification operation.",
					Description: "This clears any progress made and resets the nonce. Unlike a `DELETE` against `sys/rotate/(root/recovery)/init`, this only resets the current verification operation, not the entire rotate atttempt.",
				},
			},

			HelpSynopsis:    strings.TrimSpace(sysRotateHelp["rotate-verify"][0]),
			HelpDescription: strings.TrimSpace(sysRotateHelp["rotate-verify"][0]),
		},
		{
			Pattern: "rotate/(root|recovery)/backup",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationVerb:   "backup",
				OperationSuffix: "unseal-keys",
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.handleRotateBackupRetrieve(b.rootNamespaceExtractor),
					DisplayAttrs: &framework.DisplayAttributes{
						OperationVerb:   "read",
						OperationSuffix: "backup-key",
					},
					Responses: map[int][]framework.Response{
						http.StatusOK: {{
							Description: http.StatusText(http.StatusOK),
							Fields:      rotateBackupResponseSchema,
						}},
					},
					Summary: "Return the backup copy of PGP-encrypted unseal keys.",
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.handleRotateBackupDelete(b.rootNamespaceExtractor),
					DisplayAttrs: &framework.DisplayAttributes{
						OperationVerb:   "delete",
						OperationSuffix: "backup-key",
					},
					Responses: map[int][]framework.Response{
						http.StatusNoContent: {{
							Description: http.StatusText(http.StatusNoContent),
						}},
					},
					Summary: "Delete the backup copy of PGP-encrypted unseal keys.",
				},
			},

			HelpSynopsis:    strings.TrimSpace(sysRotateHelp["rotate-backup"][0]),
			HelpDescription: strings.TrimSpace(sysRotateHelp["rotate-backup"][0]),
		},
	}
}

// rootNamespaceExtractor satisfies namespaceExtractor signature, returning rootNamespace.
func (*SystemBackend) rootNamespaceExtractor(_ context.Context, _ *framework.FieldData) (*namespace.Namespace, error) {
	return namespace.RootNamespace, nil
}

// handleRotate handles the GET `/sys/rotate` and `/sys/rotate/keyring`
// endpoints used to trigger an encryption key rotation.
func (b *SystemBackend) handleRotate(nsExtr namespaceExtractor) framework.OperationFunc {
	return func(ctx context.Context, _ *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		ns, err := nsExtr(ctx, data)
		if err != nil {
			return handleError(err)
		}

		if err := b.Core.sealManager.RotateNamespaceBarrierKey(ctx, ns); err != nil {
			b.Backend.Logger().Error("error handling key rotation", "error", err)
			return handleError(err)
		}
		return nil, nil
	}
}

// handleKeyRotationConfigRead handles the GET `/sys/rotate/config` and GET `/sys/rotate/keyring/config`
// endpoints returning the auto rotation config.
func (b *SystemBackend) handleRotationConfigRead(nsExtr namespaceExtractor) framework.OperationFunc {
	return func(ctx context.Context, _ *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		ns, err := nsExtr(ctx, data)
		if err != nil {
			return handleError(err)
		}

		barrier := b.Core.sealManager.NamespaceBarrier(ns.Path)
		if barrier == nil {
			return handleError(ErrNotSealable)
		}

		rotateConf, err := barrier.RotationConfig()
		if err != nil {
			return handleError(err)
		}

		nsPath := ns.Path
		if ns.ID == namespace.RootNamespaceID {
			nsPath = "root"
		}

		resp := &logical.Response{
			Data: map[string]interface{}{
				"namespace":      nsPath,
				"max_operations": rotateConf.MaxOperations,
				"enabled":        !rotateConf.Disabled,
			},
		}

		if rotateConf.Interval > 0 {
			resp.Data["interval"] = rotateConf.Interval.String()
		} else {
			resp.Data["interval"] = 0
		}
		return resp, nil
	}
}

// handleKeyRotationConfigUpdate handles the POST `/sys/rotate/config` and
// `/sys/rotate/keyring/config` endpoints updating the auto rotation config.
func (b *SystemBackend) handleRotationConfigUpdate(nsExtr namespaceExtractor) framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		ns, err := nsExtr(ctx, data)
		if err != nil {
			return handleError(err)
		}

		barrier := b.Core.sealManager.NamespaceBarrier(ns.Path)
		if barrier == nil {
			return handleError(ErrNotSealable)
		}

		rotateConf, err := barrier.RotationConfig()
		if err != nil {
			return handleError(err)
		}

		maxOps, ok, err := data.GetOkErr("max_operations")
		if err != nil {
			return handleError(err)
		}
		if ok {
			rotateConf.MaxOperations = maxOps.(int64)
		}

		interval, ok, err := data.GetOkErr("interval")
		if err != nil {
			return handleError(err)
		}
		if ok {
			rotateConf.Interval = time.Second * time.Duration(interval.(int))
		}

		enabled, ok, err := data.GetOkErr("enabled")
		if err != nil {
			return handleError(err)
		}
		if ok {
			rotateConf.Disabled = !enabled.(bool)
		}

		// Reject out of range settings
		if rotateConf.Interval < minimumRotationInterval && rotateConf.Interval != 0 {
			return logical.ErrorResponse("interval must be greater or equal to %s", minimumRotationInterval.String()), logical.ErrInvalidRequest
		}

		if rotateConf.MaxOperations < absoluteOperationMinimum || rotateConf.MaxOperations > absoluteOperationMaximum {
			return logical.ErrorResponse("max_operations must be in the range [%d,%d]", absoluteOperationMinimum, absoluteOperationMaximum), logical.ErrInvalidRequest
		}

		// Store the rotation config
		if err = barrier.SetRotationConfig(ctx, rotateConf); err != nil {
			return handleError(err)
		}

		return nil, nil
	}
}

// handleRotateRoot handles the POST `/sys/rotate/root` endpoint performing
// a root key rotation without requiring existing key shares to be provided.
func (b *SystemBackend) handleRotateRoot() framework.OperationFunc {
	return func(ctx context.Context, _ *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
		// Get the seal configuration
		existingConfig, err := b.Core.SealAccess().Config(ctx)
		if err != nil {
			return nil, logical.CodedError(http.StatusInternalServerError, fmt.Errorf("failed to fetch existing config: %w", err).Error())
		}

		// Ensure the barrier is initialized
		if existingConfig == nil {
			return handleError(ErrNotInit)
		}

		// Set the rotation config
		configClone := existingConfig.Clone()
		err = b.Core.sealManager.SetRotationConfig(namespace.RootNamespace, false, configClone)
		if err != nil {
			return handleError(err)
		}

		// Generate a new key
		newKey, err := b.Core.barrier.GenerateKey(b.Core.secureRandomReader)
		if err != nil {
			b.Core.logger.Error("failed to generate root key", "error", err)
			return nil, logical.CodedError(http.StatusInternalServerError, fmt.Errorf("root key generation failed: %w", err).Error())
		}

		// Perform the rotation
		if err := b.Core.sealManager.performRootRotation(ctx, namespace.RootNamespace, newKey, configClone, b.Core.seal); err != nil {
			return nil, logical.CodedError(http.StatusInternalServerError, fmt.Errorf("failed to perform barrier rotation: %w", err).Error())
		}

		// Remove the rotation config
		err = b.Core.sealManager.SetRotationConfig(namespace.RootNamespace, false, nil)
		if err != nil {
			return handleError(err)
		}

		return nil, nil
	}
}

// handleRotateInitGet handles the GET `/sys/rotate/root/init` and `/sys/rotate/recovery/init`
// endpoints retrieving the on-going rotation (if there's any) operation status.
func (b *SystemBackend) handleRotateInitGet(nsExtr namespaceExtractor) framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		ns, err := nsExtr(ctx, data)
		if err != nil {
			return handleError(err)
		}

		recovery := strings.Contains(req.Path, "recovery")
		sealThreshold, err := b.Core.sealManager.RotationThreshold(ctx, ns, recovery)
		if err != nil {
			return handleError(err)
		}

		nsPath := ns.Path
		if ns.ID == namespace.RootNamespaceID {
			nsPath = "root"
		}

		resp := &logical.Response{
			Data: map[string]interface{}{
				"namespace":      nsPath,
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

// handleRotateInitPut handles the POST `/sys/rotate/root/init` and `/sys/rotate/recovery/init`
// endpoints starting the rotation process, returning the operation status.
func (b *SystemBackend) handleRotateInitPut(nsExtr namespaceExtractor) framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		ns, err := nsExtr(ctx, data)
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

			nsPath := ns.Path
			if ns.ID == namespace.RootNamespaceID {
				nsPath = "root"
			}

			return &logical.Response{
				Data: map[string]interface{}{
					"namespace":             nsPath,
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

		return b.handleRotateInitGet(nsExtr)(ctx, req, data)
	}
}

// handleRotateInitDelete handles the DELETE `/sys/rotate/root/init` and `/sys/rotate/recovery/init`
// endpoints cancelling any in-progress rotation.
func (b *SystemBackend) handleRotateInitDelete(nsExtr namespaceExtractor) framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		ns, err := nsExtr(ctx, data)
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

// handleRotateUpdate handles the POST `/sys/rotate/root/update` and `/sys/rotate/recovery/update`
// endpoints used for providing a single root key share progressing the rotation of the key.
func (b *SystemBackend) handleRotateUpdate(nsExtr namespaceExtractor) framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		ns, err := nsExtr(ctx, data)
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

		barrier := b.Core.sealManager.NamespaceBarrier(ns.Path)
		if barrier == nil {
			return handleError(ErrNotSealable)
		}

		// We check min and max here to ensure that a string that is base64 encoded
		// but also valid hex will not be valid and we instead base64 decode it
		min, max := barrier.KeyLength()
		max += shamir.ShareOverhead
		key, err := hex.DecodeString(reqKey)
		if err != nil || len(key) < min || len(key) > max {
			key, err = base64.StdEncoding.DecodeString(reqKey)
			if err != nil {
				return handleError(errors.New("'key' must be a valid hex or base64 string"))
			}
		}

		// Open Q: do we also need to maintain a context for a namespace lifecycle?
		ctx, cancel := context.WithCancel(namespace.RootContext(b.Core.activeContext))
		defer cancel()

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

			nsPath := ns.Path
			if ns.ID == namespace.RootNamespaceID {
				nsPath = "root"
			}

			return &logical.Response{
				Data: map[string]interface{}{
					"namespace":             nsPath,
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
			return b.handleRotateInitGet(nsExtr)(ctx, req, data)
		}
	}
}

// handleRotateVerifyGet handles the GET `/sys/rotate/root/verify` and `/sys/rotate/recovery/verify`
// endpoints retrieving the on-going rotation verification (if there's any) operation status.
func (b *SystemBackend) handleRotateVerifyGet(nsExtr namespaceExtractor) framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		ns, err := nsExtr(ctx, data)
		if err != nil {
			return handleError(err)
		}

		barrierConfig := b.Core.sealManager.NamespaceSeal(ns.UUID)
		if barrierConfig == nil {
			return handleError(errors.New("server is not yet initialized"))
		}

		recovery := strings.Contains(req.Path, "recovery")
		rotateConfig := b.Core.sealManager.RotationConfig(ns, recovery)
		if rotateConfig == nil {
			return handleError(errors.New("no rotation configuration found"))
		}

		started, progress, err := b.Core.sealManager.RotationProgress(ns, recovery, true)
		if err != nil {
			return handleError(err)
		}

		nsPath := ns.Path
		if ns.ID == namespace.RootNamespaceID {
			nsPath = "root"
		}

		config := rotateConfig.Clone()
		return &logical.Response{
			Data: map[string]interface{}{
				"namespace": nsPath,
				"started":   started,
				"nonce":     config.VerificationNonce,
				"t":         config.SecretThreshold,
				"n":         config.SecretShares,
				"progress":  progress,
			},
		}, nil
	}
}

// handleRotateVerifyPut handles the POST `/sys/rotate/root/verify` and `/sys/rotate/recovery/verify`
// endpoints used to enter a single key share to progress the rotation verification operation.
func (b *SystemBackend) handleRotateVerifyPut(nsExtr namespaceExtractor) framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		ns, err := nsExtr(ctx, data)
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

		barrier := b.Core.sealManager.NamespaceBarrier(ns.Path)
		if barrier == nil {
			return handleError(ErrNotSealable)
		}

		min, max := barrier.KeyLength()
		max += shamir.ShareOverhead
		key, err := hex.DecodeString(reqKey)
		// We check min and max here to ensure that a string that is base64 encoded
		// but also valid hex will not be valid and we instead base64 decode it
		if err != nil || len(key) < min || len(key) > max {
			key, err = base64.StdEncoding.DecodeString(reqKey)
			if err != nil {
				return handleError(errors.New("'key' must be a valid hex or base64 string"))
			}
		}

		ctx, cancel := context.WithCancel(namespace.RootContext(b.Core.activeContext))
		defer cancel()

		// Use the key to make progress on rotation (rekey) verification
		recovery := strings.Contains(req.Path, "recovery")
		result, err := b.Core.sealManager.VerifyRotation(ctx, ns, key, reqNonce, recovery)
		if err != nil {
			return handleError(err)
		}

		nsPath := ns.Path
		if ns.ID == namespace.RootNamespaceID {
			nsPath = "root"
		}

		if result != nil {
			return &logical.Response{
				Data: map[string]interface{}{
					"namespace": nsPath,
					"complete":  result.Complete,
					"nonce":     result.Nonce,
				},
			}, nil
		} else {
			return b.handleRotateVerifyGet(nsExtr)(ctx, req, data)
		}
	}
}

// handleRotateVerifyDelete handles the DELETE `/sys/rotate/root/verify` and `/sys/rotate/recovery/verify`
// endpoints cancelling any in-progress rotation verification operation.
func (b *SystemBackend) handleRotateVerifyDelete(nsExtr namespaceExtractor) framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		ns, err := nsExtr(ctx, data)
		if err != nil {
			return handleError(err)
		}

		recovery := strings.Contains(req.Path, "recovery")
		if err := b.Core.sealManager.RestartRotationVerification(ns, recovery); err != nil {
			return handleError(err)
		}
		return b.handleRotateVerifyGet(nsExtr)(ctx, req, data)
	}
}

// handleRotateBackupRetrieve handles the GET `/sys/rotate/root/backup` and `/sys/rotate/recovery/backup`
// endpoints, returning backed-up, PGP-encrypted unseal keys.
func (b *SystemBackend) handleRotateBackupRetrieve(nsExtr namespaceExtractor) framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		ns, err := nsExtr(ctx, data)
		if err != nil {
			return handleError(err)
		}

		recovery := strings.Contains(req.Path, "recovery")
		backup, err := b.Core.sealManager.RetrieveRotationBackup(ctx, ns, recovery)
		if err != nil {
			return handleError(fmt.Errorf("unable to look up backed-up keys: %w", err))
		}
		if backup == nil {
			return handleError(errors.New("no backed-up keys found"))
		}

		keysB64 := map[string][]string{}
		for index, keys := range backup.Keys {
			for _, key := range keys {
				currB64Keys := keysB64[index]
				if currB64Keys == nil {
					currB64Keys = []string{}
				}
				key, err := hex.DecodeString(key)
				if err != nil {
					return handleError(fmt.Errorf("error decoding hex-encoded backup key: %w", err))
				}
				currB64Keys = append(currB64Keys, base64.StdEncoding.EncodeToString(key))
				keysB64[index] = currB64Keys
			}
		}

		return &logical.Response{
			Data: map[string]interface{}{
				"namespace":   "root",
				"nonce":       backup.Nonce,
				"keys":        backup.Keys,
				"keys_base64": keysB64,
			},
		}, nil
	}
}

// handleRotateBackupDelete handles the DELETE `/sys/rotate/root/backup` and `/sys/rotate/recovery/backup`
// endpoints, deleting backed-up, PGP-encrypted unseal keys.
func (b *SystemBackend) handleRotateBackupDelete(nsExtr namespaceExtractor) framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		ns, err := nsExtr(ctx, data)
		if err != nil {
			return handleError(err)
		}

		recovery := strings.Contains(req.Path, "recovery")
		if err := b.Core.sealManager.DeleteRotationBackup(ctx, ns, recovery); err != nil {
			return handleError(err)
		}

		return nil, nil
	}
}

var sysRotateHelp = map[string][2]string{
	"rotation-enabled": {
		"Whether automatic rotation is enabled.",
		"",
	},
	"rotation-max-operations": {
		"The number of encryption operations performed before the barrier key is automatically rotated.",
		"",
	},
	"rotation-interval": {
		"How long after installation of an active key term that the key will be automatically rotated.",
		"",
	},

	"rotate-keyring": {
		"Rotates the backend encryption key used to persist data.",
		`
		Rotate generates a new encryption key which is used to encrypt all
		data going to the storage backend. The old encryption keys are kept
		so that data encrypted using those keys can still be decrypted.
		`,
	},
	"rotate-keyring-config": {
		"Configures settings related to the backend encryption key management.",
		`
		Configures settings related to the automatic rotation of the backend
		encryption key.
		`,
	},

	"rotate-root": {
		"Perform a root key rotation without requiring key shares to be provided.",
		"",
	},

	"rotate-init": {
		`Initialize, read status or cancel the process of the rotation of
		the root or recovery key.
		`,
		"",
	},

	"rotate-update": {
		"Progress the rotation process by providing a single key share.",
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
		rotation attempt.
		`,
		"",
	},

	"rotate-backup": {
		"Allows fetching or deleting the backup of the rotated unseal keys.",
		"",
	},
}
