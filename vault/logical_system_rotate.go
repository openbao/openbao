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

func (b *SystemBackend) rotatePaths() []*framework.Path {
	rotateRequestSchema := map[string]*framework.FieldSchema{
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

	rotateStatusSchema := map[string]*framework.FieldSchema{
		"nonce": {
			Type:     framework.TypeString,
			Required: true,
		},
		"complete": {
			Type: framework.TypeBool,
		},
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
		"progress": {
			Type:     framework.TypeInt,
			Required: true,
		},
		"required": {
			Type:     framework.TypeInt,
			Required: true,
		},
		"verification_required": {
			Type:     framework.TypeBool,
			Required: true,
		},
		"verification_nonce": {
			Type:     framework.TypeString,
			Required: true,
		},
		"keys": {
			Type: framework.TypeCommaStringSlice,
		},
		"keys_base64": {
			Type: framework.TypeCommaStringSlice,
		},
		"pgp_fingerprints": {
			Type: framework.TypeCommaStringSlice,
		},
		"backup": {
			Type: framework.TypeBool,
		},
	}

	rotateConfigSchema := map[string]*framework.FieldSchema{
		"enabled": {
			Type:        framework.TypeBool,
			Description: strings.TrimSpace(sysHelp["rotation-enabled"][0]),
		},
		"max_operations": {
			Type:        framework.TypeInt64,
			Description: strings.TrimSpace(sysHelp["rotation-max-operations"][0]),
		},
		"interval": {
			Type:        framework.TypeDurationSecond,
			Description: strings.TrimSpace(sysHelp["rotation-interval"][0]),
		},
	}

	return []*framework.Path{
		{
			// "/rotate" equivalent to "/rotate/keyring"
			Pattern: "rotate(/keyring)?",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "encryption-key",
				OperationVerb:   "rotate",
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.handleRotate(),
					Responses: map[int][]framework.Response{
						http.StatusNoContent: {{
							Description: http.StatusText(http.StatusNoContent),
						}},
					},
				},
			},

			HelpSynopsis:    strings.TrimSpace(sysHelp["rotate-keyring"][0]),
			HelpDescription: strings.TrimSpace(sysHelp["rotate-keyring"][1]),
		},
		{
			// "/rotate/config" equivalent to "/rotate/keyring/config"
			Pattern: "rotate/(keyring/)?config",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "encryption-key",
			},
			Fields: rotateConfigSchema,

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.handleKeyRotationConfigRead(),
					DisplayAttrs: &framework.DisplayAttributes{
						OperationVerb:   "read",
						OperationSuffix: "rotation-configuration",
					},
					Responses: map[int][]framework.Response{
						http.StatusOK: {{
							Description: http.StatusText(http.StatusOK),
							Fields:      rotateConfigSchema,
						}},
					},
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.handleKeyRotationConfigUpdate(),
					DisplayAttrs: &framework.DisplayAttributes{
						OperationVerb:   "configure",
						OperationSuffix: "rotation-configuration",
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

			HelpSynopsis:    strings.TrimSpace(sysHelp["rotate-config"][0]),
			HelpDescription: strings.TrimSpace(sysHelp["rotate-config"][1]),
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

			HelpSynopsis:    strings.TrimSpace(sysHelp["rotate-root"][0]),
			HelpDescription: strings.TrimSpace(sysHelp["rotate-root"][1]),
		},
		{
			Pattern: "rotate/(root|recovery)/init",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "rotate-attempt",
			},
			Fields: rotateRequestSchema,

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.handleRotateInitGet(),
					DisplayAttrs: &framework.DisplayAttributes{
						OperationVerb:   "read",
						OperationSuffix: "progress",
					},
					Responses: map[int][]framework.Response{
						http.StatusOK: {{
							Description: http.StatusText(http.StatusOK),
							Fields:      rotateRequestSchema,
						}},
					},
					Summary: "Reads the configuration and progress of the current root rotate attempt.",
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.handleRotateInitPut(),
					DisplayAttrs: &framework.DisplayAttributes{
						OperationVerb: "initialize",
					},
					Responses: map[int][]framework.Response{
						http.StatusOK: {{
							Description: http.StatusText(http.StatusOK),
							Fields:      rotateStatusSchema,
						}},
					},
					Summary:     "Initializes a new root rotate attempt.",
					Description: "Only a single rotate attempt can take place at a time, and changing the parameters of a rotate requires canceling and starting a new rotation, which will also provide a new nonce.",
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.handleRotateInitDelete(),
					DisplayAttrs: &framework.DisplayAttributes{
						OperationVerb: "cancel",
					},
					Responses: map[int][]framework.Response{
						http.StatusNoContent: {{
							Description: http.StatusText(http.StatusNoContent),
						}},
					},
					Summary:     "Cancels any in-progress rotate root operation.",
					Description: "This clears the rotate settings as well as any progress made. This must be called to change the parameters of the rotate. Note: verification is still a part of a rotate. If rotating is canceled during the verification flow, the current unseal keys remain valid.",
				},
			},

			HelpSynopsis:    strings.TrimSpace(sysHelp["rotate-init"][0]),
			HelpDescription: strings.TrimSpace(sysHelp["rotate-init"][0]),
		},
		{
			Pattern: "rotate/(root|recovery)/update",
			Fields: map[string]*framework.FieldSchema{
				"key": {
					Type:        framework.TypeString,
					Description: "Specifies a single unseal key share.",
				},
				"nonce": {
					Type:        framework.TypeString,
					Description: "Specifies the nonce of the rotation attempt.",
				},
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.handleRotateUpdate(),
					DisplayAttrs: &framework.DisplayAttributes{
						OperationPrefix: "rotate-attempt",
						OperationVerb:   "update",
					},
					Responses: map[int][]framework.Response{
						http.StatusOK: {{
							Description: http.StatusText(http.StatusOK),
							Fields:      rotateStatusSchema,
						}},
					},
					Summary: "Enter a single unseal key share to progress the rotation of the root key of OpenBao.",
				},
			},

			HelpSynopsis:    strings.TrimSpace(sysHelp["rotate-update"][0]),
			HelpDescription: strings.TrimSpace(sysHelp["rotate-update"][0]),
		},
		{
			Pattern: "rotate/(root|recovery)/verify",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "rotate-verification",
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
						OperationSuffix: "progress",
					},
					Callback: b.handleRotateVerifyGet(),
					Responses: map[int][]framework.Response{
						http.StatusOK: {{
							Description: http.StatusText(http.StatusOK),
							Fields: map[string]*framework.FieldSchema{
								"nonce":    rotateStatusSchema["nonce"],
								"started":  rotateStatusSchema["started"],
								"t":        rotateStatusSchema["t"],
								"n":        rotateStatusSchema["n"],
								"progress": rotateStatusSchema["progress"],
							},
						}},
					},
					Summary: "Read the configuration and progress of the current rotate verification attempt.",
				},
				logical.UpdateOperation: &framework.PathOperation{
					DisplayAttrs: &framework.DisplayAttributes{
						OperationVerb: "update",
					},
					Callback: b.handleRotateVerifyPut(),
					Responses: map[int][]framework.Response{
						http.StatusOK: {{
							Description: http.StatusText(http.StatusOK),
							Fields: map[string]*framework.FieldSchema{
								"nonce":    rotateStatusSchema["nonce"],
								"complete": rotateStatusSchema["complete"],
							},
						}},
					},
					Summary: "Enter a single new key share to progress the rotation verification operation.",
				},
				logical.DeleteOperation: &framework.PathOperation{
					DisplayAttrs: &framework.DisplayAttributes{
						OperationVerb: "cancel",
					},
					Callback: b.handleRotateVerifyDelete(),
					Responses: map[int][]framework.Response{
						http.StatusOK: {{
							Description: http.StatusText(http.StatusOK),
							Fields: map[string]*framework.FieldSchema{
								"nonce":    rotateStatusSchema["nonce"],
								"started":  rotateStatusSchema["started"],
								"t":        rotateStatusSchema["t"],
								"n":        rotateStatusSchema["n"],
								"progress": rotateStatusSchema["progress"],
							},
						}},
					},
					Summary:     "Cancel any in-progress rotate verification operation.",
					Description: "This clears any progress made and resets the nonce. Unlike a `DELETE` against `sys/rotate/(root/recovery)/init`, this only resets the current verification operation, not the entire rotate atttempt.",
				},
			},

			HelpSynopsis:    strings.TrimSpace(sysHelp["rotate-verify"][0]),
			HelpDescription: strings.TrimSpace(sysHelp["rotate-verify"][0]),
		},
		{
			Pattern: "rotate/(root|recovery)/backup",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "rotate",
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.handleRotateBackupRetrieve(),
					DisplayAttrs: &framework.DisplayAttributes{
						OperationVerb:   "read",
						OperationSuffix: "backup-key",
					},
					Responses: map[int][]framework.Response{
						http.StatusOK: {{
							Description: http.StatusText(http.StatusOK),
							Fields: map[string]*framework.FieldSchema{
								"nonce":       rotateStatusSchema["nonce"],
								"keys":        rotateStatusSchema["keys"],
								"keys_base64": rotateStatusSchema["keys_base64"],
							},
						}},
					},
					Summary: "Return the backup copy of PGP-encrypted unseal keys.",
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.handleRotateBackupDelete(),
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

			HelpSynopsis:    strings.TrimSpace(sysHelp["rotate-backup"][0]),
			HelpDescription: strings.TrimSpace(sysHelp["rotate-backup"][0]),
		},
	}
}

// handleRotate handles the GET `/sys/rotate` and `/sys/rotate/keyring`
// endpoints used to trigger an encryption key rotation.
func (b *SystemBackend) handleRotate() framework.OperationFunc {
	return func(ctx context.Context, _ *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
		if err := b.rotateBarrierKey(ctx); err != nil {
			b.Backend.Logger().Error("error handling key rotation", "error", err)
			return handleError(err)
		}
		return nil, nil
	}
}

// handleKeyRotationConfigRead handles the GET `/sys/rotate/config` and GET `/sys/rotate/keyring/config`
// endpoints returning the auto rotation config.
func (b *SystemBackend) handleKeyRotationConfigRead() framework.OperationFunc {
	return func(_ context.Context, _ *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
		rotateConf, err := b.Core.barrier.RotationConfig()
		if err != nil {
			return handleError(err)
		}

		resp := &logical.Response{
			Data: map[string]interface{}{
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

// handleKeyRotationConfigUpdate handles the POST `/sys/rotate/config` and POST `/sys/rotate/keyring/config`
// endpoints updating the auto rotation config.
func (b *SystemBackend) handleKeyRotationConfigUpdate() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		rotateConf, err := b.Core.barrier.RotationConfig()
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
		if err = b.Core.barrier.SetRotationConfig(ctx, rotateConf); err != nil {
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
		existingConfig, err := b.Core.SealAccess().BarrierConfig(ctx)
		if err != nil {
			return nil, logical.CodedError(http.StatusInternalServerError, fmt.Errorf("failed to fetch existing config: %w", err).Error())
		}

		// Ensure the barrier is initialized
		if existingConfig == nil {
			return handleError(ErrNotInit)
		}

		// Set the rotation config
		b.Core.rootRotationConfig = existingConfig.Clone()

		// Generate a new key
		newKey, err := b.Core.barrier.GenerateKey(b.Core.secureRandomReader)
		if err != nil {
			b.Core.logger.Error("failed to generate root key", "error", err)
			return nil, logical.CodedError(http.StatusInternalServerError, fmt.Errorf("root key generation failed: %w", err).Error())
		}

		// Perform the rotation
		if err := b.Core.performBarrierRekey(ctx, newKey); err != nil {
			return nil, logical.CodedError(http.StatusInternalServerError, fmt.Errorf("failed to perform barrier rekey: %w", err).Error())
		}

		// Remove the rotation config
		b.Core.rootRotationConfig = nil
		return nil, nil
	}
}

// handleRotateInitGet handles the GET `/sys/rotate/root/init` and `/sys/rotate/recovery/init`
// endpoints retrieving the on-going rotation (if there's any) operation status.
func (b *SystemBackend) handleRotateInitGet() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		barrierConfig, err := b.Core.SealAccess().BarrierConfig(ctx)
		if err != nil {
			return handleError(err)
		}

		if barrierConfig == nil {
			return handleError(errors.New("server is not yet initialized"))
		}

		recovery := strings.Contains(req.Path, "recovery")
		rotConf := b.Core.RotationConfig(recovery)
		sealThreshold, err := b.Core.RotationThreshold(ctx, recovery)
		if err != nil {
			return handleError(err)
		}

		resp := &logical.Response{
			Data: map[string]interface{}{
				"started":        false,
				"t":              0,
				"n":              0,
				"seal_threshold": sealThreshold,
			},
		}

		if rotConf != nil {
			started, progress, err := b.Core.RotationProgress(recovery, false)
			if err != nil {
				return handleError(err)
			}

			resp.Data["nonce"] = rotConf.Nonce
			resp.Data["started"] = started
			resp.Data["t"] = rotConf.SecretThreshold
			resp.Data["n"] = rotConf.SecretShares
			resp.Data["progress"] = progress
			resp.Data["verification_required"] = rotConf.VerificationRequired
			resp.Data["verification_nonce"] = rotConf.VerificationNonce
			if len(rotConf.PGPKeys) != 0 {
				pgpFingerprints, err := pgpkeys.GetFingerprints(rotConf.PGPKeys, nil)
				if err != nil {
					return handleError(err)
				}
				resp.Data["pgp_fingerprints"] = pgpFingerprints
				resp.Data["backup"] = rotConf.Backup
			}
		}
		return resp, nil
	}
}

// handleRotateInitPut handles the POST `/sys/rotate/root/init` and `/sys/rotate/recovery/init`
// endpoints starting the rotation process, returning the operation status.
func (b *SystemBackend) handleRotateInitPut() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
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
		result, err := b.Core.InitRotation(ctx, rotateConf, recovery)
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

		return b.handleRotateInitGet()(ctx, req, data)
	}
}

// handleRotateInitDelete handles the DELETE `/sys/rotate/root/init` and `/sys/rotate/recovery/init`
// endpoints cancelling any in-progress rotation.
func (b *SystemBackend) handleRotateInitDelete() framework.OperationFunc {
	return func(_ context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
		recovery := strings.Contains(req.Path, "recovery")
		if err := b.Core.CancelRotation(recovery); err != nil {
			return handleError(err)
		}
		return nil, nil
	}
}

// handleRotateUpdate handles the POST `/sys/rotate/root/update` and `/sys/rotate/recovery/update`
// endpoints used for providing a single root key share progressing the rotation of the key.
func (b *SystemBackend) handleRotateUpdate() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
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

		ctx, cancel := context.WithCancel(namespace.RootContext(b.Core.activeContext))
		defer cancel()

		// Use the key to make progress on rotation (rekey)
		recovery := strings.Contains(req.Path, "recovery")
		result, err := b.Core.UpdateRotation(ctx, key, reqNonce, recovery)
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
			return b.handleRotateInitGet()(ctx, req, data)
		}
	}
}

// handleRotateVerifyGet handles the GET `/sys/rotate/root/verify` and `/sys/rotate/recovery/verify`
// endpoints retrieving the on-going rotation verification (if there's any) operation status.
func (b *SystemBackend) handleRotateVerifyGet() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		barrierConfig, err := b.Core.SealAccess().BarrierConfig(ctx)
		if err != nil {
			return handleError(err)
		}
		if barrierConfig == nil {
			return handleError(errors.New("server is not yet initialized"))
		}

		recovery := strings.Contains(req.Path, "recovery")
		rotateConf := b.Core.RotationConfig(recovery)
		if rotateConf == nil {
			return handleError(errors.New("no rotation configuration found"))
		}

		started, progress, err := b.Core.RotationProgress(recovery, true)
		if err != nil {
			return handleError(err)
		}

		return &logical.Response{
			Data: map[string]interface{}{
				"started":  started,
				"nonce":    rotateConf.VerificationNonce,
				"t":        rotateConf.SecretThreshold,
				"n":        rotateConf.SecretShares,
				"progress": progress,
			},
		}, nil
	}
}

// handleRotateVerifyPut handles the POST `/sys/rotate/root/verify` and `/sys/rotate/recovery/verify`
// endpoints used to enter a single key share to progress the rotation verification operation.
func (b *SystemBackend) handleRotateVerifyPut() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
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

		min, max := b.Core.BarrierKeyLength()
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
		result, err := b.Core.VerifyRotation(ctx, key, reqNonce, recovery)
		if err != nil {
			return handleError(err)
		}

		if result != nil {
			return &logical.Response{
				Data: map[string]interface{}{
					"complete": result.Complete,
					"nonce":    result.Nonce,
				},
			}, nil
		} else {
			return b.handleRotateVerifyGet()(ctx, req, data)
		}
	}
}

// handleRotateVerifyDelete handles the DELETE `/sys/rotate/root/verify` and `/sys/rotate/recovery/verify`
// endpoints cancelling any in-progress rotation verification operation.
func (b *SystemBackend) handleRotateVerifyDelete() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		recovery := strings.Contains(req.Path, "recovery")
		if err := b.Core.RestartRotationVerification(recovery); err != nil {
			return handleError(err)
		}
		return b.handleRotateVerifyGet()(ctx, req, data)
	}
}

// handleRotateBackupRetrieve handles the GET `/sys/rotate/root/backup` and `/sys/rotate/recovery/backup`
// endpoints, returning backed-up, PGP-encrypted unseal keys.
func (b *SystemBackend) handleRotateBackupRetrieve() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		recovery := strings.Contains(req.Path, "recovery")
		backup, err := b.Core.RetrieveRotationBackup(ctx, recovery)
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
				"nonce":       backup.Nonce,
				"keys":        backup.Keys,
				"keys_base64": keysB64,
			},
		}, nil
	}
}

// handleRotateBackupDelete handles the DELETE `/sys/rotate/root/backup` and `/sys/rotate/recovery/backup`
// endpoints, deleting backed-up, PGP-encrypted unseal keys.
func (b *SystemBackend) handleRotateBackupDelete() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		recovery := strings.Contains(req.Path, "recovery")
		if err := b.Core.DeleteRotationBackup(ctx, recovery); err != nil {
			return handleError(err)
		}

		return nil, nil
	}
}
