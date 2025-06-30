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

	"github.com/openbao/openbao/helper/pgpkeys"
	"github.com/openbao/openbao/sdk/v2/framework"
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
			Required:    true,
			Description: strings.TrimSpace(sysHelp["rotation-enabled"][0]),
		},
		"max_operations": {
			Type:        framework.TypeInt64,
			Required:    true,
			Description: strings.TrimSpace(sysHelp["rotation-max-operations"][0]),
		},
		"interval": {
			Type:        framework.TypeDurationSecond,
			Required:    true,
			Description: strings.TrimSpace(sysHelp["rotation-interval"][0]),
		},
	}

	return []*framework.Path{
		{
			Pattern: "rotate",
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

			HelpSynopsis:    strings.TrimSpace(sysHelp["rotate"][0]),
			HelpDescription: strings.TrimSpace(sysHelp["rotate"][1]),
		},
		{
			Pattern: "rotate/config",
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
						OperationSuffix: "rotation",
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
		{
			Pattern: "rotate/root",
			// DisplayAttrs: &framework.DisplayAttributes{
			// 	OperationPrefix: "encryption-key",
			// 	OperationVerb:   "rotate",
			// },

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

			// HelpSynopsis:    strings.TrimSpace(sysHelp["rotate-root"][0]),
			// HelpDescription: strings.TrimSpace(sysHelp["rotate-root"][1]),
		},
		{
			Pattern: "rotate/root/config",
			// DisplayAttrs: &framework.DisplayAttributes{
			// 	OperationPrefix: "encryption-key",
			// 	OperationVerb:   "rotate",
			// },

			Fields: map[string]*framework.FieldSchema{
				"enabled":  rotateConfigSchema["rotate"],
				"interval": rotateConfigSchema["interval"],
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.handleRotateRootConfigUpdate(),
					Responses: map[int][]framework.Response{
						http.StatusNoContent: {{
							Description: http.StatusText(http.StatusNoContent),
						}},
					},
				},
			},

			// HelpSynopsis:    strings.TrimSpace(sysHelp["rotate-root"][0]),
			// HelpDescription: strings.TrimSpace(sysHelp["rotate-root"][1]),
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
					Callback: b.handleRotateVerifyPut(),
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

			// HelpSynopsis:    strings.TrimSpace(sysHelp["rekey_backup"][0]),
			// HelpDescription: strings.TrimSpace(sysHelp["rekey_backup"][0]),
		},
	}
}

// handleRotate is used to trigger a key rotation.
func (b *SystemBackend) handleRotate() framework.OperationFunc {
	return func(ctx context.Context, _ *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
		if err := b.rotateBarrierKey(ctx); err != nil {
			b.Backend.Logger().Error("error handling key rotation", "error", err)
			return handleError(err)
		}
		return nil, nil
	}
}

// handleKeyRotationConfigRead returns the barrier key rotation config.
func (b *SystemBackend) handleKeyRotationConfigRead() framework.OperationFunc {
	return func(_ context.Context, _ *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
		rotConfig, err := b.Core.barrier.RotationConfig()
		if err != nil {
			return handleError(err)
		}

		resp := &logical.Response{
			Data: map[string]interface{}{
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

// handleKeyRotationConfigRead returns the barrier key rotation config.
func (b *SystemBackend) handleKeyRotationConfigUpdate() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		rotConfig, err := b.Core.barrier.RotationConfig()
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
			rotConfig.Interval = time.Second * time.Duration(interval.(int))
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
		if err = b.Core.barrier.SetRotationConfig(ctx, rotConfig); err != nil {
			return handleError(err)
		}

		return nil, nil
	}
}

// TODO: handleRotateRoot
func (b *SystemBackend) handleRotateRoot() framework.OperationFunc {
	return func(ctx context.Context, _ *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
		// if err := b.rotateBarrierKey(ctx); err != nil {
		// 	b.Backend.Logger().Error("error handling key rotation", "error", err)
		// 	return handleError(err)
		// }
		return nil, nil
	}
}

// TODO: handleRotateRootConfigUpdate
func (b *SystemBackend) handleRotateRootConfigUpdate() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		// rotConfig, err := b.Core.barrier.RotationConfig()
		// if err != nil {
		// 	return nil, err
		// }

		// maxOps, ok, err := data.GetOkErr("max_operations")
		// if err != nil {
		// 	return nil, err
		// }
		// if ok {
		// 	rotConfig.MaxOperations = maxOps.(int64)
		// }

		// interval, ok, err := data.GetOkErr("interval")
		// if err != nil {
		// 	return nil, err
		// }
		// if ok {
		// 	rotConfig.Interval = time.Second * time.Duration(interval.(int))
		// }

		// enabled, ok, err := data.GetOkErr("enabled")
		// if err != nil {
		// 	return nil, err
		// }
		// if ok {
		// 	rotConfig.Disabled = !enabled.(bool)
		// }

		// // Reject out of range settings
		// if rotConfig.Interval < minimumRotationInterval && rotConfig.Interval != 0 {
		// 	return logical.ErrorResponse("interval must be greater or equal to %s", minimumRotationInterval.String()), logical.ErrInvalidRequest
		// }

		// if rotConfig.MaxOperations < absoluteOperationMinimum || rotConfig.MaxOperations > absoluteOperationMaximum {
		// 	return logical.ErrorResponse("max_operations must be in the range [%d,%d]", absoluteOperationMinimum, absoluteOperationMaximum), logical.ErrInvalidRequest
		// }

		// // Store the rotation config
		// if err = b.Core.barrier.SetRotationConfig(ctx, rotConfig); err != nil {
		// 	return handleError(err)
		// }

		return nil, nil
	}
}

// handleRotateInitGet
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
		rotConf, err := b.Core.RekeyConfig(recovery)
		if err != nil {
			return handleError(err)
		}

		sealThreshold, err := b.Core.RekeyThreshold(ctx, recovery)
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
			started, progress, err := b.Core.RekeyProgress(recovery, false)
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

// handleRotateInitPut
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
		if err := b.Core.RekeyInit(rotateConf, recovery); err != nil {
			return handleError(err)
		}

		return b.handleRotateInitGet()(ctx, req, data)
	}
}

// handleRotateUpdate
func (b *SystemBackend) handleRotateUpdate() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		ikey, ok, err := data.GetOkErr("key")
		if err != nil {
			return handleError(err)
		}
		if !ok || ikey.(string) == "" {
			return handleError(errors.New("'key' must be specified in request body as JSON"))
		}
		reqKey := ikey.(string)

		inonce, ok, err := data.GetOkErr("nonce")
		if err != nil {
			return handleError(err)
		}
		if !ok || inonce.(string) == "" {
			return handleError(errors.New("'nonce' must be specified in request body as JSON"))
		}
		reqNonce := inonce.(string)

		// Decode the key, which is base64 or hex encoded
		min, max := b.Core.BarrierKeyLength()
		key, err := hex.DecodeString(reqKey)
		// We check min and max here to ensure that a string that is base64 encoded
		// but also valid hex will not be valid and we instead base64 decode it
		if err != nil || len(key) < min || len(key) > max {
			key, err = base64.StdEncoding.DecodeString(reqKey)
			if err != nil {
				return handleError(errors.New("'key' must be a valid hex or base64 string"))
			}
		}

		ctx, cancel := b.Core.GetContext()
		defer cancel()

		// Use the key to make progress on rotation (rekey)
		recovery := strings.Contains(req.Path, "recovery")
		result, err := b.Core.RekeyUpdate(ctx, key, reqNonce, recovery)
		if err != nil {
			return handleError(err)
		}

		resp := &logical.Response{}
		if result != nil {
			resp.Data["complete"] = true
			resp.Data["nonce"] = reqNonce
			resp.Data["backup"] = result.Backup
			resp.Data["pgp_fingerprints"] = result.PGPFingerprints
			resp.Data["verification_required"] = result.VerificationRequired
			resp.Data["verification_nonce"] = result.VerificationNonce

			keys := make([]string, 0, len(result.SecretShares))
			keysB64 := make([]string, 0, len(result.SecretShares))
			for _, k := range result.SecretShares {
				keys = append(keys, hex.EncodeToString(k))
				keysB64 = append(keysB64, base64.StdEncoding.EncodeToString(k))
			}
			resp.Data["keys"] = keys
			resp.Data["keys_b64"] = keysB64

			return resp, nil
		} else {
			return b.handleRotateInitGet()(ctx, req, data)
		}
	}
}

// handleRotateInitDelete
func (b *SystemBackend) handleRotateInitDelete() framework.OperationFunc {
	return func(_ context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
		recovery := strings.Contains(req.Path, "recovery")
		if err := b.Core.RekeyCancel(recovery); err != nil {
			return handleError(err)
		}
		return nil, nil
	}
}

// handleRotateVerifyGet
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
		rotateConf, err := b.Core.RekeyConfig(recovery)
		if err != nil {
			return handleError(err)
		}
		if rotateConf == nil {
			return handleError(errors.New("no rotation configuration found"))
		}

		started, progress, err := b.Core.RekeyProgress(recovery, true)
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

// handleRotateVerifyPut
func (b *SystemBackend) handleRotateVerifyPut() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		ikey, ok, err := data.GetOkErr("key")
		if err != nil {
			return handleError(err)
		}
		if !ok || ikey.(string) == "" {
			return handleError(errors.New("'key' must be specified in request body as JSON"))
		}
		reqKey := ikey.(string)

		inonce, ok, err := data.GetOkErr("nonce")
		if err != nil {
			return handleError(err)
		}
		if !ok || inonce.(string) == "" {
			return handleError(errors.New("'nonce' must be specified in request body as JSON"))
		}
		reqNonce := inonce.(string)

		// Decode the key, which is base64 or hex encoded
		min, max := b.Core.BarrierKeyLength()
		key, err := hex.DecodeString(reqKey)
		// We check min and max here to ensure that a string that is base64 encoded
		// but also valid hex will not be valid and we instead base64 decode it
		if err != nil || len(key) < min || len(key) > max {
			key, err = base64.StdEncoding.DecodeString(reqKey)
			if err != nil {
				return handleError(errors.New("'key' must be a valid hex or base64 string"))
			}
		}

		ctx, cancel := b.Core.GetContext()
		defer cancel()

		// Use the key to make progress on rotation (rekey) verification
		recovery := strings.Contains(req.Path, "recovery")
		result, err := b.Core.RekeyVerify(ctx, key, reqNonce, recovery)
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

// handleRotateVerifyDelete
func (b *SystemBackend) handleRotateVerifyDelete() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		recovery := strings.Contains(req.Path, "recovery")
		if err := b.Core.RekeyVerifyRestart(recovery); err != nil {
			return handleError(err)
		}
		return b.handleRotateVerifyGet()(ctx, req, data)
	}
}

// handleRotateBackupRetrieve returns backed-up, PGP-encrypted
// unseal keys from a rotation operation.
func (b *SystemBackend) handleRotateBackupRetrieve() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		recovery := strings.Contains(req.Path, "recovery")
		backup, err := b.Core.RekeyRetrieveBackup(ctx, recovery)
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

		// Format the status
		resp := &logical.Response{
			Data: map[string]interface{}{
				"nonce":       backup.Nonce,
				"keys":        backup.Keys,
				"keys_base64": keysB64,
			},
		}

		return resp, nil
	}
}

// handleRotateBackupDelete deletes backed-up, PGP-encrypted
// unseal keys from a rotation operation
func (b *SystemBackend) handleRotateBackupDelete() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		recovery := strings.Contains(req.Path, "recovery")
		if err := b.Core.RekeyDeleteBackup(ctx, recovery); err != nil {
			return handleError(fmt.Errorf("error during deletion of backed-up keys: %w", err))
		}

		return nil, nil
	}
}
