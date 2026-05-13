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

	"github.com/hashicorp/go-secure-stdlib/base62"
	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/helper/roottoken"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func (b *SystemBackend) generateRootPaths() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "generate-root-token/attempt",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationVerb:   "generate",
				OperationSuffix: "root-token",
			},
			Fields: map[string]*framework.FieldSchema{
				"otp": {
					Type:        framework.TypeString,
					Required:    false,
					Description: "One-time password for encoding the root token.",
				},
				"pgp_key": {
					Type:        framework.TypeString,
					Required:    false,
					Description: "PGP key for encrypting the root token.",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Summary:  "Read the status of root token generation.",
					Callback: b.handleGenerateRootStatus(),
					Responses: map[int][]framework.Response{
						http.StatusOK: {{
							Description: http.StatusText(http.StatusOK),
							Fields: map[string]*framework.FieldSchema{
								"started": {
									Type:     framework.TypeBool,
									Required: true,
								},
								"complete": {
									Type:     framework.TypeBool,
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
								"otp": {
									Type:     framework.TypeString,
									Required: true,
								},
								"otp_length": {
									Type:     framework.TypeInt,
									Required: true,
								},
								"nonce": {
									Type: framework.TypeString,
								},
								"pgp_fingerprint": {
									Type:     framework.TypeString,
									Required: true,
								},
							},
						}},
					},
				},
				logical.UpdateOperation: &framework.PathOperation{
					Summary:     "Initialize root token generation.",
					Description: "Only a single root generation attempt can take place at a time. One (and only one) of otp or pgp_key are required.",
					Callback:    b.handleGenerateRootInit(),
					Responses: map[int][]framework.Response{
						http.StatusOK: {{
							Description: http.StatusText(http.StatusOK),
							Fields: map[string]*framework.FieldSchema{
								"started": {
									Type:     framework.TypeBool,
									Required: true,
								},
								"complete": {
									Type:     framework.TypeBool,
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
								"otp": {
									Type:     framework.TypeString,
									Required: true,
								},
								"otp_length": {
									Type:     framework.TypeInt,
									Required: true,
								},
								"nonce": {
									Type: framework.TypeString,
								},
								"pgp_fingerprint": {
									Type:     framework.TypeString,
									Required: true,
								},
							},
						}},
					},
				},
				logical.DeleteOperation: &framework.PathOperation{
					Summary:  "Cancel root token generation.",
					Callback: b.handleGenerateRootCancel(),
					Responses: map[int][]framework.Response{
						http.StatusNoContent: {{
							Description: http.StatusText(http.StatusNoContent),
						}},
					},
				},
			},

			HelpSynopsis:    strings.TrimSpace(generateRootSysHelp["generate-root-token"][0]),
			HelpDescription: strings.TrimSpace(generateRootSysHelp["generate-root-token"][1]),
		},
		{
			Pattern: "generate-root-token/update",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationVerb:   "update-generation-attempt",
				OperationSuffix: "root-token",
			},
			Fields: map[string]*framework.FieldSchema{
				"key": {
					Type:        framework.TypeString,
					Required:    true,
					Description: "Unseal key share.",
				},
				"nonce": {
					Type:        framework.TypeString,
					Required:    true,
					Description: "Nonce for the generation operation.",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Summary:     "Provide an unseal key share for root token generation.",
					Description: "If the threshold number of unseal key shares is reached, OpenBao will complete the root generation and issue the new token. Otherwise, this API must be called multiple times until that threshold is met. The attempt nonce must be provided with each call.",
					Callback:    b.handleGenerateRootUpdate(),
					Responses: map[int][]framework.Response{
						http.StatusOK: {{
							Description: http.StatusText(http.StatusOK),
							Fields: map[string]*framework.FieldSchema{
								"started": {
									Type:     framework.TypeBool,
									Required: true,
								},
								"complete": {
									Type:     framework.TypeBool,
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
								"nonce": {
									Type:     framework.TypeString,
									Required: true,
								},
								"encoded_token": {
									Type:     framework.TypeString,
									Required: true,
								},
								"pgp_fingerprint": {
									Type:     framework.TypeString,
									Required: true,
								},
							},
						}},
					},
				},
			},

			HelpSynopsis:    strings.TrimSpace(generateRootSysHelp["generate-root-token"][0]),
			HelpDescription: strings.TrimSpace(generateRootSysHelp["generate-root-token"][1]),
		},
		{
			Pattern: "decode-token",
			Fields: map[string]*framework.FieldSchema{
				"encoded_token": {
					Type:        framework.TypeString,
					Description: "Specifies the encoded token (result from generate-root-token call).",
				},
				"otp": {
					Type:        framework.TypeString,
					Description: "Specifies the otp code used for decoding.",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.handleGenerateRootDecodeTokenUpdate,
					DisplayAttrs: &framework.DisplayAttributes{
						OperationVerb:   "decode",
						OperationSuffix: "root-token",
					},
					Summary: "Decodes the encoded token with the otp.",
					Responses: map[int][]framework.Response{
						http.StatusOK: {{
							Description: http.StatusText(http.StatusOK),
						}},
					},
				},
			},

			HelpSynopsis:    strings.TrimSpace(generateRootSysHelp["decode-token"][0]),
			HelpDescription: strings.TrimSpace(generateRootSysHelp["decode-token"][1]),
		},
	}
}

func (b *SystemBackend) handleGenerateRootInit() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		otp := data.Get("otp").(string)
		pgpKey := data.Get("pgp_key").(string)

		var genned bool
		switch {
		case len(otp) > 0, len(pgpKey) > 0:
		default:
			genned = true
			ns, err := namespace.FromContext(ctx)
			if err != nil {
				return handleError(err)
			}

			baseLen := TokenLength
			if ns.UUID != namespace.RootNamespaceUUID {
				baseLen = NSTokenLength
			}

			if b.Core.DisableSSCTokens() {
				otp, err = base62.Random(baseLen + OldTokenPrefixLength)
			} else {
				otp, err = base62.Random(baseLen + TokenPrefixLength)
			}
			if err != nil {
				return handleError(err)
			}
		}

		if err := b.Core.GenerateRootInit(ctx, otp, pgpKey, GenerateStandardRootTokenStrategy); err != nil {
			return handleError(err)
		}

		if genned {
			return b.generateRootStatus(ctx, otp)
		}

		return b.generateRootStatus(ctx, "")
	}
}

func (b *SystemBackend) handleGenerateRootStatus() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		return b.generateRootStatus(ctx, "")
	}
}

func (b *SystemBackend) handleGenerateRootUpdate() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		nonce := ""
		key := ""

		if dataNonce, ok := data.GetOk("nonce"); ok {
			nonce = dataNonce.(string)
		}
		if dataKey, ok := data.GetOk("key"); ok {
			key = dataKey.(string)
		}

		if nonce == "" {
			return logical.ErrorResponse("nonce is required"), logical.ErrInvalidRequest
		}
		if key == "" {
			return logical.ErrorResponse("key is required"), logical.ErrInvalidRequest
		}

		key = strings.TrimSpace(key)
		decodedKey, err := hex.DecodeString(key)
		if err != nil {
			decodedKey, err = base64.StdEncoding.DecodeString(key)
			if err != nil {
				return nil, fmt.Errorf("'key' must be a valid hex or base64 string")
			}
		}

		result, err := b.Core.GenerateRootUpdate(ctx, decodedKey, nonce, GenerateStandardRootTokenStrategy)
		if err != nil {
			return nil, err
		}

		return &logical.Response{Data: map[string]interface{}{
			"started":         true,
			"complete":        result.Progress == result.Required,
			"progress":        result.Progress,
			"required":        result.Required,
			"nonce":           nonce,
			"encoded_token":   result.EncodedToken,
			"pgp_fingerprint": result.PGPFingerprint,
		}}, nil
	}
}

func (b *SystemBackend) handleGenerateRootCancel() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		if err := b.Core.GenerateRootCancel(ctx); err != nil {
			return handleError(err)
		}

		return nil, nil
	}
}

func (b *SystemBackend) handleGenerateRootDecodeTokenUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	encodedToken := data.Get("encoded_token").(string)
	otp := data.Get("otp").(string)

	if encodedToken == "" || otp == "" {
		return handleError(errors.New("provided 'encoded_token' or 'otp' is empty"))
	}

	token, err := roottoken.DecodeToken(encodedToken, otp, len(otp))
	if err != nil {
		return handleError(err)
	}

	return &logical.Response{Data: map[string]interface{}{"token": token}}, nil
}

func (b *SystemBackend) generateRootStatus(ctx context.Context, otp string) (*logical.Response, error) {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return handleError(err)
	}

	seal := b.Core.sealManager.NamespaceSeal(ns.UUID)
	if seal == nil {
		return handleError(ErrNotSealable)
	}

	sealConfig, err := seal.BarrierConfig(ctx)
	if err != nil {
		return handleError(err)
	}
	if sealConfig == nil {
		return handleError(ErrNotInit)
	}

	if seal.RecoveryKeySupported() {
		sealConfig, err = seal.RecoveryConfig(ctx)
		if err != nil {
			return handleError(err)
		}
	}

	generationConfig, err := b.Core.GenerateRootConfiguration(ctx)
	switch {
	// Return the progress as 0 in this case, root generation has not started.
	case errors.Is(err, ErrNoRootGeneration):
	case err != nil:
		return handleError(err)
	}

	progress, err := b.Core.GenerateRootProgress(ctx)
	if err != nil {
		return handleError(err)
	}

	var baseLength int
	if ns.ID == namespace.RootNamespaceID {
		baseLength = TokenLength
	} else {
		baseLength = NSTokenLength
	}

	var otpLength int
	if b.Core.DisableSSCTokens() {
		otpLength = baseLength + OldTokenPrefixLength
	} else {
		otpLength = baseLength + TokenPrefixLength
	}

	response := map[string]interface{}{
		"started":    false,
		"complete":   false,
		"progress":   progress,
		"required":   sealConfig.SecretThreshold,
		"otp":        otp,
		"otp_length": otpLength,
	}

	if generationConfig != nil {
		response["nonce"] = generationConfig.Nonce
		response["started"] = true
		response["pgp_fingerprint"] = generationConfig.PGPFingerprint
	}

	return &logical.Response{Data: response}, nil
}

var generateRootSysHelp = map[string][2]string{
	"generate-root-token": {
		"Reads status, initializes, or cancels a root token generation process.",
		`
This path responds to multiple HTTP methods which change the behavior. Those
HTTP methods are listed below.

    GET /attempt
        Reads the configuration and progress of the current root generation
        attempt.

    POST /attempt
        Initializes a new root generation attempt. Only a single root generation
        attempt can take place at a time. One (and only one) of otp or pgp_key
        are required.

    DELETE /attempt
        Cancels any in-progress root generation attempt. This clears any
        progress made. This must be called to change the OTP or PGP key being
        used.
		`,
	},
	"decode-token": {
		"Decodes encoded root token generated through `sys/generate-root-token` or unauthenticated `sys/generate-root` endpoint",
		`
This path responds to the following HTTP methods.

	POST
		Decode provided token using provided otp.
		`,
	},
}
