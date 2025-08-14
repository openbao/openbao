// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/hashicorp/go-secure-stdlib/base62"
	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func (b *SystemBackend) namespaceGenerateRootPaths() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "namespaces/(?P<name>.+)/generate-root/attempt",
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Required:    true,
					Description: "Name of the namespace.",
				},
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
					Summary:  "Read the status of root token generation for the namespace.",
					Callback: b.handleNamespaceGenerateRootStatus(),
				},
				logical.UpdateOperation: &framework.PathOperation{
					Summary:  "Initialize root token generation for the namespace.",
					Callback: b.handleNamespaceGenerateRootInit(),
				},
				logical.DeleteOperation: &framework.PathOperation{
					Summary:  "Cancel root token generation for the namespace.",
					Callback: b.handleNamespaceGenerateRootCancel(),
				},
			},
		},
		{
			Pattern: "namespaces/(?P<name>.+)/generate-root/update",
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Required:    true,
					Description: "Name of the namespace.",
				},
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
					Summary:  "Provide an unseal key share for root token generation.",
					Callback: b.handleNamespaceGenerateRootUpdate(),
				},
			},
		},
	}
}

func (b *SystemBackend) handleNamespaceGenerateRootInit() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		name := namespace.Canonicalize(data.Get("name").(string))
		if len(name) > 0 && strings.Contains(name[:len(name)-1], "/") {
			return nil, errors.New("name must not contain /")
		}

		ns, err := b.Core.namespaceStore.GetNamespaceByPath(ctx, name)
		if err != nil {
			return handleError(err)
		}

		if ns == nil {
			return nil, fmt.Errorf("namespace %q doesn't exist", name)
		}

		var genned bool

		otp := data.Get("otp").(string)
		pgpKey := data.Get("pgp_key").(string)

		switch {
		case len(otp) > 0, len(pgpKey) > 0:
		default:
			genned = true
			if b.Core.DisableSSCTokens() {
				otp, err = base62.Random(NSTokenLength + OldTokenPrefixLength)
			} else {
				otp, err = base62.Random(NSTokenLength + TokenPrefixLength)
			}
			if err != nil {
				return handleError(err)
			}
		}

		err = b.Core.GenerateRootInit(otp, pgpKey, GenerateStandardRootTokenStrategy, ns)
		if err != nil {
			return handleError(err)
		}

		if genned {
			return b.namespaceGenerateRootStatus(ctx, ns, otp)
		}

		return b.namespaceGenerateRootStatus(ctx, ns, "")
	}
}

func (b *SystemBackend) handleNamespaceGenerateRootStatus() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		name := namespace.Canonicalize(data.Get("name").(string))
		if len(name) > 0 && strings.Contains(name[:len(name)-1], "/") {
			return nil, errors.New("name must not contain /")
		}

		ns, err := b.Core.namespaceStore.GetNamespaceByPath(ctx, name)
		if err != nil {
			return handleError(err)
		}

		if ns == nil {
			return nil, fmt.Errorf("namespace %q doesn't exist", name)
		}

		return b.namespaceGenerateRootStatus(ctx, ns, "")
	}
}

func (b *SystemBackend) namespaceGenerateRootStatus(ctx context.Context, ns *namespace.Namespace, otp string) (*logical.Response, error) {
	seal := b.Core.sealManager.NamespaceSeal(ns.UUID)
	if seal == nil {
		return handleError(ErrSealNotFound)
	}

	barrierConfig, err := seal.Config(ctx)
	if err != nil {
		return handleError(err)
	}
	if barrierConfig == nil {
		return nil, fmt.Errorf("no barrier found for namespace %q", ns.Path)
	}

	generationConfig, err := b.Core.GenerateRootConfiguration(ns)
	if err != nil {
		return handleError(err)
	}

	progress, err := b.Core.GenerateRootProgress(ns)
	if err != nil {
		return handleError(err)
	}
	var otpLength int
	if b.Core.DisableSSCTokens() {
		otpLength = NSTokenLength + OldTokenPrefixLength
	} else {
		otpLength = NSTokenLength + TokenPrefixLength
	}

	response := map[string]interface{}{
		"complete":   false,
		"progress":   progress,
		"required":   barrierConfig.SecretThreshold,
		"started":    false,
		"otp_length": otpLength,
		"otp":        otp,
	}

	if generationConfig != nil {
		response["nonce"] = generationConfig.Nonce
		response["started"] = true
		response["pgp_fingerprint"] = generationConfig.PGPFingerprint
	}

	return &logical.Response{Data: response}, nil
}

func (b *SystemBackend) handleNamespaceGenerateRootUpdate() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		name := namespace.Canonicalize(data.Get("name").(string))
		if len(name) > 0 && strings.Contains(name[:len(name)-1], "/") {
			return nil, errors.New("name must not contain /")
		}

		ns, err := b.Core.namespaceStore.GetNamespaceByPath(ctx, name)
		if err != nil {
			return handleError(err)
		}
		if ns == nil {
			return nil, fmt.Errorf("namespace %q doesn't exist", name)
		}

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

		return b.namespaceGenerateRootUpdate(ctx, ns, key, nonce)
	}
}

func (b *SystemBackend) namespaceGenerateRootUpdate(ctx context.Context, ns *namespace.Namespace, key, nonce string) (*logical.Response, error) {
	key = strings.TrimSpace(key)
	decodedKey, err := hex.DecodeString(key)
	if err != nil {
		decodedKey, err = base64.StdEncoding.DecodeString(key)
		if err != nil {
			return nil, fmt.Errorf("'key' must be a valid hex or base64 string")
		}
	}

	ctx = namespace.ContextWithNamespace(ctx, ns)
	result, err := b.Core.GenerateRootUpdate(ctx, decodedKey, nonce, GenerateStandardRootTokenStrategy)
	if err != nil {
		return nil, err
	}

	return &logical.Response{Data: map[string]interface{}{
		"complete":        result.Progress == result.Required,
		"nonce":           nonce,
		"progress":        result.Progress,
		"required":        result.Required,
		"started":         true,
		"encoded_token":   result.EncodedToken,
		"pgp_fingerprint": result.PGPFingerprint,
	}}, nil
}

func (b *SystemBackend) handleNamespaceGenerateRootCancel() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		name := namespace.Canonicalize(data.Get("name").(string))

		if len(name) > 0 && strings.Contains(name[:len(name)-1], "/") {
			return nil, errors.New("name must not contain /")
		}

		ns, err := b.Core.namespaceStore.GetNamespaceByPath(ctx, name)
		if err != nil {
			return handleError(err)
		}

		if ns == nil {
			return nil, fmt.Errorf("namespace %q doesn't exist", name)
		}

		if err = b.Core.GenerateRootCancel(ns); err != nil {
			return handleError(err)
		}

		return nil, nil
	}
}
