// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package transit

import (
	"context"
	"fmt"
	"strings"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/helper/keysutil"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// The default key derivation algorithm is the cofactor Diffie-Hellman version of the elliptic curve key agreement scheme, as defined in ANSI X9.63
const defaultKeyDerivationAlgorithm = "ecdh"

func (b *backend) pathDeriveKey() *framework.Path {
	return &framework.Path{
		Pattern: "derive-key/" + framework.GenericNameRegex("name"),

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixTransit,
			OperationVerb:   "derive-key",
		},

		Fields: map[string]*framework.FieldSchema{

			"key_derivation_algorithm": {
				Type:    framework.TypeString,
				Default: defaultKeyDerivationAlgorithm,
				Description: `Key derivation algorithm to use. Valid values are:
* ecdh
Defaults to "ecdh".`,
			},

			"peer_public_key": {
				Type:        framework.TypeString,
				Description: "The pem-encoded other party's EC public key",
			},

			"base_key_name": {
				Type:        framework.TypeString,
				Description: "Name of the base key to use for derivation (own private key for ECDH)",
			},

			"base_key_version": {
				Type: framework.TypeInt,
				Description: `The version of the base key to use for derivation.
Must be 0 (for latest) or a value greater than or equal
to the min_derivation_version configured on the key.`,
			},

			"derived_key_name": {
				Type:        framework.TypeString,
				Description: "Name of the output derived key",
			},

			"derived_key_type": {
				Type:    framework.TypeString,
				Default: "aes256-gcm96",
				Description: `
The type of the output derived key. Currently, "aes128-gcm96" , "aes256-gcm96", "chacha20-poly1305", "xchacha20-poly1305" are supported.
Defaults to "aes256-gcm96".
`,
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathPolicyDeriveKeyWrite,
		},

		HelpSynopsis:    pathDeriveKeyHelpSyn,
		HelpDescription: pathDeriveKeyDesc,
	}
}

func (b *backend) pathPolicyDeriveKeyWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	derivationAlgorithm := d.Get("key_derivation_algorithm").(string)
	if derivationAlgorithm == "" {
		derivationAlgorithm = defaultKeyDerivationAlgorithm
	} else if derivationAlgorithm != defaultKeyDerivationAlgorithm {
		return logical.ErrorResponse("key derivation algorithm %s not supported", derivationAlgorithm), logical.ErrInvalidRequest
	}

	peerPublicKeyPem := d.Get("peer_public_key").(string)
	if peerPublicKeyPem == "" {
		return logical.ErrorResponse("peer public key not provided"), logical.ErrInvalidRequest
	}

	baseKeyName := d.Get("base_key_name").(string)
	baseKeyVer := d.Get("base_key_version").(int)

	derivedKeyName := d.Get("derived_key_name").(string)
	derivedkeyType := d.Get("derived_key_type").(string)

	polReq := keysutil.PolicyRequest{
		Storage:                  req.Storage,
		Name:                     derivedKeyName,
		Derived:                  false,
		Exportable:               false,
		AllowPlaintextBackup:     false,
		AutoRotatePeriod:         0,
		AllowImportedKeyRotation: false,
		IsPrivateKey:             false,
	}

	switch strings.ToLower(derivedkeyType) {
	case "aes128-gcm96":
		polReq.KeyType = keysutil.KeyType_AES128_GCM96
	case "aes256-gcm96":
		polReq.KeyType = keysutil.KeyType_AES256_GCM96
	case "chacha20-poly1305":
		polReq.KeyType = keysutil.KeyType_ChaCha20_Poly1305
	case "xchacha20-poly1305":
		polReq.KeyType = keysutil.KeyType_XChaCha20_Poly1305
	case "ecdsa-p256":
		polReq.KeyType = keysutil.KeyType_ECDSA_P256
	default:
		return logical.ErrorResponse(fmt.Sprintf("unknown key type %v", derivedkeyType)), logical.ErrInvalidRequest
	}

	p, _, err := b.GetPolicy(ctx, keysutil.PolicyRequest{
		Storage: req.Storage,
		Name:    baseKeyName,
	}, b.GetRandomReader())
	if err != nil {
		return nil, err
	}
	if p == nil {
		return logical.ErrorResponse("specified base key not found"), logical.ErrInvalidRequest
	}
	if !b.System().CachingDisabled() {
		p.Lock(false)
	}
	defer p.Unlock()

	if !p.Type.KeyAgreementSupported() {
		return logical.ErrorResponse("base key type %v does not support key agreement", p.Type), logical.ErrInvalidRequest
	}

	derivedKey, err := p.DeriveKeyECDH(baseKeyVer, []byte(peerPublicKeyPem))
	if err != nil {
		return nil, err
	}

	err = b.lm.ImportPolicy(ctx, polReq, derivedKey, b.GetRandomReader())
	if err != nil {
		return nil, err
	}

	return nil, nil
}

const pathDeriveKeyHelpSyn = `Derives a new key from a base key`
const pathDeriveKeyDesc = `This path uses the named base key from the request path to derive a new named key.
When used with the ECDH key agreement algorithm, the base key is one's own EC private key and the "peer_public_key" is the pem-encoded other party's EC public key.
The computed shared secret is the resulting derived key.`
