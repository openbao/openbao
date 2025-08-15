// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ssh

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
	"golang.org/x/crypto/ssh"
)

type keyStorageEntry struct {
	Key string `json:"key" structs:"key" mapstructure:"key"`
}

func pathConfigCA(b *backend) *framework.Path {
	fields := map[string]*framework.FieldSchema{}
	fields = addSubmitIssuerCommonFields(fields)

	return &framework.Path{
		Pattern: "config/ca",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixSSH,
		},

		Fields: fields,

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathWriteIssuerHandler,
				DisplayAttrs: &framework.DisplayAttributes{
					OperationVerb:   "configure",
					OperationSuffix: "default-ca",
				},
				Responses: map[int][]framework.Response{
					http.StatusOK: {{
						Description: "OK",
						Fields:      issuerOKResponseFields,
					}},
				},
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathDeleteIssuerHandler,
				DisplayAttrs: &framework.DisplayAttributes{
					OperationSuffix: "ca",
					OperationVerb:   "purge",
				},
				Responses: map[int][]framework.Response{
					http.StatusOK: {{
						Description: "OK",
					}},
				},
			},
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathReadIssuerHandler,
				DisplayAttrs: &framework.DisplayAttributes{
					OperationVerb:   "read",
					OperationSuffix: "default-ca",
				},
				Responses: map[int][]framework.Response{
					http.StatusOK: {{
						Description: "OK",
						Fields:      issuerOKResponseFields,
					}},
				},
			},
		},

		HelpSynopsis:    pathConfigCASyn,
		HelpDescription: pathConfigCADesc,
	}
}

func caKey(ctx context.Context, storage logical.Storage, keyType string) (*keyStorageEntry, error) {
	var path, deprecatedPath string
	switch keyType {
	case caPrivateKey:
		path = caPrivateKeyStoragePath
		deprecatedPath = caPrivateKeyStoragePathDeprecated
	case caPublicKey:
		path = caPublicKeyStoragePath
		deprecatedPath = caPublicKeyStoragePathDeprecated
	default:
		return nil, fmt.Errorf("unrecognized key type %q", keyType)
	}

	entry, err := storage.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA key of type %q: %w", keyType, err)
	}

	if entry == nil {
		// If the entry is not found, look at an older path. If found, upgrade
		// it.
		entry, err = storage.Get(ctx, deprecatedPath)
		if err != nil {
			return nil, err
		}
		if entry != nil {
			entry, err = logical.StorageEntryJSON(path, keyStorageEntry{
				Key: string(entry.Value),
			})
			if err != nil {
				return nil, err
			}
			if err := storage.Put(ctx, entry); err != nil {
				return nil, err
			}
			if err = storage.Delete(ctx, deprecatedPath); err != nil {
				return nil, err
			}
		}
	}
	if entry == nil {
		return nil, nil
	}

	var keyEntry keyStorageEntry
	if err := entry.DecodeJSON(&keyEntry); err != nil {
		return nil, err
	}

	return &keyEntry, nil
}

func generateSSHKeyPair(randomSource io.Reader, keyType string, keyBits int) (string, string, error) {
	if randomSource == nil {
		randomSource = rand.Reader
	}

	var publicKey crypto.PublicKey
	var privateBlock *pem.Block

	switch keyType {
	case ssh.KeyAlgoRSA, "rsa":
		if keyBits == 0 {
			keyBits = 4096
		}

		if keyBits < 2048 {
			return "", "", fmt.Errorf("refusing to generate weak %v key: %v bits < 2048 bits", keyType, keyBits)
		}

		privateSeed, err := rsa.GenerateKey(randomSource, keyBits)
		if err != nil {
			return "", "", err
		}

		privateBlock = &pem.Block{
			Type:    "RSA PRIVATE KEY",
			Headers: nil,
			Bytes:   x509.MarshalPKCS1PrivateKey(privateSeed),
		}

		publicKey = privateSeed.Public()
	case ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521, "ec":
		var curve elliptic.Curve
		switch keyType {
		case ssh.KeyAlgoECDSA256:
			curve = elliptic.P256()
		case ssh.KeyAlgoECDSA384:
			curve = elliptic.P384()
		case ssh.KeyAlgoECDSA521:
			curve = elliptic.P521()
		default:
			switch keyBits {
			case 0, 256:
				curve = elliptic.P256()
			case 384:
				curve = elliptic.P384()
			case 521:
				curve = elliptic.P521()
			default:
				return "", "", fmt.Errorf("unknown ECDSA key pair algorithm and bits: %v / %v", keyType, keyBits)
			}
		}

		privateSeed, err := ecdsa.GenerateKey(curve, randomSource)
		if err != nil {
			return "", "", err
		}

		marshalled, err := x509.MarshalECPrivateKey(privateSeed)
		if err != nil {
			return "", "", err
		}

		privateBlock = &pem.Block{
			Type:    "EC PRIVATE KEY",
			Headers: nil,
			Bytes:   marshalled,
		}

		publicKey = privateSeed.Public()
	case ssh.KeyAlgoED25519, "ed25519":
		_, privateSeed, err := ed25519.GenerateKey(randomSource)
		if err != nil {
			return "", "", err
		}

		privateBlock, err = ssh.MarshalPrivateKey(privateSeed, "")
		if err != nil {
			return "", "", fmt.Errorf("failed to marshal ed25519 key: %w", err)
		}

		publicKey = privateSeed.Public()
	default:
		return "", "", fmt.Errorf("unknown ssh key pair algorithm: %v", keyType)
	}

	public, err := ssh.NewPublicKey(publicKey)
	if err != nil {
		return "", "", err
	}

	return string(ssh.MarshalAuthorizedKey(public)), string(pem.EncodeToMemory(privateBlock)), nil
}

var (
	pathConfigCASyn  = `Configure the default SSH issuer used for signing and verification operations.`
	pathConfigCADesc = `
This endpoint allows configuring the default SSH issuer used for signing and verification operations.
If a 'default' issuer has already been set, this endpoint will override it.

The delete operation will remove all issuers, including the 'default' one. This operation is not reversible.

The read operation will return the 'default' issuer information.
`
)
