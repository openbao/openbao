// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package transit

import (
	"context"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/go-viper/mapstructure/v2"
	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/go-secure-stdlib/strutil"
	"golang.org/x/crypto/ed25519"

	"github.com/fatih/structs"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/helper/keysutil"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func (b *backend) pathListKeys() *framework.Path {
	return &framework.Path{
		Pattern: "keys/?$",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixTransit,
			OperationSuffix: "keys",
		},

		Fields: map[string]*framework.FieldSchema{
			"after": {
				Type:        framework.TypeString,
				Description: `Optional entry to list begin listing after, not required to exist.`,
			},
			"limit": {
				Type:        framework.TypeInt,
				Description: `Optional number of entries to return; defaults to all entries.`,
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{
				Callback: b.pathKeysList,
			},
		},

		HelpSynopsis:    pathPolicyHelpSyn,
		HelpDescription: pathPolicyHelpDesc,
	}
}

func (b *backend) pathKeys() *framework.Path {
	return &framework.Path{
		Pattern: "keys/" + framework.GenericNameRegex("name"),

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixTransit,
			OperationSuffix: "key",
		},

		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the key",
			},

			"type": {
				Type:    framework.TypeString,
				Default: "aes256-gcm96",
				Description: `
The type of key to create. Currently, "aes128-gcm96" (symmetric), "aes256-gcm96" (symmetric), "ecdsa-p256"
(asymmetric), "ecdsa-p384" (asymmetric), "ecdsa-p521" (asymmetric), "ed25519" (asymmetric), "rsa-2048" (asymmetric), "rsa-3072"
(asymmetric), "rsa-4096" (asymmetric) are supported.  Defaults to "aes256-gcm96".
`,
			},

			"derived": {
				Type: framework.TypeBool,
				Description: `Enables key derivation mode. This
allows for per-transaction unique
keys for encryption operations.`,
			},

			"convergent_encryption": {
				Type: framework.TypeBool,
				Description: `Whether to support convergent encryption.
This is only supported when using a key with
key derivation enabled and will require all
requests to carry both a context and 96-bit
(12-byte) nonce. The given nonce will be used
in place of a randomly generated nonce. As a
result, when the same context and nonce are
supplied, the same ciphertext is generated. It
is *very important* when using this mode that
you ensure that all nonces are unique for a
given context. Failing to do so will severely
impact the ciphertext's security.`,
			},

			"exportable": {
				Type: framework.TypeBool,
				Description: `Enables keys to be exportable.
This allows for all the valid keys
in the key ring to be exported.`,
			},

			"allow_plaintext_backup": {
				Type: framework.TypeBool,
				Description: `Enables taking a backup of the named
key in plaintext format. Once set,
this cannot be disabled.`,
			},

			"context": {
				Type: framework.TypeString,
				Description: `Base64 encoded context for key derivation.
When reading a key with key derivation enabled,
if the key type supports public keys, this will
return the public key for the given context.`,
			},

			"auto_rotate_period": {
				Type:    framework.TypeDurationSecond,
				Default: 0,
				Description: `Amount of time the key should live before
being automatically rotated. A value of 0
(default) disables automatic rotation for the
key.`,
			},
			"key_size": {
				Type:        framework.TypeInt,
				Default:     0,
				Description: fmt.Sprintf("The key size in bytes for the algorithm.  Only applies to HMAC and must be no fewer than %d bytes and no more than %d", keysutil.HmacMinKeySize, keysutil.HmacMaxKeySize),
			},
			"custom_metadata": {
				Type: framework.TypeMap,
				Description: `
User-provided key-value pairs that are used to describe arbitrary and
version-agnostic information about a key.`,
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathPolicyWrite,
				DisplayAttrs: &framework.DisplayAttributes{
					OperationVerb: "create",
				},
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathPolicyDelete,
				DisplayAttrs: &framework.DisplayAttributes{
					OperationVerb: "delete",
				},
			},
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathPolicyRead,
				DisplayAttrs: &framework.DisplayAttributes{
					OperationVerb: "read",
				},
			},
		},

		HelpSynopsis:    pathPolicyHelpSyn,
		HelpDescription: pathPolicyHelpDesc,
	}
}

func (b *backend) pathKeysSoftDelete() *framework.Path {
	return &framework.Path{
		Pattern: "keys/" + framework.GenericNameRegex("name") + "/soft-delete",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixTransit,
			OperationSuffix: "key",
		},

		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the key",
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathPolicySoftDelete,
				DisplayAttrs: &framework.DisplayAttributes{
					OperationVerb: "soft-delete",
				},
			},
		},

		HelpSynopsis:    pathPolicyHelpSyn,
		HelpDescription: pathPolicyHelpDesc,
	}
}

func (b *backend) pathKeysSoftDeleteRestore() *framework.Path {
	return &framework.Path{
		Pattern: "keys/" + framework.GenericNameRegex("name") + "/soft-delete-restore",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixTransit,
			OperationSuffix: "key",
		},

		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the key",
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathPolicySoftDeleteRestore,
				DisplayAttrs: &framework.DisplayAttributes{
					OperationVerb: "soft-delete-restore",
				},
			},
		},

		HelpSynopsis:    pathPolicyHelpSyn,
		HelpDescription: pathPolicyHelpDesc,
	}
}

func (b *backend) pathKeysList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	after := data.Get("after").(string)
	limit := data.Get("limit").(int)
	if limit <= 0 {
		limit = -1
	}

	entries, err := req.Storage.ListPage(ctx, "policy/", after, limit)
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}

const (
	maxCustomMetadataKeys               = 64
	maxCustomMetadataKeyLength          = 128
	maxCustomMetadataValueLength        = 512
	customMetadataValidationErrorPrefix = "custom_metadata validation failed"
)

// Perform input validation on custom_metadata field. If the key count
// exceeds maxCustomMetadataKeys, the validation will be short-circuited
// to prevent unnecessary (and potentially costly) validation to be run.
// If the key count falls at or below maxCustomMetadataKeys, multiple
// checks will be made per key and value. These checks include:
//   - 0 < length of key <= maxCustomMetadataKeyLength
//   - 0 < length of value <= maxCustomMetadataValueLength
//   - keys and values cannot include unprintable characters
func validateCustomMetadata(customMetadata map[string]string) error {
	var errs *multierror.Error

	if keyCount := len(customMetadata); keyCount > maxCustomMetadataKeys {
		errs = multierror.Append(errs, fmt.Errorf("%s: payload must contain at most %d keys, provided %d",
			customMetadataValidationErrorPrefix,
			maxCustomMetadataKeys,
			keyCount))

		return errs.ErrorOrNil()
	}

	// Perform validation on each key and value and return ALL errors
	for key, value := range customMetadata {
		if keyLen := len(key); 0 == keyLen || keyLen > maxCustomMetadataKeyLength {
			errs = multierror.Append(errs, fmt.Errorf("%s: length of key %q is %d but must be 0 < len(key) <= %d",
				customMetadataValidationErrorPrefix,
				key,
				keyLen,
				maxCustomMetadataKeyLength))
		}

		if valueLen := len(value); 0 == valueLen || valueLen > maxCustomMetadataValueLength {
			errs = multierror.Append(errs, fmt.Errorf("%s: length of value for key %q is %d but must be 0 < len(value) <= %d",
				customMetadataValidationErrorPrefix,
				key,
				valueLen,
				maxCustomMetadataValueLength))
		}

		if !strutil.Printable(key) {
			// Include unquoted format (%s) to also include the string without the unprintable
			//  characters visible to allow for easier debug and key identification
			errs = multierror.Append(errs, fmt.Errorf("%s: key %q (%s) contains unprintable characters",
				customMetadataValidationErrorPrefix,
				key,
				key))
		}

		if !strutil.Printable(value) {
			errs = multierror.Append(errs, fmt.Errorf("%s: value for key %q contains unprintable characters",
				customMetadataValidationErrorPrefix,
				key))
		}
	}

	return errs.ErrorOrNil()
}

// parseCustomMetadata is used to effectively convert the TypeMap
// (map[string]interface{}) into a TypeKVPairs (map[string]string)
// which is how custom_metadata is stored. Defining custom_metadata
// as a TypeKVPairs will convert nulls into empty strings. A null,
// however, is essential for a PATCH operation in that it signals
// the handler to remove the field. The filterNils flag should
// only be used during a patch operation.
func parseCustomMetadata(raw map[string]interface{}, filterNils bool) (map[string]string, error) {
	customMetadata := map[string]string{}
	for k, v := range raw {
		if filterNils && v == nil {
			continue
		}

		var s string
		if err := mapstructure.WeakDecode(v, &s); err != nil {
			return nil, err
		}

		customMetadata[k] = s
	}

	return customMetadata, nil
}

func (b *backend) pathPolicyWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	derived := d.Get("derived").(bool)
	convergent := d.Get("convergent_encryption").(bool)
	keyType := d.Get("type").(string)
	keySize := d.Get("key_size").(int)
	exportable := d.Get("exportable").(bool)
	allowPlaintextBackup := d.Get("allow_plaintext_backup").(bool)
	autoRotatePeriod := time.Second * time.Duration(d.Get("auto_rotate_period").(int))
	customMetadataRaw, cmOk := d.GetOk("custom_metadata")

	if autoRotatePeriod != 0 && autoRotatePeriod < time.Hour {
		return logical.ErrorResponse("auto rotate period must be 0 to disable or at least an hour"), nil
	}

	if !derived && convergent {
		return logical.ErrorResponse("convergent encryption requires derivation to be enabled"), nil
	}

	customMetadataMap := map[string]string{}
	if cmOk {
		var err error
		customMetadataMap, err = parseCustomMetadata(customMetadataRaw.(map[string]interface{}), false)
		if err != nil {
			return logical.ErrorResponse(fmt.Sprintf("%s: %s", customMetadataValidationErrorPrefix, err.Error())), nil
		}

		customMetadataErrs := validateCustomMetadata(customMetadataMap)

		if customMetadataErrs != nil {
			return logical.ErrorResponse(customMetadataErrs.Error()), nil
		}
	}

	polReq := keysutil.PolicyRequest{
		Upsert:               true,
		Storage:              req.Storage,
		Name:                 name,
		Derived:              derived,
		Convergent:           convergent,
		Exportable:           exportable,
		AllowPlaintextBackup: allowPlaintextBackup,
		AutoRotatePeriod:     autoRotatePeriod,
		CustomMetadata:       customMetadataMap,
	}

	switch keyType {
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
	case "ecdsa-p384":
		polReq.KeyType = keysutil.KeyType_ECDSA_P384
	case "ecdsa-p521":
		polReq.KeyType = keysutil.KeyType_ECDSA_P521
	case "ed25519":
		polReq.KeyType = keysutil.KeyType_ED25519
	case "rsa-2048":
		polReq.KeyType = keysutil.KeyType_RSA2048
	case "rsa-3072":
		polReq.KeyType = keysutil.KeyType_RSA3072
	case "rsa-4096":
		polReq.KeyType = keysutil.KeyType_RSA4096
	case "hmac":
		polReq.KeyType = keysutil.KeyType_HMAC
	default:
		return logical.ErrorResponse(fmt.Sprintf("unknown key type %v", keyType)), logical.ErrInvalidRequest
	}
	if keySize != 0 {
		if polReq.KeyType != keysutil.KeyType_HMAC {
			return logical.ErrorResponse(fmt.Sprintf("key_size is not valid for algorithm %v", polReq.KeyType)), logical.ErrInvalidRequest
		}
		if keySize < keysutil.HmacMinKeySize || keySize > keysutil.HmacMaxKeySize {
			return logical.ErrorResponse(fmt.Sprintf("invalid key_size %d", keySize)), logical.ErrInvalidRequest
		}
		polReq.KeySize = keySize
	}

	p, upserted, err := b.GetPolicy(ctx, polReq, b.GetRandomReader())
	if err != nil {
		return nil, err
	}
	if p == nil {
		return nil, errors.New("error generating key: returned policy was nil")
	}
	if !b.System().CachingDisabled() {
		p.Lock(false)
	}
	defer p.Unlock()

	resp, err := b.formatKeyPolicy(p, nil)
	if err != nil {
		return nil, err
	}
	if !upserted {
		resp.AddWarning(fmt.Sprintf("key %s already existed", name))
	}
	return resp, nil
}

// Built-in helper type for returning asymmetric keys
type asymKey struct {
	Name             string    `json:"name" structs:"name" mapstructure:"name"`
	PublicKey        string    `json:"public_key" structs:"public_key" mapstructure:"public_key"`
	CertificateChain string    `json:"certificate_chain" structs:"certificate_chain" mapstructure:"certificate_chain"`
	CreationTime     time.Time `json:"creation_time" structs:"creation_time" mapstructure:"creation_time"`
}

func (b *backend) pathPolicyRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)

	p, _, err := b.GetPolicy(ctx, keysutil.PolicyRequest{
		Storage: req.Storage,
		Name:    name,
	}, b.GetRandomReader())
	if err != nil {
		return nil, err
	}
	if p == nil {
		return nil, nil
	}
	if !b.System().CachingDisabled() {
		p.Lock(false)
	}
	defer p.Unlock()

	contextRaw := d.Get("context").(string)
	var context []byte
	if len(contextRaw) != 0 {
		context, err = base64.StdEncoding.DecodeString(contextRaw)
		if err != nil {
			return logical.ErrorResponse("failed to base64-decode context"), logical.ErrInvalidRequest
		}
	}

	return b.formatKeyPolicy(p, context)
}

func (b *backend) formatKeyPolicy(p *keysutil.Policy, context []byte) (*logical.Response, error) {
	// Return the response
	resp := &logical.Response{
		Data: map[string]interface{}{
			"name":                   p.Name,
			"type":                   p.Type.String(),
			"derived":                p.Derived,
			"deletion_allowed":       p.DeletionAllowed,
			"min_available_version":  p.MinAvailableVersion,
			"min_decryption_version": p.MinDecryptionVersion,
			"min_encryption_version": p.MinEncryptionVersion,
			"latest_version":         p.LatestVersion,
			"exportable":             p.Exportable,
			"allow_plaintext_backup": p.AllowPlaintextBackup,
			"supports_encryption":    p.Type.EncryptionSupported(),
			"supports_decryption":    p.Type.DecryptionSupported(),
			"supports_signing":       p.Type.SigningSupported(),
			"supports_derivation":    p.Type.DerivationSupported(),
			"auto_rotate_period":     int64(p.AutoRotatePeriod.Seconds()),
			"imported_key":           p.Imported,
			"soft_deleted":           p.SoftDeleted,
			"custom_metadata":        p.CustomMetadata,
		},
	}
	if p.KeySize != 0 {
		resp.Data["key_size"] = p.KeySize
	}

	if p.Imported {
		resp.Data["imported_key_allow_rotation"] = p.AllowImportedKeyRotation
	}

	if p.BackupInfo != nil {
		resp.Data["backup_info"] = map[string]interface{}{
			"time":    p.BackupInfo.Time,
			"version": p.BackupInfo.Version,
		}
	}
	if p.RestoreInfo != nil {
		resp.Data["restore_info"] = map[string]interface{}{
			"time":    p.RestoreInfo.Time,
			"version": p.RestoreInfo.Version,
		}
	}

	if p.Derived {
		switch p.KDF {
		case keysutil.Kdf_hmac_sha256_counter:
			resp.Data["kdf"] = "hmac-sha256-counter"
			resp.Data["kdf_mode"] = "hmac-sha256-counter"
		case keysutil.Kdf_hkdf_sha256:
			resp.Data["kdf"] = "hkdf_sha256"
		}
		resp.Data["convergent_encryption"] = p.ConvergentEncryption
		if p.ConvergentEncryption {
			resp.Data["convergent_encryption_version"] = p.ConvergentVersion
		}
	}

	switch p.Type {
	case keysutil.KeyType_AES128_GCM96, keysutil.KeyType_AES256_GCM96, keysutil.KeyType_ChaCha20_Poly1305, keysutil.KeyType_XChaCha20_Poly1305:
		retKeys := map[string]int64{}
		for k, v := range p.Keys {
			retKeys[k] = v.DeprecatedCreationTime
		}
		resp.Data["keys"] = retKeys

	case keysutil.KeyType_ECDSA_P256, keysutil.KeyType_ECDSA_P384, keysutil.KeyType_ECDSA_P521, keysutil.KeyType_ED25519, keysutil.KeyType_RSA2048, keysutil.KeyType_RSA3072, keysutil.KeyType_RSA4096:
		retKeys := map[string]map[string]interface{}{}
		for k, v := range p.Keys {
			key := asymKey{
				PublicKey:    v.FormattedPublicKey,
				CreationTime: v.CreationTime,
			}
			if key.CreationTime.IsZero() {
				key.CreationTime = time.Unix(v.DeprecatedCreationTime, 0)
			}

			if v.CertificateChain != nil {
				var pemCerts []string
				for _, derCertBytes := range v.CertificateChain {
					pemCert := strings.TrimSpace(string(pem.EncodeToMemory(
						&pem.Block{
							Type:  "CERTIFICATE",
							Bytes: derCertBytes,
						})))
					pemCerts = append(pemCerts, pemCert)
				}
				key.CertificateChain = strings.Join(pemCerts, "\n")
			}

			switch p.Type {
			case keysutil.KeyType_ECDSA_P256:
				key.Name = elliptic.P256().Params().Name
			case keysutil.KeyType_ECDSA_P384:
				key.Name = elliptic.P384().Params().Name
			case keysutil.KeyType_ECDSA_P521:
				key.Name = elliptic.P521().Params().Name
			case keysutil.KeyType_ED25519:
				if p.Derived {
					if len(context) == 0 {
						key.PublicKey = ""
					} else {
						ver, err := strconv.Atoi(k)
						if err != nil {
							return nil, fmt.Errorf("invalid version %q: %w", k, err)
						}
						derived, err := p.GetKey(context, ver, 32)
						if err != nil {
							return nil, fmt.Errorf("failed to derive key to return public component: %w", err)
						}
						pubKey := ed25519.PrivateKey(derived).Public().(ed25519.PublicKey)
						key.PublicKey = base64.StdEncoding.EncodeToString(pubKey)
					}
				}
				key.Name = "ed25519"
			case keysutil.KeyType_RSA2048, keysutil.KeyType_RSA3072, keysutil.KeyType_RSA4096:
				key.Name = "rsa-2048"
				if p.Type == keysutil.KeyType_RSA3072 {
					key.Name = "rsa-3072"
				}

				if p.Type == keysutil.KeyType_RSA4096 {
					key.Name = "rsa-4096"
				}

				pubKey, err := encodeRSAPublicKey(&v, "")
				if err != nil {
					return nil, err
				}
				key.PublicKey = pubKey
			}

			retKeys[k] = structs.New(key).Map()
		}
		resp.Data["keys"] = retKeys
	}

	return resp, nil
}

func (b *backend) pathPolicyDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)

	// Delete does its own locking
	err := b.lm.DeletePolicy(ctx, req.Storage, name)
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("error deleting policy %s: %s", name, err)), err
	}

	return nil, nil
}

func (b *backend) pathPolicySoftDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	txRollback, err := logical.StartTxStorage(ctx, req)
	if err != nil {
		return nil, err
	}
	defer txRollback()

	name := d.Get("name").(string)

	p, _, err := b.GetPolicy(ctx, keysutil.PolicyRequest{
		Storage: req.Storage,
		Name:    name,
	}, b.GetRandomReader())
	if err != nil {
		return nil, err
	}
	if p == nil {
		return nil, nil
	}
	if !b.System().CachingDisabled() {
		p.Lock(true)
	}
	defer p.Unlock()

	wasDeleted := !p.SoftDeleted
	p.SoftDeleted = true

	if err := p.Persist(ctx, req.Storage); err != nil {
		return nil, err
	}

	resp, err := b.formatKeyPolicy(p, nil)
	if err != nil {
		return nil, err
	}

	if !wasDeleted {
		resp.AddWarning("key was already marked as soft deleted")
	}

	if err := logical.EndTxStorage(ctx, req); err != nil {
		return nil, err
	}

	return resp, nil
}

func (b *backend) pathPolicySoftDeleteRestore(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	txRollback, err := logical.StartTxStorage(ctx, req)
	if err != nil {
		return nil, err
	}
	defer txRollback()

	name := d.Get("name").(string)

	p, _, err := b.GetPolicy(ctx, keysutil.PolicyRequest{
		Storage: req.Storage,
		Name:    name,
	}, b.GetRandomReader())
	if err != nil {
		return nil, err
	}
	if p == nil {
		return nil, nil
	}
	if !b.System().CachingDisabled() {
		p.Lock(true)
	}
	defer p.Unlock()

	wasRestored := p.SoftDeleted
	p.SoftDeleted = false

	if err := p.Persist(ctx, req.Storage); err != nil {
		return nil, err
	}

	resp, err := b.formatKeyPolicy(p, nil)
	if err != nil {
		return nil, err
	}

	if !wasRestored {
		resp.AddWarning("key was already restored")
	}

	if err := logical.EndTxStorage(ctx, req); err != nil {
		return nil, err
	}

	return resp, nil
}

const pathPolicyHelpSyn = `Managed named encryption keys`

const pathPolicyHelpDesc = `
This path is used to manage the named keys that are available.
Doing a write with no value against a new named key will create
it using a randomly generated key.

Keys can be soft deleted, preserving the current configuration, by
calling DELETE /transit/keys/:name/soft-delete; this can be undone
by calling UPDATE /transit/keys/:name/soft-delete-restore. While the
key is in the soft deleted state, it cannot be used for any operations
and update or rotate will not work.
`
