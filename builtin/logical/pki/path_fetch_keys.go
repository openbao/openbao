// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package pki

import (
	"context"
	"fmt"
	"net/http"

	"github.com/openbao/openbao/sdk/v2/helper/certutil"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func pathListKeys(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "keys/?$",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixPKI,
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
				Callback: b.pathListKeysHandler,
				Responses: map[int][]framework.Response{
					http.StatusOK: {{
						Description: "OK",
						Fields: map[string]*framework.FieldSchema{
							"keys": {
								Type:        framework.TypeStringSlice,
								Description: `A list of keys`,
								Required:    true,
							},
							"key_info": {
								Type:        framework.TypeMap,
								Description: `Key info with issuer name`,
								Required:    false,
							},
						},
					}},
				},
				ForwardPerformanceStandby:   false,
				ForwardPerformanceSecondary: false,
			},
		},

		HelpSynopsis:    pathListKeysHelpSyn,
		HelpDescription: pathListKeysHelpDesc,
	}
}

const (
	pathListKeysHelpSyn  = `Fetch a list of all issuer keys`
	pathListKeysHelpDesc = `This endpoint allows listing of known backing keys, returning
their identifier and their name (if set).`
)

func (b *backend) pathListKeysHandler(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if b.useLegacyBundleCaStorage() {
		return logical.ErrorResponse("Can not list keys until migration has completed"), nil
	}

	var responseKeys []string
	responseInfo := make(map[string]interface{})

	after := data.Get("after").(string)
	limit := data.Get("limit").(int)

	sc := b.makeStorageContext(ctx, req.Storage)
	entries, err := sc.listKeysPage(after, limit)
	if err != nil {
		return nil, err
	}

	config, err := sc.getKeysConfig()
	if err != nil {
		return nil, err
	}

	for _, identifier := range entries {
		key, err := sc.fetchKeyById(identifier)
		if err != nil {
			return nil, err
		}

		responseKeys = append(responseKeys, string(identifier))
		responseInfo[string(identifier)] = map[string]interface{}{
			keyNameParam: key.Name,
			"is_default": identifier == config.DefaultKeyId,
		}

	}
	return logical.ListResponseWithInfo(responseKeys, responseInfo), nil
}

func pathKey(b *backend) *framework.Path {
	pattern := "key/" + framework.GenericNameRegex(keyRefParam)

	displayAttrs := &framework.DisplayAttributes{
		OperationPrefix: operationPrefixPKI,
		OperationSuffix: "key",
	}

	return buildPathKey(b, pattern, displayAttrs)
}

func buildPathKey(b *backend, pattern string, displayAttrs *framework.DisplayAttributes) *framework.Path {
	return &framework.Path{
		Pattern:      pattern,
		DisplayAttrs: displayAttrs,

		Fields: map[string]*framework.FieldSchema{
			keyRefParam: {
				Type:        framework.TypeString,
				Description: `Reference to key; either "default" for the configured default key, an identifier of a key, or the name assigned to the key.`,
				Default:     defaultRef,
			},
			keyNameParam: {
				Type:        framework.TypeString,
				Description: `Human-readable name for this key.`,
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathGetKeyHandler,
				Responses: map[int][]framework.Response{
					http.StatusOK: {{
						Description: "OK",
						Fields: map[string]*framework.FieldSchema{
							"key_id": {
								Type:        framework.TypeString,
								Description: `Key Id`,
								Required:    true,
							},
							"key_name": {
								Type:        framework.TypeString,
								Description: `Key Name`,
								Required:    true,
							},
							"key_type": {
								Type:        framework.TypeString,
								Description: `Key Type`,
								Required:    true,
							},
							"subject_key_id": {
								Type:        framework.TypeString,
								Description: `RFC 5280 Subject Key Identifier of the public counterpart`,
								Required:    false,
							},
						},
					}},
				},
				ForwardPerformanceStandby:   false,
				ForwardPerformanceSecondary: false,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathUpdateKeyHandler,
				Responses: map[int][]framework.Response{
					http.StatusNoContent: {{
						Description: "OK",
						Fields: map[string]*framework.FieldSchema{
							"key_id": {
								Type:        framework.TypeString,
								Description: `Key Id`,
								Required:    true,
							},
							"key_name": {
								Type:        framework.TypeString,
								Description: `Key Name`,
								Required:    true,
							},
							"key_type": {
								Type:        framework.TypeString,
								Description: `Key Type`,
								Required:    true,
							},
						},
					}},
				},
				ForwardPerformanceStandby:   true,
				ForwardPerformanceSecondary: true,
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathDeleteKeyHandler,
				Responses: map[int][]framework.Response{
					http.StatusNoContent: {{
						Description: "No Content",
					}},
				},
				ForwardPerformanceStandby:   true,
				ForwardPerformanceSecondary: true,
			},
		},

		HelpSynopsis:    pathKeysHelpSyn,
		HelpDescription: pathKeysHelpDesc,
	}
}

const (
	pathKeysHelpSyn  = `Fetch a single issuer key`
	pathKeysHelpDesc = `This allows fetching information associated with the underlying key.

:ref can be either the literal value "default", in which case /config/keys
will be consulted for the present default key, an identifier of a key,
or its assigned name value.

Writing to /key/:ref allows updating of the name field associated with
the certificate.
`
)

func (b *backend) pathGetKeyHandler(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if b.useLegacyBundleCaStorage() {
		return logical.ErrorResponse("Can not get keys until migration has completed"), nil
	}

	keyRef := data.Get(keyRefParam).(string)
	if len(keyRef) == 0 {
		return logical.ErrorResponse("missing key reference"), nil
	}

	sc := b.makeStorageContext(ctx, req.Storage)
	keyId, err := sc.resolveKeyReference(keyRef)
	if err != nil {
		return nil, err
	}
	if keyId == "" {
		return logical.ErrorResponse("unable to resolve key id for reference" + keyRef), nil
	}

	key, err := sc.fetchKeyById(keyId)
	if err != nil {
		return nil, err
	}

	respData := map[string]interface{}{
		keyIdParam:   key.ID,
		keyNameParam: key.Name,
		keyTypeParam: string(key.PrivateKeyType),
	}

	pkForSkid, err := getPublicKeyFromBytes([]byte(key.PrivateKey))
	if err != nil {
		return nil, err
	}

	skid, err := certutil.GetSubjectKeyID(pkForSkid)
	if err != nil {
		return nil, err
	}
	respData[skidParam] = certutil.GetHexFormatted([]byte(skid), ":")

	return &logical.Response{Data: respData}, nil
}

func (b *backend) pathUpdateKeyHandler(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	// Since we're planning on updating keys here, grab the lock so we've
	// got a consistent view.
	b.issuersLock.Lock()
	defer b.issuersLock.Unlock()

	if b.useLegacyBundleCaStorage() {
		return logical.ErrorResponse("Can not update keys until migration has completed"), nil
	}

	keyRef := data.Get(keyRefParam).(string)
	if len(keyRef) == 0 {
		return logical.ErrorResponse("missing key reference"), nil
	}

	sc := b.makeStorageContext(ctx, req.Storage)
	keyId, err := sc.resolveKeyReference(keyRef)
	if err != nil {
		return nil, err
	}
	if keyId == "" {
		return logical.ErrorResponse("unable to resolve key id for reference" + keyRef), nil
	}

	key, err := sc.fetchKeyById(keyId)
	if err != nil {
		return nil, err
	}

	newName := data.Get(keyNameParam).(string)
	if len(newName) > 0 && !nameMatcher.MatchString(newName) {
		return logical.ErrorResponse("new key name outside of valid character limits"), nil
	}

	if newName != key.Name {
		key.Name = newName

		err := sc.writeKey(*key)
		if err != nil {
			return nil, err
		}
	}

	resp := &logical.Response{
		Data: map[string]interface{}{
			keyIdParam:   key.ID,
			keyNameParam: key.Name,
			keyTypeParam: key.PrivateKeyType,
		},
	}

	if len(newName) == 0 {
		resp.AddWarning("Name successfully deleted, you will now need to reference this key by it's Id: " + string(key.ID))
	}

	return resp, nil
}

func (b *backend) pathDeleteKeyHandler(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	// Since we're planning on updating issuers here, grab the lock so we've
	// got a consistent view.
	b.issuersLock.Lock()
	defer b.issuersLock.Unlock()

	if b.useLegacyBundleCaStorage() {
		return logical.ErrorResponse("Can not delete keys until migration has completed"), nil
	}

	keyRef := data.Get(keyRefParam).(string)
	if len(keyRef) == 0 {
		return logical.ErrorResponse("missing key reference"), nil
	}

	sc := b.makeStorageContext(ctx, req.Storage)
	keyId, err := sc.resolveKeyReference(keyRef)
	if err != nil {
		if keyId == KeyRefNotFound {
			// We failed to lookup the key, we should ignore any error here and reply as if it was deleted.
			return nil, nil
		}
		return nil, err
	}

	keyInUse, issuerId, err := sc.isKeyInUse(keyId.String())
	if err != nil {
		return nil, err
	}
	if keyInUse {
		return logical.ErrorResponse("Failed to Delete Key.  Key in Use by Issuer: %s", issuerId), nil
	}

	wasDefault, err := sc.deleteKey(keyId)
	if err != nil {
		return nil, err
	}

	var response *logical.Response
	if wasDefault {
		msg := fmt.Sprintf("Deleted key %v (via key_ref %v); this was configured as the default key. Operations without an explicit key will not work until a new default is configured.", string(keyId), keyRef)
		b.Logger().Error(msg)
		response = &logical.Response{}
		response.AddWarning(msg)
	}

	return response, nil
}
