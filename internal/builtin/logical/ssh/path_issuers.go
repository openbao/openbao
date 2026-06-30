package ssh

import (
	"context"
	"fmt"
	"net/http"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func pathIssuers(b *backend) *framework.Path {
	fields := map[string]*framework.FieldSchema{}
	fields = addIssuerRefField(fields)
	fields = addIssuerNameField(fields)

	return &framework.Path{
		Pattern: "issuer/" + framework.GenericNameRegex("issuer_ref"),

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixSSH,
			OperationSuffix: "issuer",
		},

		Fields: fields,

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathReadIssuerHandler,
				DisplayAttrs: &framework.DisplayAttributes{
					OperationVerb: "read",
				},
				Responses: map[int][]framework.Response{
					http.StatusOK: {{
						Description: "OK",
						Fields:      issuerOKResponseFields,
					}},
				},
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathUpdateIssuerHandler,
				DisplayAttrs: &framework.DisplayAttributes{
					OperationVerb: "update",
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
					OperationVerb: "delete",
				},
				Responses: map[int][]framework.Response{
					http.StatusOK: {{
						Description: "OK",
					}},
				},
			},
		},
		HelpSynopsis:    pathIssuersSyn,
		HelpDescription: pathIssuersDesc,
	}
}

func pathImportIssuer(b *backend) *framework.Path {
	fields := map[string]*framework.FieldSchema{}
	fields = addSubmitIssuerCommonFields(fields)

	fields["set_default"] = &framework.FieldSchema{
		Type:        framework.TypeBool,
		Description: `If true, this issuer will be set as the default issuer for performing operations. Only one issuer can be the default issuer and, if there's one set, it will be overridden.`,
		Default:     false,
	}

	return &framework.Path{
		Pattern: "issuers/import" + framework.OptionalGenericNameRegex("issuer_name"),

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixSSH,
			OperationVerb:   "submit",
			OperationSuffix: "issuer",
		},

		Fields: fields,

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathWriteIssuerHandler,
				DisplayAttrs: &framework.DisplayAttributes{
					OperationVerb:   "submit",
					OperationSuffix: "issuer",
				},
				Responses: map[int][]framework.Response{
					http.StatusOK: {
						{
							Description: "OK",
							Fields:      issuerOKResponseFields,
						},
					},
				},
			},
		},

		HelpSynopsis:    pathImportIssuerSyn,
		HelpDescription: pathImportIssuerDesc,
	}
}

func pathListIssuers(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "issuers/?$",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixSSH,
			OperationVerb:   "list",
			OperationSuffix: "issuers",
		},

		Fields: map[string]*framework.FieldSchema{
			"after": {
				Type:        framework.TypeString,
				Required:    false,
				Description: `Optional entry to list begin listing after, not required to exist.`,
			},
			"limit": {
				Type:        framework.TypeInt,
				Required:    false,
				Description: `Optional number of entries to return; defaults to all entries.`,
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{
				Callback: b.pathListIssuersHandler,
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
								Description: `Key info with issuer identifier`,
								Required:    false,
							},
						},
					}},
				},
			},
		},

		HelpSynopsis:    pathListIssuersSyn,
		HelpDescription: pathListIssuersDesc,
	}
}

func pathGetIssuerPublicKeyUnauthenticated(b *backend) *framework.Path {
	fields := map[string]*framework.FieldSchema{}
	fields = addIssuerRefField(fields)

	return &framework.Path{
		Pattern: "issuer/" + framework.GenericNameRegex("issuer_ref") + "/public_key",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixSSH,
			OperationVerb:   "get",
			OperationSuffix: "issuer",
		},

		Fields: fields,

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathGetIssuerPublicKeyHandler,
				Responses: map[int][]framework.Response{
					http.StatusOK: {
						{
							Description: "OK",
						},
					},
				},
			},
		},

		HelpSynopsis:    pathIssuersSyn,
		HelpDescription: pathGetIssuerUnauthenticatedDesc,
	}
}

func (b *backend) pathGetIssuerPublicKeyHandler(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	txRollback, err := logical.StartTxStorage(ctx, req)
	if err != nil {
		return nil, err
	}
	defer txRollback()

	issuerRef := getIssuerRef(d)

	sc := b.makeStorageContext(ctx, req.Storage)
	id, err := sc.resolveIssuerReference(issuerRef)
	if err != nil {
		return handleStorageContextErr(err)
	}

	issuer, err := sc.fetchIssuerById(id)
	if err != nil {
		return handleStorageContextErr(err)
	}

	if err := logical.EndTxStorage(ctx, req); err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			logical.HTTPContentType: "text/plain",
			logical.HTTPRawBody:     []byte(issuer.PublicKey),
			logical.HTTPStatusCode:  http.StatusOK,
		},
	}, nil
}

func (b *backend) pathReadIssuerHandler(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	sc := b.makeStorageContext(ctx, req.Storage)

	// This handler is used by two endpoints, `config/ca` and `issuer/{issuer_ref}`
	// If called from `config/ca`, we don't want to check the reference provided and fetch the default issuer
	isConfigCARequest := req.Path == "config/ca"

	var issuer *issuerEntry
	var err error
	if isConfigCARequest {
		issuer, err = sc.fetchDefaultIssuer()
	} else {
		issuerRef := getIssuerRef(d)
		var id string
		id, err = sc.resolveIssuerReference(issuerRef)
		if err == nil {
			issuer, err = sc.fetchIssuerById(id)
		}
	}

	if err != nil {
		return handleStorageContextErr(err)
	}

	return respondReadIssuer(issuer)
}

func (b *backend) pathUpdateIssuerHandler(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	txRollback, err := logical.StartTxStorage(ctx, req)
	if err != nil {
		return nil, err
	}
	defer txRollback()

	// Since we're planning on updating issuers here, grab the lock so we've
	// got a consistent view.
	b.issuersLock.Lock()
	defer b.issuersLock.Unlock()

	issuerRef := getIssuerRef(d)

	sc := b.makeStorageContext(ctx, req.Storage)
	id, err := sc.resolveIssuerReference(issuerRef)
	if err != nil {
		return handleStorageContextErr(err)
	}

	issuer, err := sc.fetchIssuerById(id)
	if err != nil {
		return handleStorageContextErr(err)
	}

	newName, err := getIssuerName(sc, d)
	if err != nil {
		switch err {
		// If the error is name already in use, and the new name is the
		// old name for this issuer, we're not actually updating the
		// issuer name (or causing a conflict) -- so don't err out. Other
		// errs should still be surfaced.
		case errIssuerNameInUse:
			if issuer.Name != newName {
				// When the new name is in use but isn't this name, throw an error.
				return logical.ErrorResponse(err.Error()), nil
			}
			return respondReadIssuer(issuer)
		default:
			return handleStorageContextErr(err)
		}
	}

	oldName := issuer.Name
	issuer.Name = newName

	err = sc.writeIssuer(issuer)
	if err != nil {
		return handleStorageContextErr(err)
	}

	response, _ := respondReadIssuer(issuer)
	addWarningOnDereferencing(sc, oldName, response)

	if err := logical.EndTxStorage(ctx, req); err != nil {
		return nil, err
	}

	return response, nil
}

func (b *backend) pathDeleteIssuerHandler(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// Since we're planning on updating issuers here, grab the lock so we've
	// got a consistent view.
	b.issuersLock.Lock()
	defer b.issuersLock.Unlock()

	// This handler is used by two endpoints, `config/ca` and `issuer/{issuer_ref}`
	// If called from `config/ca`, we want to delete all generated or imported issuers
	// otherwise just the one passed in by reference
	isConfigCARequest := req.Path == "config/ca"

	txRollback, err := logical.StartTxStorage(ctx, req)
	if err != nil {
		return nil, err
	}
	defer txRollback()

	sc := b.makeStorageContext(ctx, req.Storage)

	response := &logical.Response{}
	if isConfigCARequest {
		issuersDeleted, err := sc.purgeIssuers()
		if err != nil {
			return handleStorageContextErr(err, "failed to delete issuers")
		}
		if issuersDeleted > 0 {
			response.AddWarning(fmt.Sprintf("Deleted %d issuers, including default issuer if configured.", issuersDeleted))
		}
	} else {
		issuerRef := getIssuerRef(d)
		id, err := sc.resolveIssuerReference(issuerRef)
		if err != nil {
			// Return as if we deleted it if we fail to lookup the issuer.
			if id == IssuerRefNotFound {
				return nil, nil
			}
			return handleStorageContextErr(err)
		}

		issuer, err := sc.fetchIssuerById(id)
		if err != nil {
			return handleStorageContextErr(err)
		}
		if issuer.Name != "" {
			addWarningOnDereferencing(sc, issuer.Name, response)
		}
		addWarningOnDereferencing(sc, string(issuer.ID), response)

		wasDefault, err := sc.deleteIssuer(id)
		if err != nil {
			return handleStorageContextErr(err)
		}

		if wasDefault {
			response.AddWarning(fmt.Sprintf("Deleted issuer %v (via issuer_ref %v); this was configured as the default issuer. Operations without an explicit issuer will not work until a new default is configured.", id, issuerRef))
			addWarningOnDereferencing(sc, defaultRef, response)
		}
	}

	if err := logical.EndTxStorage(ctx, req); err != nil {
		return nil, err
	}

	//  If there are no warnings to be returned, the response status code should be 204
	if len(response.Warnings) == 0 {
		return nil, nil
	}

	return response, nil
}

func (b *backend) pathWriteIssuerHandler(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// Since we're planning on updating issuers here, grab the lock so we've
	// got a consistent view.
	b.issuersLock.Lock()
	defer b.issuersLock.Unlock()

	// This handler is used by two endpoints, `config/ca` and `issuers/import/{issuer_name}`
	// If called from `config/ca`, we don't want to explicitly set a name neither check if `set_default` is set
	isConfigCARequest := req.Path == "config/ca"

	publicKey, privateKey, generatedKeyMaterial, err := b.handleKeyGeneration(d)
	if err != nil {
		return handleStorageContextErr(err)
	}

	txRollback, err := logical.StartTxStorage(ctx, req)
	if err != nil {
		return nil, err
	}
	defer txRollback()

	sc := b.makeStorageContext(ctx, req.Storage)

	// Depending on the request, we may need to fetch the issuer name
	// and whether the issuer should be set as the default
	var issuerName string
	setDefault := true
	if !isConfigCARequest {

		issuerName, err = getIssuerName(sc, d)
		if err != nil && err != errIssuerNameIsEmpty {
			return handleStorageContextErr(err)
		}

		setDefault = d.Get("set_default").(bool)
	}

	issuer, existing, err := sc.ImportIssuer(publicKey, privateKey, generatedKeyMaterial, issuerName, setDefault)
	if err != nil {
		return handleStorageContextErr(err, "failed to persist the issuer")
	}

	response, _ := respondReadIssuer(issuer)
	if existing {
		response.AddWarning("An issuer with the provided public key already exists, returning the existing issuer")
	}

	if err := logical.EndTxStorage(ctx, req); err != nil {
		return nil, err
	}

	// Whether an key material is generated or submitted, we return the issuer's data always.
	return response, nil
}

func (b *backend) pathListIssuersHandler(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	var responseKeys []string
	responseInfo := make(map[string]interface{})

	after := d.Get("after").(string)
	limit := d.Get("limit").(int)

	sc := b.makeStorageContext(ctx, req.Storage)
	entries, err := sc.listIssuersPage(after, limit)
	if err != nil {
		return nil, err
	}

	config, err := sc.getIssuersConfig()
	if err != nil {
		return nil, err
	}

	// For each issuer, we need not only the identifier (as returned by
	// listIssuers), but also the name of the issuer and its public key.
	// This means we have to fetch the actual issuer object as well.
	for _, identifier := range entries {
		issuer, err := sc.fetchIssuerById(identifier)
		if err != nil {
			return nil, err
		}

		responseKeys = append(responseKeys, string(identifier))
		responseInfo[string(identifier)] = map[string]interface{}{
			"issuer_name": issuer.Name,
			"is_default":  identifier == config.DefaultIssuerID,
			"public_key":  issuer.PublicKey,
		}
	}

	return logical.ListResponseWithInfo(responseKeys, responseInfo), nil
}

func respondReadIssuer(issuer *issuerEntry) (*logical.Response, error) {
	data := map[string]interface{}{
		"issuer_id":   issuer.ID,
		"issuer_name": issuer.Name,
		"public_key":  issuer.PublicKey,
	}

	response := &logical.Response{
		Data: data,
	}

	return response, nil
}

func addWarningOnDereferencing(sc *storageContext, name string, resp *logical.Response) {
	timeout, inUseBy, err := sc.checkForRolesReferencingIssuer(name)
	if err != nil || timeout {
		if inUseBy == 0 {
			resp.AddWarning(fmt.Sprintf("Unable to check if any roles referenced this issuer by '%s'", name))
		} else {
			resp.AddWarning(fmt.Sprintf("The name '%s' was in use by at least %d roles", name, inUseBy))
		}
	} else {
		if inUseBy > 0 {
			resp.AddWarning(fmt.Sprintf("%d roles reference '%s'", inUseBy, name))
		}
	}
}

const (
	pathListIssuersSyn  = `Fetch a list of all issuers.`
	pathListIssuersDesc = `
This endpoints allows listing of all the issuers that have been generated
or submited, returning their identifier, name (if set) and public key.
`
	pathIssuersSyn  = `Fetch a single issuer.`
	pathIssuersDesc = `
This endpoint allows fetching information associated with the issuer
reference provided.

:issuer_ref can be either the literal value "default", in which case /config/issuers
will be consulted for the present default issuer, an identifier of an issuer,
or its assigned name value.

Writing to /issuer/:issuer_ref allows updating of the name field associated with
the certificate. Updates of an issuer's name can break existing roles that references.

Delete operations will remove the issuer from the backend and, if configured as default,
dereference it as the default issuer.
`
	pathGetIssuerUnauthenticatedDesc = `
This endpoint allows fetching the public key of an issuer without authentication.
`

	pathImportIssuerSyn  = `Submit a new issuer with an optional explicit name.`
	pathImportIssuerDesc = `
This endpoint allows submitting a new issuer with an optional explicit name. If the
name is not provided, the issuer will be created with an empty name. The issuer will
be set as the default issuer if the 'set_default' field is set to true.On the
submission of the first issuer, the default reference will be set to it independently
of this parameter.
`
)
