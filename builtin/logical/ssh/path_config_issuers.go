package ssh

import (
	"context"
	"fmt"
	"net/http"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func pathConfigIssuers(b *backend) *framework.Path {
	configIssuerSchema := map[int][]framework.Response{
		http.StatusOK: {{
			Description: "OK",
			Fields: map[string]*framework.FieldSchema{
				"default": {
					Type:        framework.TypeString,
					Description: `Reference (name or identifier) to issuer set as the default.`,
					Required:    true,
				},
			},
		}},
	}
	return &framework.Path{
		Pattern: "config/issuers",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixSSH,
			OperationSuffix: "issuer-config",
		},

		Fields: map[string]*framework.FieldSchema{
			defaultRef: {
				Type:        framework.TypeString,
				Description: `Reference (name or identifier) to issuer to be used as the default.`,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathReadDefaultIssuerHandler,
				DisplayAttrs: &framework.DisplayAttributes{
					OperationSuffix: "read",
				},
				Responses: configIssuerSchema,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathWriteDefaultIssuerHandler,
				DisplayAttrs: &framework.DisplayAttributes{
					OperationVerb: "write",
				},
				Responses: configIssuerSchema,
			},
		},

		HelpSynopsis:    pathConfigIssuersSyn,
		HelpDescription: pathConfigIssuersDesc,
	}
}

func (b *backend) pathReadDefaultIssuerHandler(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	sc := b.makeStorageContext(ctx, req.Storage)
	config, err := sc.getIssuersConfig()
	if err != nil {
		return handleStorageContextErr(err, "error loading issuers configuration")
	}

	if len(config.DefaultIssuerID) == 0 {
		return logical.ErrorResponse("no default issuer currently configured"), nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			defaultRef: config.DefaultIssuerID,
		},
	}, nil
}

func (b *backend) pathWriteDefaultIssuerHandler(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// Since we're planning on updating issuers here, grab the lock so we've
	// got a consistent view.
	b.issuersLock.Lock()
	defer b.issuersLock.Unlock()

	txRollback, err := logical.StartTxStorage(ctx, req)
	if err != nil {
		return nil, err
	}
	defer txRollback()

	sc := b.makeStorageContext(ctx, req.Storage)

	// Validate the new default reference.
	newDefault := getDefaultRef(d)
	if len(newDefault) == 0 || newDefault == defaultRef {
		return logical.ErrorResponse("invalid issuer specification; must be non-empty and can't be 'default'."), nil
	}
	parsedIssuer, err := sc.resolveIssuerReference(newDefault)
	if err != nil {
		return handleStorageContextErr(err, "error resolving issuer reference")
	}

	// Update the config
	config, err := sc.getIssuersConfig()
	if err != nil {
		return handleStorageContextErr(err, "unable to fetch existing issuers configuration")
	}

	response := &logical.Response{}
	if parsedIssuer == config.DefaultIssuerID {
		response.AddWarning("The default issuer is already set to the specified issuer.")
		return response, nil
	}

	oldDefault := config.DefaultIssuerID
	config.DefaultIssuerID = parsedIssuer

	if err := sc.setIssuersConfig(config); err != nil {
		return handleStorageContextErr(err, "error updating issuer configuration")
	}

	if err := logical.EndTxStorage(ctx, req); err != nil {
		return nil, err
	}

	response.Data = map[string]interface{}{
		defaultRef: config.DefaultIssuerID,
	}

	if len(oldDefault) != 0 {
		warningMessage := fmt.Sprintf("Previous default (%s) has been updated with the issuer '%s'", oldDefault, newDefault)
		if parsedIssuer != newDefault {
			warningMessage += fmt.Sprintf(" (resolved to %s)", parsedIssuer)
		}
		response.AddWarning(warningMessage)
	}
	return response, nil
}

const (
	pathConfigIssuersSyn  = `Configure or read the default SSH certificate issuer.`
	pathConfigIssuersDesc = `
This endpoint allows configuring or reading the default issuer for SSH certificates.

The body parameter 'default' is the reference (name or identifier) to the default issuer.
`
)
