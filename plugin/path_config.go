package kerberos

import (
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"gopkg.in/jcmturner/gokrb5.v3/keytab"
)

type kerberosConfig struct {
	Keytab         string `json:"keytab"`
	ServiceAccount string `json:"service_account"`
}

func pathConfig(b *kerberosBackend) *framework.Path {
	return &framework.Path{
		Pattern: "config$",
		Fields: map[string]*framework.FieldSchema{
			"keytab": {
				Type:        framework.TypeString,
				Description: `Base64 encoded keytab`,
			},
			"service_account": {
				Type:        framework.TypeString,
				Description: `Service Account`,
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.CreateOperation: b.pathConfigWrite,
			logical.UpdateOperation: b.pathConfigWrite,
			logical.ReadOperation:   b.pathConfigRead,
		},

		HelpSynopsis:    confHelpSynopsis,
		HelpDescription: confHelpDescription,
	}
}

func (b *kerberosBackend) pathConfigRead(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if config, err := b.config(req.Storage); err != nil {
		return nil, err
	} else if config == nil {
		return nil, nil
	} else {
		return &logical.Response{
			Data: map[string]interface{}{
				"keytab":          config.Keytab,
				"service_account": config.ServiceAccount,
			},
		}, nil
	}
}

func (b *kerberosBackend) pathConfigWrite(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	serviceAccount := data.Get("service_account").(string)
	if serviceAccount == "" {
		return nil, errors.New("data does not contain service_account")
	}

	kt := data.Get("keytab").(string)
	if kt == "" {
		return nil, errors.New("data does not contain keytab")
	}

	// Check that the keytab is valid by parsing with krb5go
	binary, err := base64.StdEncoding.DecodeString(kt)
	if err != nil {
		return nil, fmt.Errorf("could not base64 decode keytab: %v", err)
	}
	_, err = keytab.Parse(binary)
	if err != nil {
		return nil, fmt.Errorf("invalid keytab: %v", err)
	}

	config := &kerberosConfig{
		Keytab:         kt,
		ServiceAccount: serviceAccount,
	}

	entry, err := logical.StorageEntryJSON("config", config)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(entry); err != nil {
		return nil, err
	}
	return nil, nil
}

const confHelpSynopsis = `Configures the Kerberos keytab and service account.`
const confHelpDescription = `
The keytab must be base64 encoded, use the output of base64 <vault.keytab>.
`
