package kerberos

import (
	"context"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/ldaputil"
	"github.com/hashicorp/vault/sdk/logical"
)

const ldapConfPath = "config/ldap"

func pathConfigLdap(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: ldapConfPath,
		Fields:  ldaputil.ConfigFields(),

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation:   b.pathConfigLdapRead,
			logical.UpdateOperation: b.pathConfigLdapWrite,
		},

		HelpSynopsis:    pathConfigLdapHelpSyn,
		HelpDescription: pathConfigLdapHelpDesc,
	}
}

// ConfigLDAP reads the present ldap config.
func (b *backend) ConfigLdap(ctx context.Context, req *logical.Request) (*ldaputil.ConfigEntry, error) {
	entry, err := req.Storage.Get(ctx, ldapConfPath)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	cfg := &ldaputil.ConfigEntry{}
	if err := entry.DecodeJSON(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (b *backend) pathConfigLdapRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	cfg, err := b.ConfigLdap(ctx, req)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, nil
	}
	return &logical.Response{
		Data: cfg.PasswordlessMap(),
	}, nil
}

func (b *backend) pathConfigLdapWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	existingCfg, err := b.ConfigLdap(ctx, req)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	// existingCfg might be nil here but that's ok because
	// NewConfigEntry will just do the right thing.
	newCfg, err := ldaputil.NewConfigEntry(existingCfg, d)
	if err != nil {
		return nil, err
	}

	entry, err := logical.StorageEntryJSON(ldapConfPath, newCfg)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}
	return nil, nil
}

const pathConfigLdapHelpSyn = `
Configure the LDAP server to connect to, along with its options.
`

const pathConfigLdapHelpDesc = `
This endpoint allows you to configure the LDAP server to connect to and its
configuration options.

The LDAP URL can use either the "ldap://" or "ldaps://" schema. In the former
case, an unencrypted connection will be made with a default port of 389, unless
the "starttls" parameter is set to true, in which case TLS will be used. In the
latter case, a SSL connection will be established with a default port of 636.

## A NOTE ON ESCAPING

It is up to the administrator to provide properly escaped DNs. This includes
the user DN, bind DN for search, and so on.

The only DN escaping performed by this backend is on usernames given at login
time when they are inserted into the final bind DN, and uses escaping rules
defined in RFC 4514.

Additionally, Active Directory has escaping rules that differ slightly from the
RFC; in particular it requires escaping of '#' regardless of position in the DN
(the RFC only requires it to be escaped when it is the first character), and
'=', which the RFC indicates can be escaped with a backslash, but does not
contain in its set of required escapes. If you are using Active Directory and
these appear in your usernames, please ensure that they are escaped, in
addition to being properly escaped in your configured DNs.

For reference, see https://www.ietf.org/rfc/rfc4514.txt and
http://social.technet.microsoft.com/wiki/contents/articles/5312.active-directory-characters-to-escape.aspx
`
