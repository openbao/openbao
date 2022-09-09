package openldap

import (
	"fmt"

	"github.com/go-ldap/ldif"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault-plugin-secrets-openldap/client"
)

type ldapClient interface {
	UpdatePassword(conf *client.Config, dn string, newPassword string) error
	UpdateRootPassword(conf *client.Config, newPassword string) error
	Execute(conf *client.Config, entries []*ldif.Entry, continueOnError bool) (err error)
}

func NewClient(logger hclog.Logger) *Client {
	return &Client{
		ldap: client.New(logger),
	}
}

var _ ldapClient = (*Client)(nil)

type Client struct {
	ldap client.Client
}

func (c *Client) UpdatePassword(conf *client.Config, dn string, newPassword string) error {
	filters := map[*client.Field][]string{client.FieldRegistry.ObjectClass: {"*"}}

	newValues, err := client.GetSchemaFieldRegistry(conf.Schema, newPassword)
	if err != nil {
		return fmt.Errorf("error updating password: %s", err)
	}

	return c.ldap.UpdatePassword(conf, dn, newValues, filters)
}

func (c *Client) UpdateRootPassword(conf *client.Config, newPassword string) error {
	filters := map[*client.Field][]string{client.FieldRegistry.ObjectClass: {"*"}}
	newValues, err := client.GetSchemaFieldRegistry(conf.Schema, newPassword)
	if err != nil {
		return fmt.Errorf("error updating password: %s", err)
	}

	return c.ldap.UpdatePassword(conf, conf.BindDN, newValues, filters)
}

func (c *Client) Execute(conf *client.Config, entries []*ldif.Entry, continueOnError bool) (err error) {
	return c.ldap.Execute(conf, entries, continueOnError)
}
