package kerberos

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/api"
	"github.com/tyrannosaurus-becks/gokrb5/client"
	"github.com/tyrannosaurus-becks/gokrb5/config"
	"github.com/tyrannosaurus-becks/gokrb5/keytab"
	"github.com/tyrannosaurus-becks/gokrb5/spnego"
)

// Auth fulfills the CLI handler interface in Vault and is intended to
// be used there.
func Auth(c *api.Client, m map[string]string) (*api.Secret, error) {
	mount, ok := m["mount"]
	if !ok {
		mount = "kerberos"
	}
	username := m["username"]
	if username == "" {
		return nil, errors.New(`"username" is required`)
	}
	service := m["service"]
	if service == "" {
		return nil, errors.New(`"service" is required`)
	}
	realm := m["realm"]
	if realm == "" {
		return nil, errors.New(`"realm" is required`)
	}
	keytabPath := m["keytab_path"]
	if keytabPath == "" {
		return nil, errors.New(`"keytab_path" is required`)
	}
	krb5ConfPath := m["krb5conf_path"]
	if krb5ConfPath == "" {
		return nil, errors.New(`"krb5conf_path" is required`)
	}

	loginCfg := &LoginCfg{
		Username:     username,
		Service:      service,
		Realm:        realm,
		KeytabPath:   keytabPath,
		Krb5ConfPath: krb5ConfPath,
	}

	authHeaderVal, err := GetAuthHeaderVal(loginCfg)
	if err != nil {
		return nil, err
	}
	headers := http.Header{}
	headers.Set(spnego.HTTPHeaderAuthRequest, authHeaderVal)
	c.SetHeaders(headers)

	path := fmt.Sprintf("auth/%s/login", mount)

	secret, err := c.Logical().Write(path, nil)
	if err != nil {
		return nil, err
	}
	if secret == nil {
		return nil, errors.New("empty response from credential provider")
	}
	return secret, nil
}

// LoginCfg is a struct with explicitly-named string fields to prevent
// bugs related to incorrectly ordering the strings being passed into
// GetAuthHeaderVal.
type LoginCfg struct {
	Username, Service, Realm, KeytabPath, Krb5ConfPath string
}

// GetAuthHeaderVal is a convenience function that takes a given loginCfg
// and returns the value for the "Authorization" header that should be
// provided to Vault for a successful SPNEGO login.
func GetAuthHeaderVal(loginCfg *LoginCfg) (string, error) {
	kt, err := keytab.Load(loginCfg.KeytabPath)
	if err != nil {
		return "", errwrap.Wrapf("couldn't load keytab: {{err}}", err)
	}

	krb5Conf, err := config.Load(loginCfg.Krb5ConfPath)
	if err != nil {
		return "", errwrap.Wrapf("couldn't parse krb5Conf: {{err}}", err)
	}

	cl := client.NewClientWithKeytab(loginCfg.Username, loginCfg.Realm, kt, krb5Conf, client.AssumePreAuthentication(true))
	if err := cl.Login(); err != nil {
		return "", errwrap.Wrapf("couldn't log in: {{err}}", err)
	}
	defer cl.Destroy()

	spnegoClient := spnego.SPNEGOClient(cl, loginCfg.Service)
	if err := spnegoClient.AcquireCred(); err != nil {
		return "", errwrap.Wrapf("couldn't acquire client credential: {{err}}", err)
	}
	spnegoToken, err := spnegoClient.InitSecContext()
	if err != nil {
		return "", errwrap.Wrapf("couldn't initialize context: {{err}}", err)
	}
	marshalledToken, err := spnegoToken.Marshal()
	if err != nil {
		return "", errwrap.Wrapf("couldn't marshal SPNEGO: {{err}}", err)
	}
	authHeaderVal := "Negotiate " + base64.StdEncoding.EncodeToString(marshalledToken)
	return authHeaderVal, nil
}
