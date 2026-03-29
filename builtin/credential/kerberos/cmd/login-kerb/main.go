// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

// Package main within login-kerb is used for testing the important
// neck of code within the CLI handler. It's used in automated
// integration tests to ensure logins can be performed. It also
// can be useful with "$ make dev-env" for manually testing whether
// logins succeed with new code modifications.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/hashicorp/go-cleanhttp"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"github.com/openbao/openbao/api/v2"
	kerberos "github.com/openbao/openbao/builtin/credential/kerberos"
)

var (
	username               string
	service                string
	realm                  string
	keytabPath             string
	krb5ConfPath           string
	vaultAddr              string
	disableFASTNegotiation bool
)

func init() {
	flag.StringVar(&username, "username", "", `ex: 'grace'`)
	flag.StringVar(&service, "service", "", `ex: 'HTTP/myservice'`)
	flag.StringVar(&realm, "realm", "", `ex: 'MATRIX.LAN'`)
	flag.StringVar(&keytabPath, "keytab_path", "", `ex: '/etc/krb5/krb5.keytab'`)
	flag.StringVar(&krb5ConfPath, "krb5conf_path", "", `ex: '/etc/krb5/krb5.conf'`)
	flag.StringVar(&vaultAddr, "vault_addr", "", `ex: 'http://localhost:8200'`)
	flag.BoolVar(&disableFASTNegotiation, "disable_fast_negotiation", false, `ex: '-disable_fast_negotiation'`)
}

/*
Example usage inside the $DOMAIN_JOINED_CONTAINER:

login-kerb \
	-username=$DOMAIN_USER_ACCOUNT \
	-service="HTTP/$VAULT_CONTAINER_PREFIX.$DNS_NAME:8200" \
	-realm=$REALM_NAME \
	-keytab_path=$KRB5_CLIENT_KTNAME \
	-krb5conf_path=$KRB5_CONFIG \
	-vault_addr="http://$VAULT_CONTAINER_PREFIX.$DNS_NAME:8200" \
	-disable_fast_negotiation
*/

func main() {
	flag.Parse()
	if username == "" {
		fmt.Println(`"username" is required`)
		os.Exit(1)
	}
	if service == "" {
		fmt.Println(`"service" is required`)
		os.Exit(1)
	}
	if realm == "" {
		fmt.Println(`"realm" is required`)
		os.Exit(1)
	}
	if keytabPath == "" {
		fmt.Println(`"keytab_path" is required`)
		os.Exit(1)
	}
	if krb5ConfPath == "" {
		fmt.Println(`"krb5conf_path" is required`)
		os.Exit(1)
	}
	if vaultAddr == "" {
		vaultAddr = api.ReadBaoVariable("BAO_ADDR")
		if vaultAddr == "" {
			fmt.Println(`"vault_addr" is required`)
			os.Exit(1)
		}
	}

	loginCfg := &kerberos.LoginCfg{
		Username:               username,
		Service:                service,
		Realm:                  realm,
		KeytabPath:             keytabPath,
		Krb5ConfPath:           krb5ConfPath,
		DisableFASTNegotiation: disableFASTNegotiation,
	}

	authHeaderVal, err := kerberos.GetAuthHeaderVal(loginCfg)
	if err != nil {
		fmt.Printf("couldn't get auth header: %s", err)
		os.Exit(1)
	}

	req, err := http.NewRequest(http.MethodPost, vaultAddr+"/v1/auth/kerberos/login", nil)
	if err != nil {
		fmt.Printf("couldn't create http request: %s\n", err)
		os.Exit(1)
	}
	req.Header.Set(spnego.HTTPHeaderAuthRequest, authHeaderVal)

	resp, err := cleanhttp.DefaultClient().Do(req)
	if err != nil {
		fmt.Printf("request failed: %s\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close() //nolint:errcheck

	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		fmt.Printf("unexpected OpenBao response %d: %s\n", resp.StatusCode, b)
		os.Exit(1)
	}

	respBody := make(map[string]interface{})
	if err := json.Unmarshal(b, &respBody); err != nil {
		fmt.Printf("err unmarshalling json: %s\n", err)
		os.Exit(1)
	}
	authRaw, ok := respBody["auth"]
	if !ok {
		fmt.Printf("auth doesn't exist in %s\n", respBody)
		os.Exit(1)
	}
	auth, ok := authRaw.(map[string]interface{})
	if !ok {
		fmt.Printf("couldn't convert %s, it's a %t\n", authRaw, authRaw)
		os.Exit(1)
	}
	tokenRaw, ok := auth["client_token"]
	if !ok {
		fmt.Printf("client_token doesn't exist in %s\n", auth)
		os.Exit(1)
	}
	fmt.Printf("OpenBao token through Go: %s\n", tokenRaw)
}
