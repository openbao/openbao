// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"log"
	"os"

	jwtauth "github.com/hashicorp/vault-plugin-auth-jwt"
	"github.com/openbao/openbao/api"
	"github.com/openbao/openbao/sdk/plugin"
)

func main() {
	apiClientMeta := &api.PluginAPIClientMeta{}
	flags := apiClientMeta.FlagSet()

	if err := flags.Parse(os.Args[1:]); err != nil {
		log.Println(err)
		os.Exit(1)
	}

	tlsConfig := apiClientMeta.GetTLSConfig()
	tlsProviderFunc := api.VaultPluginTLSProvider(tlsConfig)

	err := plugin.ServeMultiplex(&plugin.ServeOpts{
		BackendFactoryFunc: jwtauth.Factory,
		// set the TLSProviderFunc so that the plugin maintains backwards
		// compatibility with Vault versions that don’t support plugin AutoMTLS
		TLSProviderFunc: tlsProviderFunc,
	})
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
}
