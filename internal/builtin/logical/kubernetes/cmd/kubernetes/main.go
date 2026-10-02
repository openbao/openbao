// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"errors"
	"flag"
	"os"

	"github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/sdk/v2/plugin"
	kubesecrets "github.com/openbao/openbao/v2/internal/builtin/logical/kubernetes"
)

func main() {
	apiClientMeta := &api.PluginAPIClientMeta{}
	flags := apiClientMeta.FlagSet()

	logger := hclog.New(&hclog.LoggerOptions{})
	if err := flags.Parse(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}

		logger.Error("error parsing arguments", "error", err)
		os.Exit(1)
	}

	tlsConfig := apiClientMeta.GetTLSConfig()
	tlsProviderFunc := api.VaultPluginTLSProvider(tlsConfig)

	err := plugin.ServeMultiplex(&plugin.ServeOpts{
		BackendFactoryFunc: kubesecrets.Factory,
		// set the TLSProviderFunc so that the plugin maintains backwards
		// compatibility with Vault versions that don’t support plugin AutoMTLS
		TLSProviderFunc: tlsProviderFunc,
	})
	if err != nil {
		logger.Error("plugin shutting down", "error", err)
		os.Exit(1)
	}
}
