package main

import (
	"os"

	log "github.com/mgutz/logxi/v1"

	"github.com/hashicorp/vault-plugin-auth-kubernetes"
	"github.com/hashicorp/vault/helper/pluginutil"
	"github.com/hashicorp/vault/logical/plugin"
)

func main() {
	apiClientMeta := &pluginutil.APIClientMeta{}
	flags := apiClientMeta.FlagSet()
	flags.Parse(os.Args[1:])

	tlsConfig := apiClientMeta.GetTLSConfig()
	tlsProviderFunc := pluginutil.VaultPluginTLSProvider(tlsConfig)

	err := plugin.Serve(&plugin.ServeOpts{
		BackendFactoryFunc: kubeauth.Factory,
		TLSProviderFunc:    tlsProviderFunc,
	})
	if err != nil {
		log.Error("plugin shutting down", "error", err)
		os.Exit(1)
	}
}
