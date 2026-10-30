package main

import (
	"os"

	"github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/sdk/v2/plugin"
	"github.com/openbao/openbao/v2/internal/builtin/logical/kv"
)

func main() {
	if err := plugin.Serve(&plugin.ServeOpts{
		BackendFactoryFunc: kv.Factory,
	}); err != nil {
		logger := hclog.New(&hclog.LoggerOptions{})
		logger.Error("plugin shutting down", "error", err)
		os.Exit(1)
	}
}
