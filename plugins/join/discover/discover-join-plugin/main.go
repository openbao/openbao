package main

import (
	"os"

	"github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/plugins/join/discover"
	"github.com/openbao/openbao/sdk/v2/joinplugin"
)

func main() {
	logger := hclog.New(&hclog.LoggerOptions{
		Level:      hclog.Info,
		JSONFormat: true,
	})

	if err := joinplugin.Serve(joinplugin.ServeOpts{
		Factory: discover.Factory,
		Logger:  logger,
	}); err != nil {
		logger.Error(err.Error())
		os.Exit(1)
	}
}
