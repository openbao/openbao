package main

import (
	"os"

	"github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/sdk/v2/joinplugin"
	"github.com/openbao/openbao/v2/internal/builtin/join/static"
)

func main() {
	logger := hclog.Default()

	if err := joinplugin.Serve(joinplugin.ServeOpts{
		Factory: static.Factory,
		Logger:  logger,
	}); err != nil {
		logger.Error(err.Error())
		os.Exit(1)
	}
}
