package main

import (
	"github.com/openbao/openbao/sdk/v2/joinplugin"
	"github.com/openbao/openbao/v2/internal/builtin/join/static"
)

func main() {
	joinplugin.Serve(&joinplugin.ServeOpts{Factory: static.Factory})
}
