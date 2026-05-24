package main

import (
	"github.com/openbao/openbao/plugins/join/static"
	"github.com/openbao/openbao/sdk/v2/joinplugin"
)

func main() {
	joinplugin.Serve(&joinplugin.ServeOpts{Factory: static.Factory})
}
