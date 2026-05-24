package joinplugin

import (
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
)

type ServeOpts struct {
	Factory Factory
	Logger  hclog.Logger
}

func Serve(opts *ServeOpts) {
	logger := opts.Logger
	if logger == nil {
		logger = hclog.New(&hclog.LoggerOptions{
			Level:      hclog.Info,
			JSONFormat: true,
		})
	}

	factory := func() (Join, error) {
		return opts.Factory(&JoinConfig{Logger: logger})
	}

	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: HandshakeConfig,
		VersionedPlugins: map[int]plugin.PluginSet{
			1: {"join": &joinPlugin{factory: factory}},
		},
		GRPCServer: plugin.DefaultGRPCServer,
		Logger:     logger,
	})
}
