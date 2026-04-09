package joinplugin

import (
	"os"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
)

type ServeOpts struct {
	Factory Factory
	Logger  hclog.Logger
}

func Serve(opts ServeOpts) error {
	logger := opts.Logger
	if logger == nil {
		logger = hclog.New(&hclog.LoggerOptions{
			Level:      hclog.Info,
			Output:     os.Stderr,
			JSONFormat: true,
		})
	}

	impl, err := opts.Factory()
	if err != nil {
		// Don't log returned error, caller will handle it,
		return err
	}

	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: HandshakeConfig,
		VersionedPlugins: map[int]plugin.PluginSet{
			1: {"join": &joinPlugin{impl: impl}},
		},
		GRPCServer: plugin.DefaultGRPCServer,
		Logger:     logger,
	})
	return nil
}
