package joinplugin

import "github.com/hashicorp/go-plugin"

type ServeOpts struct {
	Factory Factory
}

func Serve(opts ServeOpts) error {
	impl, err := opts.Factory()
	if err != nil {
		return err
	}

	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: HandshakeConfig,
		Plugins: plugin.PluginSet{
			"join": &JoinPlugin{Impl: impl},
		},
		GRPCServer: plugin.DefaultGRPCServer,
	})
	return nil
}
