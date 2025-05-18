package joinplugin

import (
	"context"
	"errors"
	"fmt"

	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
	"github.com/openbao/openbao/sdk/v2/helper/pluginutil"
)

type JoinPluginClient struct {
	Join

	client *plugin.Client
}

func (c *JoinPluginClient) Cleanup(ctx context.Context) error {
	c.client.Kill()
	return nil
}

func NewJoin(ctx context.Context, pluginName string, plugins map[string]pluginutil.PluginRunner, logger log.Logger) (Join, error) {
	pluginRunner, found := plugins[pluginName]
	if !found {
		return nil, fmt.Errorf("no plugin with name %s found", pluginName)
	}

	if pluginRunner.Builtin {
		rawFactory, err := pluginRunner.BuiltinFactory()
		if err != nil {
			return nil, fmt.Errorf("error getting plugin type: %q", err)
		}

		factory, ok := rawFactory.(Factory)
		if !ok {
			return nil, fmt.Errorf("unsupported backend type: %q", pluginName)
		}

		return factory()
	} else {
		return NewPluginClient(ctx, &pluginRunner, logger)
	}
}

// This is largely duplicated from sdk/plugin/plugin.go
func NewPluginClient(ctx context.Context, pluginRunner *pluginutil.PluginRunner, logger log.Logger) (Join, error) {
	client, err := pluginRunner.RunConfig(ctx)
	if err != nil {
		return nil, err
	}

	rpcClient, err := client.Client()
	if err != nil {
		return nil, err
	}

	raw, err := rpcClient.Dispense("join")
	if err != nil {
		return nil, err
	}

	join, ok := raw.(*gRPCClient)
	if !ok {
		return nil, errors.New("unsupported plugin client type")
	}
	return &JoinPluginClient{Join: join, client: client}, nil
}
