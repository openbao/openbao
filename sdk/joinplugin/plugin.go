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
		rawJoin, err := pluginRunner.BuiltinFactory()
		if err != nil {
			return nil, fmt.Errorf("error getting plugin type: %q", err)
		}

		join, ok := rawJoin.(Join)
		if !ok {
			return nil, fmt.Errorf("unsupported backend type: %q", pluginName)
		}

		return join, nil
	} else {
		return NewPluginClient(ctx, &pluginRunner, logger)
	}
}

// This is largely duplicated from sdk/plugin/plugin.go
func NewPluginClient(ctx context.Context, pluginRunner *pluginutil.PluginRunner, logger log.Logger) (Join, error) {
	// We must use metadata mode, as we can't use mTLS before joining the cluster
	client, err := pluginRunner.RunConfig(
		ctx,
		pluginutil.Logger(logger),
		pluginutil.MetadataMode(true),
		pluginutil.HandshakeConfig(HandshakeConfig),
		pluginutil.PluginSets(map[int]plugin.PluginSet{
			1: {"join": new(JoinPlugin)},
		}),
	)
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
