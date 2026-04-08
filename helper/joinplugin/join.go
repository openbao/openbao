package joinplugin

import (
	"context"
	"fmt"

	"github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/command/server"
	"github.com/openbao/openbao/helper/pluginutil/catalog"
	"github.com/openbao/openbao/plugins/join/discover"
	"github.com/openbao/openbao/plugins/join/static"
	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/openbao/openbao/sdk/v2/joinplugin"
)

type Catalog struct {
	*catalog.Catalog
}

var builtins = map[string]joinplugin.Factory{
	"static":   static.Factory,
	"discover": discover.Factory,
}

func NewCatalog(logger hclog.Logger, config *server.Config) (*Catalog, error) {
	base, err := catalog.NewCatalog(
		logger,
		config,
		consts.PluginTypeJoin,
		joinplugin.HandshakeConfig,
		joinplugin.PluginSets,
	)
	if err != nil {
		return nil, err
	}

	return &Catalog{base}, nil
}

func (c *Catalog) NewJoin(name string) (joinplugin.Join, bool, error) {
	client, ok, err := c.GetClient(name)
	if err != nil {
		return nil, false, err
	}
	if !ok {
		if factory, ok := builtins[name]; ok {
			plugin, err := factory()
			return plugin, true, err
		}
		return nil, false, fmt.Errorf("unknown join: %s", name)
	}

	raw, err := client.Dispense("join")
	if err != nil {
		client.Close()
		return nil, false, err
	}

	plugin := raw.(joinplugin.Join)
	return &join{client, plugin}, false, nil
}

type join struct {
	client *catalog.Client
	joinplugin.Join
}

func (j *join) Cleanup(ctx context.Context) error {
	err := j.Join.Cleanup(ctx)
	j.client.Close()
	j.client = nil
	return err
}
