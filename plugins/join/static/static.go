package static

import (
	"context"
	"net/url"
	"strconv"

	"github.com/go-viper/mapstructure/v2"
	"github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/sdk/v2/joinplugin"
)

func Factory(cfg *joinplugin.JoinConfig) (joinplugin.Join, error) {
	return &Static{logger: cfg.Logger}, nil
}

type Static struct {
	logger hclog.Logger
}

type staticConfig struct {
	Addresses []string `mapstructure:"addresses"`
}

func (d *Static) Candidates(ctx context.Context, config map[string]any) ([]joinplugin.Addr, error) {
	var cfg staticConfig
	if err := mapstructure.WeakDecode(config, &cfg); err != nil {
		return nil, err
	}

	candidates := make([]joinplugin.Addr, 0, len(cfg.Addresses))
	for _, rawUrl := range cfg.Addresses {
		url, err := url.Parse(rawUrl)
		if err != nil {
			return nil, err
		}
		host := url.Hostname()
		portStr := url.Port()
		if portStr == "" {
			portStr = "8200"
		}
		port, err := strconv.ParseUint(portStr, 10, 16)
		if err != nil {
			return nil, err
		}
		candidates = append(candidates, joinplugin.Addr{Scheme: url.Scheme, Host: host, Port: uint16(port)})
	}

	return candidates, nil
}

func (d *Static) Cleanup(ctx context.Context) error {
	return nil
}
