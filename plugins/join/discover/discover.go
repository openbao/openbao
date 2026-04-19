package discover

import (
	"context"
	"fmt"
	"strings"

	"github.com/go-viper/mapstructure/v2"
	"github.com/hashicorp/go-discover"
	"github.com/hashicorp/go-discover/provider/k8s"
	"github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/sdk/v2/joinplugin"
)

func Factory(cfg *joinplugin.JoinConfig) (joinplugin.Join, error) {
	providers := make(map[string]discover.Provider)
	for k, v := range discover.Providers {
		providers[k] = v
	}
	providers["k8s"] = &k8s.Provider{}

	disco, err := discover.New(discover.WithProviders(providers))
	if err != nil {
		return nil, err
	}

	return &Discover{logger: cfg.Logger, disco: disco}, nil
}

type Discover struct {
	logger hclog.Logger
	disco  *discover.Discover
}

type discoverConfig struct {
	Provider string            `mapstructure:"provider"`
	Args     map[string]string `mapstructure:"args"`
	Port     uint16            `mapstructure:"port"`
	Scheme   string            `mapstructure:"scheme"`
}

func (d *Discover) Candidates(ctx context.Context, config map[string]any) ([]joinplugin.Addr, error) {
	var cfg discoverConfig
	if err := mapstructure.WeakDecode(config, &cfg); err != nil {
		return nil, err
	}

	if cfg.Provider == "" {
		return nil, fmt.Errorf("`provider` name must be provided")
	}
	if cfg.Port == 0 {
		cfg.Port = 8200
	}
	if cfg.Scheme == "" {
		cfg.Scheme = "https"
	}

	discover := make([]string, 0, len(cfg.Args)+1)
	discover = append(discover, cfg.Provider)
	for k, v := range cfg.Args {
		discover = append(discover, fmt.Sprintf("%s=%s", k, v))
	}

	ips, err := d.disco.Addrs(strings.Join(discover, " "), d.logger.StandardLogger(nil))
	if err != nil {
		return nil, err
	}

	addrs := make([]joinplugin.Addr, len(ips))
	for _, ip := range ips {
		if strings.Count(ip, ":") >= 2 && !strings.HasPrefix(ip, "[") {
			// An IPv6 address in implicit form, however we need it in explicit form to use in a URL.
			ip = fmt.Sprintf("[%s]", ip)
		}
		addrs = append(addrs, joinplugin.Addr{Scheme: cfg.Scheme, Host: ip, Port: cfg.Port})
	}

	return addrs, nil
}

func (d *Discover) Cleanup(ctx context.Context) error {
	return nil
}
