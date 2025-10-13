package discover

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/hashicorp/go-discover"
	"github.com/hashicorp/go-discover/provider/k8s"
	"github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/sdk/v2/joinplugin"
)

func Factory() (joinplugin.Join, error) {
	logger := hclog.Default()

	providers := make(map[string]discover.Provider)
	for k, v := range discover.Providers {
		providers[k] = v
	}
	providers["k8s"] = &k8s.Provider{}

	disco, err := discover.New(discover.WithProviders(providers))
	if err != nil {
		return nil, err
	}

	return &Discover{logger: logger, disco: disco}, nil
}

type Discover struct {
	logger hclog.Logger
	disco  *discover.Discover
}

func (d *Discover) Candidates(ctx context.Context, config map[string]string) ([]joinplugin.Addr, error) {
	args, found := config["discover"]
	if !found {
		return nil, fmt.Errorf("`discover` string must be provided")
	}

	portStr := config["port"]
	if portStr == "" {
		portStr = "8200"
	}
	port, err := strconv.ParseUint(config["port"], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid `port`: %s", portStr)
	}
	scheme := config["scheme"]
	if scheme == "" {
		scheme = "https"
	}

	ips, err := d.disco.Addrs(args, d.logger.StandardLogger(nil))
	if err != nil {
		return nil, err
	}

	addrs := make([]joinplugin.Addr, len(ips))
	for _, ip := range ips {
		if strings.Count(ip, ":") >= 2 && !strings.HasPrefix(ip, "[") {
			// An IPv6 address in implicit form, however we need it in explicit form to use in a URL.
			ip = fmt.Sprintf("[%s]", ip)
		}
		addrs = append(addrs, joinplugin.Addr{Scheme: scheme, Host: ip, Port: uint16(port)})
	}

	return addrs, nil
}

func (d *Discover) Cleanup(ctx context.Context) error {
	return nil
}
