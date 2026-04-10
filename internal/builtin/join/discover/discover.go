package discover

import (
	"context"
	"fmt"
	"maps"
	"net"
	"strconv"
	"strings"

	"github.com/hashicorp/go-discover"
	"github.com/hashicorp/go-discover/provider/k8s"
	"github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/sdk/v2/joinplugin"
)

func Factory(cfg *joinplugin.JoinConfig) (joinplugin.Join, error) {
	providers := make(map[string]discover.Provider)
	maps.Copy(providers, discover.Providers)
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

func (d *Discover) Candidates(ctx context.Context, config map[string]string) ([]joinplugin.Addr, error) {
	args, found := config["discover"]
	if !found {
		return nil, fmt.Errorf("`discover` string must be provided")
	}

	portStr := config["port"]
	if portStr == "" {
		portStr = "8200"
	}
	configPort, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid `port`: %s", portStr)
	}
	scheme := config["scheme"]
	if scheme == "" {
		scheme = "https"
	}

	discoveries, err := d.disco.Addrs(args, d.logger.StandardLogger(nil))
	if err != nil {
		return nil, err
	}

	addrs := make([]joinplugin.Addr, 0, len(discoveries))
	for _, discovery := range discoveries {
		host, port, err := ensureHostPort(discovery, uint16(configPort))
		if err != nil {
			d.logger.Error("invalid discovered address", "address", discovery, "error", err)
			continue
		}
		addrs = append(addrs, joinplugin.Addr{Scheme: scheme, Host: host, Port: port})
	}

	return addrs, nil
}

func ensureHostPort(addr string, configPort uint16) (string, uint16, error) {
	if host, portStr, err := net.SplitHostPort(addr); err == nil {
		port, err := strconv.ParseUint(portStr, 10, 16)
		return host, uint16(port), err
	}
	// Normalize bracketed IPv6 addresses, so `net.JoinHostPort` later doesn't
	// double-bracket them.
	addr = strings.TrimPrefix(strings.TrimSuffix(addr, "]"), "[")
	return addr, configPort, nil
}

func (d *Discover) Cleanup(ctx context.Context) error {
	return nil
}
