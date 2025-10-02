package static

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/sdk/v2/joinplugin"
)

func Factory() (joinplugin.Join, error) {
	logger := hclog.Default()

	return &Static{logger: logger}, nil
}

type Static struct {
	logger hclog.Logger
}

func (d *Static) Candidates(ctx context.Context, config map[string]string) ([]joinplugin.Addr, error) {
	addrsConfig, found := config["addresses"]
	if !found {
		return nil, fmt.Errorf("`addresses` string must be provided")
	}

	urls := strings.Split(addrsConfig, ",")
	candidates := make([]joinplugin.Addr, 0, len(urls))
	for _, rawUrl := range urls {
		url, err := url.Parse(rawUrl)
		if err != nil {
			d.logger.Warn("failed to parse URL", rawUrl, err)
		}
		host := url.Hostname()
		portStr := url.Port()
		if portStr == "" {
			portStr = "8200"
		}
		port, err := strconv.ParseUint(portStr, 10, 16)
		if err != nil {
			d.logger.Warn("failed to parse port", portStr)
		}
		candidates = append(candidates, joinplugin.Addr{Scheme: url.Scheme, Host: host, Port: uint16(port)})
	}

	return candidates, nil
}

func (d *Static) Cleanup(ctx context.Context) error {
	return nil
}
