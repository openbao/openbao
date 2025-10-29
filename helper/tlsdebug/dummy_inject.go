//go:build !tlsdebug

package tlsdebug

import (
	"crypto/tls"

	"github.com/hashicorp/go-hclog"
)

func Inject(_ hclog.Logger, config *tls.Config) *tls.Config {
	return config
}
