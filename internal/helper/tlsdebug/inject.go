//go:build tlsdebug

package tlsdebug

import (
	"crypto/tls"
	"os"
	"sync"

	"github.com/hashicorp/go-hclog"
)

var openKeyLogFile = sync.OnceValues(func() (*os.File, error) {
	return os.CreateTemp("", "openbao_tls_session_key_log_")
})

func Inject(logger hclog.Logger, config *tls.Config) *tls.Config {
	if config == nil {
		return nil
	}

	file, err := openKeyLogFile()
	if err != nil {
		logger.Error("could not open TLS key log file", "error", err)
	}

	logger.Warn("injecting session key logger into TLS config", "log_file", file.Name())
	config.KeyLogWriter = file

	return config
}
