package kubesecrets

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/go-secure-stdlib/fileutil"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

var (
	// jwtReloadPeriod is the time period how often the in-memory copy of local
	// service account token can be used, before reading it again from disk.
	//
	// The value is selected according to recommendation in Kubernetes 1.21 changelog:
	// "Clients should reload the token from disk periodically (once per minute
	// is recommended) to ensure they continue to use a valid token."
	jwtReloadPeriod = 1 * time.Minute

	// caReloadPeriod is the time period how often the in-memory copy of local
	// CA cert can be used, before reading it again from disk.
	caReloadPeriod = 1 * time.Hour
)

// backend wraps the backend framework and adds a map for storing key value pairs
type backend struct {
	*framework.Backend

	// localSATokenReader caches the service account token in memory.
	// It periodically reloads the token to support token rotation/renewal.
	// Local token is used when running in a pod with following configuration
	// - token_reviewer_jwt is not set
	// - disable_local_ca_jwt is false
	localSATokenReader *fileutil.CachingFileReader

	// localCACertReader contains the local CA certificate. Local CA certificate is
	// used when running in a pod with following configuration
	// - kubernetes_ca_cert is not set
	// - disable_local_ca_jwt is false
	localCACertReader *fileutil.CachingFileReader
}

var _ logical.Factory = Factory

// Factory configures and returns Mock backends
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b, err := newBackend()
	if err != nil {
		return nil, err
	}

	if conf == nil {
		return nil, fmt.Errorf("configuration passed into backend is nil")
	}

	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}

	return b, nil
}

func newBackend() (*backend, error) {
	b := &backend{
		localSATokenReader: fileutil.NewCachingFileReader(localJWTPath, jwtReloadPeriod),
		localCACertReader:  fileutil.NewCachingFileReader(localCACertPath, caReloadPeriod),
	}

	b.Backend = &framework.Backend{
		BackendType: logical.TypeLogical,
		Help:        strings.TrimSpace(backendHelp),
		Paths: framework.PathAppend(
			[]*framework.Path{
				b.pathConfig(),
			},
			b.pathRoles(),
		),
		PathsSpecial: &logical.Paths{
			LocalStorage: []string{
				framework.WALPrefix,
			},
			SealWrapStorage: []string{
				"config",
				"role/*",
			},
		},
	}

	return b, nil
}

const backendHelp = `
The Kubernetes Secret Backend generates Kubernetes service account tokens with associated roles and role bindings.
`
