package kubesecrets

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/helper/logging"
	"github.com/hashicorp/vault/sdk/logical"
)

var (
	defaultLeaseTTLVal = time.Hour * 12
	maxLeaseTTLVal     = time.Hour * 24
)

func getTestBackend(t *testing.T) (*backend, logical.Storage) {
	t.Helper()

	config := logical.TestBackendConfig()
	config.StorageView = new(logical.InmemStorage)
	config.Logger = logging.NewVaultLogger(hclog.Trace)
	config.System = &logical.StaticSystemView{
		DefaultLeaseTTLVal: defaultLeaseTTLVal,
		MaxLeaseTTLVal:     maxLeaseTTLVal,
	}

	b, err := Factory(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	return b.(*backend), config.StorageView
}
