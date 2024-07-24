// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package kubesecrets

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/sdk/v2/helper/logging"
	"github.com/openbao/openbao/sdk/v2/logical"
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
