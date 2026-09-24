// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package agentproxyshared

import (
	"os"
	"testing"

	hclog "github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/sdk/v2/helper/logging"
	"github.com/openbao/openbao/v2/internal/command/agentproxyshared/cache"
	"github.com/stretchr/testify/require"
)

func testNewLeaseCache(t *testing.T, responses []*cache.SendResponse) *cache.LeaseCache {
	t.Helper()

	client, err := api.NewClient(api.DefaultConfig())
	require.NoError(t, err)
	lc, err := cache.NewLeaseCache(&cache.LeaseCacheConfig{
		Client:      client,
		BaseContext: t.Context(),
		Proxier:     cache.NewMockProxier(responses),
		Logger:      logging.NewVaultLogger(hclog.Trace).Named("cache.leasecache"),
	})
	require.NoError(t, err)
	return lc
}

func populateTempFile(t *testing.T, name, contents string) *os.File {
	t.Helper()

	file, err := os.CreateTemp(t.TempDir(), name)
	require.NoError(t, err)

	_, err = file.WriteString(contents)
	require.NoError(t, err)

	err = file.Close()
	require.NoError(t, err)

	return file
}

// Test_AddPersistentStorageToLeaseCache Tests that AddPersistentStorageToLeaseCache() correctly
// adds persistent storage to a lease cache
func Test_AddPersistentStorageToLeaseCache(t *testing.T) {
	tempDir := t.TempDir()
	serviceAccountTokenFile := populateTempFile(t, "proxy-config.hcl", "token")

	persistConfig := &PersistConfig{
		Type:                    "kubernetes",
		Path:                    tempDir,
		KeepAfterImport:         false,
		ExitOnErr:               false,
		ServiceAccountTokenFile: serviceAccountTokenFile.Name(),
	}

	leaseCache := testNewLeaseCache(t, nil)
	if leaseCache.PersistentStorage() != nil {
		t.Fatal("persistent storage was available before ours was added")
	}

	deferFunc, token, err := AddPersistentStorageToLeaseCache(t.Context(), leaseCache, persistConfig, logging.NewVaultLogger(hclog.Info))
	require.NoError(t, err)

	if leaseCache.PersistentStorage() == nil {
		t.Fatal("persistent storage was not added")
	}

	if token != "" {
		t.Fatal("expected token to be empty")
	}

	if deferFunc == nil {
		t.Fatal("expected deferFunc to not be nil")
	}
}
