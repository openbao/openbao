// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	metrics "github.com/hashicorp/go-metrics/compat"
	"github.com/openbao/openbao/v2/internal/helper/metricsutil"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"github.com/openbao/openbao/sdk/v2/physical"
	"github.com/openbao/openbao/v2/internal/vault/seal"
)

// phy implements physical.Backend. It maps keys to a slice of entries.
// Each call to Put appends the entry to the slice of entries for that
// key. No deduplication is done. This allows the test for UpgradeKeys to
// verify entries are only being updated when the underlying encryption key
// has been updated.
type phy struct {
	t       *testing.T
	entries map[string][]*physical.Entry
}

var _ physical.Backend = (*phy)(nil)

func newTestBackend(t *testing.T) *phy {
	return &phy{
		t:       t,
		entries: make(map[string][]*physical.Entry),
	}
}

func (p *phy) Put(_ context.Context, entry *physical.Entry) error {
	p.entries[entry.Key] = append(p.entries[entry.Key], entry)
	return nil
}

func (p *phy) Get(_ context.Context, key string) (*physical.Entry, error) {
	entries := p.entries[key]
	if entries == nil {
		return nil, nil
	}
	return entries[len(entries)-1], nil
}

func (p *phy) Delete(_ context.Context, key string) error {
	p.t.Errorf("Delete called on phy: key: %v", key)
	return nil
}

func (p *phy) List(_ context.Context, prefix string) ([]string, error) {
	p.t.Errorf("List called on phy: prefix: %v", prefix)
	return []string{}, nil
}

func (p *phy) ListPage(_ context.Context, prefix string, after string, limit int) ([]string, error) {
	p.t.Errorf("ListPage called on phy: prefix: %v", prefix)
	return []string{}, nil
}

func (p *phy) Len() int {
	return len(p.entries)
}

// TestAutoSeal_UpgradeKeys verifies that UpgradeKeys correctly upgrades recovery key
// and stored shares entries. Additionally we test an edge case when no recovery key
// exists yet but UpgradeKeys still does not fail and re-encrypts the stored keys.
func TestAutoSeal_UpgradeKeys(t *testing.T) {
	core, _, _ := TestCoreUnsealed(t)
	testSeal, toggleableWrapper := seal.NewTestSeal(nil)

	var encKeys []string
	changeKey := func(key string) {
		encKeys = append(encKeys, key)
		toggleableWrapper.Wrapper.(*wrapping.TestWrapper).SetKeyId(key)
	}

	// Set initial encryption key.
	changeKey("kaz")

	autoSeal, err := NewAutoSeal(testSeal)
	require.NoError(t, err)

	autoSeal.SetCore(core)
	pBackend := newTestBackend(t)
	core.physical = pBackend

	// The upgrade keys path uses core.seal for the recovery config,
	// so point it at the autoSeal under test to simulate root namespace seal.
	core.seal = autoSeal

	ctx := t.Context()

	inkeys := [][]byte{[]byte("grist"), []byte("house")}
	require.NoError(t, autoSeal.SetStoredKeys(ctx, inkeys))

	t.Run("happy path", func(t *testing.T) {
		inRecoveryKey := []byte("falernum")
		require.NoError(t, autoSeal.SetRecoveryKey(ctx, inRecoveryKey))

		check := func() {
			outkeys, err := autoSeal.GetStoredKeys(ctx)
			require.NoError(t, err)
			require.Equal(t, inkeys, outkeys)

			outRecoveryKey, err := autoSeal.RecoveryKey(ctx)
			require.NoError(t, err)
			require.Equal(t, inRecoveryKey, outRecoveryKey)

			// There should only be 2 entries in the physical backend.
			// One for the stored keys and one for the recovery key.
			require.Len(t, pBackend.entries, 2)

			for _, phyEntries := range pBackend.entries {
				// Calling UpgradeKeys should only add an entry if the key has changed.
				require.Equal(t, len(encKeys), len(phyEntries))

				// Each phyEntry should correspond to a key at the same index
				// in encKeys. Iterate over each phyEntry and verify it was
				// encrypted with its corresponding key in encKeys.
				for i, phyEntry := range phyEntries {
					blobInfo := &wrapping.BlobInfo{}
					require.NoError(t, proto.Unmarshal(phyEntry.Value, blobInfo))
					require.NotNil(t, blobInfo.KeyInfo)
					require.Equal(t, encKeys[i], blobInfo.KeyInfo.KeyId)
				}
			}
		}

		// Verify the current state is correct before calling UpgradeKeys.
		check()

		// Call UpgradeKeys before changing the encryption key and verify
		// nothing has changed.
		require.NoError(t, autoSeal.UpgradeKeys(ctx))
		check()

		// Change the encryption key, call UpgradeKeys, then verify
		// the stored keys and recovery key has been re-encrypted with
		// the new encryption key.
		changeKey("primanti")
		require.NoError(t, autoSeal.UpgradeKeys(ctx))
		check()
	})

	t.Run("no recovery key", func(t *testing.T) {
		// Emulate a recovery config with zero key shares and no recovery key stored.
		require.NoError(t, autoSeal.SetRecoveryConfig(ctx, &SealConfig{Type: "static"}))

		// Nothing to upgrade while the encryption key hasn't changed.
		require.NoError(t, autoSeal.UpgradeKeys(ctx))

		// Change the encryption key; the stored keys must still be re-encrypted
		// even though there is no recovery key to upgrade.
		changeKey("primanti")
		require.NoError(t, autoSeal.UpgradeKeys(ctx))

		keysBlob := pBackend.entries[StoredBarrierKeysPath]
		require.Equal(t, 2, len(keysBlob))

		blobInfo := &wrapping.BlobInfo{}
		require.NoError(t, proto.Unmarshal(keysBlob[len(keysBlob)-1].Value, blobInfo))

		require.NotNil(t, blobInfo.KeyInfo)
		require.Equal(t, "primanti", blobInfo.KeyInfo.KeyId)
	})
}

func TestAutoSeal_HealthCheck(t *testing.T) {
	inmemSink := metrics.NewInmemSink(
		1000000*time.Hour,
		2000000*time.Hour,
	)

	metricsConf := metrics.DefaultConfig("")
	metricsConf.EnableHostname = false
	metricsConf.EnableHostnameLabel = false
	metricsConf.EnableServiceLabel = false
	metricsConf.EnableTypePrefix = false

	metrics.NewGlobal(metricsConf, inmemSink)

	testSealAccess, setErr := seal.NewToggleableTestSeal(nil)
	core, _, _ := TestCoreUnsealedWithConfig(t, &CoreConfig{
		MetricSink: metricsutil.NewClusterMetricSink("", inmemSink),
	})
	autoSeal, err := NewAutoSealWithHealthCheck(
		testSealAccess,
		true,
		time.Minute,
		10*time.Millisecond,
		10*time.Millisecond,
	)
	require.NoError(t, err)

	autoSeal.SetCore(core)
	core.seal = autoSeal
	autoSeal.StartHealthCheck()
	defer autoSeal.StopHealthCheck()
	setErr(errors.New("disconnected"))

	asu := strings.Join(autoSealUnavailableDuration, ".") + ";cluster=" + core.clusterName
	tries := 10
	for ; tries > 0; tries-- {
		intervals := inmemSink.Data()
		if len(intervals) == 1 {
			interval := inmemSink.Data()[0]

			if _, ok := interval.Gauges[asu]; ok {
				if interval.Gauges[asu].Value > 0 {
					break
				}
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	if tries == 0 {
		t.Fatalf("Expected value metric %s to be non-zero", asu)
	}

	setErr(nil)
	time.Sleep(50 * time.Millisecond)
	intervals := inmemSink.Data()
	if len(intervals) == 1 {
		interval := inmemSink.Data()[0]

		if _, ok := interval.Gauges[asu]; !ok {
			t.Fatalf("Expected metrics to include a value for gauge %s", asu)
		}
		if interval.Gauges[asu].Value != 0 {
			t.Fatalf("Expected value metric %s to be zero", asu)
		}
	}
}
