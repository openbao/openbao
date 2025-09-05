// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package pki

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/helper/jsonutil"
	"golang.org/x/crypto/acme"

	"github.com/openbao/openbao/helper/testhelpers"
	"github.com/openbao/openbao/sdk/v2/helper/testhelpers/schema"

	"github.com/armon/go-metrics"

	"github.com/openbao/openbao/api/v2"
	vaulthttp "github.com/openbao/openbao/http"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/vault"

	"github.com/stretchr/testify/require"
)

func TestTidyConfigs(t *testing.T) {
	t.Parallel()

	var cfg tidyConfig
	operations := strings.Split(cfg.AnyTidyConfig(), " / ")
	require.Greater(t, len(operations), 1, "expected more than one operation")
	t.Logf("Got tidy operations: %v", operations)

	lastOp := operations[len(operations)-1]

	for _, operation := range operations {
		b, s := CreateBackendWithStorage(t)

		resp, err := CBWrite(b, s, "config/auto-tidy", map[string]interface{}{
			"enabled": true,
			operation: true,
		})
		requireSuccessNonNilResponse(t, resp, err, "expected to be able to enable auto-tidy operation "+operation)

		resp, err = CBRead(b, s, "config/auto-tidy")
		requireSuccessNonNilResponse(t, resp, err, "expected to be able to read auto-tidy operation for operation "+operation)
		require.True(t, resp.Data[operation].(bool), "expected operation to be enabled after reading auto-tidy config "+operation)

		resp, err = CBWrite(b, s, "config/auto-tidy", map[string]interface{}{
			"enabled": true,
			operation: false,
			lastOp:    true,
		})
		requireSuccessNonNilResponse(t, resp, err, "expected to be able to disable auto-tidy operation "+operation)

		resp, err = CBRead(b, s, "config/auto-tidy")
		requireSuccessNonNilResponse(t, resp, err, "expected to be able to read auto-tidy operation for operation "+operation)
		require.False(t, resp.Data[operation].(bool), "expected operation to be disabled after reading auto-tidy config "+operation)

		resp, err = CBWrite(b, s, "tidy", map[string]interface{}{
			operation: true,
		})
		requireSuccessNonNilResponse(t, resp, err, "expected to be able to start tidy operation with "+operation)
		if len(resp.Warnings) > 0 {
			t.Logf("got warnings while starting manual tidy: %v", resp.Warnings)
			for _, warning := range resp.Warnings {
				if strings.Contains(warning, "Manual tidy requested but no tidy operations were set.") {
					t.Fatalf("expected to be able to enable tidy operation with just %v but got warning: %v / (resp=%v)", operation, warning, resp)
				}
			}
		}

		lastOp = operation
	}

	// pause_duration is tested elsewhere in other tests.
	type configSafetyBufferValueStr struct {
		Config       string
		FirstValue   int
		SecondValue  int
		DefaultValue int
	}
	configSafetyBufferValues := []configSafetyBufferValueStr{
		{
			Config:       "safety_buffer",
			FirstValue:   1,
			SecondValue:  2,
			DefaultValue: int(defaultTidyConfig.SafetyBuffer / time.Second),
		},
		{
			Config:       "revoked_safety_buffer",
			FirstValue:   1,
			SecondValue:  2,
			DefaultValue: int(defaultTidyConfig.SafetyBuffer / time.Second),
		},
		{
			Config:       "issuer_safety_buffer",
			FirstValue:   1,
			SecondValue:  2,
			DefaultValue: int(defaultTidyConfig.IssuerSafetyBuffer / time.Second),
		},
		{
			Config:       "acme_account_safety_buffer",
			FirstValue:   1,
			SecondValue:  2,
			DefaultValue: int(defaultTidyConfig.AcmeAccountSafetyBuffer / time.Second),
		},
	}

	for _, flag := range configSafetyBufferValues {
		b, s := CreateBackendWithStorage(t)

		resp, err := CBRead(b, s, "config/auto-tidy")
		requireSuccessNonNilResponse(t, resp, err, "expected to be able to read auto-tidy operation for flag "+flag.Config)
		require.Equal(t, resp.Data[flag.Config].(int), flag.DefaultValue, "expected initial auto-tidy config to match default value for "+flag.Config)

		resp, err = CBWrite(b, s, "config/auto-tidy", map[string]interface{}{
			"enabled":         true,
			"tidy_cert_store": true,
			flag.Config:       flag.FirstValue,
		})
		requireSuccessNonNilResponse(t, resp, err, "expected to be able to set auto-tidy config option "+flag.Config)

		resp, err = CBRead(b, s, "config/auto-tidy")
		requireSuccessNonNilResponse(t, resp, err, "expected to be able to read auto-tidy operation for config "+flag.Config)
		require.Equal(t, resp.Data[flag.Config].(int), flag.FirstValue, "expected value to be set after reading auto-tidy config "+flag.Config)

		resp, err = CBWrite(b, s, "config/auto-tidy", map[string]interface{}{
			"enabled":         true,
			"tidy_cert_store": true,
			flag.Config:       flag.SecondValue,
		})
		requireSuccessNonNilResponse(t, resp, err, "expected to be able to set auto-tidy config option "+flag.Config)

		resp, err = CBRead(b, s, "config/auto-tidy")
		requireSuccessNonNilResponse(t, resp, err, "expected to be able to read auto-tidy operation for config "+flag.Config)
		require.Equal(t, resp.Data[flag.Config].(int), flag.SecondValue, "expected value to be set after reading auto-tidy config "+flag.Config)

		resp, err = CBWrite(b, s, "tidy", map[string]interface{}{
			"tidy_cert_store": true,
			flag.Config:       flag.FirstValue,
		})
		t.Logf("tidy run results: resp=%v/err=%v", resp, err)
		requireSuccessNonNilResponse(t, resp, err, "expected to be able to start tidy operation with "+flag.Config)
		if len(resp.Warnings) > 0 {
			for _, warning := range resp.Warnings {
				if strings.Contains(warning, "unrecognized parameter") && strings.Contains(warning, flag.Config) {
					t.Fatalf("warning '%v' claims parameter '%v' is unknown", warning, flag.Config)
				}
			}
		}

		time.Sleep(2 * time.Second)

		resp, err = CBRead(b, s, "tidy-status")
		requireSuccessNonNilResponse(t, resp, err, "expected to be able to start tidy operation with "+flag.Config)
		t.Logf("got response: %v for config: %v", resp, flag.Config)
		require.Equal(t, resp.Data[flag.Config].(int), flag.FirstValue, "expected flag to be set in tidy-status for config "+flag.Config)
	}
}

func TestAutoTidy(t *testing.T) {
	t.Parallel()

	// While we'd like to reduce this duration, we need to wait until
	// the rollback manager timer ticks. With the new helper, we can
	// modify the rollback manager timer period directly, allowing us
	// to shorten the total test time significantly.
	//
	// We set the delta CRL time to ensure it executes prior to the
	// main CRL rebuild, and the new CRL doesn't rebuild until after
	// we're done.
	newPeriod := 1 * time.Second

	// This test requires the periodicFunc to trigger, which requires we stand
	// up a full test cluster.
	coreConfig := &vault.CoreConfig{
		LogicalBackends: map[string]logical.Factory{
			"pki": Factory,
		},
		// See notes below about usage of /sys/raw for reading cluster
		// storage without barrier encryption.
		EnableRaw:      true,
		RollbackPeriod: newPeriod,
	}
	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
	})
	cluster.Start()
	defer cluster.Cleanup()
	client := cluster.Cores[0].Client

	// Mount PKI
	err := client.Sys().Mount("pki", &api.MountInput{
		Type: "pki",
		Config: api.MountConfigInput{
			DefaultLeaseTTL: "10m",
			MaxLeaseTTL:     "60m",
		},
	})
	require.NoError(t, err)

	// Generate root.
	resp, err := client.Logical().Write("pki/root/generate/internal", map[string]interface{}{
		"ttl":         "40h",
		"common_name": "Root X1",
		"key_type":    "ec",
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotEmpty(t, resp.Data)
	require.NotEmpty(t, resp.Data["issuer_id"])
	issuerId := resp.Data["issuer_id"]

	// Run tidy so status is not empty when we run it later...
	_, err = client.Logical().Write("pki/tidy", map[string]interface{}{
		"tidy_revoked_certs": true,
	})
	require.NoError(t, err)

	// Setup a testing role.
	_, err = client.Logical().Write("pki/roles/local-testing", map[string]interface{}{
		"allow_any_name":    true,
		"enforce_hostnames": false,
		"key_type":          "ec",
	})
	require.NoError(t, err)

	// Write the auto-tidy config.
	_, err = client.Logical().Write("pki/config/auto-tidy", map[string]interface{}{
		"enabled":            true,
		"interval_duration":  "1s",
		"tidy_cert_store":    true,
		"tidy_revoked_certs": true,
		"safety_buffer":      "1s",
	})
	require.NoError(t, err)

	// Issue a cert and revoke it.
	resp, err = client.Logical().Write("pki/issue/local-testing", map[string]interface{}{
		"common_name": "example.com",
		"ttl":         "10s",
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotNil(t, resp.Data)
	require.NotEmpty(t, resp.Data["serial_number"])
	require.NotEmpty(t, resp.Data["certificate"])
	leafSerial := resp.Data["serial_number"].(string)
	leafCert := parseCert(t, resp.Data["certificate"].(string))

	// Read cert before revoking
	resp, err = client.Logical().Read("pki/cert/" + leafSerial)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotNil(t, resp.Data)
	require.NotEmpty(t, resp.Data["certificate"])
	revocationTime, err := (resp.Data["revocation_time"].(json.Number)).Int64()
	require.NoError(t, err)
	require.Equal(t, int64(0), revocationTime, "revocation time was not zero")
	require.Empty(t, resp.Data["revocation_time_rfc3339"], "revocation_time_rfc3339 was not empty")
	require.Empty(t, resp.Data["issuer_id"], "issuer_id was not empty")

	_, err = client.Logical().Write("pki/revoke", map[string]interface{}{
		"serial_number": leafSerial,
	})
	require.NoError(t, err)

	// Cert should still exist.
	resp, err = client.Logical().Read("pki/cert/" + leafSerial)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotNil(t, resp.Data)
	require.NotEmpty(t, resp.Data["certificate"])
	revocationTime, err = (resp.Data["revocation_time"].(json.Number)).Int64()
	require.NoError(t, err, "failed converting %s to int", resp.Data["revocation_time"])
	revTime := time.Unix(revocationTime, 0)
	now := time.Now()
	if !(now.After(revTime) && now.Add(-10*time.Minute).Before(revTime)) {
		t.Fatalf("parsed revocation time not within the last 10 minutes current time: %s, revocation time: %s", now, revTime)
	}
	utcLoc, err := time.LoadLocation("UTC")
	require.NoError(t, err, "failed to parse UTC location?")

	rfc3339RevocationTime, err := time.Parse(time.RFC3339Nano, resp.Data["revocation_time_rfc3339"].(string))
	require.NoError(t, err, "failed parsing revocation_time_rfc3339 field: %s", resp.Data["revocation_time_rfc3339"])

	require.Equal(t, revTime.In(utcLoc), rfc3339RevocationTime.Truncate(time.Second),
		"revocation times did not match revocation_time: %s, "+"rfc3339 time: %s", revTime, rfc3339RevocationTime)
	require.Equal(t, issuerId, resp.Data["issuer_id"], "issuer_id on leaf cert did not match")

	// Wait for cert to expire and the safety buffer to elapse.
	time.Sleep(time.Until(leafCert.NotAfter) + 3*time.Second)

	// Wait for auto-tidy to run afterwards.
	waitForAutoTidyToFinish(t, client)

	// Cert should no longer exist.
	resp, err = client.Logical().Read("pki/cert/" + leafSerial)
	require.Nil(t, err)
	require.Nil(t, resp)
}

func TestTidyCancellation(t *testing.T) {
	t.Parallel()

	numLeaves := 100

	b, s := CreateBackendWithStorage(t)

	// Create a root, a role, and a bunch of leaves.
	_, err := CBWrite(b, s, "root/generate/internal", map[string]interface{}{
		"common_name": "root example.com",
		"issuer_name": "root",
		"ttl":         "20m",
		"key_type":    "ec",
	})
	require.NoError(t, err)
	_, err = CBWrite(b, s, "roles/local-testing", map[string]interface{}{
		"allow_any_name":    true,
		"enforce_hostnames": false,
		"key_type":          "ec",
	})
	require.NoError(t, err)
	for i := 0; i < numLeaves; i++ {
		_, err = CBWrite(b, s, "issue/local-testing", map[string]interface{}{
			"common_name": "testing",
			"ttl":         "1s",
		})
		require.NoError(t, err)
	}

	// Kick off a tidy operation (which runs in the background), but with
	// a slow-ish pause between certificates.
	resp, err := CBWrite(b, s, "tidy", map[string]interface{}{
		"tidy_cert_store": true,
		"safety_buffer":   "1s",
		"pause_duration":  "1s",
	})
	if err != nil {
		t.Fatal(err)
	}

	schema.ValidateResponse(t, schema.GetResponseSchema(t, b.Route("tidy"), logical.UpdateOperation), resp, true)

	// If we wait six seconds, the operation should still be running. That's
	// how we check that pause_duration works.
	time.Sleep(3 * time.Second)

	resp, err = CBRead(b, s, "tidy-status")

	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotNil(t, resp.Data)
	require.Equal(t, resp.Data["state"], "Running")

	// If we now cancel the operation, the response should say Cancelling.
	cancelResp, err := CBWrite(b, s, "tidy-cancel", map[string]interface{}{})
	schema.ValidateResponse(t, schema.GetResponseSchema(t, b.Route("tidy-cancel"), logical.UpdateOperation), resp, true)
	require.NoError(t, err)
	require.NotNil(t, cancelResp)
	require.NotNil(t, cancelResp.Data)
	state := cancelResp.Data["state"].(string)
	howMany := cancelResp.Data["cert_store_deleted_count"].(uint)

	if state == "Cancelled" {
		// Rest of the test can't run; log and exit.
		t.Log("Went to cancel the operation but response was already cancelled")
		return
	}

	require.Equal(t, state, "Cancelling")

	// Wait a little longer, and ensure we only processed at most 2 more certs
	// after the cancellation respon.
	time.Sleep(3 * time.Second)

	statusResp, err := CBRead(b, s, "tidy-status")
	schema.ValidateResponse(t, schema.GetResponseSchema(t, b.Route("tidy-status"), logical.ReadOperation), resp, true)
	require.NoError(t, err)
	require.NotNil(t, statusResp)
	require.NotNil(t, statusResp.Data)
	require.Equal(t, statusResp.Data["state"], "Cancelled")
	nowMany := statusResp.Data["cert_store_deleted_count"].(uint)
	if howMany+3 <= nowMany {
		t.Fatalf("expected to only process at most 3 more certificates, but processed (%v >>> %v) certs", nowMany, howMany)
	}
}

func TestTidyIssuers(t *testing.T) {
	t.Parallel()

	b, s := CreateBackendWithStorage(t)

	// Create a root that expires quickly and one valid for longer.
	_, err := CBWrite(b, s, "root/generate/internal", map[string]interface{}{
		"common_name": "root1 example.com",
		"issuer_name": "root-expired",
		"ttl":         "1s",
		"key_type":    "ec",
	})
	require.NoError(t, err)

	_, err = CBWrite(b, s, "root/generate/internal", map[string]interface{}{
		"common_name": "root2 example.com",
		"issuer_name": "root-valid",
		"ttl":         "60m",
		"key_type":    "rsa",
	})
	require.NoError(t, err)

	// Sleep long enough to expire the root.
	time.Sleep(2 * time.Second)

	// First tidy run shouldn't remove anything; too long of safety buffer.
	_, err = CBWrite(b, s, "tidy", map[string]interface{}{
		"tidy_expired_issuers": true,
		"issuer_safety_buffer": "60m",
	})
	require.NoError(t, err)

	// Wait for tidy to finish.
	time.Sleep(2 * time.Second)

	// Expired issuer should exist.
	resp, err := CBRead(b, s, "issuer/root-expired")
	requireSuccessNonNilResponse(t, resp, err, "expired should still be present")
	resp, err = CBRead(b, s, "issuer/root-valid")
	requireSuccessNonNilResponse(t, resp, err, "valid should still be present")

	// Second tidy run with shorter safety buffer shouldn't remove the
	// expired one, as it should be the default issuer.
	_, err = CBWrite(b, s, "tidy", map[string]interface{}{
		"tidy_expired_issuers": true,
		"issuer_safety_buffer": "1s",
	})
	require.NoError(t, err)

	// Wait for tidy to finish.
	time.Sleep(2 * time.Second)

	// Expired issuer should still exist.
	resp, err = CBRead(b, s, "issuer/root-expired")
	requireSuccessNonNilResponse(t, resp, err, "expired should still be present")
	resp, err = CBRead(b, s, "issuer/root-valid")
	requireSuccessNonNilResponse(t, resp, err, "valid should still be present")

	// Update the default issuer.
	_, err = CBWrite(b, s, "config/issuers", map[string]interface{}{
		"default": "root-valid",
	})
	require.NoError(t, err)

	// Third tidy run should remove the expired one.
	_, err = CBWrite(b, s, "tidy", map[string]interface{}{
		"tidy_expired_issuers": true,
		"issuer_safety_buffer": "1s",
	})
	require.NoError(t, err)

	// Wait for tidy to finish.
	time.Sleep(2 * time.Second)

	// Valid issuer should exist still; other should be removed.
	resp, err = CBRead(b, s, "issuer/root-expired")
	require.Error(t, err)
	require.Nil(t, resp)
	resp, err = CBRead(b, s, "issuer/root-valid")
	requireSuccessNonNilResponse(t, resp, err, "valid should still be present")

	// Finally, one more tidy should cause no changes.
	_, err = CBWrite(b, s, "tidy", map[string]interface{}{
		"tidy_expired_issuers": true,
		"issuer_safety_buffer": "1s",
	})
	require.NoError(t, err)

	// Wait for tidy to finish.
	time.Sleep(2 * time.Second)

	// Valid issuer should exist still; other should be removed.
	resp, err = CBRead(b, s, "issuer/root-expired")
	require.Error(t, err)
	require.Nil(t, resp)
	resp, err = CBRead(b, s, "issuer/root-valid")
	requireSuccessNonNilResponse(t, resp, err, "valid should still be present")

	// Ensure we have safety buffer and expired issuers set correctly.
	statusResp, err := CBRead(b, s, "tidy-status")
	require.NoError(t, err)
	require.NotNil(t, statusResp)
	require.NotNil(t, statusResp.Data)
	require.Equal(t, statusResp.Data["issuer_safety_buffer"], 1)
	require.Equal(t, statusResp.Data["tidy_expired_issuers"], true)
}

func TestTidyIssuerConfig(t *testing.T) {
	t.Parallel()

	b, s := CreateBackendWithStorage(t)

	// Ensure the default auto-tidy config matches expectations
	resp, err := CBRead(b, s, "config/auto-tidy")
	schema.ValidateResponse(t, schema.GetResponseSchema(t, b.Route("config/auto-tidy"), logical.ReadOperation), resp, true)
	requireSuccessNonNilResponse(t, resp, err)

	jsonBlob, err := json.Marshal(&defaultTidyConfig)
	require.NoError(t, err)
	var defaultConfigMap map[string]interface{}
	err = json.Unmarshal(jsonBlob, &defaultConfigMap)
	require.NoError(t, err)

	// Coerce defaults to API response types.
	defaultConfigMap["interval_duration"] = int(time.Duration(defaultConfigMap["interval_duration"].(float64)) / time.Second)
	defaultConfigMap["issuer_safety_buffer"] = int(time.Duration(defaultConfigMap["issuer_safety_buffer"].(float64)) / time.Second)
	defaultConfigMap["safety_buffer"] = int(time.Duration(defaultConfigMap["safety_buffer"].(float64)) / time.Second)
	defaultConfigMap["revoked_safety_buffer"] = int(defaultConfigMap["safety_buffer"].(int))
	defaultConfigMap["pause_duration"] = time.Duration(defaultConfigMap["pause_duration"].(float64)).String()
	defaultConfigMap["page_size"] = int(defaultConfigMap["page_size"].(float64))
	defaultConfigMap["acme_account_safety_buffer"] = int(time.Duration(defaultConfigMap["acme_account_safety_buffer"].(float64)) / time.Second)

	require.Equal(t, defaultConfigMap, resp.Data)

	// Ensure setting issuer-tidy related fields stick.
	resp, err = CBWrite(b, s, "config/auto-tidy", map[string]interface{}{
		"tidy_expired_issuers": true,
		"issuer_safety_buffer": "5s",
	})
	schema.ValidateResponse(t, schema.GetResponseSchema(t, b.Route("config/auto-tidy"), logical.UpdateOperation), resp, true)

	requireSuccessNonNilResponse(t, resp, err)
	require.Equal(t, true, resp.Data["tidy_expired_issuers"])
	require.Equal(t, 5, resp.Data["issuer_safety_buffer"])
}

// TestCertStorageMetrics ensures that when enabled, metrics are able to count the number of certificates in storage and
// number of revoked certificates in storage.  Moreover, this test ensures that the gauge is emitted periodically, so
// that the metric does not disappear or go stale.
func TestCertStorageMetrics(t *testing.T) {
	// This tests uses the same setup as TestAutoTidy
	newPeriod := 1 * time.Second

	// We set up a metrics accumulator
	inmemSink := metrics.NewInmemSink(
		2*newPeriod,  // A short time period is ideal here to test metrics are emitted every periodic func
		10*newPeriod) // Do not keep a huge amount of metrics in the sink forever, clear them out to save memory usage.

	metricsConf := metrics.DefaultConfig("")
	metricsConf.EnableHostname = false
	metricsConf.EnableHostnameLabel = false
	metricsConf.EnableServiceLabel = false
	metricsConf.EnableTypePrefix = false

	_, err := metrics.NewGlobal(metricsConf, inmemSink)
	if err != nil {
		t.Fatal(err)
	}

	// This test requires the periodicFunc to trigger, which requires we stand
	// up a full test cluster.
	coreConfig := &vault.CoreConfig{
		LogicalBackends: map[string]logical.Factory{
			"pki": Factory,
		},
		// See notes below about usage of /sys/raw for reading cluster
		// storage without barrier encryption.
		EnableRaw:      true,
		RollbackPeriod: newPeriod,
	}
	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
		NumCores:    1,
	})
	cluster.Start()
	defer cluster.Cleanup()
	client := cluster.Cores[0].Client

	// Mount PKI
	err = client.Sys().Mount("pki", &api.MountInput{
		Type: "pki",
		Config: api.MountConfigInput{
			DefaultLeaseTTL: "10m",
			MaxLeaseTTL:     "60m",
		},
	})
	require.NoError(t, err)

	// Generate root.
	resp, err := client.Logical().Write("pki/root/generate/internal", map[string]interface{}{
		"ttl":         "40h",
		"common_name": "Root X1",
		"key_type":    "ec",
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotEmpty(t, resp.Data)
	require.NotEmpty(t, resp.Data["issuer_id"])

	// Set up a testing role.
	_, err = client.Logical().Write("pki/roles/local-testing", map[string]interface{}{
		"allow_any_name":    true,
		"enforce_hostnames": false,
		"key_type":          "ec",
	})
	require.NoError(t, err)

	// Run tidy so that tidy-status is not empty
	_, err = client.Logical().Write("pki/tidy", map[string]interface{}{
		"tidy_revoked_certs": true,
	})
	require.NoError(t, err)

	// Since certificate counts are off by default, we shouldn't see counts in the tidy status
	tidyStatus, err := client.Logical().Read("pki/tidy-status")
	if err != nil {
		t.Fatal(err)
	}
	// backendUUID should exist, we need this for metrics
	backendUUID := tidyStatus.Data["internal_backend_uuid"].(string)
	// "current_cert_store_count", "current_revoked_cert_count"
	countData, ok := tidyStatus.Data["current_cert_store_count"]
	if ok && countData != nil {
		t.Fatalf("Certificate counting should be off by default, but current cert store count %v appeared in tidy status in unconfigured mount", countData)
	}
	revokedCountData, ok := tidyStatus.Data["current_revoked_cert_count"]
	if ok && revokedCountData != nil {
		t.Fatalf("Certificate counting should be off by default, but revoked cert count %v appeared in tidy status in unconfigured mount", revokedCountData)
	}

	// Since certificate counts are off by default, those metrics should not exist yet
	stableMetric := inmemSink.Data()
	mostRecentInterval := stableMetric[len(stableMetric)-1]
	_, ok = mostRecentInterval.Gauges["secrets.pki."+backendUUID+".total_revoked_certificates_stored"]
	if ok {
		t.Fatal("Certificate counting should be off by default, but revoked cert count was emitted as a metric in an unconfigured mount")
	}
	_, ok = mostRecentInterval.Gauges["secrets.pki."+backendUUID+".total_certificates_stored"]
	if ok {
		t.Fatal("Certificate counting should be off by default, but total certificate count was emitted as a metric in an unconfigured mount")
	}

	// Write the auto-tidy config.
	_, err = client.Logical().Write("pki/config/auto-tidy", map[string]interface{}{
		"enabled":                                  true,
		"interval_duration":                        "1s",
		"tidy_cert_store":                          true,
		"tidy_revoked_certs":                       true,
		"safety_buffer":                            "1s",
		"maintain_stored_certificate_counts":       true,
		"publish_stored_certificate_count_metrics": false,
	})
	require.NoError(t, err)

	// Reload the Mount - Otherwise Stored Certificate Counts Will Not Be Populated
	// Sealing cores as plugin reload triggers the race detector - VAULT-13635
	testhelpers.EnsureCoresSealed(t, cluster)
	testhelpers.EnsureCoresUnsealed(t, cluster)

	// Wait until a tidy run has completed.
	testhelpers.RetryUntil(t, 5*time.Second, func() error {
		resp, err = client.Logical().Read("pki/tidy-status")
		if err != nil {
			return fmt.Errorf("error reading tidy status: %w", err)
		}
		if finished, ok := resp.Data["time_finished"]; !ok || finished == "" || finished == nil {
			return fmt.Errorf("tidy time_finished not run yet: %v", finished)
		}
		return nil
	})

	// Since publish_stored_certificate_count_metrics is still false, these metrics should still not exist yet
	stableMetric = inmemSink.Data()
	mostRecentInterval = stableMetric[len(stableMetric)-1]
	_, ok = mostRecentInterval.Gauges["secrets.pki."+backendUUID+".total_revoked_certificates_stored"]
	if ok {
		t.Fatal("Certificate counting should be off by default, but revoked cert count was emitted as a metric in an unconfigured mount")
	}
	_, ok = mostRecentInterval.Gauges["secrets.pki."+backendUUID+".total_certificates_stored"]
	if ok {
		t.Fatal("Certificate counting should be off by default, but total certificate count was emitted as a metric in an unconfigured mount")
	}

	// But since certificate counting is on, the metrics should exist on tidyStatus endpoint:
	tidyStatus, err = client.Logical().Read("pki/tidy-status")
	require.NoError(t, err, "failed reading tidy-status endpoint")

	// backendUUID should exist, we need this for metrics
	backendUUID = tidyStatus.Data["internal_backend_uuid"].(string)
	// "current_cert_store_count", "current_revoked_cert_count"
	certStoreCount, ok := tidyStatus.Data["current_cert_store_count"]
	if !ok {
		t.Fatal("Certificate counting has been turned on, but current cert store count does not appear in tidy status")
	}
	if certStoreCount != json.Number("1") {
		t.Fatalf("Only created one certificate, but a got a certificate count of %v", certStoreCount)
	}
	revokedCertCount, ok := tidyStatus.Data["current_revoked_cert_count"]
	if !ok {
		t.Fatal("Certificate counting has been turned on, but revoked cert store count does not appear in tidy status")
	}
	if revokedCertCount != json.Number("0") {
		t.Fatalf("Have not yet revoked a certificate, but got a revoked cert store count of %v", revokedCertCount)
	}

	// Write the auto-tidy config, again, this time turning on metrics
	_, err = client.Logical().Write("pki/config/auto-tidy", map[string]interface{}{
		"enabled":                                  true,
		"interval_duration":                        "1s",
		"tidy_cert_store":                          true,
		"tidy_revoked_certs":                       true,
		"safety_buffer":                            "1s",
		"maintain_stored_certificate_counts":       true,
		"publish_stored_certificate_count_metrics": true,
	})
	require.NoError(t, err, "failed updating auto-tidy configuration")

	// Issue a cert and revoke it.
	resp, err = client.Logical().Write("pki/issue/local-testing", map[string]interface{}{
		"common_name": "example.com",
		"ttl":         "10s",
	})
	require.NoError(t, err, "failed to issue leaf certificate")
	require.NotNil(t, resp, "nil response without error on issuing leaf certificate")
	require.NotNil(t, resp.Data, "empty Data without error on issuing leaf certificate")
	require.NotEmpty(t, resp.Data["serial_number"])
	require.NotEmpty(t, resp.Data["certificate"])
	leafSerial := resp.Data["serial_number"].(string)
	leafCert := parseCert(t, resp.Data["certificate"].(string))

	// Read cert before revoking
	resp, err = client.Logical().Read("pki/cert/" + leafSerial)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotNil(t, resp.Data)
	require.NotEmpty(t, resp.Data["certificate"])
	revocationTime, err := (resp.Data["revocation_time"].(json.Number)).Int64()
	require.Equal(t, int64(0), revocationTime, "revocation time was not zero")
	require.Empty(t, resp.Data["revocation_time_rfc3339"], "revocation_time_rfc3339 was not empty")
	require.Empty(t, resp.Data["issuer_id"], "issuer_id was not empty")

	revokeResp, err := client.Logical().Write("pki/revoke", map[string]interface{}{
		"serial_number": leafSerial,
	})
	require.NoError(t, err, "failed revoking serial number: %s", leafSerial)

	for _, warning := range revokeResp.Warnings {
		if strings.Contains(warning, "already expired; refusing to add to CRL") {
			t.Skip("Skipping test as we missed the revocation window of our leaf cert")
		}
	}

	// We read the auto-tidy endpoint again, to ensure any metrics logic has completed (lock on config)
	_, err = client.Logical().Read("/pki/config/auto-tidy")
	require.NoError(t, err, "failed to read auto-tidy configuration")

	// Check Metrics After Cert Has Be Created and Revoked
	tidyStatus, err = client.Logical().Read("pki/tidy-status")
	require.NoError(t, err, "failed to read tidy-status")

	backendUUID = tidyStatus.Data["internal_backend_uuid"].(string)
	certStoreCount, ok = tidyStatus.Data["current_cert_store_count"]
	if !ok {
		t.Fatal("Certificate counting has been turned on, but current cert store count does not appear in tidy status")
	}
	if certStoreCount != json.Number("2") {
		t.Fatalf("Created root and leaf certificate, but a got a certificate count of %v", certStoreCount)
	}
	revokedCertCount, ok = tidyStatus.Data["current_revoked_cert_count"]
	if !ok {
		t.Fatal("Certificate counting has been turned on, but revoked cert store count does not appear in tidy status")
	}
	if revokedCertCount != json.Number("1") {
		t.Fatalf("Revoked one certificate, but got a revoked cert store count of %v\n:%v", revokedCertCount, tidyStatus)
	}
	// This should now be initialized
	certCountError, ok := tidyStatus.Data["certificate_counting_error"]
	if ok && certCountError.(string) != "" {
		t.Fatalf("Expected certificate count error to disappear after initialization, but got error %v", certCountError)
	}

	testhelpers.RetryUntil(t, newPeriod*5, func() error {
		stableMetric = inmemSink.Data()
		mostRecentInterval = stableMetric[len(stableMetric)-1]
		revokedCertCountGaugeValue, ok := mostRecentInterval.Gauges["secrets.pki."+backendUUID+".total_revoked_certificates_stored"]
		if !ok {
			return errors.New("turned on metrics, but revoked cert count was not emitted")
		}
		if revokedCertCountGaugeValue.Value != 1 {
			return fmt.Errorf("revoked one certificate, but metrics emitted a revoked cert store count of %v", revokedCertCountGaugeValue)
		}
		certStoreCountGaugeValue, ok := mostRecentInterval.Gauges["secrets.pki."+backendUUID+".total_certificates_stored"]
		if !ok {
			return errors.New("turned on metrics, but total certificate count was not emitted")
		}
		if certStoreCountGaugeValue.Value != 2 {
			return fmt.Errorf("stored two certificiates, but total certificate count emitted was %v", certStoreCountGaugeValue.Value)
		}
		return nil
	})

	// Wait for cert to expire and the safety buffer to elapse.
	sleepFor := time.Until(leafCert.NotAfter) + 3*time.Second
	t.Logf("%v: Sleeping for %v, leaf certificate expires: %v", time.Now().Format(time.RFC3339), sleepFor, leafCert.NotAfter)
	time.Sleep(sleepFor)

	// Wait for auto-tidy to run afterwards.
	waitForAutoTidyToFinish(t, client)

	// After Tidy, Cert Store Count Should Still Be Available, and Be Updated:
	// Check Metrics After Cert Has Be Created and Revoked
	tidyStatus, err = client.Logical().Read("pki/tidy-status")
	if err != nil {
		t.Fatal(err)
	}
	backendUUID = tidyStatus.Data["internal_backend_uuid"].(string)
	// "current_cert_store_count", "current_revoked_cert_count"
	certStoreCount, ok = tidyStatus.Data["current_cert_store_count"]
	if !ok {
		t.Fatal("Certificate counting has been turned on, but current cert store count does not appear in tidy status")
	}
	if certStoreCount != json.Number("1") {
		t.Fatalf("Created root and leaf certificate, deleted leaf, but a got a certificate count of %v", certStoreCount)
	}
	revokedCertCount, ok = tidyStatus.Data["current_revoked_cert_count"]
	if !ok {
		t.Fatal("Certificate counting has been turned on, but revoked cert store count does not appear in tidy status")
	}
	if revokedCertCount != json.Number("0") {
		t.Fatalf("Revoked certificate has been tidied, but got a revoked cert store count of %v", revokedCertCount)
	}

	testhelpers.RetryUntil(t, newPeriod*5, func() error {
		stableMetric = inmemSink.Data()
		mostRecentInterval = stableMetric[len(stableMetric)-1]
		revokedCertCountGaugeValue, ok := mostRecentInterval.Gauges["secrets.pki."+backendUUID+".total_revoked_certificates_stored"]
		if !ok {
			return errors.New("turned on metrics, but revoked cert count was not emitted")
		}
		if revokedCertCountGaugeValue.Value != 0 {
			return fmt.Errorf("revoked certificate has been tidied, but metrics emitted a revoked cert store count of %v", revokedCertCountGaugeValue)
		}
		certStoreCountGaugeValue, ok := mostRecentInterval.Gauges["secrets.pki."+backendUUID+".total_certificates_stored"]
		if !ok {
			return errors.New("turned on metrics, but total certificate count was not emitted")
		}
		if certStoreCountGaugeValue.Value != 1 {
			return fmt.Errorf("only one of two certificates left after tidy, but total certificate count emitted was %v", certStoreCountGaugeValue.Value)
		}
		return nil
	})
}

// This test uses the default safety buffer with backdating.
func TestTidyAcmeWithBackdate(t *testing.T) {
	t.Parallel()

	cluster, client, _ := setupAcmeBackend(t)
	defer cluster.Cleanup()
	testCtx := context.Background()

	// Grab the mount UUID for sys/raw invocations.
	pkiMount := findStorageMountUuid(t, client, "pki")

	// Register an Account, do nothing with it
	baseAcmeURL := "/v1/pki/acme/"
	accountKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "failed creating rsa key")

	acmeClient := getAcmeClientForCluster(t, cluster, baseAcmeURL, accountKey)

	// Create new account with order/cert
	t.Logf("Testing register on %s", baseAcmeURL)
	acct, err := acmeClient.Register(testCtx, &acme.Account{}, func(tosURL string) bool { return true })
	t.Logf("got account URI: %v", acct.URI)
	require.NoError(t, err, "failed registering account")
	identifiers := []string{"*.localdomain"}
	order, err := acmeClient.AuthorizeOrder(testCtx, []acme.AuthzID{
		{Type: "dns", Value: identifiers[0]},
	})
	require.NoError(t, err, "failed creating order")

	// HACK: Update authorization/challenge to completed as we can't really do it properly in this workflow test.
	markAuthorizationSuccess(t, client, acmeClient, acct, order)

	goodCr := &x509.CertificateRequest{DNSNames: []string{identifiers[0]}}
	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, "failed generated key for CSR")
	csr, err := x509.CreateCertificateRequest(rand.Reader, goodCr, csrKey)
	require.NoError(t, err, "failed generating csr")
	certs, _, err := acmeClient.CreateOrderCert(testCtx, order.FinalizeURL, csr, true)
	require.NoError(t, err, "order finalization failed")
	require.GreaterOrEqual(t, len(certs), 1, "expected at least one cert in bundle")

	acmeCert, err := x509.ParseCertificate(certs[0])
	require.NoError(t, err, "failed parsing acme cert")

	// -> Ensure we see it in storage. Since we don't have direct storage
	// access, use sys/raw interface.
	acmeThumbprintsPath := path.Join("sys/raw/logical", pkiMount, acmeThumbprintPrefix)
	listResp, err := client.Logical().ListWithContext(testCtx, acmeThumbprintsPath)
	require.NoError(t, err, "failed listing ACME thumbprints")
	require.NotEmpty(t, listResp.Data["keys"], "expected non-empty list response")

	// Run Tidy
	_, err = client.Logical().Write("pki/tidy", map[string]interface{}{
		"tidy_acme": true,
	})
	require.NoError(t, err)

	// Wait for tidy to finish.
	waitForTidyToFinish(t, client, "pki")

	// Check that the Account is Still There, Still Valid.
	account, err := acmeClient.GetReg(context.Background(), "" /* legacy unused param*/)
	require.NoError(t, err, "received account looking up acme account")
	require.Equal(t, acme.StatusValid, account.Status)

	// Find the associated thumbprint
	listResp, err = client.Logical().ListWithContext(testCtx, acmeThumbprintsPath)
	require.NoError(t, err)
	require.NotNil(t, listResp)
	thumbprintEntries := listResp.Data["keys"].([]interface{})
	require.Equal(t, len(thumbprintEntries), 1)
	thumbprint := thumbprintEntries[0].(string)

	// Let "Time Pass"; this is a HACK, this function sys-writes to overwrite the date on objects in storage
	duration := time.Until(acmeCert.NotAfter) + 31*24*time.Hour
	accountId := acmeClient.KID[strings.LastIndex(string(acmeClient.KID), "/")+1:]
	orderId := order.URI[strings.LastIndex(order.URI, "/")+1:]
	backDateAcmeOrderSys(t, testCtx, client, string(accountId), orderId, duration, pkiMount)

	// Run Tidy -> clean up order
	_, err = client.Logical().Write("pki/tidy", map[string]interface{}{
		"tidy_acme": true,
	})
	require.NoError(t, err)

	// Wait for tidy to finish.
	tidyResp := waitForTidyToFinish(t, client, "pki")

	require.Equal(t, tidyResp.Data["acme_orders_deleted_count"], json.Number("1"),
		"expected to revoke a single ACME order: %v", tidyResp)
	require.Equal(t, tidyResp.Data["acme_account_revoked_count"], json.Number("0"),
		"no ACME account should have been revoked: %v", tidyResp)
	require.Equal(t, tidyResp.Data["acme_account_deleted_count"], json.Number("0"),
		"no ACME account should have been revoked: %v", tidyResp)

	// Make sure our order is indeed deleted.
	_, err = acmeClient.GetOrder(context.Background(), order.URI)
	require.ErrorContains(t, err, "order does not exist")

	// Check that the Account is Still There, Still Valid.
	account, err = acmeClient.GetReg(context.Background(), "" /* legacy unused param*/)
	require.NoError(t, err, "received account looking up acme account")
	require.Equal(t, acme.StatusValid, account.Status)

	// Now back date the account to make sure we revoke it
	backDateAcmeAccountSys(t, testCtx, client, thumbprint, duration, pkiMount)

	// Run Tidy -> mark account revoked
	_, err = client.Logical().Write("pki/tidy", map[string]interface{}{
		"tidy_acme": true,
	})
	require.NoError(t, err)

	// Wait for tidy to finish.
	tidyResp = waitForTidyToFinish(t, client, "pki")
	require.Equal(t, tidyResp.Data["acme_orders_deleted_count"], json.Number("0"),
		"no ACME orders should have been deleted: %v", tidyResp)
	require.Equal(t, tidyResp.Data["acme_account_revoked_count"], json.Number("1"),
		"expected to revoke a single ACME account: %v", tidyResp)
	require.Equal(t, tidyResp.Data["acme_account_deleted_count"], json.Number("0"),
		"no ACME account should have been revoked: %v", tidyResp)

	// Lookup our account to make sure we get the appropriate revoked status
	account, err = acmeClient.GetReg(context.Background(), "" /* legacy unused param*/)
	require.NoError(t, err, "received account looking up acme account")
	require.Equal(t, acme.StatusRevoked, account.Status)

	// Let "Time Pass"; this is a HACK, this function sys-writes to overwrite the date on objects in storage
	backDateAcmeAccountSys(t, testCtx, client, thumbprint, duration, pkiMount)

	// Run Tidy -> remove account
	_, err = client.Logical().Write("pki/tidy", map[string]interface{}{
		"tidy_acme": true,
	})
	require.NoError(t, err)

	// Wait for tidy to finish.
	waitForTidyToFinish(t, client, "pki")

	// Check Account No Longer Appears
	listResp, err = client.Logical().ListWithContext(testCtx, acmeThumbprintsPath)
	require.NoError(t, err)
	if listResp != nil {
		thumbprintEntries = listResp.Data["keys"].([]interface{})
		require.Equal(t, 0, len(thumbprintEntries))
	}

	// Nor Under Account
	_, acctKID := path.Split(acct.URI)
	acctPath := path.Join("sys/raw/logical", pkiMount, acmeAccountPrefix, acctKID)
	t.Logf("account path: %v", acctPath)
	getResp, err := client.Logical().ReadWithContext(testCtx, acctPath)
	require.NoError(t, err)
	require.Nil(t, getResp)
}

// This test uses a smaller safety buffer.
func TestTidyAcmeWithSafetyBuffer(t *testing.T) {
	t.Parallel()

	// This would still be way easier if I could do both sides
	cluster, client, _ := setupAcmeBackend(t)
	defer cluster.Cleanup()
	testCtx := context.Background()

	// Grab the mount UUID for sys/raw invocations.
	pkiMount := findStorageMountUuid(t, client, "pki")

	// Register an Account, do nothing with it
	baseAcmeURL := "/v1/pki/acme/"
	accountKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "failed creating rsa key")

	acmeClient := getAcmeClientForCluster(t, cluster, baseAcmeURL, accountKey)

	// Create new account
	t.Logf("Testing register on %s", baseAcmeURL)
	acct, err := acmeClient.Register(testCtx, &acme.Account{}, func(tosURL string) bool { return true })
	t.Logf("got account URI: %v", acct.URI)
	require.NoError(t, err, "failed registering account")

	// -> Ensure we see it in storage. Since we don't have direct storage
	// access, use sys/raw interface.
	acmeThumbprintsPath := path.Join("sys/raw/logical", pkiMount, acmeThumbprintPrefix)
	listResp, err := client.Logical().ListWithContext(testCtx, acmeThumbprintsPath)
	require.NoError(t, err, "failed listing ACME thumbprints")
	require.NotEmpty(t, listResp.Data["keys"], "expected non-empty list response")
	thumbprintEntries := listResp.Data["keys"].([]interface{})
	require.Equal(t, len(thumbprintEntries), 1)

	// Wait for the account to expire.
	time.Sleep(2 * time.Second)

	// Run Tidy -> mark account revoked
	_, err = client.Logical().Write("pki/tidy", map[string]interface{}{
		"tidy_acme":                  true,
		"acme_account_safety_buffer": "1s",
	})
	require.NoError(t, err)

	// Wait for tidy to finish.
	statusResp := waitForTidyToFinish(t, client, "pki")
	require.Equal(t, statusResp.Data["acme_account_revoked_count"], json.Number("1"), "expected to revoke a single ACME account")

	// Wait for the account to expire.
	time.Sleep(2 * time.Second)

	// Run Tidy -> remove account
	_, err = client.Logical().Write("pki/tidy", map[string]interface{}{
		"tidy_acme":                  true,
		"acme_account_safety_buffer": "1s",
	})
	require.NoError(t, err)

	// Wait for tidy to finish.
	waitForTidyToFinish(t, client, "pki")

	// Check Account No Longer Appears
	listResp, err = client.Logical().ListWithContext(testCtx, acmeThumbprintsPath)
	require.NoError(t, err)
	if listResp != nil {
		thumbprintEntries = listResp.Data["keys"].([]interface{})
		require.Equal(t, 0, len(thumbprintEntries))
	}

	// Nor Under Account
	_, acctKID := path.Split(acct.URI)
	acctPath := path.Join("sys/raw/logical", pkiMount, acmeAccountPrefix, acctKID)
	t.Logf("account path: %v", acctPath)
	getResp, err := client.Logical().ReadWithContext(testCtx, acctPath)
	require.NoError(t, err)
	require.Nil(t, getResp)
}

// The sys tests refer to all of the tests using sys/raw/logical which work off of a client
func backDateAcmeAccountSys(t *testing.T, testContext context.Context, client *api.Client, thumbprintString string, backdateAmount time.Duration, mount string) {
	rawThumbprintPath := path.Join("sys/raw/logical/", mount, acmeThumbprintPrefix+thumbprintString)
	thumbprintResp, err := client.Logical().ReadWithContext(testContext, rawThumbprintPath)
	if err != nil {
		t.Fatalf("unable to fetch thumbprint response at %v: %v", rawThumbprintPath, err)
	}

	var thumbprint acmeThumbprint
	err = jsonutil.DecodeJSON([]byte(thumbprintResp.Data["value"].(string)), &thumbprint)
	if err != nil {
		t.Fatalf("unable to decode thumbprint response %v to find account entry: %v", thumbprintResp.Data, err)
	}

	accountPath := path.Join("sys/raw/logical", mount, acmeAccountPrefix+thumbprint.Kid)
	accountResp, err := client.Logical().ReadWithContext(testContext, accountPath)
	if err != nil {
		t.Fatalf("unable to fetch account entry %v: %v", thumbprint.Kid, err)
	}

	var account acmeAccount
	err = jsonutil.DecodeJSON([]byte(accountResp.Data["value"].(string)), &account)
	if err != nil {
		t.Fatalf("unable to decode acme account %v: %v", accountResp, err)
	}

	t.Logf("got account before update: %v", account)

	account.AccountCreatedDate = backDate(account.AccountCreatedDate, backdateAmount)
	account.MaxCertExpiry = backDate(account.MaxCertExpiry, backdateAmount)
	account.AccountRevokedDate = backDate(account.AccountRevokedDate, backdateAmount)

	t.Logf("got account after update: %v", account)

	encodeJSON, err := jsonutil.EncodeJSON(account)
	if err != nil {
		t.Fatalf("json encoding failed: %v", err)
	}

	_, err = client.Logical().WriteWithContext(context.Background(), accountPath, map[string]interface{}{
		"value":    base64.StdEncoding.EncodeToString(encodeJSON),
		"encoding": "base64",
	})
	if err != nil {
		t.Fatalf("error saving backdated account entry at %v: %v", accountPath, err)
	}

	ordersPath := path.Join("sys/raw/logical", mount, acmeAccountPrefix, thumbprint.Kid, "/orders/")
	ordersRaw, err := client.Logical().ListWithContext(context.Background(), ordersPath)
	require.NoError(t, err, "failed listing orders")

	if ordersRaw == nil {
		t.Log("skipping backdating orders as there are none")
		return
	}

	require.NotNil(t, ordersRaw, "got no response data")
	require.NotNil(t, ordersRaw.Data, "got no response data")

	orders := ordersRaw.Data

	for _, orderId := range orders["keys"].([]interface{}) {
		backDateAcmeOrderSys(t, testContext, client, thumbprint.Kid, orderId.(string), backdateAmount, mount)
	}

	// No need to change certificates entries here - no time is stored on AcmeCertEntry
}

func backDateAcmeOrderSys(t *testing.T, testContext context.Context, client *api.Client, accountKid string, orderId string, backdateAmount time.Duration, mount string) {
	rawOrderPath := path.Join("sys/raw/logical/", mount, acmeAccountPrefix, accountKid, "orders", orderId)
	orderResp, err := client.Logical().ReadWithContext(testContext, rawOrderPath)
	if err != nil {
		t.Fatalf("unable to fetch order entry %v on account %v at %v", orderId, accountKid, rawOrderPath)
	}

	var order *acmeOrder
	err = jsonutil.DecodeJSON([]byte(orderResp.Data["value"].(string)), &order)
	if err != nil {
		t.Fatalf("error decoding order entry %v on account %v, %v produced: %v", orderId, accountKid, orderResp, err)
	}

	order.Expires = backDate(order.Expires, backdateAmount)
	order.CertificateExpiry = backDate(order.CertificateExpiry, backdateAmount)

	encodeJSON, err := jsonutil.EncodeJSON(order)
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.Logical().WriteWithContext(context.Background(), rawOrderPath, map[string]interface{}{
		"value":    base64.StdEncoding.EncodeToString(encodeJSON),
		"encoding": "base64",
	})
	if err != nil {
		t.Fatalf("error saving backdated order entry %v on account %v : %v", orderId, accountKid, err)
	}

	for _, authId := range order.AuthorizationIds {
		backDateAcmeAuthorizationSys(t, testContext, client, accountKid, authId, backdateAmount, mount)
	}
}

func backDateAcmeAuthorizationSys(t *testing.T, testContext context.Context, client *api.Client, accountKid string, authId string, backdateAmount time.Duration, mount string) {
	rawAuthPath := path.Join("sys/raw/logical/", mount, acmeAccountPrefix, accountKid, "/authorizations/", authId)

	authResp, err := client.Logical().ReadWithContext(testContext, rawAuthPath)
	if err != nil {
		t.Fatalf("unable to fetch authorization %v : %v", rawAuthPath, err)
	}

	var auth *ACMEAuthorization
	err = jsonutil.DecodeJSON([]byte(authResp.Data["value"].(string)), &auth)
	if err != nil {
		t.Fatalf("error decoding auth %v, auth entry %v produced %v", rawAuthPath, authResp, err)
	}

	expiry, err := auth.GetExpires()
	if err != nil {
		t.Fatalf("could not get expiry on %v: %v", rawAuthPath, err)
	}
	newExpiry := backDate(expiry, backdateAmount)
	auth.Expires = time.Time.Format(newExpiry, time.RFC3339)

	encodeJSON, err := jsonutil.EncodeJSON(auth)
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.Logical().WriteWithContext(context.Background(), rawAuthPath, map[string]interface{}{
		"value":    base64.StdEncoding.EncodeToString(encodeJSON),
		"encoding": "base64",
	})
	if err != nil {
		t.Fatalf("error updating authorization date on %v: %v", rawAuthPath, err)
	}
}

func backDate(original time.Time, change time.Duration) time.Time {
	if original.IsZero() {
		return original
	}

	zeroTime := time.Time{}

	if original.Before(zeroTime.Add(change)) {
		return zeroTime
	}

	return original.Add(-change)
}

func waitForTidyToFinish(t *testing.T, client *api.Client, mount string) *api.Secret {
	var statusResp *api.Secret
	testhelpers.RetryUntil(t, 5*time.Second, func() error {
		var err error

		tidyStatusPath := mount + "/tidy-status"
		statusResp, err = client.Logical().Read(tidyStatusPath)
		if err != nil {
			return fmt.Errorf("failed reading path: %s: %w", tidyStatusPath, err)
		}
		if state, ok := statusResp.Data["state"]; !ok || state == "Running" {
			return errors.New("tidy status state is still running")
		}

		if errorOccurred, ok := statusResp.Data["error"]; !ok || !(errorOccurred == nil || errorOccurred == "") {
			return fmt.Errorf("tidy status returned an error: %s", errorOccurred)
		}

		return nil
	})

	t.Logf("got tidy status: %v", statusResp.Data)
	return statusResp
}

func waitForAutoTidyToFinish(t *testing.T, client *api.Client) {
	var foundTidyRunning string
	var foundTidyFinished bool
	timeoutChan := time.After(120 * time.Second)

	for {
		if foundTidyRunning != "" && foundTidyFinished {
			break
		}

		select {
		case <-timeoutChan:
			t.Fatalf("expected auto-tidy to run (%v) and finish (%v) before timeout", foundTidyRunning, foundTidyFinished)
		default:
			time.Sleep(250 * time.Millisecond)

			resp, err := client.Logical().Read("pki/tidy-status")
			require.NoError(t, err)
			require.NotNil(t, resp)
			require.NotNil(t, resp.Data)
			require.NotEmpty(t, resp.Data["state"])
			require.NotEmpty(t, resp.Data["time_started"])

			state := resp.Data["state"].(string)
			started := resp.Data["time_started"].(string)
			t.Logf("Resp: %v", resp.Data)

			// We want the _next_ tidy run after the cert expires. This
			// means if we're currently finished when we hit this the
			// first time, we want to wait for the next run.
			if foundTidyRunning == "" {
				foundTidyRunning = started
			} else if foundTidyRunning != started && state == "Finished" {
				foundTidyFinished = true
			}
		}
	}
}

func waitForManualTidy(t *testing.T, client *api.Client, tidyConfig map[string]interface{}) {
	status, err := client.Logical().Read("pki/tidy-status")
	require.NoError(t, err, "got error reading initial tidy status")

	t.Logf("initial status resp: %v", status)

	_, err = client.Logical().Write("pki/tidy", tidyConfig)
	require.NoError(t, err, "got error starting tidy")

	timeoutChan := time.After(120 * time.Second)

	for {
		select {
		case <-timeoutChan:
			t.Fatal("expected manual tidy to run before timeout")
		default:
			time.Sleep(50 * time.Millisecond)

			newStatus, err := client.Logical().Read("pki/tidy-status")
			require.NoError(t, err, "got error reading subsequent tidy status")

			if newStatus.Data["state"].(string) == "Finished" {
				thisStart, err := time.Parse(time.RFC3339, newStatus.Data["time_started"].(string))
				require.NoError(t, err, "failed to parse time")
				lastStartRaw, ok := status.Data["time_started"]
				if !ok || lastStartRaw == nil {
					return
				}

				lastStart, err := time.Parse(time.RFC3339, lastStartRaw.(string))
				require.NoError(t, err, "failed to parse time")

				if thisStart.After(lastStart) {
					return
				}
			}
		}
	}
}

func TestTidyWithInvalidCertInStore(t *testing.T) {
	t.Parallel()
	b, s := CreateBackendWithStorage(t)

	// Invalid certificate content to simulate an unprocessable cert in the store
	invalidCert := `
MIIBrjCCARegAwIBAgIBATANBgkqhkiG9w0BAQsFADAPMQ0wCwYDVQQDEwR0ZXN0
MCIYDzAwMDEwMTAxMDAwMDAwWhgPMDAwMTAxMDEwMDAwMDBaMA8xDTALBgNVBAMT
BHRlc3QwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMiFchnHms9l9NninAIz
SkY9acwl9Bk2AtmJrNCenFpiA17AcOO5q8DJYwdXi6WPKlVgcyH+ysW8XMWkq+CP
yhtF/+LMzl9odaUF2iUy3vgTC5gxGLWH5URVssx21Und2Pm2f4xyou5IVxbS9dxy
jLvV9PEY9BIb0H+zFthjhihDAgMBAAGjFjAUMAgGAioDBAIFADAIBgIqAwQCBQAw
DQYJKoZIhvcNAQELBQADgYEAlhQ4TQQKIQ8GUyzGiN/75TCtQtjhMGemxc0cNgre
d9rmm4DjydH0t7/sMCB56lQrfhJNplguzsbjFW4l245KbNKHfLiqwEGUgZjBNKur
ot6qX/skahLtt0CNOaFIge75HVKe/69OrWQGdp18dkay/KS4Glu8YMKIjOhfrUi1
NZA=`

	// Decode base64 to get raw DER bytes
	invalidCertDER, err := base64.StdEncoding.DecodeString(invalidCert)
	require.NoError(t, err, "failed to decode base64 certificate content")

	// Generate a root, a role, and both short (1s) and long (5s) TTL certs
	_, err = CBWrite(b, s, "root/generate/internal", map[string]interface{}{
		"common_name": "root example.com",
		"issuer_name": "root",
		"ttl":         "20m",
		"key_type":    "ec",
	})
	require.NoError(t, err)
	_, err = CBWrite(b, s, "roles/local-testing", map[string]interface{}{
		"allow_any_name":    true,
		"enforce_hostnames": false,
		"key_type":          "ec",
	})
	require.NoError(t, err)
	_, err = CBWrite(b, s, "issue/local-testing", map[string]interface{}{
		"common_name": "long-lived",
		"ttl":         "5s",
	})
	require.NoError(t, err)
	resp, err := CBWrite(b, s, "issue/local-testing", map[string]interface{}{
		"common_name": "short-lived",
		"ttl":         "1s",
	})
	require.NoError(t, err)
	shortLivedCert := parseCert(t, resp.Data["certificate"].(string))
	shortLivedSerial := resp.Data["serial_number"].(string)

	// Write invalid certificate to storage
	err = s.Put(ctx, &logical.StorageEntry{
		Key:   "certs/1",
		Value: invalidCertDER,
	})
	require.NoError(t, err, "failed to add invalid certificate to the store for testing")

	// check root, invalid and valid certs are in store
	resp, err = CBList(b, s, "certs")
	require.NoError(t, err)
	certKeys := resp.Data["keys"].([]string)
	require.Len(t, certKeys, 4, "expected 4 certificates in the store")

	// Wait for short lived cert to expire and the safety buffer to elapse.
	time.Sleep(time.Until(shortLivedCert.NotAfter) + 1*time.Second)

	// Define tidy configuration
	tidyConfig := &tidyConfig{
		CertStore:    true,
		InvalidCerts: true,
		SafetyBuffer: 1,
	}

	// Call doTidyCertStore directly
	_, err = b.doTidyCertStore(context.Background(), &logical.Request{Storage: s}, b.Logger(), tidyConfig)
	require.NoError(t, err, "tidy operation should complete without errors")

	resp, err = CBList(b, s, "certs")
	require.NoError(t, err, "unable to list certificates in store")
	certKeys = resp.Data["keys"].([]string)

	// Verify root and long-lived leaf certs are in cert store, while the expired and invalid certs are not.
	require.Len(t, certKeys, 2, "expected two certificates to remain in the store")
	require.NotContains(t, certKeys, "1", "invalid certificate '1' should have been removed from the store")
	require.NotContains(t, certKeys, shortLivedSerial, "expired cert should have been removed from the store")
}

func TestTidyWithInvalidRevokedCertInStore(t *testing.T) {
	t.Parallel()
	b, s := CreateBackendWithStorage(t)

	// Invalid certificate content to simulate an unprocessable cert in the store
	invalidCert := `
MIIBrjCCARegAwIBAgIBATANBgkqhkiG9w0BAQsFADAPMQ0wCwYDVQQDEwR0ZXN0
MCIYDzAwMDEwMTAxMDAwMDAwWhgPMDAwMTAxMDEwMDAwMDBaMA8xDTALBgNVBAMT
BHRlc3QwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMiFchnHms9l9NninAIz
SkY9acwl9Bk2AtmJrNCenFpiA17AcOO5q8DJYwdXi6WPKlVgcyH+ysW8XMWkq+CP
yhtF/+LMzl9odaUF2iUy3vgTC5gxGLWH5URVssx21Und2Pm2f4xyou5IVxbS9dxy
jLvV9PEY9BIb0H+zFthjhihDAgMBAAGjFjAUMAgGAioDBAIFADAIBgIqAwQCBQAw
DQYJKoZIhvcNAQELBQADgYEAlhQ4TQQKIQ8GUyzGiN/75TCtQtjhMGemxc0cNgre
d9rmm4DjydH0t7/sMCB56lQrfhJNplguzsbjFW4l245KbNKHfLiqwEGUgZjBNKur
ot6qX/skahLtt0CNOaFIge75HVKe/69OrWQGdp18dkay/KS4Glu8YMKIjOhfrUi1
NZA=`

	// Decode base64 to get raw DER bytes
	invalidCertDER, err := base64.StdEncoding.DecodeString(invalidCert)
	require.NoError(t, err, "failed to decode base64 certificate content")

	// Write invalid certificate to storage
	err = s.Put(ctx, &logical.StorageEntry{
		Key:   "certs/1",
		Value: invalidCertDER,
	})
	require.NoError(t, err, "failed to add invalid certificate to the store for testing")

	// Write invalid cert to revocation storage.
	info := revocationInfo{
		CertificateBytes:  invalidCertDER,
		RevocationTime:    time.Now().Add(-5 * time.Second).Unix(),
		RevocationTimeUTC: time.Now().Add(-5 * time.Second).UTC(),
	}
	revEntry, err := logical.StorageEntryJSON(revokedPath+"1", info)
	require.NoError(t, err)
	err = s.Put(ctx, revEntry)
	require.NoError(t, err, "failed to write revocation entry")

	// check root, invalid and valid certs are in store
	resp, err := CBList(b, s, "certs")
	require.NoError(t, err)
	certKeys := resp.Data["keys"].([]string)
	require.Len(t, certKeys, 1, "expected invalid certificate in the store")

	// Check revoked cert is in the store.
	resp, err = CBList(b, s, "certs/revoked")
	require.NoError(t, err)
	certKeys = resp.Data["keys"].([]string)
	require.Len(t, certKeys, 1, "expected invalid certificate in the revocation store")

	// Define tidy configuration
	tidyConfig := &tidyConfig{
		InvalidCerts: true,
		SafetyBuffer: 1,
	}

	// Call tidy directly
	_, err = b.doTidyCertStore(context.Background(), &logical.Request{Storage: s}, b.Logger(), tidyConfig)
	require.NoError(t, err, "tidy operation should complete without errors")

	// There should still be a single entry here
	resp, err = CBList(b, s, "certs/revoked")
	require.NoError(t, err)
	require.Len(t, resp.Data["keys"].([]string), 1, "expected a single pending revocation entry")

	_, err = b.doTidyRevocationStore(context.Background(), &logical.Request{Storage: s}, b.Logger(), tidyConfig, 0)
	require.NoError(t, err, "tidy revoked operation should complete without errors")

	// Verify we have nothing in either list.
	resp, err = CBList(b, s, "certs")
	require.NoError(t, err, "unable to list certificates in store")
	require.Empty(t, resp.Data)

	resp, err = CBList(b, s, "certs/revoked")
	require.NoError(t, err)
	require.Empty(t, resp.Data)
}

func TestRevokedSafetyBufferConfig(t *testing.T) {
	t.Parallel()

	b, s := CreateBackendWithStorage(t)

	// Verify that the default of revoked_safety_buffer is the default of safety_buffer when neither are set
	resp, err := CBWrite(b, s, "config/auto-tidy", map[string]interface{}{})
	requireSuccessNonNilResponse(t, resp, err, "expected to write auto-tidy config")
	resp, err = CBRead(b, s, "config/auto-tidy")
	requireSuccessNonNilResponse(t, resp, err, "expected to read auto-tidy config")
	require.Equal(t, resp.Data["safety_buffer"].(int), resp.Data["revoked_safety_buffer"].(int), "expected revoked_safety_buffer to be set to safetyBuffer")

	// Verify that revoked_safety_buffer defaults to safety_buffer when safety_buffer is explicitly set
	safetyBuffer := 3600
	resp, err = CBWrite(b, s, "config/auto-tidy", map[string]interface{}{
		"safety_buffer": safetyBuffer,
	})
	requireSuccessNonNilResponse(t, resp, err, "expected to be able to set safety_buffer")

	resp, err = CBRead(b, s, "config/auto-tidy")
	requireSuccessNonNilResponse(t, resp, err, "expected to read auto-tidy config")
	require.Equal(t, safetyBuffer, resp.Data["revoked_safety_buffer"].(int), "expected revoked_safety_buffer to be set to safetyBuffer")
	require.Equal(t, safetyBuffer, resp.Data["safety_buffer"].(int), "expected safety_buffer to be set to safetyBuffer")

	// Verify that revoked_safety_buffer defaults to safety_buffer when safety_buffer is explicitly set multiple times,
	// and revoked_safety_buffer is not set explicitly.
	safetyBuffer2 := 200
	resp, err = CBWrite(b, s, "config/auto-tidy", map[string]interface{}{
		"safety_buffer": safetyBuffer2,
	})
	requireSuccessNonNilResponse(t, resp, err, "expected to be able to set safety_buffer")

	resp, err = CBRead(b, s, "config/auto-tidy")
	requireSuccessNonNilResponse(t, resp, err, "expected to read auto-tidy config")
	require.Equal(t, safetyBuffer2, resp.Data["revoked_safety_buffer"].(int), "expected revoked_safety_buffer to be set to safetyBuffer2")
	require.Equal(t, safetyBuffer2, resp.Data["safety_buffer"].(int), "expected safety_buffer to be set to safetyBuffer2")

	// Verify that revoked_safety_buffer can be explicitly set
	revokedSafetyBuffer := 400
	resp, err = CBWrite(b, s, "config/auto-tidy", map[string]interface{}{
		"safety_buffer":         safetyBuffer,
		"revoked_safety_buffer": revokedSafetyBuffer,
	})
	requireSuccessNonNilResponse(t, resp, err, "expected to be able to set revoked_safety_buffer")

	resp, err = CBRead(b, s, "config/auto-tidy")
	requireSuccessNonNilResponse(t, resp, err, "expected to read auto-tidy config")
	require.Equal(t, revokedSafetyBuffer, resp.Data["revoked_safety_buffer"].(int), "expected revoked_safety_buffer to be set to revokedSafetyBuffer")
	require.Equal(t, safetyBuffer, resp.Data["safety_buffer"].(int), "expected safety_buffer to be set to safetyBuffer")
}

func TestSafetyBufferVsRevokedSafetyBuffer(t *testing.T) {
	t.Parallel()

	// Short interval duration to trigger frequent auto-tidy runs
	newPeriod := 1 * time.Second

	// Set up the test cluster
	coreConfig := &vault.CoreConfig{
		LogicalBackends: map[string]logical.Factory{
			"pki": Factory,
		},
		EnableRaw:      true,
		RollbackPeriod: newPeriod,
	}
	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
	})
	cluster.Start()
	defer cluster.Cleanup()
	client := cluster.Cores[0].Client

	// Mount PKI
	err := client.Sys().Mount("pki", &api.MountInput{
		Type: "pki",
		Config: api.MountConfigInput{
			DefaultLeaseTTL: "10m",
			MaxLeaseTTL:     "60m",
		},
	})
	require.NoError(t, err)

	// Generate a root certificate
	resp, err := client.Logical().Write("pki/root/generate/internal", map[string]interface{}{
		"ttl":         "40h",
		"common_name": "Root X1",
		"key_type":    "ec",
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotEmpty(t, resp.Data)

	// Run tidy so status is not empty when we run it later
	_, err = client.Logical().Write("pki/tidy", map[string]interface{}{
		"tidy_revoked_certs": true,
	})
	require.NoError(t, err)

	// Set up a role for testing
	_, err = client.Logical().Write("pki/roles/local-testing", map[string]interface{}{
		"allow_any_name":    true,
		"enforce_hostnames": false,
		"key_type":          "ec",
	})
	require.NoError(t, err)

	// Configure auto-tidy with different safety buffers
	_, err = client.Logical().Write("pki/config/auto-tidy", map[string]interface{}{
		"enabled":               true,
		"interval_duration":     "1s",
		"tidy_cert_store":       true,
		"tidy_revoked_certs":    true,
		"safety_buffer":         "2s",
		"revoked_safety_buffer": "15s",
	})
	require.NoError(t, err)

	// Issue a certificate that expires soon
	resp, err = client.Logical().Write("pki/issue/local-testing", map[string]interface{}{
		"common_name": "example.com",
		"ttl":         "5s",
	})
	require.NoError(t, err)
	leafSerial := resp.Data["serial_number"].(string)
	leafCert := parseCert(t, resp.Data["certificate"].(string))

	// Issue and revoke another certificate
	resp, err = client.Logical().Write("pki/issue/local-testing", map[string]interface{}{
		"common_name": "revoked-example.com",
		"ttl":         "10s",
	})
	require.NoError(t, err)
	revokedSerial := resp.Data["serial_number"].(string)
	revokedCert := parseCert(t, resp.Data["certificate"].(string))

	_, err = client.Logical().Write("pki/revoke", map[string]interface{}{
		"serial_number": revokedSerial,
	})
	require.NoError(t, err)

	// Issue a certificate that expires after the revoked
	// certificate. This expiration needs to be longer than
	// revoked_safety_buffer+revoked.ttl.
	resp, err = client.Logical().Write("pki/issue/local-testing", map[string]interface{}{
		"common_name": "example.com",
		"ttl":         "35s",
	})
	require.NoError(t, err)
	lastLeafSerial := resp.Data["serial_number"].(string)
	lastLeafCert := parseCert(t, resp.Data["certificate"].(string))

	// Wait for the first certificate to expire and the safety buffer to elapse
	time.Sleep(time.Until(leafCert.NotAfter) + 3*time.Second)

	// Wait for auto-tidy to run afterwards.
	waitForAutoTidyToFinish(t, client)

	// The expired certificate should be tidied now
	resp, err = client.Logical().Read("pki/cert/" + leafSerial)
	require.Nil(t, err)
	require.Nil(t, resp)

	// Ensure the revoked certificate is not tidied before revoked_safety_buffer has passed
	time.Sleep(time.Until(revokedCert.NotAfter) + 3*time.Second)
	waitForAutoTidyToFinish(t, client)

	// The revoked certificate should still be present: we've not passed
	// revoked_safety_buffer, only safety_buffer.
	resp, err = client.Logical().Read("pki/cert/" + revokedSerial)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotNil(t, resp.Data["certificate"], "Revoked certificate should not be tidied before revoked_safety_buffer")

	// Wait for the revoked_safety_buffer to pass
	time.Sleep(time.Until(revokedCert.NotAfter) + 16*time.Second)
	waitForAutoTidyToFinish(t, client)

	// Confirm the revoked certificate has been tidied
	resp, err = client.Logical().Read("pki/cert/" + revokedSerial)
	require.Nil(t, err)
	require.Nil(t, resp)

	// Confirm the final certificate has not been tidied.
	resp, err = client.Logical().Read("pki/cert/" + lastLeafSerial)
	require.NoError(t, err)
	require.NotNil(t, resp)

	// Ensure it is cleaned up afterwards.
	time.Sleep(time.Until(lastLeafCert.NotAfter) + 3*time.Second)
	waitForAutoTidyToFinish(t, client)

	resp, err = client.Logical().Read("pki/cert/" + lastLeafSerial)
	require.Nil(t, err)
	require.Nil(t, resp)
}

func TestTidyPaginationConfig(t *testing.T) {
	t.Parallel()

	b, s := CreateBackendWithStorage(t)

	// Verify that the default of page_size is 1000
	resp, err := CBWrite(b, s, "config/auto-tidy", map[string]interface{}{})
	requireSuccessNonNilResponse(t, resp, err, "expected to write auto-tidy config")
	resp, err = CBRead(b, s, "config/auto-tidy")
	requireSuccessNonNilResponse(t, resp, err, "expected to read auto-tidy config")
	require.Equal(t, 1000, resp.Data["page_size"].(int), "expected page_size to be defaulted to 1000")

	// Verify that page_size can be explicitly set
	pageSize := 75
	resp, err = CBWrite(b, s, "config/auto-tidy", map[string]interface{}{
		"page_size": pageSize,
	})
	requireSuccessNonNilResponse(t, resp, err, "expected to be able to set page_size")

	resp, err = CBRead(b, s, "config/auto-tidy")
	requireSuccessNonNilResponse(t, resp, err, "expected to read auto-tidy config")
	require.Equal(t, pageSize, resp.Data["page_size"].(int), "expected page_size to be set to pageSize")

	// Expect an error when setting page_size to less than 5
	pageSizeInvalid := 4
	resp, err = CBWrite(b, s, "config/auto-tidy", map[string]interface{}{
		"page_size": pageSizeInvalid,
	})
	require.Error(t, err, "expected error when setting page_size less than 5")
	require.Contains(t, err.Error(), "page_size must be at least 5", "page_size must be greater than five")

	// Check page size is still the previous value
	resp, err = CBRead(b, s, "config/auto-tidy")
	requireSuccessNonNilResponse(t, resp, err, "expected to read auto-tidy config")
	require.Equal(t, pageSize, resp.Data["page_size"].(int), "expected page_size to be set to pageSize")
}

func TestTidyPagination(t *testing.T) {
	t.Parallel()

	// Short interval duration to trigger frequent auto-tidy runs
	newPeriod := 1 * time.Second

	// Set up the test cluster
	coreConfig := &vault.CoreConfig{
		LogicalBackends: map[string]logical.Factory{
			"pki": Factory,
		},
		EnableRaw:      true,
		RollbackPeriod: newPeriod,
	}
	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
	})
	cluster.Start()
	defer cluster.Cleanup()
	client := cluster.Cores[0].Client

	// Mount PKI
	err := client.Sys().Mount("pki", &api.MountInput{
		Type: "pki",
		Config: api.MountConfigInput{
			DefaultLeaseTTL: "10m",
			MaxLeaseTTL:     "60m",
		},
	})
	require.NoError(t, err)

	// Generate a root certificate
	resp, err := client.Logical().Write("pki/root/generate/internal", map[string]interface{}{
		"ttl":         "40h",
		"common_name": "Root X1",
		"key_type":    "ec",
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotEmpty(t, resp.Data)
	rootSerial := resp.Data["serial_number"].(string)

	// Run tidy so status is not empty when we run it later
	_, err = client.Logical().Write("pki/tidy", map[string]interface{}{
		"tidy_revoked_certs": true,
	})
	require.NoError(t, err)

	// Set up a role for testing
	_, err = client.Logical().Write("pki/roles/local-testing", map[string]interface{}{
		"allow_any_name":    true,
		"enforce_hostnames": false,
		"key_type":          "ec",
	})
	require.NoError(t, err)

	// Configure auto-tidy
	_, err = client.Logical().Write("pki/config/auto-tidy", map[string]interface{}{
		"enabled":               true,
		"interval_duration":     "1s",
		"tidy_cert_store":       true,
		"tidy_revoked_certs":    true,
		"page_size":             5,
		"safety_buffer":         "1s",
		"revoked_safety_buffer": "1s",
	})
	require.NoError(t, err)

	// Issue 27 leaf certificates to populate the cert store.
	// This number is chosen to ensure that the tidy operation can process multiple pages,
	// even when the page size limit is set below the total number of certificates.
	for i := 0; i < 26; i++ {
		_, err = client.Logical().Write("pki/issue/local-testing", map[string]interface{}{
			"common_name": "example.com",
			"ttl":         "1s",
		})
		require.NoError(t, err)
	}
	// the last leaf cert being issued
	resp, err = client.Logical().Write("pki/issue/local-testing", map[string]interface{}{
		"common_name": "last.com",
		"ttl":         "1s",
	})
	require.NoError(t, err)
	lastCert := parseCert(t, resp.Data["certificate"].(string))

	// Issue another 4 leaf certificates then revoke them. This is done to ensure that
	// the tidy operation can process certificates less than its the page size.
	for i := 0; i < 4; i++ {
		resp, err = client.Logical().Write("pki/issue/local-testing", map[string]interface{}{
			"common_name": "revoked.com",
			"ttl":         "1s",
		})
		require.NoError(t, err)
		revokedSerial := resp.Data["serial_number"].(string)

		_, err = client.Logical().Write("pki/revoke", map[string]interface{}{
			"serial_number": revokedSerial,
		})
		require.NoError(t, err)
	}

	// Wait for the last certificate to expire, revoked safety buffer and safety buffer to elapse
	time.Sleep(time.Until(lastCert.NotAfter) + 3*time.Second)

	// Wait for auto-tidy to run afterwards.
	waitForAutoTidyToFinish(t, client)

	// List remaining certificates in the cert store
	resp, err = client.Logical().List("pki/certs/")
	require.NoError(t, err, "unable to list certificates in store")

	// Check that only the root certificate remains
	certKeys := resp.Data["keys"].([]interface{})
	require.Len(t, certKeys, 1, "expected only root cert to remain in the store")
	require.Contains(t, certKeys, rootSerial, "expected only root cert to remain in the store")
}
