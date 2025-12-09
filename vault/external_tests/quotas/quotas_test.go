// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package quotas

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/sdk/v2/helper/testhelpers/schema"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"

	"github.com/openbao/openbao/builtin/credential/userpass"
	"github.com/openbao/openbao/builtin/logical/pki"
	"github.com/openbao/openbao/helper/testhelpers/teststorage"
	"github.com/openbao/openbao/vault"
)

var coreConfig = &vault.CoreConfig{
	LogicalBackends: map[string]logical.Factory{
		"pki": pki.Factory,
	},
	CredentialBackends: map[string]logical.Factory{
		"userpass": userpass.Factory,
	},
}

func setupMounts(t *testing.T, client *api.Client) {
	t.Helper()

	err := client.Sys().EnableAuthWithOptions("userpass", &api.EnableAuthOptions{
		Type: "userpass",
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.Logical().Write("auth/userpass/users/foo", map[string]interface{}{
		"password": "bar",
	})
	if err != nil {
		t.Fatal(err)
	}

	err = client.Sys().Mount("pki", &api.MountInput{
		Type: "pki",
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.Logical().Write("pki/root/generate/internal", map[string]interface{}{
		"common_name": "testvault.com",
		"ttl":         "200h",
		"ip_sans":     "127.0.0.1",
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.Logical().Write("pki/roles/test", map[string]interface{}{
		"require_cn":       false,
		"allowed_domains":  "testvault.com",
		"allow_subdomains": true,
		"max_ttl":          "2h",
		"generate_lease":   true,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func teardownMounts(t *testing.T, client *api.Client) {
	t.Helper()
	if err := client.Sys().Unmount("pki"); err != nil {
		t.Fatal(err)
	}
	if err := client.Sys().DisableAuth("userpass"); err != nil {
		t.Fatal(err)
	}
	if err := client.Sys().DisableAuth("approle"); err != nil {
		t.Fatal(err)
	}
}

func testRPS(reqFunc func(numSuccess, numFail *atomic.Int32), d time.Duration) (int32, int32, time.Duration) {
	numSuccess := &atomic.Int32{}
	numFail := &atomic.Int32{}

	start := time.Now()
	end := start.Add(d)
	for time.Now().Before(end) {
		reqFunc(numSuccess, numFail)
	}

	return numSuccess.Load(), numFail.Load(), time.Since(start)
}

func testRPSWithNS(reqFunc func(numSuccess, numFail *atomic.Int32, ns string), d time.Duration, ns string) (int32, int32, time.Duration) {
	numSuccess := &atomic.Int32{}
	numFail := &atomic.Int32{}

	start := time.Now()
	end := start.Add(d)
	for time.Now().Before(end) {
		reqFunc(numSuccess, numFail, ns)
	}

	return numSuccess.Load(), numFail.Load(), time.Since(start)
}

func TestQuotas_RateLimit_DupName(t *testing.T) {
	conf, opts := teststorage.ClusterSetup(coreConfig, nil, nil)
	opts.NoDefaultQuotas = true
	opts.RequestResponseCallback = schema.ResponseValidatingCallback(t)
	cluster := vault.NewTestCluster(t, conf, opts)
	cluster.Start()
	defer cluster.Cleanup()
	core := cluster.Cores[0].Core
	client := cluster.Cores[0].Client
	vault.TestWaitActive(t, core)

	// create a rate limit quota w/ 'secret' path
	_, err := client.Logical().Write("sys/quotas/rate-limit/secret-rlq", map[string]interface{}{
		"rate": 7.7,
		"path": "secret",
	})
	require.NoError(t, err)

	s, err := client.Logical().Read("sys/quotas/rate-limit/secret-rlq")
	require.NoError(t, err)
	require.NotEmpty(t, s.Data)

	// create a rate limit quota w/ empty path (same name)
	_, err = client.Logical().Write("sys/quotas/rate-limit/secret-rlq", map[string]interface{}{
		"rate": 7.7,
		"path": "",
	})
	require.NoError(t, err)

	// list again and verify that only 1 item is returned
	s, err = client.Logical().List("sys/quotas/rate-limit")
	require.NoError(t, err)

	require.Len(t, s.Data, 1, "incorrect number of quotas")
}

func TestQuotas_RateLimit_DupPath(t *testing.T) {
	conf, opts := teststorage.ClusterSetup(coreConfig, nil, nil)
	opts.NoDefaultQuotas = true
	opts.RequestResponseCallback = schema.ResponseValidatingCallback(t)
	cluster := vault.NewTestCluster(t, conf, opts)
	cluster.Start()
	defer cluster.Cleanup()

	core := cluster.Cores[0].Core
	client := cluster.Cores[0].Client
	vault.TestWaitActive(t, core)
	// create a global rate limit quota
	_, err := client.Logical().Write("sys/quotas/rate-limit/global-rlq", map[string]interface{}{
		"rate": 10,
		"path": "",
	})
	require.NoError(t, err)

	// create a rate limit quota w/ 'secret' path
	_, err = client.Logical().Write("sys/quotas/rate-limit/secret-rlq", map[string]interface{}{
		"rate": 7.7,
		"path": "secret",
	})
	require.NoError(t, err)

	s, err := client.Logical().Read("sys/quotas/rate-limit/secret-rlq")
	require.NoError(t, err)
	require.NotEmpty(t, s.Data)

	// create a rate limit quota w/ empty path (same name)
	_, err = client.Logical().Write("sys/quotas/rate-limit/secret-rlq", map[string]interface{}{
		"rate": 7.7,
		"path": "",
	})

	if err == nil {
		t.Fatal("Duplicated paths were accepted")
	}
}

func TestQuotas_RateLimitQuota_ExemptPaths(t *testing.T) {
	conf, opts := teststorage.ClusterSetup(coreConfig, nil, nil)
	opts.NoDefaultQuotas = true
	opts.RequestResponseCallback = schema.ResponseValidatingCallback(t)
	cluster := vault.NewTestCluster(t, conf, opts)
	cluster.Start()
	defer cluster.Cleanup()

	core := cluster.Cores[0].Core
	client := cluster.Cores[0].Client
	vault.TestWaitActive(t, core)

	_, err := client.Logical().Write("sys/quotas/rate-limit/rlq", map[string]interface{}{
		"rate": 7.7,
	})
	require.NoError(t, err)

	// ensure exempt paths are not empty by default
	resp, err := client.Logical().Read("sys/quotas/config")
	require.NoError(t, err)
	require.NotEmpty(t, resp.Data["rate_limit_exempt_paths"].([]interface{}), "expected no exempt paths by default")

	reqFunc := func(numSuccess, numFail *atomic.Int32) {
		_, err := client.Logical().Read("sys/quotas/rate-limit/rlq")

		if err != nil {
			numFail.Add(1)
		} else {
			numSuccess.Add(1)
		}
	}

	numSuccess, numFail, elapsed := testRPS(reqFunc, 5*time.Second)
	ideal := 8 + (7.7 * float64(elapsed) / float64(time.Second))
	want := int32(ideal + 1)
	require.NotZerof(t, numFail, "expected some requests to fail; numSuccess: %d, elapsed: %d", numSuccess, elapsed)
	require.LessOrEqualf(t, numSuccess, want, "too many successful requests;numSuccess: %d, numFail: %d, elapsed: %d", numSuccess, numFail, elapsed)

	// allow time (1s) for rate limit to refill before updating the quota config
	time.Sleep(time.Second)

	_, err = client.Logical().Write("sys/quotas/config", map[string]interface{}{
		"rate_limit_exempt_paths": []string{"sys/quotas/rate-limit"},
	})
	require.NoError(t, err)

	// all requests should success
	numSuccess, numFail, _ = testRPS(reqFunc, 5*time.Second)
	require.NotZero(t, numSuccess)
	require.Zero(t, numFail)
}

func TestQuotas_RateLimitQuota_DefaultExemptPaths(t *testing.T) {
	conf, opts := teststorage.ClusterSetup(coreConfig, nil, nil)
	opts.NoDefaultQuotas = true
	opts.RequestResponseCallback = schema.ResponseValidatingCallback(t)
	cluster := vault.NewTestCluster(t, conf, opts)
	cluster.Start()
	defer cluster.Cleanup()

	core := cluster.Cores[0].Core
	client := cluster.Cores[0].Client
	vault.TestWaitActive(t, core)

	_, err := client.Logical().Write("sys/quotas/rate-limit/rlq", map[string]interface{}{
		"rate": 1,
	})
	require.NoError(t, err)

	resp, err := client.Logical().Read("sys/health")
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotNil(t, resp.Data)

	// The second sys/health call should not fail as /v1/sys/health is
	// part of the default exempt paths
	resp, err = client.Logical().Read("sys/health")
	require.NoError(t, err)
	// If the response is nil, then we are being rate limited
	require.NotNil(t, resp)
	require.NotNil(t, resp.Data)
}

func TestQuotas_RateLimitQuota_Mount(t *testing.T) {
	conf, opts := teststorage.ClusterSetup(coreConfig, nil, nil)
	cluster := vault.NewTestCluster(t, conf, opts)
	cluster.Start()
	defer cluster.Cleanup()

	core := cluster.Cores[0].Core
	client := cluster.Cores[0].Client
	vault.TestWaitActive(t, core)

	setupMounts(t, client)

	reqFunc := func(numSuccess, numFail *atomic.Int32) {
		_, err := client.Logical().Read("pki/cert/ca_chain")

		if err != nil {
			numFail.Add(1)
		} else {
			numSuccess.Add(1)
		}
	}

	// Create a rate limit quota with a low RPS of 7.7, which means we can process
	// ⌈7.7⌉*2 requests in the span of roughly a second -- 8 initially, followed
	// by a refill rate of 7.7 per-second.
	_, err := client.Logical().Write("sys/quotas/rate-limit/rlq", map[string]interface{}{
		"rate": 7.7,
		"path": "pki/",
	})
	if err != nil {
		t.Fatal(err)
	}

	numSuccess, numFail, elapsed := testRPS(reqFunc, 5*time.Second)

	// evaluate the ideal RPS as (ceil(RPS) + (RPS * totalSeconds))
	ideal := 8 + (7.7 * float64(elapsed) / float64(time.Second))

	// ensure there were some failed requests
	if numFail == 0 {
		t.Fatalf("expected some requests to fail; numSuccess: %d, numFail: %d, elapsed: %d", numSuccess, numFail, elapsed)
	}

	// ensure that we should never get more requests than allowed
	if want := int32(ideal + 1); numSuccess > want {
		t.Fatalf("too many successful requests; want: %d, numSuccess: %d, numFail: %d, elapsed: %d", want, numSuccess, numFail, elapsed)
	}

	// update the rate limit quota with a high RPS such that no requests should fail
	_, err = client.Logical().Write("sys/quotas/rate-limit/rlq", map[string]interface{}{
		"rate": 10000.0,
		"path": "pki/",
	})
	if err != nil {
		t.Fatal(err)
	}

	_, numFail, _ = testRPS(reqFunc, 5*time.Second)
	if numFail > 0 {
		t.Fatalf("unexpected number of failed requests: %d", numFail)
	}

	teardownMounts(t, client)
}

func TestQuotas_RateLimitQuota_MountPrecedence(t *testing.T) {
	conf, opts := teststorage.ClusterSetup(coreConfig, nil, nil)
	opts.NoDefaultQuotas = true
	cluster := vault.NewTestCluster(t, conf, opts)
	cluster.Start()
	defer cluster.Cleanup()

	core := cluster.Cores[0].Core
	client := cluster.Cores[0].Client

	vault.TestWaitActive(t, core)

	// create PKI mount
	setupMounts(t, client)

	// create a root rate limit quota
	_, err := client.Logical().Write("sys/quotas/rate-limit/root-rlq", map[string]interface{}{
		"name": "root-rlq",
		"rate": 14.7,
	})
	if err != nil {
		t.Fatal(err)
	}

	// create a mount rate limit quota with a lower RPS than the root rate limit quota
	_, err = client.Logical().Write("sys/quotas/rate-limit/mount-rlq", map[string]interface{}{
		"name": "mount-rlq",
		"rate": 7.7,
		"path": "pki/",
	})
	if err != nil {
		t.Fatal(err)
	}

	// ensure mount rate limit quota takes precedence over root rate limit quota
	reqFunc := func(numSuccess, numFail *atomic.Int32) {
		_, err := client.Logical().Read("pki/cert/ca_chain")

		if err != nil {
			numFail.Add(1)
		} else {
			numSuccess.Add(1)
		}
	}

	// ensure mount rate limit quota takes precedence over root rate limit quota
	numSuccess, numFail, elapsed := testRPS(reqFunc, 5*time.Second)

	// evaluate the ideal RPS as (ceil(RPS) + (RPS * totalSeconds))
	ideal := 8 + (7.7 * float64(elapsed) / float64(time.Second))

	// ensure there were some failed requests
	if numFail == 0 {
		t.Fatalf("expected some requests to fail; numSuccess: %d, numFail: %d, elapsed: %d", numSuccess, numFail, elapsed)
	}

	// ensure that we should never get more requests than allowed
	if want := int32(ideal + 1); numSuccess > want {
		t.Fatalf("too many successful requests; want: %d, numSuccess: %d, numFail: %d, elapsed: %d", want, numSuccess, numFail, elapsed)
	}

	teardownMounts(t, client)
}

func TestQuotas_RateLimitQuota(t *testing.T) {
	conf, opts := teststorage.ClusterSetup(coreConfig, nil, nil)
	opts.NoDefaultQuotas = true
	cluster := vault.NewTestCluster(t, conf, opts)
	cluster.Start()
	defer cluster.Cleanup()

	core := cluster.Cores[0].Core
	client := cluster.Cores[0].Client

	vault.TestWaitActive(t, core)

	// Create a rate limit quota with a low RPS of 7.7, which means we can process
	// ⌈7.7⌉*2 requests in the span of roughly a second -- 8 initially, followed
	// by a refill rate of 7.7 per-second.
	_, err := client.Logical().Write("sys/quotas/rate-limit/rlq", map[string]interface{}{
		"rate": 7.7,
	})
	if err != nil {
		t.Fatal(err)
	}

	reqFunc := func(numSuccess, numFail *atomic.Int32) {
		_, err := client.Logical().Read("sys/quotas/rate-limit/rlq")

		if err != nil {
			numFail.Add(1)
		} else {
			numSuccess.Add(1)
		}
	}

	numSuccess, numFail, elapsed := testRPS(reqFunc, 5*time.Second)

	// evaluate the ideal RPS as (ceil(RPS) + (RPS * totalSeconds))
	ideal := 8 + (7.7 * float64(elapsed) / float64(time.Second))

	// ensure there were some failed requests
	if numFail == 0 {
		t.Fatalf("expected some requests to fail; numSuccess: %d, numFail: %d, elapsed: %d", numSuccess, numFail, elapsed)
	}

	// ensure that we should never get more requests than allowed
	if want := int32(ideal + 1); numSuccess > want {
		t.Fatalf("too many successful requests; want: %d, numSuccess: %d, numFail: %d, elapsed: %d", want, numSuccess, numFail, elapsed)
	}

	// allow time (1s) for rate limit to refill before updating the quota
	time.Sleep(time.Second)

	// update the rate limit quota with a high RPS such that no requests should fail
	_, err = client.Logical().Write("sys/quotas/rate-limit/rlq", map[string]interface{}{
		"rate": 10000.0,
	})
	if err != nil {
		t.Fatal(err)
	}

	_, numFail, _ = testRPS(reqFunc, 5*time.Second)
	if numFail > 0 {
		t.Fatalf("unexpected number of failed requests: %d", numFail)
	}
}

func TestQuotas_RateLimitQuotaNS(t *testing.T) {
	conf, opts := teststorage.ClusterSetup(coreConfig, nil, nil)
	opts.NoDefaultQuotas = true
	cluster := vault.NewTestCluster(t, conf, opts)
	cluster.Start()
	defer cluster.Cleanup()

	core := cluster.Cores[0].Core
	client := cluster.Cores[0].Client

	vault.TestWaitActive(t, core)

	// Create a global rate limit with a low RPS of 7.7, which means we can process
	// ⌈7.7⌉*2 requests in the span of roughly a second -- 8 initially, followed
	// by a refill rate of 7.7 per-second.
	// As inheritable is set to true, the quota will be inherited by child namespaces
	_, err := client.Logical().Write("sys/quotas/rate-limit/global-rlq", map[string]interface{}{
		"rate": 7.7,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Create Parent Namespace ns1
	// ns1 intentionaly does not have a quota, so it should be able to do more requests than root
	_, err = client.Logical().Write("sys/namespaces/ns1", map[string]interface{}{})
	if err != nil {
		t.Fatal(err)
	}

	// Create Childnamespace, so we get a hierarchy of ns1/ns1.1
	client.SetNamespace("ns1")
	_, err = client.Logical().Write("sys/namespaces/ns1.1", map[string]interface{}{})
	if err != nil {
		t.Fatal(err)
	}
	client.ClearNamespace()

	// Create a rate limit for namespace ns1/ns1.1 with a higher RPS than the global quota
	_, err = client.Logical().Write("sys/quotas/rate-limit/ns1.1-rlq", map[string]interface{}{
		"rate": 9.9,
		"path": "ns1/ns1.1",
	})
	if err != nil {
		t.Fatal(err)
	}

	reqFunc := func(numSuccess, numFail *atomic.Int32, ns string) {
		// list all namespaces in ns1/ns1.1
		// the quota of ns1 should apply
		client.SetNamespace(ns)
		_, err := client.Logical().List("sys/namespaces")

		if err != nil {
			numFail.Add(1)
		} else {
			numSuccess.Add(1)
		}
		client.ClearNamespace()
	}

	// Test global rate limit quota
	numSuccess, numFail, elapsed := testRPSWithNS(reqFunc, 5*time.Second, "")
	// evaluate the ideal RPS as (ceil(RPS) + (RPS * totalSeconds))
	ideal := 8 + (7.7 * float64(elapsed) / float64(time.Second))
	// ensure there were some failed requests
	if numFail == 0 {
		t.Fatalf("expected some requests to fail; numSuccess: %d, numFail: %d, elapsed: %d", numSuccess, numFail, elapsed)
	}
	// ensure that we should never get more requests than allowed
	if want := int32(ideal + 1); numSuccess > want {
		t.Fatalf("too many successful requests; want: %d, numSuccess: %d, numFail: %d, elapsed: %d", want, numSuccess, numFail, elapsed)
	}

	// Test ns1 quota
	// Global quota should apply!
	_, numFail, _ = testRPSWithNS(reqFunc, 5*time.Second, "ns1")
	// ensure there were some failed requests
	if numFail == 0 {
		t.Fatalf("expected some requests to fail; numSuccess: %d, numFail: %d, elapsed: %d", numSuccess, numFail, elapsed)
	}
	// ensure that we should never get more requests than allowed
	if want := int32(ideal + 1); numSuccess > want {
		t.Fatalf("too many successful requests; want: %d, numSuccess: %d, numFail: %d, elapsed: %d", want, numSuccess, numFail, elapsed)
	}

	// Test ns1/ns1.1 rate limit quota
	// Should allow more requests than the global quota, as the rate limit for ns1/ns1.1 is higher
	numSuccess, numFail, elapsed = testRPSWithNS(reqFunc, 5*time.Second, "ns1/ns1.1")
	// evaluate the ideal RPS as (ceil(RPS) + (RPS * totalSeconds))
	newIdeal := 10 + (9.9 * float64(elapsed) / float64(time.Second))
	// ensure there were some failed requests
	if numFail == 0 {
		t.Fatalf("expected some requests to fail; numSuccess: %d, numFail: %d, elapsed: %d", numSuccess, numFail, elapsed)
	}
	// ensure that we should never get more requests than allowed
	if want := int32(newIdeal + 1); numSuccess > want {
		t.Fatalf("too many successful requests; want: %d, numSuccess: %d, numFail: %d, elapsed: %d", want, numSuccess, numFail, elapsed)
	}
}

func TestQuotas_RateLimitQuotaInheritableNS(t *testing.T) {
	conf, opts := teststorage.ClusterSetup(coreConfig, nil, nil)
	opts.NoDefaultQuotas = true
	cluster := vault.NewTestCluster(t, conf, opts)
	cluster.Start()
	defer cluster.Cleanup()

	core := cluster.Cores[0].Core
	client := cluster.Cores[0].Client

	vault.TestWaitActive(t, core)

	// Create Parent Namespace
	_, err := client.Logical().Write("sys/namespaces/ns1", map[string]interface{}{})
	if err != nil {
		t.Fatal(err)
	}

	// Create a rate limit quota for parent namespace with a low RPS of 7.7, which means we can process
	// ⌈7.7⌉*2 requests in the span of roughly a second -- 8 initially, followed
	// by a refill rate of 7.7 per-second.
	// As inheritable is set to true, the quota will be inherited by child namespaces
	_, err = client.Logical().Write("sys/quotas/rate-limit/rlq", map[string]interface{}{
		"rate":        7.7,
		"path":        "ns1",
		"inheritable": true,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Create Childnamespace, so we get a hierarchy of ns1/ns1.1
	client.SetNamespace("ns1")
	_, err = client.Logical().Write("sys/namespaces/ns1.1", map[string]interface{}{})
	if err != nil {
		t.Fatal(err)
	}
	client.ClearNamespace()

	reqFunc := func(numSuccess, numFail *atomic.Int32, ns string) {
		// list all namespaces in ns1/ns1.1
		// the quota of ns1 should apply
		client.SetNamespace(ns)
		_, err := client.Logical().List("sys/namespaces")

		if err != nil {
			numFail.Add(1)
		} else {
			numSuccess.Add(1)
		}
		client.ClearNamespace()
	}

	numSuccess, numFail, elapsed := testRPSWithNS(reqFunc, 5*time.Second, "ns1/ns1.1")

	// evaluate the ideal RPS as (ceil(RPS) + (RPS * totalSeconds))
	ideal := 8 + (7.7 * float64(elapsed) / float64(time.Second))

	// ensure there were some failed requests
	if numFail == 0 {
		t.Fatalf("expected some requests to fail; numSuccess: %d, numFail: %d, elapsed: %d", numSuccess, numFail, elapsed)
	}

	// ensure that we should never get more requests than allowed
	if want := int32(ideal + 1); numSuccess > want {
		t.Fatalf("too many successful requests; want: %d, numSuccess: %d, numFail: %d, elapsed: %d", want, numSuccess, numFail, elapsed)
	}

	// allow time (1s) for rate limit to refill before updating the quota
	time.Sleep(time.Second)

	// update the rate limit quota to inheritable false
	// as a result the quota should not anymore apply to ns1.1, but only ns1
	_, err = client.Logical().Write("sys/quotas/rate-limit/rlq", map[string]interface{}{
		"rate":        7.7,
		"path":        "ns1",
		"inheritable": false,
	})
	if err != nil {
		t.Fatal(err)
	}

	// as there is no quota for ns1/ns1.1, there should be no fails
	_, numFail, _ = testRPSWithNS(reqFunc, 5*time.Second, "ns1/ns1.1")
	if numFail > 0 {
		t.Fatalf("unexpected number of failed requests: %d", numFail)
	}

	// as there the quota applies to ns1, there should be some fail
	numSuccess, numFail, elapsed = testRPSWithNS(reqFunc, 5*time.Second, "ns1")
	// ensure there were some failed requests
	if numFail == 0 {
		t.Fatalf("expected some requests to fail; numSuccess: %d, numFail: %d, elapsed: %d", numSuccess, numFail, elapsed)
	}
	// ensure that we should never get more requests than allowed
	if want := int32(ideal + 1); numSuccess > want {
		t.Fatalf("too many successful requests; want: %d, numSuccess: %d, numFail: %d, elapsed: %d", want, numSuccess, numFail, elapsed)
	}
}
