// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package quotas

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/sdk/v2/helper/testhelpers/schema"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
	"github.com/tsaarni/certyaml"

	"github.com/openbao/openbao/v2/internal/audit"
	auditFile "github.com/openbao/openbao/v2/internal/builtin/audit/file"
	"github.com/openbao/openbao/v2/internal/builtin/credential/approle"
	"github.com/openbao/openbao/v2/internal/builtin/credential/cert"
	"github.com/openbao/openbao/v2/internal/builtin/credential/userpass"
	"github.com/openbao/openbao/v2/internal/builtin/logical/pki"
	"github.com/openbao/openbao/v2/internal/helper/configutil"
	"github.com/openbao/openbao/v2/internal/helper/testhelpers/teststorage"
	vaulthttp "github.com/openbao/openbao/v2/internal/http"
	"github.com/openbao/openbao/v2/internal/vault"
	"github.com/openbao/openbao/v2/internal/vault/quotas"
)

var coreConfig = &vault.CoreConfig{
	LogicalBackends: map[string]logical.Factory{
		"pki": pki.Factory,
	},
	CredentialBackends: map[string]logical.Factory{
		"userpass": userpass.Factory,
		"approle":  approle.Factory,
		"cert":     cert.Factory,
	},
	AuditBackends: map[string]audit.Factory{
		"file": auditFile.Factory,
	},
}

func setupMounts(t *testing.T, client *api.Client, auth string) {
	t.Helper()

	switch auth {
	case "userpass":
		require.NoError(t, client.Sys().EnableAuthWithOptions("userpass", &api.EnableAuthOptions{
			Type: "userpass",
		}))
		_, err := client.Logical().Write("auth/userpass/users/foo", map[string]any{
			"password": "bar",
		})
		require.NoError(t, err)
	case "approle":
		require.NoError(t, client.Sys().EnableAuthWithOptions("approle", &api.EnableAuthOptions{
			Type: "approle",
		}))
	case "cert":
		require.NoError(t, client.Sys().EnableAuthWithOptions("cert", &api.EnableAuthOptions{
			Type: "cert",
		}))
	}

	require.NoError(t, client.Sys().Mount("pki", &api.MountInput{
		Type: "pki",
	}))

	_, err := client.Logical().Write("pki/root/generate/internal", map[string]any{
		"common_name": "testvault.com",
		"ttl":         "200h",
		"ip_sans":     "127.0.0.1",
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.Logical().Write("pki/roles/test", map[string]any{
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
	require.NoError(t, client.Sys().Unmount("pki"))
	require.NoError(t, client.Sys().DisableAuth("userpass"))
	require.NoError(t, client.Sys().DisableAuth("approle"))
	require.NoError(t, client.Sys().DisableAuth("cert"))
}

func setupAppRoleRateLimitQuota(t *testing.T, client *api.Client, path, role string, rate int) (string, string) {
	t.Helper()
	_, err := client.Logical().Write(fmt.Sprintf("%s/role/%s", path, role), map[string]any{})
	require.NoError(t, err)

	data, err := client.Logical().Read(fmt.Sprintf("auth/approle/role/%s/role-id", role))
	require.NoError(t, err)
	roleID := data.Data["role_id"].(string)

	data, err = client.Logical().Write(fmt.Sprintf("auth/approle/role/%s/secret-id", role), nil)
	require.NoError(t, err)
	secretID := data.Data["secret_id"].(string)

	_, err = client.Logical().Write(fmt.Sprintf("sys/quotas/rate-limit/rlq-%s", role), map[string]any{
		"path":     path,
		"role":     role,
		"rate":     rate,
		"interval": "1h",
	})
	require.NoError(t, err)

	return roleID, secretID
}

// formLogin logs in via the approle auth mount using form content-type.
func formLogin(t *testing.T, client *api.Client, vals url.Values) int {
	t.Helper()
	req := client.NewRequest("POST", "/v1/auth/approle/login")
	req.Headers.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Body = strings.NewReader(vals.Encode())
	resp, _ := client.RawRequest(req)
	if resp != nil {
		defer resp.Body.Close() //nolint:errcheck
	}
	require.NotNil(t, resp)
	return resp.StatusCode
}

// certLogin logs in via the cert auth mount, presenting the client certificate
// through the listener's configured forwarded cert header.
func certLogin(t *testing.T, client *api.Client, certDER []byte) int {
	t.Helper()
	req := client.NewRequest("POST", "/v1/auth/cert/login")
	req.Headers.Set("Content-Type", "application/json")
	req.Headers.Set("X-Forwarded-Client-Cert", base64.StdEncoding.EncodeToString(certDER))
	resp, _ := client.RawRequest(req)
	if resp != nil {
		defer resp.Body.Close() //nolint:errcheck
	}
	require.NotNil(t, resp)
	return resp.StatusCode
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
	_, err := client.Logical().Write("sys/quotas/rate-limit/secret-rlq", map[string]any{
		"rate": 7.7,
		"path": "secret",
	})
	require.NoError(t, err)

	s, err := client.Logical().Read("sys/quotas/rate-limit/secret-rlq")
	require.NoError(t, err)
	require.NotEmpty(t, s.Data)

	// create a rate limit quota w/ empty path (same name)
	_, err = client.Logical().Write("sys/quotas/rate-limit/secret-rlq", map[string]any{
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
	_, err := client.Logical().Write("sys/quotas/rate-limit/global-rlq", map[string]any{
		"rate": 10,
		"path": "",
	})
	require.NoError(t, err)

	// create a rate limit quota w/ 'secret' path
	_, err = client.Logical().Write("sys/quotas/rate-limit/secret-rlq", map[string]any{
		"rate": 7.7,
		"path": "secret",
	})
	require.NoError(t, err)

	s, err := client.Logical().Read("sys/quotas/rate-limit/secret-rlq")
	require.NoError(t, err)
	require.NotEmpty(t, s.Data)

	// create a rate limit quota w/ empty path (same name)
	_, err = client.Logical().Write("sys/quotas/rate-limit/secret-rlq", map[string]any{
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

	_, err := client.Logical().Write("sys/quotas/rate-limit/rlq", map[string]any{
		"rate": 7.7,
	})
	require.NoError(t, err)

	// ensure exempt paths are not empty by default
	resp, err := client.Logical().Read("sys/quotas/config")
	require.NoError(t, err)
	require.NotEmpty(t, resp.Data["rate_limit_exempt_paths"].([]any), "expected no exempt paths by default")

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

	_, err = client.Logical().Write("sys/quotas/config", map[string]any{
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

	_, err := client.Logical().Write("sys/quotas/rate-limit/rlq", map[string]any{
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

func TestQuotas_RateLimitQuota_AuditLogging(t *testing.T) {
	conf, opts := teststorage.ClusterSetup(coreConfig, nil, nil)
	opts.NoDefaultQuotas = true
	opts.RequestResponseCallback = schema.ResponseValidatingCallback(t)
	cluster := vault.NewTestCluster(t, conf, opts)
	cluster.Start()
	defer cluster.Cleanup()

	core := cluster.Cores[0].Core
	client := cluster.Cores[0].Client
	vault.TestWaitActive(t, core)

	// Enable Audit Logging
	_, err := client.Logical().WriteWithContext(t.Context(), "sys/quotas/config", map[string]any{
		"enable_rate_limit_audit_logging": true,
	})
	require.NoError(t, err)

	// Create temporary audit log file
	auditLogFile, err := os.Create(path.Join(t.TempDir(), "audit.json"))
	require.NoError(t, err)

	require.NoError(t, client.Sys().EnableAuditWithOptions("file", &api.EnableAuditOptions{
		Type: "file",
		Options: map[string]string{
			"file_path": auditLogFile.Name(),
		},
	}))

	// Set limit to 1
	_, err = client.Logical().WriteWithContext(t.Context(), "sys/quotas/rate-limit/rlq", map[string]any{
		"rate": 1,
	})
	require.NoError(t, err)

	// First requests should pass
	_, err = client.Sys().ListNamespacesWithContext(t.Context())
	require.NoError(t, err)

	// Second request should fail
	_, err = client.Sys().ListNamespacesWithContext(t.Context())
	require.ErrorContains(t, err, "429") // HTTP 429 => "Too Many Requests"

	// Count matching audit log entries
	decoder := json.NewDecoder(auditLogFile)
	var auditRecord map[string]any
	var rateLimitAuditLogCount int
	for decoder.Decode(&auditRecord) == nil {
		if auditRecord["type"] == "request" {
			if error, ok := auditRecord["error"]; ok && strings.HasSuffix(error.(string), quotas.ErrRateLimitQuotaExceeded.Error()) {
				rateLimitAuditLogCount++
			}
		}
	}

	require.Equal(t, 1, rateLimitAuditLogCount, "expected exactly one rate limit exceeded audit log entry")
}

// TestQuotas_RateLimitQuota_Approle verifies the RLQ correctly applying
// to the role when using AppRole auth backend with login using form payload.
func TestQuotas_RateLimitQuota_Approle(t *testing.T) {
	conf, opts := teststorage.ClusterSetup(coreConfig, nil, nil)
	opts.NoDefaultQuotas = true
	cluster := vault.NewTestCluster(t, conf, opts)
	cluster.Start()
	defer cluster.Cleanup()

	core := cluster.Cores[0].Core
	client := cluster.Cores[0].Client
	vault.TestWaitActive(t, core)
	setupMounts(t, client, "approle")

	roleID, secretID := setupAppRoleRateLimitQuota(t, client, "auth/approle", "r1", 1)
	resp, err := client.Logical().Read("sys/quotas/rate-limit/rlq-r1")
	require.NoError(t, err)
	require.Equal(t, "r1", resp.Data["role"].(string))

	_, err = client.Logical().Write("auth/approle/login", map[string]any{
		"role_id":   roleID,
		"secret_id": secretID,
	})
	require.NoError(t, err)

	// Second call should result in 429 status code.
	_, err = client.Logical().Write("auth/approle/login", map[string]any{
		"role_id":   roleID,
		"secret_id": secretID,
	})
	require.Error(t, err)

	roleID, secretID = setupAppRoleRateLimitQuota(t, client, "auth/approle", "r2", 1)
	resp, err = client.Logical().Read("sys/quotas/rate-limit/rlq-r2")
	require.NoError(t, err)
	require.Equal(t, "r2", resp.Data["role"].(string))

	formVals := url.Values{}
	formVals.Add("role_id", roleID)
	formVals.Add("secret_id", secretID)
	require.Equal(t, 200, formLogin(t, client, formVals))
	require.Equal(t, 429, formLogin(t, client, formVals))

	// Validate RLQ with higher rate.
	rate := 100
	roleID, secretID = setupAppRoleRateLimitQuota(t, client, "auth/approle", "r3", rate)
	resp, err = client.Logical().Read("sys/quotas/rate-limit/rlq-r3")
	require.NoError(t, err)
	require.Equal(t, "r3", resp.Data["role"].(string))

	formVals = url.Values{}
	formVals.Add("role_id", roleID)
	formVals.Add("secret_id", secretID)

	for range rate / 2 {
		_, err = client.Logical().Write("auth/approle/login", map[string]any{
			"role_id":   roleID,
			"secret_id": secretID,
		})
		require.NoError(t, err)
		require.Equal(t, 200, formLogin(t, client, formVals))
	}
	require.Equal(t, 429, formLogin(t, client, formVals))
	_, err = client.Logical().Write("auth/approle/login", map[string]any{
		"role_id":   roleID,
		"secret_id": secretID,
	})
	require.Error(t, err)
}

// TestQuotas_RateLimitQuota_Cert verifies the RLQ correctly applying
// to the role when using certificate auth backend.
func TestQuotas_RateLimitQuota_Cert(t *testing.T) {
	conf, opts := teststorage.ClusterSetup(coreConfig, nil, nil)
	opts.NoDefaultQuotas = true
	opts.HandlerFunc = vaulthttp.Handler
	opts.DefaultHandlerProperties = vault.HandlerProperties{ListenerConfig: &configutil.Listener{XForwardedForClientCertHeader: "X-Forwarded-Client-Cert"}}
	cluster := vault.NewTestCluster(t, conf, opts)
	cluster.Start()
	defer cluster.Cleanup()

	core := cluster.Cores[0].Core
	client := cluster.Cores[0].Client
	vault.TestWaitActive(t, core)

	setupMounts(t, client, "cert")

	testCert := &certyaml.Certificate{
		Subject:         "cn=cert.example.com",
		SubjectAltNames: []string{"DNS:cert.example.com", "IP:127.0.0.1"},
	}
	require.NoError(t, testCert.Generate())

	_, err := client.Logical().Write("auth/cert/certs/r1", map[string]any{
		"certificate": string(testCert.CertPEM()),
	})
	require.NoError(t, err)

	secondCert := &certyaml.Certificate{
		Subject:         "cn=cert.another.com",
		SubjectAltNames: []string{"DNS:cert.another.com", "IP:127.0.0.1"},
	}
	require.NoError(t, secondCert.Generate())

	_, err = client.Logical().Write("auth/cert/certs/r2", map[string]any{
		"certificate": string(secondCert.CertPEM()),
	})
	require.NoError(t, err)

	// Verify role-based rlq.
	_, err = client.Logical().Write("sys/quotas/rate-limit/rlq-r1", map[string]any{
		"path":     "auth/cert/",
		"role":     "r1",
		"rate":     1,
		"interval": "1h",
	})
	require.NoError(t, err)

	resp, err := client.Logical().Read("sys/quotas/rate-limit/rlq-r1")
	require.NoError(t, err)
	require.Equal(t, "r1", resp.Data["role"].(string))
	require.Equal(t, 200, certLogin(t, client, testCert.GeneratedCert.Certificate[0]))
	require.Equal(t, 429, certLogin(t, client, testCert.GeneratedCert.Certificate[0]))

	// Verify only mount-based rlq.
	_, err = client.Logical().Write("sys/quotas/rate-limit/rlq-r2", map[string]any{
		"path":     "auth/cert/",
		"rate":     1,
		"interval": "1h",
	})
	require.NoError(t, err)
	require.Equal(t, 200, certLogin(t, client, secondCert.GeneratedCert.Certificate[0]))
	require.Equal(t, 429, certLogin(t, client, secondCert.GeneratedCert.Certificate[0]))
}

func TestQuotas_RateLimitQuota_Mount(t *testing.T) {
	conf, opts := teststorage.ClusterSetup(coreConfig, nil, nil)
	cluster := vault.NewTestCluster(t, conf, opts)
	cluster.Start()
	defer cluster.Cleanup()

	core := cluster.Cores[0].Core
	client := cluster.Cores[0].Client
	vault.TestWaitActive(t, core)

	setupMounts(t, client, "userpass")

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
	_, err := client.Logical().Write("sys/quotas/rate-limit/rlq", map[string]any{
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
	_, err = client.Logical().Write("sys/quotas/rate-limit/rlq", map[string]any{
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

	setupMounts(t, client, "userpass")

	// create a root rate limit quota
	_, err := client.Logical().Write("sys/quotas/rate-limit/root-rlq", map[string]any{
		"name": "root-rlq",
		"rate": 14.7,
	})
	if err != nil {
		t.Fatal(err)
	}

	// create a mount rate limit quota with a lower RPS than the root rate limit quota
	_, err = client.Logical().Write("sys/quotas/rate-limit/mount-rlq", map[string]any{
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
	_, err := client.Logical().Write("sys/quotas/rate-limit/rlq", map[string]any{
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
	_, err = client.Logical().Write("sys/quotas/rate-limit/rlq", map[string]any{
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
	_, err := client.Logical().Write("sys/quotas/rate-limit/global-rlq", map[string]any{
		"rate": 7.7,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Create Parent Namespace ns1
	// ns1 intentionaly does not have a quota, so it should be able to do more requests than root
	_, err = client.Logical().Write("sys/namespaces/ns1", map[string]any{})
	if err != nil {
		t.Fatal(err)
	}

	// Create Childnamespace, so we get a hierarchy of ns1/ns1.1
	client.SetNamespace("ns1")
	_, err = client.Logical().Write("sys/namespaces/ns1.1", map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	client.ClearNamespace()

	// Create a rate limit for namespace ns1/ns1.1 with a higher RPS than the global quota
	_, err = client.Logical().Write("sys/quotas/rate-limit/ns1.1-rlq", map[string]any{
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
	_, err := client.Logical().Write("sys/namespaces/ns1", map[string]any{})
	if err != nil {
		t.Fatal(err)
	}

	// Create a rate limit quota for parent namespace with a low RPS of 7.7, which means we can process
	// ⌈7.7⌉*2 requests in the span of roughly a second -- 8 initially, followed
	// by a refill rate of 7.7 per-second.
	// As inheritable is set to true, the quota will be inherited by child namespaces
	_, err = client.Logical().Write("sys/quotas/rate-limit/rlq", map[string]any{
		"rate":        7.7,
		"path":        "ns1",
		"inheritable": true,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Create Childnamespace, so we get a hierarchy of ns1/ns1.1
	client.SetNamespace("ns1")
	_, err = client.Logical().Write("sys/namespaces/ns1.1", map[string]any{})
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
	_, err = client.Logical().Write("sys/quotas/rate-limit/rlq", map[string]any{
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
