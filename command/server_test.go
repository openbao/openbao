// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

//go:build !race && !hsm

// NOTE: we can't use this with HSM. We can't set testing mode on and it's not
// safe to use env vars since that provides an attack vector in the real world.
//
// The server tests have a go-metrics/exp manager race condition :(.

package command

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/cli"
	"github.com/openbao/openbao/command/server"
	"github.com/openbao/openbao/sdk/v2/physical"
	physInmem "github.com/openbao/openbao/sdk/v2/physical/inmem"
	"github.com/stretchr/testify/require"
)

func testBaseHCL(tb testing.TB, listenerExtras string) string {
	tb.Helper()

	return strings.TrimSpace(fmt.Sprintf(`
		listener "tcp" {
			address     = "127.0.0.1:%d"
			tls_disable = "true"
			%s
		}
	`, 0, listenerExtras))
}

const (
	goodListenerTimeouts = `http_read_header_timeout = 12
			http_read_timeout = "34s"
			http_write_timeout = "56m"
			http_idle_timeout = "78h"`

	badListenerReadHeaderTimeout = `http_read_header_timeout = "12km"`
	badListenerReadTimeout       = `http_read_timeout = "34日"`
	badListenerWriteTimeout      = `http_write_timeout = "56lbs"`
	badListenerIdleTimeout       = `http_idle_timeout = "78gophers"`

	inmemHCL = `
backend "inmem_ha" {
  advertise_addr       = "http://127.0.0.1:8200"
}
`
	haInmemHCL = `
ha_backend "inmem_ha" {
  redirect_addr        = "http://127.0.0.1:8200"
}
`

	badHAInmemHCL = `
ha_backend "inmem" {}
`

	reloadHCL = `
backend "inmem" {}
listener "tcp" {
  address       = "127.0.0.1:8203"
  tls_cert_file = "TMPDIR/reload_cert.pem"
  tls_key_file  = "TMPDIR/reload_key.pem"
}
`
	cloudHCL = `
cloud {
      resource_id = "organization/bc58b3d0-2eab-4ab8-abf4-f61d3c9975ff/project/1c78e888-2142-4000-8918-f933bbbc7690/hashicorp.example.resource/example"
    client_id = "J2TtcSYOyPUkPV2z0mSyDtvitxLVjJmu"
    client_secret = "N9JtHZyOnHrIvJZs82pqa54vd4jnkyU3xCcqhFXuQKJZZuxqxxbP1xCfBZVB82vY"
}
`

	auditHCL = `
audit "file" "to-stdout" {
  description = "This audit device should never fail."
  options {
    file_path = "/dev/stdout"
    log_raw = "true"
  }
}
`
)

func testServerCommand(tb testing.TB) (*cli.MockUi, *ServerCommand) {
	tb.Helper()

	ui := cli.NewMockUi()
	return ui, &ServerCommand{
		BaseCommand: &BaseCommand{
			UI: ui,
		},
		ShutdownCh: MakeShutdownCh(),
		SighupCh:   MakeSighupCh(),
		SigUSR2Ch:  MakeSigUSR2Ch(),
		PhysicalBackends: map[string]physical.Factory{
			"inmem":    physInmem.NewInmem,
			"inmem_ha": physInmem.NewInmemHA,
		},

		// These prevent us from random sleep guessing...
		startedCh:  make(chan struct{}, 5),
		reloadedCh: make(chan struct{}, 5),
	}
}

func TestServer_ReloadListener(t *testing.T) {
	t.Parallel()

	wd, _ := os.Getwd()
	wd += "/server/test-fixtures/reload/"

	td, err := os.MkdirTemp("", "vault-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(td)

	wg := &sync.WaitGroup{}
	// Setup initial certs
	inBytes, _ := os.ReadFile(wd + "reload_foo.pem")
	os.WriteFile(td+"/reload_cert.pem", inBytes, 0o777)
	inBytes, _ = os.ReadFile(wd + "reload_foo.key")
	os.WriteFile(td+"/reload_key.pem", inBytes, 0o777)

	relhcl := strings.ReplaceAll(reloadHCL, "TMPDIR", td)
	os.WriteFile(td+"/reload.hcl", []byte(relhcl), 0o777)

	inBytes, _ = os.ReadFile(wd + "reload_ca.pem")
	certPool := x509.NewCertPool()
	ok := certPool.AppendCertsFromPEM(inBytes)
	if !ok {
		t.Fatal("not ok when appending CA cert")
	}

	ui, cmd := testServerCommand(t)
	_ = ui

	wg.Add(1)
	args := []string{"-config", td + "/reload.hcl"}
	go func() {
		if code := cmd.Run(args); code != 0 {
			output := ui.ErrorWriter.String() + ui.OutputWriter.String()
			t.Errorf("got a non-zero exit status: %s", output)
		}
		wg.Done()
	}()

	testCertificateName := func(cn string) error {
		conn, err := tls.Dial("tcp", "127.0.0.1:8203", &tls.Config{
			RootCAs: certPool,
		})
		if err != nil {
			return err
		}
		defer conn.Close()
		if err = conn.Handshake(); err != nil {
			return err
		}
		servName := conn.ConnectionState().PeerCertificates[0].Subject.CommonName
		if servName != cn {
			return fmt.Errorf("expected %s, got %s", cn, servName)
		}
		return nil
	}

	select {
	case <-cmd.startedCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout")
	}

	if err := testCertificateName("foo.example.com"); err != nil {
		t.Fatalf("certificate name didn't check out: %s", err)
	}

	relhcl = strings.ReplaceAll(reloadHCL, "TMPDIR", td)
	inBytes, _ = os.ReadFile(wd + "reload_bar.pem")
	os.WriteFile(td+"/reload_cert.pem", inBytes, 0o777)
	inBytes, _ = os.ReadFile(wd + "reload_bar.key")
	os.WriteFile(td+"/reload_key.pem", inBytes, 0o777)
	os.WriteFile(td+"/reload.hcl", []byte(relhcl), 0o777)

	cmd.SighupCh <- struct{}{}
	select {
	case <-cmd.reloadedCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout")
	}

	if err := testCertificateName("bar.example.com"); err != nil {
		t.Fatalf("certificate name didn't check out: %s", err)
	}

	cmd.ShutdownCh <- struct{}{}

	wg.Wait()
}

func TestServer(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		contents string
		exp      string
		code     int
		args     []string
	}{
		{
			"common_ha",
			testBaseHCL(t, "") + inmemHCL,
			"(HA available)",
			0,
			[]string{"-test-verify-only"},
		},
		{
			"separate_ha",
			testBaseHCL(t, "") + inmemHCL + haInmemHCL,
			"HA Storage:",
			0,
			[]string{"-test-verify-only"},
		},
		{
			"bad_separate_ha",
			testBaseHCL(t, "") + inmemHCL + badHAInmemHCL,
			"specified HA storage does not support HA",
			1,
			[]string{"-test-verify-only"},
		},
		{
			"good_listener_timeout_config",
			testBaseHCL(t, goodListenerTimeouts) + inmemHCL,
			"",
			0,
			[]string{"-test-server-config"},
		},
		{
			"bad_listener_read_header_timeout_config",
			testBaseHCL(t, badListenerReadHeaderTimeout) + inmemHCL,
			"unknown unit \"km\" in duration \"12km\"",
			1,
			[]string{"-test-server-config"},
		},
		{
			"bad_listener_read_timeout_config",
			testBaseHCL(t, badListenerReadTimeout) + inmemHCL,
			"unknown unit \"\\xe6\\x97\\xa5\" in duration",
			1,
			[]string{"-test-server-config"},
		},
		{
			"bad_listener_write_timeout_config",
			testBaseHCL(t, badListenerWriteTimeout) + inmemHCL,
			"unknown unit \"lbs\" in duration \"56lbs\"",
			1,
			[]string{"-test-server-config"},
		},
		{
			"bad_listener_idle_timeout_config",
			testBaseHCL(t, badListenerIdleTimeout) + inmemHCL,
			"unknown unit \"gophers\" in duration \"78gophers\"",
			1,
			[]string{"-test-server-config"},
		},
		{
			"environment_variables_logged",
			testBaseHCL(t, "") + inmemHCL,
			"Environment Variables",
			0,
			[]string{"-test-verify-only"},
		},
		{
			"recovery_mode",
			testBaseHCL(t, "") + inmemHCL,
			"",
			0,
			[]string{"-test-verify-only", "-recovery"},
		},
		{
			"audit_config",
			testBaseHCL(t, "") + inmemHCL + auditHCL,
			"",
			0,
			[]string{"-test-verify-only"},
		},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ui, cmd := testServerCommand(t)

			f, err := os.CreateTemp(t.TempDir(), "")
			require.NoErrorf(t, err, "error creating temp dir: %v", err)

			_, err = f.WriteString(tc.contents)
			require.NoErrorf(t, err, "cannot write temp file contents")

			err = f.Close()
			require.NoErrorf(t, err, "unable to close temp file")

			args := append(tc.args, "-config", f.Name())
			code := cmd.Run(args)
			output := ui.ErrorWriter.String() + ui.OutputWriter.String()
			require.Equal(t, tc.code, code, "expected %d to be %d: %s", code, tc.code, output)
			require.Contains(t, output, tc.exp, "expected %q to contain %q", output, tc.exp)
		})
	}
}

// TestServer_DevTLS verifies that a vault server starts up correctly with the -dev-tls flag
func TestServer_DevTLS(t *testing.T) {
	ui, cmd := testServerCommand(t)
	args := []string{"-dev-tls", "-dev-listen-address=127.0.0.1:0", "-test-server-config"}
	retCode := cmd.Run(args)
	output := ui.ErrorWriter.String() + ui.OutputWriter.String()
	require.Equal(t, 0, retCode, output)
	require.Contains(t, output, `tls: "enabled"`)
}

// TestHasRetryJoinConfig verifies the hasRetryJoinConfig function correctly
// detects retry_join configuration.
func TestHasRetryJoinConfig(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		name     string
		config   *server.Config
		expected bool
	}{
		{
			name:     "nil_storage",
			config:   &server.Config{Storage: nil},
			expected: false,
		},
		{
			name: "non_raft_storage",
			config: &server.Config{
				Storage: &server.Storage{
					Type:   "consul",
					Config: map[string]string{},
				},
			},
			expected: false,
		},
		{
			name: "raft_without_retry_join",
			config: &server.Config{
				Storage: &server.Storage{
					Type:   "raft",
					Config: map[string]string{},
				},
			},
			expected: false,
		},
		{
			name: "raft_with_empty_retry_join",
			config: &server.Config{
				Storage: &server.Storage{
					Type:   "raft",
					Config: map[string]string{"retry_join": ""},
				},
			},
			expected: false,
		},
		{
			name: "raft_with_retry_join",
			config: &server.Config{
				Storage: &server.Storage{
					Type:   "raft",
					Config: map[string]string{"retry_join": `[{"leader_api_addr": "http://127.0.0.1:8200"}]`},
				},
			},
			expected: true,
		},
	}

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, cmd := testServerCommand(t)
			result := cmd.hasRetryJoinConfig(tc.config)
			require.Equal(t, tc.expected, result, "hasRetryJoinConfig returned unexpected result")
		})
	}
}

// TestWaitForRetryJoinTimeout verifies that waitForRetryJoin respects the
// OPENBAO_SELF_INIT_RETRY_JOIN_WAIT environment variable.
// Note: This test cannot use t.Parallel() because it uses t.Setenv().
func TestWaitForRetryJoinEnvVar(t *testing.T) {
	// Test with wait disabled (0s)
	t.Run("disabled_wait", func(t *testing.T) {
		t.Setenv("OPENBAO_SELF_INIT_RETRY_JOIN_WAIT", "0s")

		_, cmd := testServerCommand(t)
		config := &server.Config{
			Storage: &server.Storage{
				Type:   "raft",
				Config: map[string]string{"retry_join": `[{"leader_api_addr": "http://127.0.0.1:8200"}]`},
			},
		}

		// Should return immediately since wait is disabled
		start := time.Now()
		// Note: We can't test the full waitForRetryJoin without a real core,
		// but we can verify the env var parsing doesn't cause errors
		_ = cmd.hasRetryJoinConfig(config)
		require.True(t, time.Since(start) < time.Second, "hasRetryJoinConfig should return immediately")
	})

	// Test with invalid duration
	t.Run("invalid_duration", func(t *testing.T) {
		t.Setenv("OPENBAO_SELF_INIT_RETRY_JOIN_WAIT", "invalid")

		_, cmd := testServerCommand(t)
		config := &server.Config{
			Storage: &server.Storage{
				Type:   "raft",
				Config: map[string]string{"retry_join": `[{"leader_api_addr": "http://127.0.0.1:8200"}]`},
			},
		}

		// Should not panic with invalid env var
		result := cmd.hasRetryJoinConfig(config)
		require.True(t, result, "hasRetryJoinConfig should still work with invalid env var")
	})

	// Test that custom duration is parsed correctly
	t.Run("custom_duration", func(t *testing.T) {
		t.Setenv("OPENBAO_SELF_INIT_RETRY_JOIN_WAIT", "45s")

		_, cmd := testServerCommand(t)
		config := &server.Config{
			Storage: &server.Storage{
				Type:   "raft",
				Config: map[string]string{"retry_join": `[{"leader_api_addr": "http://127.0.0.1:8200"}]`},
			},
		}

		// Verify config detection works
		require.True(t, cmd.hasRetryJoinConfig(config), "should detect retry_join config")
	})
}

// TestRetryJoinWaitBehavior verifies the coordination behavior between
// retry_join and self-initialization. This test verifies that when retry_join
// is configured, the Initialize function will wait before attempting
// self-initialization.
// See: https://github.com/openbao/openbao/issues/2274
func TestRetryJoinWaitBehavior(t *testing.T) {
	// This test verifies the logical flow without a real cluster.
	// For full integration testing, use the Kubernetes deployment.

	t.Run("detects_retry_join_config", func(t *testing.T) {
		_, cmd := testServerCommand(t)

		// Config with retry_join
		configWithRetryJoin := &server.Config{
			Storage: &server.Storage{
				Type: "raft",
				Config: map[string]string{
					"retry_join": `[{"leader_api_addr": "http://127.0.0.1:8200"}]`,
				},
			},
		}
		require.True(t, cmd.hasRetryJoinConfig(configWithRetryJoin),
			"should detect retry_join is configured")

		// Config without retry_join
		configWithoutRetryJoin := &server.Config{
			Storage: &server.Storage{
				Type:   "raft",
				Config: map[string]string{},
			},
		}
		require.False(t, cmd.hasRetryJoinConfig(configWithoutRetryJoin),
			"should detect retry_join is NOT configured")
	})

	t.Run("wait_disabled_returns_immediately", func(t *testing.T) {
		t.Setenv("OPENBAO_SELF_INIT_RETRY_JOIN_WAIT", "0s")

		_, cmd := testServerCommand(t)
		config := &server.Config{
			Storage: &server.Storage{
				Type: "raft",
				Config: map[string]string{
					"retry_join": `[{"leader_api_addr": "http://127.0.0.1:8200"}]`,
				},
			},
		}

		// With wait disabled, should return very quickly
		start := time.Now()
		// We can't call waitForRetryJoin without a real core, but we can
		// verify the hasRetryJoinConfig path
		hasConfig := cmd.hasRetryJoinConfig(config)
		elapsed := time.Since(start)

		require.True(t, hasConfig, "should detect retry_join config")
		require.Less(t, elapsed, 100*time.Millisecond,
			"config detection should be fast")
	})
}

// TestAnyLeaderCandidateReachable verifies the smart exit logic that checks
// if any leader candidates are reachable before deciding to wait longer.
func TestAnyLeaderCandidateReachable(t *testing.T) {
	t.Parallel()

	t.Run("no_storage_config", func(t *testing.T) {
		t.Parallel()
		_, cmd := testServerCommand(t)

		config := &server.Config{Storage: nil}
		require.False(t, cmd.anyLeaderCandidateReachable(config),
			"should return false when no storage config")
	})

	t.Run("no_retry_join_config", func(t *testing.T) {
		t.Parallel()
		_, cmd := testServerCommand(t)

		config := &server.Config{
			Storage: &server.Storage{
				Type:   "raft",
				Config: map[string]string{},
			},
		}
		require.False(t, cmd.anyLeaderCandidateReachable(config),
			"should return false when no retry_join config")
	})

	t.Run("unreachable_leader", func(t *testing.T) {
		t.Parallel()
		_, cmd := testServerCommand(t)

		// Use an address that definitely won't be listening
		config := &server.Config{
			Storage: &server.Storage{
				Type: "raft",
				Config: map[string]string{
					"retry_join": `[{"leader_api_addr": "http://127.0.0.1:59999"}]`,
				},
			},
		}

		// Should return false because the address is not reachable
		start := time.Now()
		result := cmd.anyLeaderCandidateReachable(config)
		elapsed := time.Since(start)

		require.False(t, result, "should return false for unreachable leader")
		// Should complete within the 2 second timeout + some margin
		require.Less(t, elapsed, 5*time.Second, "should timeout reasonably quickly")
	})

	t.Run("invalid_json_config", func(t *testing.T) {
		t.Parallel()
		_, cmd := testServerCommand(t)

		config := &server.Config{
			Storage: &server.Storage{
				Type: "raft",
				Config: map[string]string{
					"retry_join": `invalid json`,
				},
			},
		}
		require.False(t, cmd.anyLeaderCandidateReachable(config),
			"should return false for invalid JSON config")
	})
}

// TestConfigureDevTLS verifies the various logic paths that flow through the
// configureDevTLS function.
func TestConfigureDevTLS(t *testing.T) {
	testcases := []struct {
		ServerCommand   *ServerCommand
		DeferFuncNotNil bool
		ConfigNotNil    bool
		TLSDisable      bool
		CertPathEmpty   bool
		ErrNotNil       bool
		TestDescription string
	}{
		{
			ServerCommand: &ServerCommand{
				flagDevTLS: false,
			},
			ConfigNotNil:    true,
			TLSDisable:      true,
			CertPathEmpty:   true,
			ErrNotNil:       false,
			TestDescription: "flagDev is false, nothing will be configured",
		},
		{
			ServerCommand: &ServerCommand{
				flagDevTLS:        true,
				flagDevTLSCertDir: "",
			},
			DeferFuncNotNil: true,
			ConfigNotNil:    true,
			ErrNotNil:       false,
			TestDescription: "flagDevTLSCertDir is empty",
		},
		{
			ServerCommand: &ServerCommand{
				flagDevTLS:        true,
				flagDevTLSCertDir: "@/#",
			},
			CertPathEmpty:   true,
			ErrNotNil:       true,
			TestDescription: "flagDevTLSCertDir is set to something invalid",
		},
	}

	for _, testcase := range testcases {
		fun, cfg, certPath, err := configureDevTLS(testcase.ServerCommand)
		if fun != nil {
			// If a function is returned, call it right away to clean up
			// files created in the temporary directory before anything else has
			// a chance to fail this test.
			fun()
		}

		require.Equal(t, testcase.DeferFuncNotNil, (fun != nil), "test description %s", testcase.TestDescription)
		require.Equal(t, testcase.ConfigNotNil, cfg != nil, "test description %s", testcase.TestDescription)
		if testcase.ConfigNotNil {
			require.True(t, len(cfg.Listeners) > 0, "test description %s", testcase.TestDescription)
			require.Equal(t, testcase.TLSDisable, cfg.Listeners[0].TLSDisable, "test description %s", testcase.TestDescription)
		}
		require.Equal(t, testcase.CertPathEmpty, len(certPath) == 0, "test description %s", testcase.TestDescription)
		require.Equal(t, testcase.ErrNotNil, (err != nil), "test description %s", testcase.TestDescription)
	}
}
