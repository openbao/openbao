// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"fmt"
	"os"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	gatedio "github.com/hashicorp/go-gatedio"
	"github.com/openbao/openbao/command/template/config"
	"github.com/openbao/openbao/command/template/signals"
)

func TestCLI_ParseFlags(t *testing.T) {
	f, err := os.CreateTemp("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())

	cases := []struct {
		name string
		f    []string
		e    *config.Config
		err  bool
	}{
		{
			"config",
			[]string{"-config", f.Name()},
			&config.Config{},
			false,
		},
		{
			"dedup",
			[]string{"-dedup"},
			&config.Config{
				Dedup: &config.DedupConfig{
					Enabled: config.Bool(true),
				},
			},
			false,
		},
		{
			"exec",
			[]string{"-exec", "command"},
			&config.Config{
				Exec: &config.ExecConfig{
					Enabled: config.Bool(true),
					Command: []string{"command"},
				},
			},
			false,
		},
		{
			"exec-kill-signal",
			[]string{"-exec-kill-signal", "SIGUSR1"},
			&config.Config{
				Exec: &config.ExecConfig{
					KillSignal: config.Signal(syscall.SIGUSR1),
				},
			},
			false,
		},
		{
			"exec-kill-timeout",
			[]string{"-exec-kill-timeout", "10s"},
			&config.Config{
				Exec: &config.ExecConfig{
					KillTimeout: config.TimeDuration(10 * time.Second),
				},
			},
			false,
		},
		{
			"exec-reload-signal",
			[]string{"-exec-reload-signal", "SIGUSR1"},
			&config.Config{
				Exec: &config.ExecConfig{
					ReloadSignal: config.Signal(syscall.SIGUSR1),
				},
			},
			false,
		},
		{
			"exec-splay",
			[]string{"-exec-splay", "10s"},
			&config.Config{
				Exec: &config.ExecConfig{
					Splay: config.TimeDuration(10 * time.Second),
				},
			},
			false,
		},
		{
			"exec-env-pristine",
			[]string{"-exec-env-pristine"},
			&config.Config{
				Exec: &config.ExecConfig{
					Env: &config.EnvConfig{
						Pristine: config.Bool(true),
					},
				},
			},
			false,
		},
		{
			"exec-env-custom",
			[]string{"-exec-env-custom", "SOME_ENV_VARIABLE=VALUE"},
			&config.Config{
				Exec: &config.ExecConfig{
					Env: &config.EnvConfig{
						Custom: []string{"SOME_ENV_VARIABLE=VALUE"},
					},
				},
			},
			false,
		},
		{
			"exec-env-custom-multiple",
			[]string{
				"-exec-env-custom", "SOME_ENV_VARIABLE=VALUE",
				"-exec-env-custom", "ANOTHER_ENV_VARIABLE=VALUE",
			},
			&config.Config{
				Exec: &config.ExecConfig{
					Env: &config.EnvConfig{
						Custom: []string{
							"SOME_ENV_VARIABLE=VALUE",
							"ANOTHER_ENV_VARIABLE=VALUE",
						},
					},
				},
			},
			false,
		},
		{
			"exec-env-allowlist",
			[]string{"-exec-env-allowlist", "SOME_*"},
			&config.Config{
				Exec: &config.ExecConfig{
					Env: &config.EnvConfig{
						Allowlist: []string{"SOME_*"},
					},
				},
			},
			false,
		},
		{
			"exec-env-allowlist-multiple",
			[]string{
				"-exec-env-allowlist", "SOME_*",
				"-exec-env-allowlist", "ANOTHER_*",
			},
			&config.Config{
				Exec: &config.ExecConfig{
					Env: &config.EnvConfig{
						Allowlist: []string{
							"SOME_*",
							"ANOTHER_*",
						},
					},
				},
			},
			false,
		},
		{
			"exec-env-denylist",
			[]string{"-exec-env-denylist", "VAULT_*"},
			&config.Config{
				Exec: &config.ExecConfig{
					Env: &config.EnvConfig{
						Denylist: []string{"VAULT_*"},
					},
				},
			},
			false,
		},
		{
			"exec-env-denylist-multiple",
			[]string{
				"-exec-env-denylist", "VAULT_*",
			},
			&config.Config{
				Exec: &config.ExecConfig{
					Env: &config.EnvConfig{
						Denylist: []string{
							"VAULT_*",
						},
					},
				},
			},
			false,
		},
		{
			"kill-signal",
			[]string{"-kill-signal", "SIGUSR1"},
			&config.Config{
				KillSignal: config.Signal(syscall.SIGUSR1),
			},
			false,
		},
		{
			"log-level",
			[]string{"-log-level", "DEBUG"},
			&config.Config{
				LogLevel: config.String("DEBUG"),
			},
			false,
		},
		{
			"log-file",
			[]string{"-log-file", "something.log"},
			&config.Config{
				FileLog: &config.LogFileConfig{
					LogFilePath: config.String("something.log"),
				},
			},
			false,
		},
		{
			"log-rotate-bytes",
			[]string{"-log-rotate-bytes", "102400"},
			&config.Config{
				FileLog: &config.LogFileConfig{
					LogRotateBytes: config.Int(102400),
				},
			},
			false,
		},
		{
			"log-rotate-duration",
			[]string{"-log-rotate-duration", "24h"},
			&config.Config{
				FileLog: &config.LogFileConfig{
					LogRotateDuration: config.TimeDuration(24 * time.Hour),
				},
			},
			false,
		},
		{
			"log-rotate-max-files",
			[]string{"-log-rotate-max-files", "10"},
			&config.Config{
				FileLog: &config.LogFileConfig{
					LogRotateMaxFiles: config.Int(10),
				},
			},
			false,
		},
		{
			"max-stale",
			[]string{"-max-stale", "10s"},
			&config.Config{
				MaxStale: config.TimeDuration(10 * time.Second),
			},
			false,
		},
		{
			"pid-file",
			[]string{"-pid-file", "/var/pid/file"},
			&config.Config{
				PidFile: config.String("/var/pid/file"),
			},
			false,
		},
		{
			"reload-signal",
			[]string{"-reload-signal", "SIGUSR1"},
			&config.Config{
				ReloadSignal: config.Signal(syscall.SIGUSR1),
			},
			false,
		},
		{
			"reload-signal-signil",
			[]string{"-reload-signal", "SIGNULL"},
			&config.Config{
				ReloadSignal: config.Signal(signals.SIGNULL),
			},
			false,
		},
		{
			"syslog",
			[]string{"-syslog"},
			&config.Config{
				Syslog: &config.SyslogConfig{
					Enabled: config.Bool(true),
				},
			},
			false,
		},
		{
			"syslog-facility",
			[]string{"-syslog-facility", "LOCAL0"},
			&config.Config{
				Syslog: &config.SyslogConfig{
					Facility: config.String("LOCAL0"),
				},
			},
			false,
		},
		{
			"template",
			[]string{"-template", "/tmp/in.tpl"},
			&config.Config{
				Templates: &config.TemplateConfigs{
					&config.TemplateConfig{
						Source: config.String("/tmp/in.tpl"),
					},
				},
			},
			false,
		},
		{
			"vault-addr",
			[]string{"-vault-addr", "vault_addr"},
			&config.Config{
				Vault: &config.VaultConfig{
					Address: config.String("vault_addr"),
				},
			},
			false,
		},
		{
			"vault-retry",
			[]string{"-vault-retry"},
			&config.Config{
				Vault: &config.VaultConfig{
					Retry: &config.RetryConfig{
						Enabled: config.Bool(true),
					},
				},
			},
			false,
		},
		{
			"vault-retry-attempts",
			[]string{"-vault-retry-attempts", "20"},
			&config.Config{
				Vault: &config.VaultConfig{
					Retry: &config.RetryConfig{
						Attempts: config.Int(20),
					},
				},
			},
			false,
		},
		{
			"vault-retry-backoff",
			[]string{"-vault-retry-backoff", "30s"},
			&config.Config{
				Vault: &config.VaultConfig{
					Retry: &config.RetryConfig{
						Backoff: config.TimeDuration(30 * time.Second),
					},
				},
			},
			false,
		},
		{
			"vault-retry-max-backoff",
			[]string{"-vault-retry-max-backoff", "60s"},
			&config.Config{
				Vault: &config.VaultConfig{
					Retry: &config.RetryConfig{
						MaxBackoff: config.TimeDuration(60 * time.Second),
					},
				},
			},
			false,
		},
		{
			"vault-renew-token",
			[]string{"-vault-renew-token"},
			&config.Config{
				Vault: &config.VaultConfig{
					RenewToken: config.Bool(true),
				},
			},
			false,
		},
		{
			"vault-ssl",
			[]string{"-vault-ssl"},
			&config.Config{
				Vault: &config.VaultConfig{
					SSL: &config.SSLConfig{
						Enabled: config.Bool(true),
					},
				},
			},
			false,
		},
		{
			"vault-ssl-ca-cert",
			[]string{"-vault-ssl-ca-cert", "ca_cert"},
			&config.Config{
				Vault: &config.VaultConfig{
					SSL: &config.SSLConfig{
						CaCert: config.String("ca_cert"),
					},
				},
			},
			false,
		},
		{
			"vault-ssl-ca-path",
			[]string{"-vault-ssl-ca-path", "ca_path"},
			&config.Config{
				Vault: &config.VaultConfig{
					SSL: &config.SSLConfig{
						CaPath: config.String("ca_path"),
					},
				},
			},
			false,
		},
		{
			"vault-ssl-cert",
			[]string{"-vault-ssl-cert", "cert"},
			&config.Config{
				Vault: &config.VaultConfig{
					SSL: &config.SSLConfig{
						Cert: config.String("cert"),
					},
				},
			},
			false,
		},
		{
			"vault-ssl-key",
			[]string{"-vault-ssl-key", "key"},
			&config.Config{
				Vault: &config.VaultConfig{
					SSL: &config.SSLConfig{
						Key: config.String("key"),
					},
				},
			},
			false,
		},
		{
			"vault-ssl-server-name",
			[]string{"-vault-ssl-server-name", "server_name"},
			&config.Config{
				Vault: &config.VaultConfig{
					SSL: &config.SSLConfig{
						ServerName: config.String("server_name"),
					},
				},
			},
			false,
		},
		{
			"vault-ssl-verify",
			[]string{"-vault-ssl-verify"},
			&config.Config{
				Vault: &config.VaultConfig{
					SSL: &config.SSLConfig{
						Verify: config.Bool(true),
					},
				},
			},
			false,
		},
		{
			"vault-token",
			[]string{"-vault-token", "token"},
			&config.Config{
				Vault: &config.VaultConfig{
					Token: config.String("token"),
				},
			},
			false,
		},
		{
			"vault-agent-token-file",
			[]string{"-vault-agent-token-file", "/tmp/vault/agent/token"},
			&config.Config{
				Vault: &config.VaultConfig{
					VaultAgentTokenFile: config.String("/tmp/vault/agent/token"),
				},
			},
			false,
		},
		{
			"vault-transport-dial-keep-alive",
			[]string{"-vault-transport-dial-keep-alive", "30s"},
			&config.Config{
				Vault: &config.VaultConfig{
					Transport: &config.TransportConfig{
						DialKeepAlive: config.TimeDuration(30 * time.Second),
					},
				},
			},
			false,
		},
		{
			"vault-transport-dial-timeout",
			[]string{"-vault-transport-dial-timeout", "30s"},
			&config.Config{
				Vault: &config.VaultConfig{
					Transport: &config.TransportConfig{
						DialTimeout: config.TimeDuration(30 * time.Second),
					},
				},
			},
			false,
		},
		{
			"vault-transport-disable-keep-alives",
			[]string{"-vault-transport-disable-keep-alives"},
			&config.Config{
				Vault: &config.VaultConfig{
					Transport: &config.TransportConfig{
						DisableKeepAlives: config.Bool(true),
					},
				},
			},
			false,
		},
		{
			"vault-transport-max-idle-conns-per-host",
			[]string{"-vault-transport-max-idle-conns-per-host", "100"},
			&config.Config{
				Vault: &config.VaultConfig{
					Transport: &config.TransportConfig{
						MaxIdleConnsPerHost: config.Int(100),
					},
				},
			},
			false,
		},
		{
			"vault-transport-tls-handshake-timeout",
			[]string{"-vault-transport-tls-handshake-timeout", "30s"},
			&config.Config{
				Vault: &config.VaultConfig{
					Transport: &config.TransportConfig{
						TLSHandshakeTimeout: config.TimeDuration(30 * time.Second),
					},
				},
			},
			false,
		},
		{
			"vault-unwrap-token",
			[]string{"-vault-unwrap-token"},
			&config.Config{
				Vault: &config.VaultConfig{
					UnwrapToken: config.Bool(true),
				},
			},
			false,
		},
		{
			"vault-default-lease-duration",
			[]string{"-vault-default-lease-duration", "60s"},
			&config.Config{
				Vault: &config.VaultConfig{
					DefaultLeaseDuration: config.TimeDuration(60 * time.Second),
				},
			},
			false,
		},
		{
			"wait_min",
			[]string{"-wait", "10s"},
			&config.Config{
				Wait: &config.WaitConfig{
					Min: config.TimeDuration(10 * time.Second),
					Max: config.TimeDuration(40 * time.Second),
				},
			},
			false,
		},
		{
			"wait_min_max",
			[]string{"-wait", "10s:30s"},
			&config.Config{
				Wait: &config.WaitConfig{
					Min: config.TimeDuration(10 * time.Second),
					Max: config.TimeDuration(30 * time.Second),
				},
			},
			false,
		},
		{
			"once-wait",
			[]string{"-once", "-wait", "10s"},
			&config.Config{
				Wait: &config.WaitConfig{
					Enabled: config.Bool(false),
				},
				Once: true,
			},
			false,
		},
		{
			"parse-only",
			[]string{"-parse-only"},
			&config.Config{
				ParseOnly: true,
			},
			false,
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			out := gatedio.NewByteBuffer()
			cli := NewCLI(out, out)

			a, _, _, _, err := cli.ParseFlags(tc.f)
			if (err != nil) != tc.err {
				t.Fatal(err)
			}
			a.Finalize()

			var e *config.Config
			if tc.e != nil {
				e = config.DefaultConfig().Merge(tc.e)
				e.Finalize()
			}

			if !reflect.DeepEqual(e, a) {
				t.Errorf("Config diff: %soutput: %q", e.Diff(a), out)
			}
		})
	}
}

func TestCLI_Run(t *testing.T) {
	cases := []struct {
		name string
		args []string
		f    func(*testing.T, int, string)
	}{
		{
			"help",
			[]string{"-h"},
			func(t *testing.T, i int, s string) {
				if i != 0 {
					t.Error("expected 0 exit")
				}
			},
		},
		{
			"version",
			[]string{"-v"},
			func(t *testing.T, i int, s string) {
				if i != 0 {
					t.Error("expected 0 exit")
				}
			},
		},
		{
			"too_many_args",
			[]string{"foo", "bar", "baz"},
			func(t *testing.T, i int, s string) {
				if i == 0 {
					t.Error("expected error")
				}
				if !strings.Contains(s, "extra args") {
					t.Errorf("\nexp: %q\nact: %q", "extra args", s)
				}
			},
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			out := gatedio.NewByteBuffer()
			cli := NewCLI(out, out)

			tc.args = append([]string{"consul-template"}, tc.args...)
			exit := cli.Run(tc.args)
			tc.f(t, exit, out.String())
		})
	}
}
