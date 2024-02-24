// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package config

import (
	"fmt"
	"os"
	"reflect"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/hashicorp/consul-template/signals"
	"github.com/hashicorp/vault/api"
)

func TestMain(m *testing.M) {
	// clear out any potential local config for tests
	os.Unsetenv("VAULT_ADDR")
	os.Unsetenv("VAULT_TOKEN")
	os.Unsetenv("VAULT_DEV_ROOT_TOKEN_ID")
	homePath, _ = os.MkdirTemp("", "")

	os.Exit(m.Run())
}

func testFile(t *testing.T, contents string) (path string, remove func()) {
	testFile, err := os.CreateTemp("", "test.")
	if err != nil {
		t.Fatal(err)
	}
	if len(contents) > 0 {
		if _, err := testFile.Write([]byte(contents)); err != nil {
			t.Fatal(err)
		}
	}
	return testFile.Name(), func() { os.Remove(testFile.Name()) }
}

func TestParse(t *testing.T) {
	testFilePath, remove := testFile(t, "")
	defer remove()

	cases := []struct {
		name string
		i    string
		e    *Config
		err  bool
	}{
		{
			"consul_address",
			`consul {
				address = "1.2.3.4"
			}`,
			&Config{
				Consul: &ConsulConfig{
					Address: String("1.2.3.4"),
				},
			},
			false,
		},
		{
			"consul_auth",
			`consul {
				auth {
					username = "username"
					password = "password"
				}
			}`,
			&Config{
				Consul: &ConsulConfig{
					Auth: &AuthConfig{
						Username: String("username"),
						Password: String("password"),
					},
				},
			},
			false,
		},
		{
			"consul_retry",
			`consul {
				retry {
					backoff  = "2s"
					attempts = 10
				}
			}`,
			&Config{
				Consul: &ConsulConfig{
					Retry: &RetryConfig{
						Attempts: Int(10),
						Backoff:  TimeDuration(2 * time.Second),
					},
				},
			},
			false,
		},
		{
			"consul_ssl",
			`consul {
				ssl {}
			}`,
			&Config{
				Consul: &ConsulConfig{
					SSL: &SSLConfig{},
				},
			},
			false,
		},
		{
			"consul_ssl_enabled",
			`consul {
				ssl {
					enabled = true
				}
			}`,
			&Config{
				Consul: &ConsulConfig{
					SSL: &SSLConfig{
						Enabled: Bool(true),
					},
				},
			},
			false,
		},
		{
			"consul_ssl_verify",
			`consul {
				ssl {
					verify = true
				}
			}`,
			&Config{
				Consul: &ConsulConfig{
					SSL: &SSLConfig{
						Verify: Bool(true),
					},
				},
			},
			false,
		},
		{
			"consul_ssl_cert",
			`consul {
				ssl {
					cert = "cert"
				}
			}`,
			&Config{
				Consul: &ConsulConfig{
					SSL: &SSLConfig{
						Cert: String("cert"),
					},
				},
			},
			false,
		},
		{
			"consul_ssl_key",
			`consul {
				ssl {
					key = "key"
				}
			}`,
			&Config{
				Consul: &ConsulConfig{
					SSL: &SSLConfig{
						Key: String("key"),
					},
				},
			},
			false,
		},
		{
			"consul_ssl_ca_cert",
			`consul {
				ssl {
					ca_cert = "ca_cert"
				}
			}`,
			&Config{
				Consul: &ConsulConfig{
					SSL: &SSLConfig{
						CaCert: String("ca_cert"),
					},
				},
			},
			false,
		},
		{
			"consul_ssl_ca_path",
			`consul {
				ssl {
					ca_path = "ca_path"
				}
			}`,
			&Config{
				Consul: &ConsulConfig{
					SSL: &SSLConfig{
						CaPath: String("ca_path"),
					},
				},
			},
			false,
		},
		{
			"consul_ssl_server_name",
			`consul {
				ssl {
					server_name = "server_name"
				}
			}`,
			&Config{
				Consul: &ConsulConfig{
					SSL: &SSLConfig{
						ServerName: String("server_name"),
					},
				},
			},
			false,
		},
		{
			"consul_token",
			`consul {
				token = "token"
			}`,
			&Config{
				Consul: &ConsulConfig{
					Token: String("token"),
				},
			},
			false,
		},
		{
			"consul_transport_dial_keep_alive",
			`consul {
				transport {
					dial_keep_alive = "10s"
				}
			}`,
			&Config{
				Consul: &ConsulConfig{
					Transport: &TransportConfig{
						DialKeepAlive: TimeDuration(10 * time.Second),
					},
				},
			},
			false,
		},
		{
			"consul_transport_dial_timeout",
			`consul {
				transport {
					dial_timeout = "10s"
				}
			}`,
			&Config{
				Consul: &ConsulConfig{
					Transport: &TransportConfig{
						DialTimeout: TimeDuration(10 * time.Second),
					},
				},
			},
			false,
		},
		{
			"consul_transport_disable_keep_alives",
			`consul {
				transport {
					disable_keep_alives = true
				}
			}`,
			&Config{
				Consul: &ConsulConfig{
					Transport: &TransportConfig{
						DisableKeepAlives: Bool(true),
					},
				},
			},
			false,
		},
		{
			"consul_transport_max_idle_conns_per_host",
			`consul {
				transport {
					max_idle_conns_per_host = 100
				}
			}`,
			&Config{
				Consul: &ConsulConfig{
					Transport: &TransportConfig{
						MaxIdleConnsPerHost: Int(100),
					},
				},
			},
			false,
		},
		{
			"consul_transport_tls_handshake_timeout",
			`consul {
				transport {
					tls_handshake_timeout = "30s"
				}
			}`,
			&Config{
				Consul: &ConsulConfig{
					Transport: &TransportConfig{
						TLSHandshakeTimeout: TimeDuration(30 * time.Second),
					},
				},
			},
			false,
		},
		{
			"deduplicate",
			`deduplicate {
				enabled				= true
				prefix				= "foo/bar"
				max_stale			= "100s"
				TTL					= "500s"
				block_query_wait	= "200s"
			}`,
			&Config{
				Dedup: &DedupConfig{
					Enabled:            Bool(true),
					Prefix:             String("foo/bar"),
					MaxStale:           TimeDuration(100 * time.Second),
					TTL:                TimeDuration(500 * time.Second),
					BlockQueryWaitTime: TimeDuration(200 * time.Second),
				},
			},
			false,
		},
		{
			"default_left_delimiter",
			`default_delimiters {
				left = "<"
			}`,
			&Config{
				DefaultDelims: &DefaultDelims{
					Left: String("<"),
				},
			},
			false,
		},
		{
			"default_right_delimiter",
			`default_delimiters {
				right = ">"
			}`,
			&Config{
				DefaultDelims: &DefaultDelims{
					Right: String(">"),
				},
			},
			false,
		},
		{
			"exec",
			`exec {}`,
			&Config{
				Exec: &ExecConfig{},
			},
			false,
		},
		{
			"exec_command",
			`exec {
				command = "command"
			}`,
			&Config{
				Exec: &ExecConfig{
					Command: []string{"command"},
				},
			},
			false,
		},
		{
			"exec_enabled",
			`exec {
				enabled = true
			 }`,
			&Config{
				Exec: &ExecConfig{
					Enabled: Bool(true),
				},
			},
			false,
		},
		{
			"exec_env",
			`exec {
				env {}
			 }`,
			&Config{
				Exec: &ExecConfig{
					Env: &EnvConfig{},
				},
			},
			false,
		},
		{
			"exec_env_denylist",
			`exec {
				env {
					denylist = ["a", "b"]
				}
			 }`,
			&Config{
				Exec: &ExecConfig{
					Env: &EnvConfig{
						Denylist: []string{"a", "b"},
					},
				},
			},
			false,
		},
		{
			"exec_env_custom",
			`exec {
				env {
					custom = ["a=b", "c=d"]
				}
			}`,
			&Config{
				Exec: &ExecConfig{
					Env: &EnvConfig{
						Custom: []string{"a=b", "c=d"},
					},
				},
			},
			false,
		},
		{
			"exec_env_pristine",
			`exec {
				env {
					pristine = true
				}
			 }`,
			&Config{
				Exec: &ExecConfig{
					Env: &EnvConfig{
						Pristine: Bool(true),
					},
				},
			},
			false,
		},
		{
			"exec_env_allowlist",
			`exec {
				env {
					allowlist = ["a", "b"]
				}
			 }`,
			&Config{
				Exec: &ExecConfig{
					Env: &EnvConfig{
						Allowlist: []string{"a", "b"},
					},
				},
			},
			false,
		},
		{
			"exec_kill_signal",
			`exec {
				kill_signal = "SIGUSR1"
			 }`,
			&Config{
				Exec: &ExecConfig{
					KillSignal: Signal(syscall.SIGUSR1),
				},
			},
			false,
		},
		{
			"exec_kill_timeout",
			`exec {
				kill_timeout = "30s"
			 }`,
			&Config{
				Exec: &ExecConfig{
					KillTimeout: TimeDuration(30 * time.Second),
				},
			},
			false,
		},
		{
			"exec_reload_signal",
			`exec {
				reload_signal = "SIGUSR1"
			 }`,
			&Config{
				Exec: &ExecConfig{
					ReloadSignal: Signal(syscall.SIGUSR1),
				},
			},
			false,
		},
		{
			"exec_reload_signal_null",
			`exec {
				reload_signal = "SIGNULL"
			 }`,
			&Config{
				Exec: &ExecConfig{
					ReloadSignal: Signal(signals.SIGNULL),
				},
			},
			false,
		},
		{
			"exec_splay",
			`exec {
				splay = "30s"
			 }`,
			&Config{
				Exec: &ExecConfig{
					Splay: TimeDuration(30 * time.Second),
				},
			},
			false,
		},
		{
			"exec_timeout",
			`exec {
				timeout = "30s"
			 }`,
			&Config{
				Exec: &ExecConfig{
					Timeout: TimeDuration(30 * time.Second),
				},
			},
			false,
		},
		{
			"kill_signal",
			`kill_signal = "SIGUSR1"`,
			&Config{
				KillSignal: Signal(syscall.SIGUSR1),
			},
			false,
		},
		{
			"log_level",
			`log_level = "WARN"`,
			&Config{
				LogLevel: String("WARN"),
			},
			false,
		},
		{
			"log_file",
			`log_file {}`,
			&Config{
				FileLog: &LogFileConfig{},
			},
			false,
		},
		{
			"log_file_path",
			`log_file {
				path = "something.log"
			}`,
			&Config{
				FileLog: &LogFileConfig{
					LogFilePath: String("something.log"),
				},
			},
			false,
		},
		{
			"log_file_path_no_filename",
			`log_file {
				path = "./logs"
			}`,
			&Config{
				FileLog: &LogFileConfig{
					LogFilePath: String("./logs"),
				},
			},
			false,
		},
		{
			"log_file_log_rotate_bytes",
			`log_file {
				log_rotate_bytes = 102400
			}`,
			&Config{
				FileLog: &LogFileConfig{
					LogRotateBytes: Int(102400),
				},
			},
			false,
		},
		{
			"log_file_log_rotate_duration",
			`log_file {
				log_rotate_duration = "24h"
			}`,
			&Config{
				FileLog: &LogFileConfig{
					LogRotateDuration: TimeDuration(24 * time.Hour),
				},
			},
			false,
		},
		{
			"log_file_log_rotate_max_files",
			`log_file {
				log_rotate_max_files = 10
			}`,
			&Config{
				FileLog: &LogFileConfig{
					LogRotateMaxFiles: Int(10),
				},
			},
			false,
		},
		{
			"max_stale",
			`max_stale = "10s"`,
			&Config{
				MaxStale: TimeDuration(10 * time.Second),
			},
			false,
		},
		{
			"block_query_wait",
			`block_query_wait = "61s"`,
			&Config{
				BlockQueryWaitTime: TimeDuration(61 * time.Second),
			},
			false,
		},
		{
			"pid_file",
			`pid_file = "/var/pid"`,
			&Config{
				PidFile: String("/var/pid"),
			},
			false,
		},
		{
			"reload_signal",
			`reload_signal = "SIGUSR1"`,
			&Config{
				ReloadSignal: Signal(syscall.SIGUSR1),
			},
			false,
		},
		{
			"reload_signal_default",
			``,
			&Config{
				ReloadSignal: nil,
			},
			false,
		},
		{
			"reload_signal_null",
			`reload_signal = "SIGNULL"`,
			&Config{
				ReloadSignal: &signals.SIGNULL,
			},
			false,
		},
		{
			"reload_signal_blank",
			`reload_signal = ""`,
			&Config{
				ReloadSignal: &signals.SIGNULL,
			},
			false,
		},
		{
			"reload_signal_blank_exec",
			`reload_signal = ""
			exec {
				reload_signal = ""
			 }`,
			&Config{
				ReloadSignal: &signals.SIGNULL,
				Exec: &ExecConfig{
					ReloadSignal: &signals.SIGNULL,
				},
			},
			false,
		},
		{
			"reload_signal_exec_override",
			`reload_signal = ""
			exec {
				reload_signal = "SIGUSR1"
			 }`,
			&Config{
				ReloadSignal: &signals.SIGNULL,
				Exec: &ExecConfig{
					ReloadSignal: Signal(syscall.SIGUSR1),
				},
			},
			false,
		},
		{
			"syslog",
			`syslog {}`,
			&Config{
				Syslog: &SyslogConfig{},
			},
			false,
		},
		{
			"syslog_enabled",
			`syslog {
				enabled = true
			}`,
			&Config{
				Syslog: &SyslogConfig{
					Enabled: Bool(true),
				},
			},
			false,
		},
		{
			"syslog_facility",
			`syslog {
				facility = "facility"
			}`,
			&Config{
				Syslog: &SyslogConfig{
					Facility: String("facility"),
				},
			},
			false,
		},
		{
			"syslog_name",
			`syslog {
				name = "name"
			}`,
			&Config{
				Syslog: &SyslogConfig{
					Name: String("name"),
				},
			},
			false,
		},
		{
			"template",
			`template {}`,
			&Config{
				Templates: &TemplateConfigs{
					&TemplateConfig{},
				},
			},
			false,
		},
		{
			"template_multi",
			`template {}
			template {}`,
			&Config{
				Templates: &TemplateConfigs{
					&TemplateConfig{},
					&TemplateConfig{},
				},
			},
			false,
		},
		{
			"template_backup",
			`template {
				backup = true
			}`,
			&Config{
				Templates: &TemplateConfigs{
					&TemplateConfig{
						Backup: Bool(true),
					},
				},
			},
			false,
		},
		{
			"template_command",
			`template {
				command = "command"
			}`,
			&Config{
				Templates: &TemplateConfigs{
					&TemplateConfig{
						Command: []string{"command"},
					},
				},
			},
			false,
		},
		{
			"template_command_timeout",
			`template {
				command_timeout = "10s"
			}`,
			&Config{
				Templates: &TemplateConfigs{
					&TemplateConfig{
						CommandTimeout: TimeDuration(10 * time.Second),
					},
				},
			},
			false,
		},
		{
			"template_contents",
			`template {
				contents = "contents"
			}`,
			&Config{
				Templates: &TemplateConfigs{
					&TemplateConfig{
						Contents: String("contents"),
					},
				},
			},
			false,
		},
		{
			"template_destination",
			`template {
				destination = "destination"
			}`,
			&Config{
				Templates: &TemplateConfigs{
					&TemplateConfig{
						Destination: String("destination"),
					},
				},
			},
			false,
		},
		{
			"template_error_on_missing_key",
			`template {
						error_on_missing_key = true
					}`,
			&Config{
				Templates: &TemplateConfigs{
					&TemplateConfig{
						ErrMissingKey: Bool(true),
					},
				},
			},
			false,
		},
		{
			"template_exec",
			`template {
				exec {}
			}`,
			&Config{
				Templates: &TemplateConfigs{
					&TemplateConfig{
						Exec: &ExecConfig{},
					},
				},
			},
			false,
		},
		{
			"template_exec_command",
			`template {
				exec {
					command = "command"
				}
			}`,
			&Config{
				Templates: &TemplateConfigs{
					&TemplateConfig{
						Exec: &ExecConfig{
							Command: []string{"command"},
						},
					},
				},
			},
			false,
		},
		{
			"template_exec_enabled",
			`template {
				exec {
					enabled = true
				}
			 }`,
			&Config{
				Templates: &TemplateConfigs{
					&TemplateConfig{
						Exec: &ExecConfig{
							Enabled: Bool(true),
						},
					},
				},
			},
			false,
		},
		{
			"template_exec_env",
			`template {
				exec {
					env {}
				}
			 }`,
			&Config{
				Templates: &TemplateConfigs{
					&TemplateConfig{
						Exec: &ExecConfig{
							Env: &EnvConfig{},
						},
					},
				},
			},
			false,
		},
		{
			"template_exec_env_denylist",
			`template {
				exec {
					env {
						denylist = ["a", "b"]
					}
				}
			 }`,
			&Config{
				Templates: &TemplateConfigs{
					&TemplateConfig{
						Exec: &ExecConfig{
							Env: &EnvConfig{
								Denylist: []string{"a", "b"},
							},
						},
					},
				},
			},
			false,
		},
		{
			"template_exec_env_denylist_deprecated",
			`template {
				exec {
					env {
						blacklist = ["a", "b"]
					}
				}
			 }`,
			&Config{
				Templates: &TemplateConfigs{
					&TemplateConfig{
						Exec: &ExecConfig{
							Env: &EnvConfig{
								DenylistDeprecated: []string{"a", "b"},
							},
						},
					},
				},
			},
			false,
		},
		{
			"template_exec_env_custom",
			`template {
				exec {
					env {
						custom = ["a=b", "c=d"]
					}
				}
			 }`,
			&Config{
				Templates: &TemplateConfigs{
					&TemplateConfig{
						Exec: &ExecConfig{
							Env: &EnvConfig{
								Custom: []string{"a=b", "c=d"},
							},
						},
					},
				},
			},
			false,
		},
		{
			"template_exec_env_pristine",
			`template {
				exec {
					env {
						pristine = true
					}
				}
			 }`,
			&Config{
				Templates: &TemplateConfigs{
					&TemplateConfig{
						Exec: &ExecConfig{
							Env: &EnvConfig{
								Pristine: Bool(true),
							},
						},
					},
				},
			},
			false,
		},
		{
			"template_exec_env_allowlist",
			`template {
				exec {
					env {
						allowlist = ["a", "b"]
					}
				}
			 }`,
			&Config{
				Templates: &TemplateConfigs{
					&TemplateConfig{
						Exec: &ExecConfig{
							Env: &EnvConfig{
								Allowlist: []string{"a", "b"},
							},
						},
					},
				},
			},
			false,
		},
		{
			"template_exec_env_allowlist_deprecated",
			`template {
				exec {
					env {
						whitelist = ["a", "b"]
					}
				}
			 }`,
			&Config{
				Templates: &TemplateConfigs{
					&TemplateConfig{
						Exec: &ExecConfig{
							Env: &EnvConfig{
								AllowlistDeprecated: []string{"a", "b"},
							},
						},
					},
				},
			},
			false,
		},
		{
			"template_exec_kill_signal",
			`template {
				exec {
					kill_signal = "SIGUSR1"
				}
			 }`,
			&Config{
				Templates: &TemplateConfigs{
					&TemplateConfig{
						Exec: &ExecConfig{
							KillSignal: Signal(syscall.SIGUSR1),
						},
					},
				},
			},
			false,
		},
		{
			"template_exec_kill_timeout",
			`template {
				exec {
					kill_timeout = "30s"
				}
			 }`,
			&Config{
				Templates: &TemplateConfigs{
					&TemplateConfig{
						Exec: &ExecConfig{
							KillTimeout: TimeDuration(30 * time.Second),
						},
					},
				},
			},
			false,
		},
		{
			"template_exec_reload_signal",
			`template {
				exec {
					reload_signal = "SIGUSR1"
				}
			 }`,
			&Config{
				Templates: &TemplateConfigs{
					&TemplateConfig{
						Exec: &ExecConfig{
							ReloadSignal: Signal(syscall.SIGUSR1),
						},
					},
				},
			},
			false,
		},
		{
			"template_exec_splay",
			`template {
				exec {
					splay = "30s"
				}
			 }`,
			&Config{
				Templates: &TemplateConfigs{
					&TemplateConfig{
						Exec: &ExecConfig{
							Splay: TimeDuration(30 * time.Second),
						},
					},
				},
			},
			false,
		},
		{
			"template_exec_timeout",
			`template {
				exec {
					timeout = "30s"
				}
			 }`,
			&Config{
				Templates: &TemplateConfigs{
					&TemplateConfig{
						Exec: &ExecConfig{
							Timeout: TimeDuration(30 * time.Second),
						},
					},
				},
			},
			false,
		},

		{
			"template_perms",
			`template {
				perms = "0600"
			}`,
			&Config{
				Templates: &TemplateConfigs{
					&TemplateConfig{
						Perms: FileMode(0o600),
					},
				},
			},
			false,
		},
		{
			"template_uid",
			`template {
				user = "1000"
			}`,
			&Config{
				Templates: &TemplateConfigs{
					&TemplateConfig{
						User: String("1000"),
					},
				},
			},
			false,
		},
		{
			"template_gid",
			`template {
				group = "1000"
			}`,
			&Config{
				Templates: &TemplateConfigs{
					&TemplateConfig{
						Group: String("1000"),
					},
				},
			},
			false,
		},
		{
			"template_uid_backward_compat",
			`template {
				uid = 1000
			}`,
			&Config{
				Templates: &TemplateConfigs{
					&TemplateConfig{
						Uid: Int(1000),
					},
				},
			},
			false,
		},
		{
			"template_gid_backward_compat",
			`template {
				gid = 1000
			}`,
			&Config{
				Templates: &TemplateConfigs{
					&TemplateConfig{
						Gid: Int(1000),
					},
				},
			},
			false,
		},
		{
			"template_uid_gid_default",
			`template {
			}`,
			&Config{
				Templates: &TemplateConfigs{
					&TemplateConfig{
						User:  nil,
						Group: nil,
						Uid:   nil,
						Gid:   nil,
					},
				},
			},
			false,
		},
		{
			"template_source",
			`template {
				source = "source"
			}`,
			&Config{
				Templates: &TemplateConfigs{
					&TemplateConfig{
						Source: String("source"),
					},
				},
			},
			false,
		},
		{
			"template_wait",
			`template {
				wait {
					min = "10s"
					max = "20s"
				}
			}`,
			&Config{
				Templates: &TemplateConfigs{
					&TemplateConfig{
						Wait: &WaitConfig{
							Min: TimeDuration(10 * time.Second),
							Max: TimeDuration(20 * time.Second),
						},
					},
				},
			},
			false,
		},
		{
			"template_wait_as_string",
			`template {
				wait = "10s:20s"
			}`,
			&Config{
				Templates: &TemplateConfigs{
					&TemplateConfig{
						Wait: &WaitConfig{
							Min: TimeDuration(10 * time.Second),
							Max: TimeDuration(20 * time.Second),
						},
					},
				},
			},
			false,
		},
		{
			"template_left_delimiter",
			`template {
				left_delimiter = "<"
			}`,
			&Config{
				Templates: &TemplateConfigs{
					&TemplateConfig{
						LeftDelim: String("<"),
					},
				},
			},
			false,
		},
		{
			"template_right_delimiter",
			`template {
				right_delimiter = ">"
			}`,
			&Config{
				Templates: &TemplateConfigs{
					&TemplateConfig{
						RightDelim: String(">"),
					},
				},
			},
			false,
		},
		{
			"vault",
			`vault {}`,
			&Config{
				Vault: &VaultConfig{},
			},
			false,
		},
		{
			"vault_enabled",
			`vault {
				enabled = true
			}`,
			&Config{
				Vault: &VaultConfig{
					Enabled: Bool(true),
				},
			},
			false,
		},
		{
			"vault_address",
			`vault {
				address = "address"
			}`,
			&Config{
				Vault: &VaultConfig{
					Address: String("address"),
				},
			},
			false,
		},
		{
			"vault_user_agent",
			`vault {
				client_user_agent = "my-user-agent"
			}`,
			&Config{
				Vault: &VaultConfig{
					ClientUserAgent: String("my-user-agent"),
				},
			},
			false,
		},
		{
			"vault_token",
			`vault {
				token = "token"
			}`,
			&Config{
				Vault: &VaultConfig{
					Token: String("token"),
				},
			},
			false,
		},
		{
			"vault_agent_token_file",
			`vault {
				vault_agent_token_file = "` + testFilePath + `"
			}`,
			&Config{
				Vault: &VaultConfig{
					VaultAgentTokenFile: String(testFilePath),
				},
			},
			false,
		},
		{
			"vault_transport_dial_keep_alive",
			`vault {
				transport {
					dial_keep_alive = "10s"
				}
			}`,
			&Config{
				Vault: &VaultConfig{
					Transport: &TransportConfig{
						DialKeepAlive: TimeDuration(10 * time.Second),
					},
				},
			},
			false,
		},
		{
			"vault_transport_dial_timeout",
			`vault {
				transport {
					dial_timeout = "10s"
				}
			}`,
			&Config{
				Vault: &VaultConfig{
					Transport: &TransportConfig{
						DialTimeout: TimeDuration(10 * time.Second),
					},
				},
			},
			false,
		},
		{
			"vault_transport_disable_keep_alives",
			`vault {
				transport {
					disable_keep_alives = true
				}
			}`,
			&Config{
				Vault: &VaultConfig{
					Transport: &TransportConfig{
						DisableKeepAlives: Bool(true),
					},
				},
			},
			false,
		},
		{
			"vault_transport_max_idle_conns_per_host",
			`vault {
				transport {
					max_idle_conns_per_host = 100
				}
			}`,
			&Config{
				Vault: &VaultConfig{
					Transport: &TransportConfig{
						MaxIdleConnsPerHost: Int(100),
					},
				},
			},
			false,
		},
		{
			"vault_transport_tls_handshake_timeout",
			`vault {
				transport {
					tls_handshake_timeout = "30s"
				}
			}`,
			&Config{
				Vault: &VaultConfig{
					Transport: &TransportConfig{
						TLSHandshakeTimeout: TimeDuration(30 * time.Second),
					},
				},
			},
			false,
		},
		{
			"vault_unwrap_token",
			`vault {
				unwrap_token = true
			}`,
			&Config{
				Vault: &VaultConfig{
					UnwrapToken: Bool(true),
				},
			},
			false,
		},
		{
			"vault_renew_token",
			`vault {
				renew_token = true
			}`,
			&Config{
				Vault: &VaultConfig{
					RenewToken: Bool(true),
				},
			},
			false,
		},
		{
			"vault_retry_backoff",
			`vault {
				retry {
					backoff = "5s"
				}
			}`,
			&Config{
				Vault: &VaultConfig{
					Retry: &RetryConfig{
						Backoff: TimeDuration(5 * time.Second),
					},
				},
			},
			false,
		},
		{
			"vault_retry_enabled",
			`vault {
				retry {
					enabled = true
				}
			}`,
			&Config{
				Vault: &VaultConfig{
					Retry: &RetryConfig{
						Enabled: Bool(true),
					},
				},
			},
			false,
		},
		{
			"vault_retry_disabled",
			`vault {
				retry {
					enabled = false
				}
			}`,
			&Config{
				Vault: &VaultConfig{
					Retry: &RetryConfig{
						Enabled: Bool(false),
					},
				},
			},
			false,
		},
		{
			"vault_retry_max_attempts",
			`vault {
				retry {
					attempts = 10
				}
			}`,
			&Config{
				Vault: &VaultConfig{
					Retry: &RetryConfig{
						Attempts: Int(10),
					},
				},
			},
			false,
		},
		{
			"vault_ssl",
			`vault {
				ssl {}
			}`,
			&Config{
				Vault: &VaultConfig{
					SSL: &SSLConfig{},
				},
			},
			false,
		},
		{
			"vault_ssl_enabled",
			`vault {
				ssl {
					enabled = true
				}
			}`,
			&Config{
				Vault: &VaultConfig{
					SSL: &SSLConfig{
						Enabled: Bool(true),
					},
				},
			},
			false,
		},
		{
			"vault_ssl_verify",
			`vault {
				ssl {
					verify = true
				}
			}`,
			&Config{
				Vault: &VaultConfig{
					SSL: &SSLConfig{
						Verify: Bool(true),
					},
				},
			},
			false,
		},
		{
			"vault_ssl_cert",
			`vault {
				ssl {
					cert = "cert"
				}
			}`,
			&Config{
				Vault: &VaultConfig{
					SSL: &SSLConfig{
						Cert: String("cert"),
					},
				},
			},
			false,
		},
		{
			"vault_ssl_key",
			`vault {
				ssl {
					key = "key"
				}
			}`,
			&Config{
				Vault: &VaultConfig{
					SSL: &SSLConfig{
						Key: String("key"),
					},
				},
			},
			false,
		},
		{
			"vault_ssl_ca_cert",
			`vault {
				ssl {
					ca_cert = "ca_cert"
				}
			}`,
			&Config{
				Vault: &VaultConfig{
					SSL: &SSLConfig{
						CaCert: String("ca_cert"),
					},
				},
			},
			false,
		},
		{
			"vault_ssl_ca_path",
			`vault {
				ssl {
					ca_path = "ca_path"
				}
			}`,
			&Config{
				Vault: &VaultConfig{
					SSL: &SSLConfig{
						CaPath: String("ca_path"),
					},
				},
			},
			false,
		},
		{
			"vault_ssl_server_name",
			`vault {
				ssl {
					server_name = "server_name"
				}
			}`,
			&Config{
				Vault: &VaultConfig{
					SSL: &SSLConfig{
						ServerName: String("server_name"),
					},
				},
			},
			false,
		},
		{
			"vault_default_lease_duration",
			`vault {
				default_lease_duration = "60s"
			}`,
			&Config{
				Vault: &VaultConfig{
					DefaultLeaseDuration: TimeDuration(60 * time.Second),
				},
			},
			false,
		},
		{
			"wait",
			`wait {
				min = "10s"
				max = "20s"
			}`,
			&Config{
				Wait: &WaitConfig{
					Min: TimeDuration(10 * time.Second),
					Max: TimeDuration(20 * time.Second),
				},
			},
			false,
		},
		{
			// Previous wait declarations used this syntax, but now use the stanza
			// syntax. Keep this around for backwards-compat.
			"wait_as_string",
			`wait = "10s:20s"`,
			&Config{
				Wait: &WaitConfig{
					Min: TimeDuration(10 * time.Second),
					Max: TimeDuration(20 * time.Second),
				},
			},
			false,
		},

		// Parse JSON file permissions as a string. There is a mapstructure
		// function for testing this, but this is double-tested because it has
		// regressed twice.
		{
			"json_file_perms",
			`{
				"template": {
					"perms": "0600"
				}
			}`,
			&Config{
				Templates: &TemplateConfigs{
					&TemplateConfig{
						Perms: FileMode(0o600),
					},
				},
			},
			false,
		},
		{
			"hcl_file_perms",
			`template {
				perms = "0600"
			}

			template {
				perms = 0600
			}`,
			&Config{
				Templates: &TemplateConfigs{
					&TemplateConfig{
						Perms: FileMode(0o600),
					},
					&TemplateConfig{
						Perms: FileMode(0o600),
					},
				},
			},
			false,
		},

		// General validation
		{
			"invalid_key",
			`not_a_valid_key = "hello"`,
			nil,
			true,
		},
		{
			"invalid_stanza",
			`not_a_valid_stanza {
				a = "b"
			}`,
			nil,
			true,
		},
		{
			"mapstructure_error",
			`consul = true`,
			nil,
			true,
		},
		{
			"nomad",
			`nomad {}`,
			&Config{
				Nomad: &NomadConfig{},
			},
			false,
		},
		{
			"nomad_address",
			`nomad {
              address = "http://10.10.10.2:4646"
            }`,
			&Config{
				Nomad: &NomadConfig{
					Address: String("http://10.10.10.2:4646"),
				},
			},
			false,
		},
		{
			"nomad_namespace",
			`nomad {
              namespace = "platform"
            }`,
			&Config{
				Nomad: &NomadConfig{
					Namespace: String("platform"),
				},
			},
			false,
		},
		{
			"nomad_token",
			`nomad {
              token = "sssssshhhhhh"
            }`,
			&Config{
				Nomad: &NomadConfig{
					Token: String("sssssshhhhhh"),
				},
			},
			false,
		},
		{
			"nomad_auth_username",
			`nomad {
              auth_username = "admin"
            }`,
			&Config{
				Nomad: &NomadConfig{
					AuthUsername: String("admin"),
				},
			},
			false,
		},
		{
			"nomad_auth_password",
			`nomad {
              auth_password = "admin"
            }`,
			&Config{
				Nomad: &NomadConfig{
					AuthPassword: String("admin"),
				},
			},
			false,
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			c, err := Parse(tc.i)
			if (err != nil) != tc.err {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(tc.e, c) {
				t.Errorf("Config diff: %s", tc.e.Diff(c))
			}
		})
	}
}

func TestFinalize(t *testing.T) {
	testFileContents := "testing123"
	testFilePath, remove := testFile(t, testFileContents)
	defer remove()

	type finalizer interface {
		Finalize()
	}

	// Testing Once disabling Wait
	cases := []struct {
		name    string
		isEqual func(*Config, *Config) (bool, error)
		test    *Config
		expt    *Config
	}{
		{
			"null-case",
			nil,
			&Config{
				Wait: &WaitConfig{
					Enabled: Bool(true),
					Min:     TimeDuration(10 * time.Second),
					Max:     TimeDuration(20 * time.Second),
				},
			},
			&Config{
				Wait: &WaitConfig{
					Enabled: Bool(true),
					Min:     TimeDuration(10 * time.Second),
					Max:     TimeDuration(20 * time.Second),
				},
			},
		},
		{
			"reload_defaults",
			func(act, exp *Config) (bool, error) {
				sv := SignalVal
				switch {
				case act == nil || exp == nil:
					return false, fmt.Errorf("bad test input")
				case sv(act.ReloadSignal) != sv(exp.ReloadSignal):
					return false, fmt.Errorf("signals don't match: %v!=%v",
						sv(act.ReloadSignal), sv(exp.ReloadSignal))
				case act.Exec == nil || exp.Exec == nil:
					return false, fmt.Errorf("Exec config should not be empty")
				case sv(act.Exec.ReloadSignal) != sv(exp.Exec.ReloadSignal):
					return false, fmt.Errorf("exec signals don't match: %v!=%v",
						sv(act.Exec.ReloadSignal), sv(exp.Exec.ReloadSignal))
				default:
					return true, nil
				}
			},
			&Config{
				ReloadSignal: nil,
				Exec:         &ExecConfig{ReloadSignal: nil},
			},
			&Config{
				ReloadSignal: Signal(DefaultReloadSignal),
				Exec:         &ExecConfig{ReloadSignal: nil},
			},
		},
		{
			"vault_agent_token_file",
			func(act, exp *Config) (bool, error) {
				actToken := *act.Vault.Token
				expToken := *exp.Vault.Token
				if actToken != expToken {
					return false, fmt.Errorf("tokens don't match: %v != %v",
						actToken, expToken)
				}
				actTokenFile := *act.Vault.VaultAgentTokenFile
				expTokenFile := *exp.Vault.VaultAgentTokenFile
				if actTokenFile != expTokenFile {
					return false, fmt.Errorf("tokenfiles don't match: %v != %v",
						actTokenFile, expTokenFile)
				}
				return true, nil
			},
			&Config{
				Vault: &VaultConfig{
					VaultAgentTokenFile: String(testFilePath),
				},
			},
			&Config{
				Vault: &VaultConfig{
					Address:             String(""),
					Namespace:           String(""),
					VaultAgentTokenFile: String(testFilePath),
					Token:               String(testFileContents),
				},
			},
		},
		{
			"once-disables-wait",
			nil,
			&Config{
				Wait: &WaitConfig{
					Enabled: Bool(true),
					Min:     TimeDuration(10 * time.Second),
					Max:     TimeDuration(20 * time.Second),
				},
				Once: true,
			},
			&Config{
				Wait: &WaitConfig{
					Enabled: Bool(false),
					Min:     nil,
					Max:     nil,
				},
			},
		},
		{
			"uid_backward_compat",
			func(act, exp *Config) (bool, error) {
				for i, tA := range *act.Templates {
					for j, tE := range *exp.Templates {
						if i != j {
							continue
						}
						userInt, _ := strconv.Atoi(*tE.User)
						if userInt != *tA.Uid {
							return false, fmt.Errorf("\nexp: %#v\nact: %#v", *tE.User, *tA.User)
						}
					}
				}
				return true, nil
			},
			&Config{
				Templates: &TemplateConfigs{
					&TemplateConfig{
						Uid: Int(1000),
					},
				},
			},
			&Config{
				Templates: &TemplateConfigs{
					&TemplateConfig{
						User: String("1000"),
					},
				},
			},
		},
		{
			"gid_backward_compat",
			func(act, exp *Config) (bool, error) {
				for i, tA := range *act.Templates {
					for j, tE := range *exp.Templates {
						if i != j {
							continue
						}
						groupInt, _ := strconv.Atoi(*tE.Group)
						if groupInt != *tA.Gid {
							return false, fmt.Errorf("\nexp: %#v\nact: %#v", *tE.Group, *tA.Group)
						}
					}
				}
				return true, nil
			},
			&Config{
				Templates: &TemplateConfigs{
					&TemplateConfig{
						Gid: Int(1000),
					},
				},
			},
			&Config{
				Templates: &TemplateConfigs{
					&TemplateConfig{
						Group: String("1000"),
					},
				},
			},
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			tc.test.Finalize()
			switch tc.isEqual {
			case nil:
				if !reflect.DeepEqual(tc.expt.Wait, tc.test.Wait) {
					t.Errorf("\nexp: %#v\nact: %#v", *tc.expt.Wait, *tc.test.Wait)
				}
			default:
				if eq, err := tc.isEqual(tc.test, tc.expt); !eq {
					t.Errorf(err.Error())
				}
			}
		})
	}
}

func TestConfig_Merge(t *testing.T) {
	cases := []struct {
		name string
		a    *Config
		b    *Config
		r    *Config
	}{
		{
			"nil_a",
			nil,
			&Config{},
			&Config{},
		},
		{
			"nil_b",
			&Config{},
			nil,
			&Config{},
		},
		{
			"nil_both",
			nil,
			nil,
			nil,
		},
		{
			"empty",
			&Config{},
			&Config{},
			&Config{},
		},
		{
			"consul",
			&Config{
				Consul: &ConsulConfig{
					Address: String("consul"),
				},
			},
			&Config{
				Consul: &ConsulConfig{
					Address: String("consul-diff"),
				},
			},
			&Config{
				Consul: &ConsulConfig{
					Address: String("consul-diff"),
				},
			},
		},
		{
			"deduplicate",
			&Config{
				Dedup: &DedupConfig{
					Enabled: Bool(true),
				},
			},
			&Config{
				Dedup: &DedupConfig{
					Enabled: Bool(false),
				},
			},
			&Config{
				Dedup: &DedupConfig{
					Enabled: Bool(false),
				},
			},
		},
		{
			"exec",
			&Config{
				Exec: &ExecConfig{
					Command: []string{"command"},
				},
			},
			&Config{
				Exec: &ExecConfig{
					Command: []string{"command-diff"},
				},
			},
			&Config{
				Exec: &ExecConfig{
					Command: []string{"command-diff"},
				},
			},
		},
		{
			"kill_signal",
			&Config{
				KillSignal: Signal(syscall.SIGUSR1),
			},
			&Config{
				KillSignal: Signal(syscall.SIGUSR2),
			},
			&Config{
				KillSignal: Signal(syscall.SIGUSR2),
			},
		},
		{
			"log_level",
			&Config{
				LogLevel: String("log_level"),
			},
			&Config{
				LogLevel: String("log_level-diff"),
			},
			&Config{
				LogLevel: String("log_level-diff"),
			},
		},
		{
			"file_log",
			&Config{
				FileLog: &LogFileConfig{
					LogFilePath: String("something.log"),
				},
			},
			&Config{
				FileLog: &LogFileConfig{
					LogFilePath: String("somethingelse.log"),
				},
			},
			&Config{
				FileLog: &LogFileConfig{
					LogFilePath: String("somethingelse.log"),
				},
			},
		},
		{
			"max_stale",
			&Config{
				MaxStale: TimeDuration(10 * time.Second),
			},
			&Config{
				MaxStale: TimeDuration(20 * time.Second),
			},
			&Config{
				MaxStale: TimeDuration(20 * time.Second),
			},
		},
		{
			"block_query_wait",
			&Config{
				BlockQueryWaitTime: TimeDuration(1 * time.Second),
			},
			&Config{
				BlockQueryWaitTime: TimeDuration(61 * time.Second),
			},
			&Config{
				BlockQueryWaitTime: TimeDuration(61 * time.Second),
			},
		},
		{
			"block_query_wait_nil",
			&Config{
				BlockQueryWaitTime: TimeDuration(1 * time.Second),
			},
			&Config{
				BlockQueryWaitTime: nil,
			},
			&Config{
				BlockQueryWaitTime: TimeDuration(1 * time.Second),
			},
		},
		{
			"pid_file",
			&Config{
				PidFile: String("pid_file"),
			},
			&Config{
				PidFile: String("pid_file-diff"),
			},
			&Config{
				PidFile: String("pid_file-diff"),
			},
		},
		{
			"reload_signal",
			&Config{
				ReloadSignal: Signal(syscall.SIGUSR1),
			},
			&Config{
				ReloadSignal: Signal(syscall.SIGUSR2),
			},
			&Config{
				ReloadSignal: Signal(syscall.SIGUSR2),
			},
		},
		{
			"syslog",
			&Config{
				Syslog: &SyslogConfig{
					Enabled: Bool(true),
				},
			},
			&Config{
				Syslog: &SyslogConfig{
					Enabled: Bool(false),
				},
			},
			&Config{
				Syslog: &SyslogConfig{
					Enabled: Bool(false),
				},
			},
		},
		{
			"template_configs",
			&Config{
				Templates: &TemplateConfigs{
					&TemplateConfig{
						Source: String("one"),
					},
				},
			},
			&Config{
				Templates: &TemplateConfigs{
					&TemplateConfig{
						Source: String("two"),
					},
				},
			},
			&Config{
				Templates: &TemplateConfigs{
					&TemplateConfig{
						Source: String("one"),
					},
					&TemplateConfig{
						Source: String("two"),
					},
				},
			},
		},
		{
			"vault",
			&Config{
				Vault: &VaultConfig{
					Enabled: Bool(true),
				},
			},
			&Config{
				Vault: &VaultConfig{
					Enabled: Bool(false),
				},
			},
			&Config{
				Vault: &VaultConfig{
					Enabled: Bool(false),
				},
			},
		},
		{
			"wait",
			&Config{
				Wait: &WaitConfig{
					Min: TimeDuration(10 * time.Second),
					Max: TimeDuration(20 * time.Second),
				},
			},
			&Config{
				Wait: &WaitConfig{
					Min: TimeDuration(20 * time.Second),
					Max: TimeDuration(50 * time.Second),
				},
			},
			&Config{
				Wait: &WaitConfig{
					Min: TimeDuration(20 * time.Second),
					Max: TimeDuration(50 * time.Second),
				},
			},
		},
		{
			"parse-only",
			&Config{
				ParseOnly: false,
			},
			&Config{
				ParseOnly: true,
			},
			&Config{
				ParseOnly: true,
			},
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			r := tc.a.Merge(tc.b)
			if !reflect.DeepEqual(tc.r, r) {
				t.Errorf("Config diff: %s", tc.r.Diff(r))
			}
		})
	}
}

func TestFromPath(t *testing.T) {
	f, err := os.CreateTemp("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())

	emptyDir, err := os.MkdirTemp(os.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(emptyDir)

	configDir, err := os.MkdirTemp(os.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(configDir)
	cf1, err := os.CreateTemp(configDir, "")
	if err != nil {
		t.Fatal(err)
	}
	d := []byte(`
		consul {
			address = "1.2.3.4"
		}
	`)
	if err = os.WriteFile(cf1.Name(), d, 0o644); err != nil {
		t.Fatal(err)
	}
	cf2, err := os.CreateTemp(configDir, "")
	if err != nil {
		t.Fatal(err)
	}
	d = []byte(`
		consul {
			token = "token"
		}
	`)
	if err := os.WriteFile(cf2.Name(), d, 0o644); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		path string
		e    *Config
		err  bool
	}{
		{
			"missing_dir",
			"/not/a/real/dir",
			nil,
			true,
		},
		{
			"file",
			f.Name(),
			&Config{},
			false,
		},
		{
			"empty_dir",
			emptyDir,
			nil,
			false,
		},
		{
			"config_dir",
			configDir,
			&Config{
				Consul: &ConsulConfig{
					Address: String("1.2.3.4"),
					Token:   String("token"),
				},
			},
			false,
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			c, err := FromPath(tc.path)
			if (err != nil) != tc.err {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(tc.e, c) {
				t.Errorf("\nexp: %#v\nact: %#v", tc.e, c)
			}
		})
	}
}

func TestDefaultConfig(t *testing.T) {
	// Can't use t.Parallel() as this sets/unsets environment variables
	cases := []struct {
		env string
		val string
		e   *Config
		err bool
	}{
		{
			"CONSUL_HTTP_ADDR",
			"1.2.3.4",
			&Config{
				Consul: &ConsulConfig{
					Address: String("1.2.3.4"),
				},
			},
			false,
		},
		{
			"CONSUL_TEMPLATE_LOG_LEVEL",
			"DEBUG",
			&Config{
				LogLevel: String("DEBUG"),
			},
			false,
		},
		{
			"CONSUL_TOKEN",
			"token",
			&Config{
				Consul: &ConsulConfig{
					Token: String("token"),
				},
			},
			false,
		},
		{
			"VAULT_ADDR",
			"http://1.2.3.4:8200",
			&Config{
				Vault: &VaultConfig{
					Address: String("http://1.2.3.4:8200"),
				},
			},
			false,
		},
		{
			"VAULT_TOKEN",
			"abcd1234",
			&Config{
				Vault: &VaultConfig{
					Token: String("abcd1234"),
				},
			},
			false,
		},
		{
			"VAULT_UNWRAP_TOKEN",
			"true",
			&Config{
				Vault: &VaultConfig{
					UnwrapToken: Bool(true),
				},
			},
			false,
		},
		{
			"VAULT_UNWRAP_TOKEN",
			"false",
			&Config{
				Vault: &VaultConfig{
					UnwrapToken: Bool(false),
				},
			},
			false,
		},
		{
			api.EnvVaultCAPath,
			"ca_path",
			&Config{
				Vault: &VaultConfig{
					SSL: &SSLConfig{
						CaPath: String("ca_path"),
					},
				},
			},
			false,
		},
		{
			api.EnvVaultCACert,
			"ca_cert",
			&Config{
				Vault: &VaultConfig{
					SSL: &SSLConfig{
						CaCert: String("ca_cert"),
					},
				},
			},
			false,
		},
		{
			api.EnvVaultTLSServerName,
			"server_name",
			&Config{
				Vault: &VaultConfig{
					SSL: &SSLConfig{
						ServerName: String("server_name"),
					},
				},
			},
			false,
		},
		{
			"VAULT_K8S_AUTH_ROLE_NAME",
			"VAULT_K8S_AUTH_ROLE_NAME",
			&Config{
				Vault: &VaultConfig{
					K8SAuthRoleName: String("VAULT_K8S_AUTH_ROLE_NAME"),
				},
			},
			false,
		},
		{
			"VAULT_K8S_SERVICE_ACCOUNT_TOKEN",
			"VAULT_K8S_SERVICE_ACCOUNT_TOKEN",
			&Config{
				Vault: &VaultConfig{
					K8SServiceAccountToken: String("VAULT_K8S_SERVICE_ACCOUNT_TOKEN"),
				},
			},
			false,
		},
		{
			"VAULT_K8S_SERVICE_ACCOUNT_TOKEN_PATH",
			"VAULT_K8S_SERVICE_ACCOUNT_TOKEN_PATH",
			&Config{
				Vault: &VaultConfig{
					K8SServiceAccountTokenPath: String("VAULT_K8S_SERVICE_ACCOUNT_TOKEN_PATH"),
				},
			},
			false,
		},
		{
			"VAULT_K8S_SERVICE_MOUNT_PATH",
			"VAULT_K8S_SERVICE_MOUNT_PATH",
			&Config{
				Vault: &VaultConfig{
					K8SServiceMountPath: String("VAULT_K8S_SERVICE_MOUNT_PATH"),
				},
			},
			false,
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.env), func(t *testing.T) {
			r := DefaultConfig().Merge(tc.e)
			r.Finalize()

			t.Setenv(tc.env, tc.val)
			c := DefaultConfig()
			c.Finalize()

			if !reflect.DeepEqual(r, c) {
				t.Errorf("Config diff: %s", r.Diff(c))
			}
		})
	}
}
