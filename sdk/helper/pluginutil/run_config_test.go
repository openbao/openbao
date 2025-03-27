// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package pluginutil

import (
	"context"
	"fmt"
	"os/exec"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/sdk/v2/helper/wrapping"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestMakeConfig(t *testing.T) {
	type testCase struct {
		rc runConfig

		responseWrapInfo      *wrapping.ResponseWrapInfo
		responseWrapInfoErr   error
		responseWrapInfoTimes int

		mlockEnabled      bool
		mlockEnabledTimes int

		expectedConfig  *plugin.ClientConfig
		expectTLSConfig bool
	}

	tests := map[string]testCase{
		"metadata mode, not-AutoMTLS": {
			rc: runConfig{
				command: "echo",
				args:    []string{"foo", "bar"},
				sha256:  []byte("some_sha256"),
				env:     []string{"initial=true"},
				PluginClientConfig: PluginClientConfig{
					PluginSets: map[int]plugin.PluginSet{
						1: {
							"bogus": nil,
						},
					},
					HandshakeConfig: plugin.HandshakeConfig{
						ProtocolVersion:  1,
						MagicCookieKey:   "magic_cookie_key",
						MagicCookieValue: "magic_cookie_value",
					},
					Logger:         hclog.NewNullLogger(),
					IsMetadataMode: true,
					AutoMTLS:       false,
				},
			},

			responseWrapInfoTimes: 0,

			mlockEnabled:      false,
			mlockEnabledTimes: 1,

			expectedConfig: &plugin.ClientConfig{
				HandshakeConfig: plugin.HandshakeConfig{
					ProtocolVersion:  1,
					MagicCookieKey:   "magic_cookie_key",
					MagicCookieValue: "magic_cookie_value",
				},
				VersionedPlugins: map[int]plugin.PluginSet{
					1: {
						"bogus": nil,
					},
				},
				Cmd: commandWithEnv(
					"echo",
					[]string{"foo", "bar"},
					[]string{
						"initial=true",
						fmt.Sprintf("%s=%s", PluginVaultVersionEnv, "dummyversion"),
						fmt.Sprintf("%s=%s", api.UpstreamVariableName(PluginVaultVersionEnv), "dummyversion"),
						fmt.Sprintf("%s=%t", PluginMetadataModeEnv, true),
						fmt.Sprintf("%s=%t", api.UpstreamVariableName(PluginMetadataModeEnv), true),
						fmt.Sprintf("%s=%t", PluginAutoMTLSEnv, false),
						fmt.Sprintf("%s=%t", api.UpstreamVariableName(PluginAutoMTLSEnv), false),
					},
				),
				SecureConfig: &plugin.SecureConfig{
					Checksum: []byte("some_sha256"),
					// Hash is generated
				},
				AllowedProtocols: []plugin.Protocol{
					plugin.ProtocolGRPC,
				},
				Logger:   hclog.NewNullLogger(),
				AutoMTLS: false,
			},
			expectTLSConfig: false,
		},
		"non-metadata mode, not-AutoMTLS": {
			rc: runConfig{
				command: "echo",
				args:    []string{"foo", "bar"},
				sha256:  []byte("some_sha256"),
				env:     []string{"initial=true"},
				PluginClientConfig: PluginClientConfig{
					PluginSets: map[int]plugin.PluginSet{
						1: {
							"bogus": nil,
						},
					},
					HandshakeConfig: plugin.HandshakeConfig{
						ProtocolVersion:  1,
						MagicCookieKey:   "magic_cookie_key",
						MagicCookieValue: "magic_cookie_value",
					},
					Logger:         hclog.NewNullLogger(),
					IsMetadataMode: false,
					AutoMTLS:       false,
				},
			},

			responseWrapInfo: &wrapping.ResponseWrapInfo{
				Token: "testtoken",
			},
			responseWrapInfoTimes: 1,

			mlockEnabled:      true,
			mlockEnabledTimes: 1,

			expectedConfig: &plugin.ClientConfig{
				HandshakeConfig: plugin.HandshakeConfig{
					ProtocolVersion:  1,
					MagicCookieKey:   "magic_cookie_key",
					MagicCookieValue: "magic_cookie_value",
				},
				VersionedPlugins: map[int]plugin.PluginSet{
					1: {
						"bogus": nil,
					},
				},
				Cmd: commandWithEnv(
					"echo",
					[]string{"foo", "bar"},
					[]string{
						"initial=true",
						fmt.Sprintf("%s=%t", PluginMlockEnabled, true),
						fmt.Sprintf("%s=%t", api.UpstreamVariableName(PluginMlockEnabled), true),
						fmt.Sprintf("%s=%s", PluginVaultVersionEnv, "dummyversion"),
						fmt.Sprintf("%s=%s", api.UpstreamVariableName(PluginVaultVersionEnv), "dummyversion"),
						fmt.Sprintf("%s=%t", PluginMetadataModeEnv, false),
						fmt.Sprintf("%s=%t", api.UpstreamVariableName(PluginMetadataModeEnv), false),
						fmt.Sprintf("%s=%t", PluginAutoMTLSEnv, false),
						fmt.Sprintf("%s=%t", api.UpstreamVariableName(PluginAutoMTLSEnv), false),
						fmt.Sprintf("%s=%s", PluginUnwrapTokenEnv, "testtoken"),
						fmt.Sprintf("%s=%s", api.UpstreamVariableName(PluginUnwrapTokenEnv), "testtoken"),
					},
				),
				SecureConfig: &plugin.SecureConfig{
					Checksum: []byte("some_sha256"),
					// Hash is generated
				},
				AllowedProtocols: []plugin.Protocol{
					plugin.ProtocolGRPC,
				},
				Logger:   hclog.NewNullLogger(),
				AutoMTLS: false,
			},
			expectTLSConfig: true,
		},
		"metadata mode, AutoMTLS": {
			rc: runConfig{
				command: "echo",
				args:    []string{"foo", "bar"},
				sha256:  []byte("some_sha256"),
				env:     []string{"initial=true"},
				PluginClientConfig: PluginClientConfig{
					PluginSets: map[int]plugin.PluginSet{
						1: {
							"bogus": nil,
						},
					},
					HandshakeConfig: plugin.HandshakeConfig{
						ProtocolVersion:  1,
						MagicCookieKey:   "magic_cookie_key",
						MagicCookieValue: "magic_cookie_value",
					},
					Logger:         hclog.NewNullLogger(),
					IsMetadataMode: true,
					AutoMTLS:       true,
				},
			},

			responseWrapInfoTimes: 0,

			mlockEnabled:      false,
			mlockEnabledTimes: 1,

			expectedConfig: &plugin.ClientConfig{
				HandshakeConfig: plugin.HandshakeConfig{
					ProtocolVersion:  1,
					MagicCookieKey:   "magic_cookie_key",
					MagicCookieValue: "magic_cookie_value",
				},
				VersionedPlugins: map[int]plugin.PluginSet{
					1: {
						"bogus": nil,
					},
				},
				Cmd: commandWithEnv(
					"echo",
					[]string{"foo", "bar"},
					[]string{
						"initial=true",
						fmt.Sprintf("%s=%s", PluginVaultVersionEnv, "dummyversion"),
						fmt.Sprintf("%s=%s", api.UpstreamVariableName(PluginVaultVersionEnv), "dummyversion"),
						fmt.Sprintf("%s=%t", PluginMetadataModeEnv, true),
						fmt.Sprintf("%s=%t", api.UpstreamVariableName(PluginMetadataModeEnv), true),
						fmt.Sprintf("%s=%t", PluginAutoMTLSEnv, true),
						fmt.Sprintf("%s=%t", api.UpstreamVariableName(PluginAutoMTLSEnv), true),
					},
				),
				SecureConfig: &plugin.SecureConfig{
					Checksum: []byte("some_sha256"),
					// Hash is generated
				},
				AllowedProtocols: []plugin.Protocol{
					plugin.ProtocolGRPC,
				},
				Logger:   hclog.NewNullLogger(),
				AutoMTLS: true,
			},
			expectTLSConfig: false,
		},
		"not-metadata mode, AutoMTLS": {
			rc: runConfig{
				command: "echo",
				args:    []string{"foo", "bar"},
				sha256:  []byte("some_sha256"),
				env:     []string{"initial=true"},
				PluginClientConfig: PluginClientConfig{
					PluginSets: map[int]plugin.PluginSet{
						1: {
							"bogus": nil,
						},
					},
					HandshakeConfig: plugin.HandshakeConfig{
						ProtocolVersion:  1,
						MagicCookieKey:   "magic_cookie_key",
						MagicCookieValue: "magic_cookie_value",
					},
					Logger:         hclog.NewNullLogger(),
					IsMetadataMode: false,
					AutoMTLS:       true,
				},
			},

			responseWrapInfoTimes: 0,

			mlockEnabled:      false,
			mlockEnabledTimes: 1,

			expectedConfig: &plugin.ClientConfig{
				HandshakeConfig: plugin.HandshakeConfig{
					ProtocolVersion:  1,
					MagicCookieKey:   "magic_cookie_key",
					MagicCookieValue: "magic_cookie_value",
				},
				VersionedPlugins: map[int]plugin.PluginSet{
					1: {
						"bogus": nil,
					},
				},
				Cmd: commandWithEnv(
					"echo",
					[]string{"foo", "bar"},
					[]string{
						"initial=true",
						fmt.Sprintf("%s=%s", PluginVaultVersionEnv, "dummyversion"),
						fmt.Sprintf("%s=%s", api.UpstreamVariableName(PluginVaultVersionEnv), "dummyversion"),
						fmt.Sprintf("%s=%t", PluginMetadataModeEnv, false),
						fmt.Sprintf("%s=%t", api.UpstreamVariableName(PluginMetadataModeEnv), false),
						fmt.Sprintf("%s=%t", PluginAutoMTLSEnv, true),
						fmt.Sprintf("%s=%t", api.UpstreamVariableName(PluginAutoMTLSEnv), true),
					},
				),
				SecureConfig: &plugin.SecureConfig{
					Checksum: []byte("some_sha256"),
					// Hash is generated
				},
				AllowedProtocols: []plugin.Protocol{
					plugin.ProtocolGRPC,
				},
				Logger:   hclog.NewNullLogger(),
				AutoMTLS: true,
			},
			expectTLSConfig: false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			mockWrapper := new(mockRunnerUtil)
			mockWrapper.On("ResponseWrapData", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
				Return(test.responseWrapInfo, test.responseWrapInfoErr)
			mockWrapper.On("MlockEnabled").
				Return(test.mlockEnabled)
			test.rc.Wrapper = mockWrapper
			defer mockWrapper.AssertNumberOfCalls(t, "ResponseWrapData", test.responseWrapInfoTimes)
			defer mockWrapper.AssertNumberOfCalls(t, "MlockEnabled", test.mlockEnabledTimes)

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			config, err := test.rc.makeConfig(ctx)
			if err != nil {
				t.Fatalf("no error expected, got: %s", err)
			}

			// The following fields are generated, so we just need to check for existence, not specific value
			// The value must be nilled out before performing a DeepEqual check
			hsh := config.SecureConfig.Hash
			if hsh == nil {
				t.Fatal("Missing SecureConfig.Hash")
			}
			config.SecureConfig.Hash = nil

			if test.expectTLSConfig && config.TLSConfig == nil {
				t.Fatal("TLS config expected, got nil")
			}
			if !test.expectTLSConfig && config.TLSConfig != nil {
				t.Fatalf("no TLS config expected, got: %#v", config.TLSConfig)
			}
			config.TLSConfig = nil

			require.Equal(t, test.expectedConfig, config)
		})
	}
}

func commandWithEnv(cmd string, args []string, env []string) *exec.Cmd {
	c := exec.Command(cmd, args...)
	c.Env = env
	return c
}

var _ RunnerUtil = &mockRunnerUtil{}

type mockRunnerUtil struct {
	mock.Mock
}

func (m *mockRunnerUtil) VaultVersion(ctx context.Context) (string, error) {
	return "dummyversion", nil
}

func (m *mockRunnerUtil) NewPluginClient(ctx context.Context, config PluginClientConfig) (PluginClient, error) {
	args := m.Called(ctx, config)
	return args.Get(0).(PluginClient), args.Error(1)
}

func (m *mockRunnerUtil) ResponseWrapData(ctx context.Context, data map[string]interface{}, ttl time.Duration, jwt bool) (*wrapping.ResponseWrapInfo, error) {
	args := m.Called(ctx, data, ttl, jwt)
	return args.Get(0).(*wrapping.ResponseWrapInfo), args.Error(1)
}

func (m *mockRunnerUtil) MlockEnabled() bool {
	args := m.Called()
	return args.Bool(0)
}
