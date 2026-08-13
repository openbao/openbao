// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package server

import (
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/stretchr/testify/require"
)

func TestPluginConfigParsing(t *testing.T) {
	configData := `
storage "inmem" {}

listener "tcp" {
  address = "127.0.0.1:8200"
  tls_disable = true
}

plugin_directory = "/opt/openbao/plugins"

plugin "secret" "aws" {
  image = "ghcr.io/openbao/openbao-plugin-secrets-aws"
  version = "v0.0.1"
  binary_name = "openbao-plugin-secrets-aws"
  sha256sum = "9fdd8be7947e4a4caf7cce4f0e02695081b6c85178aa912df5d37be97363144c"
}

plugin "auth" "gcp" {
  image = "ghcr.io/openbao/openbao-plugin-auth-gcp"
  version = "v0.21.0"
  sha256sum = "f586717376b20763b3ecef0412cdd6cbb4f8295b9679da4bfa4e1f75b8e00a63"
}

plugin "kms" "pkcs11" {
  image = "ghcr.io/openbao/openbao-plugin-kms-pkcs11@sha256:ba3229ef91ab1040122d1389f9d015f3f211076835cf6914977c09d3697b4697"
  version = "v0.1.0"
}

plugin "kms" "ovhcloud" {
  image = "ghcr.io/openbao/openbao-plugin-kms-ovhcloud:v0.0.1@sha256:0ac993bbd5589845ef0b60f9b106ebadf82903de8bccaafce8abb04d7094d9ed"
}

plugin_download_behavior = "fail"
`

	config, err := ParseConfig(configData, "test")
	require.NoError(t, err)

	require.Equal(t, "/opt/openbao/plugins", config.PluginDirectory)
	require.Equal(t, config.PluginDownloadBehavior, "fail")

	for _, c := range config.Plugins {
		c.RawImage = ""
	}

	require.Equal(t, config.Plugins, []*PluginConfig{
		{
			Type:       "secret",
			Name:       "aws",
			Version:    "v0.0.1",
			BinaryName: "openbao-plugin-secrets-aws",
			SHA256Sum:  "9fdd8be7947e4a4caf7cce4f0e02695081b6c85178aa912df5d37be97363144c",
			Image:      name.MustParseReference("ghcr.io/openbao/openbao-plugin-secrets-aws", name.WithDefaultTag("v0.0.1")),
		},
		{
			Type:      "auth",
			Name:      "gcp",
			Version:   "v0.21.0",
			SHA256Sum: "f586717376b20763b3ecef0412cdd6cbb4f8295b9679da4bfa4e1f75b8e00a63",
			Image:     name.MustParseReference("ghcr.io/openbao/openbao-plugin-auth-gcp", name.WithDefaultTag("v0.21.0")),
		},
		{
			Type:    "kms",
			Name:    "pkcs11",
			Version: "v0.1.0",
			Image:   name.MustParseReference("ghcr.io/openbao/openbao-plugin-kms-pkcs11@sha256:ba3229ef91ab1040122d1389f9d015f3f211076835cf6914977c09d3697b4697"),
		},
		{
			Type:    "kms",
			Name:    "ovhcloud",
			Version: "v0.0.1",
			Image:   name.MustParseReference("ghcr.io/openbao/openbao-plugin-kms-ovhcloud:v0.0.1@sha256:0ac993bbd5589845ef0b60f9b106ebadf82903de8bccaafce8abb04d7094d9ed"),
		},
	})

	errors := config.Validate("test")
	for _, err := range errors {
		require.NoError(t, err)
	}
}

func TestPluginConfigValidation(t *testing.T) {
	tests := []struct {
		name        string
		configData  string
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid config with sha256sum",
			configData: `
storage "inmem" {}
listener "tcp" { 
  address = "127.0.0.1:8200"
  tls_disable = true 
}
plugin "secret" "aws" {
  image = "ghcr.io/openbao/openbao-plugin-secrets-aws"
  version = "v0.0.1"
  binary_name = "openbao-plugin-secrets-aws"
  sha256sum = "9fdd8be7947e4a4caf7cce4f0e02695081b6c85178aa912df5d37be97363144c"
}`,
			expectError: false,
		},
		{
			name: "valid config with manifest digest",
			configData: `
storage "inmem" {}
listener "tcp" {
  address = "127.0.0.1:8200"
  tls_disable = true
}
plugin "secret" "aws" {
  image = "ghcr.io/openbao/openbao-plugin-secrets-aws@sha256:9fdd8be7947e4a4caf7cce4f0e02695081b6c85178aa912df5d37be97363144c"
  version = "v0.0.1"
}`,
			expectError: false,
		},
		{
			name: "missing url",
			configData: `
storage "inmem" {}
listener "tcp" {
  address = "127.0.0.1:8200"
  tls_disable = true
}
plugin "secret" "aws" {
  version = "v0.0.1"
  binary_name = "openbao-plugin-secrets-aws"
  sha256sum = "9fdd8be7947e4a4caf7cce4f0e02695081b6c85178aa912df5d37be97363144c"
}`,
			expectError: true,
			errorMsg:    "image and command cannot both be empty",
		},
		{
			name: "missing sha256sum or manifest digest",
			configData: `
storage "inmem" {}
listener "tcp" {
  address = "127.0.0.1:8200"
  tls_disable = true
}
plugin "secret" "aws" {
  image = "ghcr.io/openbao/openbao-plugin-secrets-aws"
  version = "v0.0.1"
}`,
			expectError: true,
			errorMsg:    "sha256sum must be set if image is not pinned by digest",
		},
		{
			name: "invalid sha256sum length",
			configData: `
storage "inmem" {}
listener "tcp" {
  address = "127.0.0.1:8200"
  tls_disable = true
}
plugin "secret" "aws" {
  image = "ghcr.io/openbao/openbao-plugin-secrets-aws"
  version = "v0.0.1:v0.0.1"
  binary_name = "openbao-plugin-secrets-aws"
  sha256sum = "9fdd8be7947e4a4caf7cce4"
}`,
			expectError: true,
			errorMsg:    "sha256sum must be exactly 64 characters",
		},
		{
			name: "invalid sha256sum characters",
			configData: `
storage "inmem" {}
listener "tcp" {
  address = "127.0.0.1:8200"
  tls_disable = true
}
plugin "secret" "aws" {
  image = "ghcr.io/openbao/openbao-plugin-secrets-aws"
  version = "v0.0.1:v0.0.1"
  binary_name = "openbao-plugin-secrets-aws"
  sha256sum = "gfdd8be7947e4a4caf7cce4f0e02695081b6c85178aa912df5d37be97363144c"
}`,
			expectError: true,
			errorMsg:    "sha256sum is not valid hex encoded",
		},
		{
			name: "invalid download behavior",
			configData: `
storage "inmem" {}
listener "tcp" {
  address = "127.0.0.1:8200"
  tls_disable = true
}
plugin_download_behavior = "invalid_value"`,
			expectError: true,
			errorMsg:    "must be either \"fail\" or \"continue\"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config, err := ParseConfig(tt.configData, "test")
			if err != nil {
				t.Fatalf("Error parsing config: %v", err)
			}

			errors := config.Validate("test")
			hasError := len(errors) > 0

			if hasError != tt.expectError {
				if tt.expectError {
					t.Errorf("Expected validation error but got none")
				} else {
					t.Errorf("Unexpected validation errors:")
					for _, err := range errors {
						t.Errorf("  %s", err.String())
					}
				}
			}

			if tt.expectError && tt.errorMsg != "" {
				found := false
				for _, err := range errors {
					if strings.Contains(err.Problem, tt.errorMsg) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected error message containing '%s', but didn't find it in:", tt.errorMsg)
					for _, err := range errors {
						t.Errorf("  %s", err.String())
					}
				}
			}
		})
	}
}
