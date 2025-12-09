// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package server

import (
	"strings"
	"testing"
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
  binary_name = "openbao-plugin-auth-gcp"
  sha256sum = "f586717376b20763b3ecef0412cdd6cbb4f8295b9679da4bfa4e1f75b8e00a63"
}

plugin_download_behavior = "fail"
`

	config, err := ParseConfig(configData, "test")
	if err != nil {
		t.Fatalf("Error parsing config: %v", err)
	}

	// Test plugin directory
	if config.PluginDirectory != "/opt/openbao/plugins" {
		t.Errorf("Expected plugin directory '/opt/openbao/plugins', got '%s'", config.PluginDirectory)
	}

	// Test plugin download behavior
	if config.PluginDownloadBehavior != "fail" {
		t.Errorf("Expected plugin download behavior 'fail', got '%s'", config.PluginDownloadBehavior)
	}

	// Test plugins
	if len(config.Plugins) != 2 {
		t.Fatalf("Expected 2 plugins, got %d", len(config.Plugins))
	}

	awsPlugin := config.Plugins[0]
	if awsPlugin.Slug() != "secret-aws" {
		t.Fatal("secret-aws plugin not found")
	}

	if awsPlugin.URL() != "ghcr.io/openbao/openbao-plugin-secrets-aws:v0.0.1" {
		t.Errorf("Expected AWS plugin URL 'ghcr.io/openbao/openbao-plugin-secrets-aws:v0.0.1', got '%s'", awsPlugin.URL())
	}
	if awsPlugin.BinaryName != "openbao-plugin-secrets-aws" {
		t.Errorf("Expected AWS plugin binary 'openbao-plugin-secrets-aws', got '%s'", awsPlugin.BinaryName)
	}
	if awsPlugin.SHA256Sum != "9fdd8be7947e4a4caf7cce4f0e02695081b6c85178aa912df5d37be97363144c" {
		t.Errorf("Expected AWS plugin SHA256 '9fdd8be7947e4a4caf7cce4f0e02695081b6c85178aa912df5d37be97363144c', got '%s'", awsPlugin.SHA256Sum)
	}

	// Test validation
	errors := config.Validate("test")
	if len(errors) > 0 {
		t.Errorf("Validation failed with errors:")
		for _, err := range errors {
			t.Errorf("  %s", err.String())
		}
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
			name: "valid config",
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
			name: "invalid url",
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
  sha256sum = "9fdd8be7947e4a4caf7cce4f0e02695081b6c85178aa912df5d37be97363144c"
}`,
			expectError: true,
			errorMsg:    "image and version do not form a valid image reference",
		},
		{
			name: "missing binary_name",
			configData: `
storage "inmem" {}
listener "tcp" { 
  address = "127.0.0.1:8200"
  tls_disable = true 
}
plugin "secret" "aws" {
  image = "ghcr.io/openbao/openbao-plugin-secrets-aws"
  version = "v0.0.1"
  sha256sum = "9fdd8be7947e4a4caf7cce4f0e02695081b6c85178aa912df5d37be97363144c"
}`,
			expectError: true,
			errorMsg:    "binary_name cannot be empty",
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
