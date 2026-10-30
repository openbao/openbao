// Copyright (c) OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package dbtlsutil

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDecode(t *testing.T) {
	t.Run("use_tls enables system-root TLS", func(t *testing.T) {
		config, err := Decode(map[string]any{"use_tls": true})
		require.NoError(t, err)
		require.True(t, config.Configured())
	})

	t.Run("requires complete client identity", func(t *testing.T) {
		_, err := Decode(map[string]any{"tls_certificate": "certificate"})
		require.EqualError(t, err, "both tls_certificate and tls_key are required for mutual TLS")
	})

	t.Run("decodes verification settings", func(t *testing.T) {
		config, err := Decode(map[string]any{
			"tls_server_name": "database.example.com",
			"insecure":        true,
		})
		require.NoError(t, err)
		require.True(t, config.Configured())

		tlsConfig, err := config.Build("fallback.example.com")
		require.NoError(t, err)
		require.Equal(t, "database.example.com", tlsConfig.ServerName)
		require.True(t, tlsConfig.InsecureSkipVerify)
	})
}

func TestBuildRejectsInvalidPEM(t *testing.T) {
	config := Config{CA: "not PEM"}
	_, err := config.Build("database.example.com")
	require.EqualError(t, err, "failed to parse tls_ca PEM")
}
