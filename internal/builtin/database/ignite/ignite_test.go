// Copyright (c) AppsCode Inc.
// SPDX-License-Identifier: MPL-2.0

package ignite

import (
	"os"
	"testing"

	dbplugin "github.com/openbao/openbao/sdk/v2/database/dbplugin/v5"
	"github.com/openbao/openbao/sdk/v2/database/helper/dbutil"
	"github.com/openbao/openbao/v2/internal/helper/dbtlsutil"
	"github.com/stretchr/testify/require"
)

func TestIgnite_TypeAndVersion(t *testing.T) {
	db := newIgnite()
	typ, err := db.Type()
	require.NoError(t, err)
	require.Equal(t, igniteTypeName, typ)
	require.Equal(t, ReportedVersion, db.PluginVersion().Version)
}

func TestIgnite_SafeIdentifier(t *testing.T) {
	require.NoError(t, safeIdentifier("V_TEST_TEST"))
	require.Error(t, safeIdentifier(""))
	require.Error(t, safeIdentifier(`bad"quote`))
	require.Error(t, safeIdentifier("bad'quote"))
	require.Error(t, safeIdentifier("bad;semi"))
}

func TestIgnite_SafePassword(t *testing.T) {
	require.NoError(t, safePassword("BaoIgnite-1234"))
	require.Error(t, safePassword(""))
	require.Error(t, safePassword("bad'quote"))
}

func TestIgnite_RenderTemplate(t *testing.T) {
	out := renderTemplate(`CREATE USER "{{name}}" WITH PASSWORD '{{password}}'`,
		map[string]string{"name": "V_T", "password": "pw"})
	require.Equal(t, `CREATE USER "V_T" WITH PASSWORD 'pw'`, out)
}

func TestIgnite_NormalizeTarget(t *testing.T) {
	// url only: host parsed, default port applied
	cfg := &igniteConfig{URL: "http://ignite.ignite-kubevault-test.svc"}
	require.NoError(t, normalizeTarget(cfg))
	require.Equal(t, "ignite.ignite-kubevault-test.svc", cfg.Host)
	require.Equal(t, defaultPort, cfg.Port)

	// url with explicit port wins over default
	cfg = &igniteConfig{URL: "tcp://ignite:10801"}
	require.NoError(t, normalizeTarget(cfg))
	require.Equal(t, "ignite", cfg.Host)
	require.Equal(t, 10801, cfg.Port)

	// explicit host/port override url entirely
	cfg = &igniteConfig{URL: "http://ignored:1", Host: "real", Port: 1234}
	require.NoError(t, normalizeTarget(cfg))
	require.Equal(t, "real", cfg.Host)
	require.Equal(t, 1234, cfg.Port)

	// nothing provided
	require.Error(t, normalizeTarget(&igniteConfig{}))

	// bad port in url
	require.Error(t, normalizeTarget(&igniteConfig{URL: "http://host:notaport"}))

	// unparseable url
	require.Error(t, normalizeTarget(&igniteConfig{URL: "://bad"}))
}

func TestIgnite_InitializeRequiresCredentials(t *testing.T) {
	db := newIgnite()
	_, err := db.Initialize(t.Context(), dbplugin.InitializeRequest{
		Config: map[string]any{"url": "http://ignite:10800"},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "username and password are required")
}

func TestIgnite_InitializePlaintextConfig(t *testing.T) {
	db := newIgnite()
	resp, err := db.Initialize(t.Context(), dbplugin.InitializeRequest{
		Config: map[string]any{
			"url":      "tcp://ignite:10800",
			"username": "ignite",
			"password": "password",
		},
	})
	require.NoError(t, err)
	require.NotNil(t, resp.Config)
	require.False(t, db.config.tlsConfigured())
}

func TestIgnite_NewUserRequiresStatements(t *testing.T) {
	db := newIgnite()
	_, err := db.NewUser(t.Context(), dbplugin.NewUserRequest{
		UsernameConfig: dbplugin.UsernameMetadata{DisplayName: "t", RoleName: "t"},
	})
	require.ErrorIs(t, err, dbutil.ErrEmptyCreationStatement)
}

// TestIgnite_Acceptance runs against a real Ignite cluster with
// authentication enabled. Set BAO_ACC=1 and IGNITE_ADDR (host:port of
// the thin client listener), plus IGNITE_USER/IGNITE_PASSWORD.
func TestIgnite_Acceptance(t *testing.T) {
	addr := os.Getenv("IGNITE_ADDR")
	if os.Getenv("BAO_ACC") != "1" || addr == "" {
		t.Skip("set BAO_ACC=1 and IGNITE_ADDR to run Ignite acceptance tests")
	}
	user := os.Getenv("IGNITE_USER")
	pass := os.Getenv("IGNITE_PASSWORD")

	cfg := map[string]any{
		"url":      "tcp://" + addr,
		"username": user,
		"password": pass,
	}
	if v := os.Getenv("IGNITE_CA_CERT"); v != "" {
		cfg["tls_ca"] = v
	}
	if v := os.Getenv("IGNITE_INSECURE"); v != "" {
		cfg["tls_skip_verify"] = true
	}

	db := newIgnite()
	_, err := db.Initialize(t.Context(), dbplugin.InitializeRequest{
		Config:           cfg,
		VerifyConnection: true,
	})
	require.NoError(t, err)
	defer db.Close() //nolint:errcheck

	resp, err := db.NewUser(t.Context(), dbplugin.NewUserRequest{
		UsernameConfig: dbplugin.UsernameMetadata{DisplayName: "acc", RoleName: "acc"},
		Statements: dbplugin.Statements{
			Commands: []string{`CREATE USER "{{name}}" WITH PASSWORD '{{password}}';`},
		},
		Password: "BaoAccPass-1234",
	})
	require.NoError(t, err)
	require.Regexp(t, `^V_[A-Z0-9_]+$`, resp.Username)

	_, err = db.UpdateUser(t.Context(), dbplugin.UpdateUserRequest{
		Username: resp.Username,
		Password: &dbplugin.ChangePassword{NewPassword: "NewAccPass-5678"},
	})
	require.NoError(t, err)

	_, err = db.DeleteUser(t.Context(), dbplugin.DeleteUserRequest{Username: resp.Username})
	require.NoError(t, err)
}

func TestIgnite_BuildTLSConfig(t *testing.T) {
	t.Run("plaintext by default when no TLS options provided", func(t *testing.T) {
		cfg := &igniteConfig{Host: "ignite.example.com", Port: 10800}
		tlsCfg, err := buildTLSConfig(cfg)
		require.NoError(t, err)
		require.Nil(t, tlsCfg, "expected nil tls.Config when TLS was not requested")
	})

	t.Run("nil config returns nil", func(t *testing.T) {
		tlsCfg, err := buildTLSConfig(nil)
		require.NoError(t, err)
		require.Nil(t, tlsCfg)
	})

	t.Run("insecure explicitly enables TLS with InsecureSkipVerify", func(t *testing.T) {
		cfg := &igniteConfig{Host: "ignite.example.com", Port: 10800, tls: dbtlsutil.Config{SkipVerify: true}}
		tlsCfg, err := buildTLSConfig(cfg)
		require.NoError(t, err)
		require.NotNil(t, tlsCfg)
		require.True(t, tlsCfg.InsecureSkipVerify)
		require.Equal(t, "ignite.example.com", tlsCfg.ServerName)
	})

	t.Run("mutual TLS requires both tls_certificate and tls_key", func(t *testing.T) {
		_, err := dbtlsutil.Decode(map[string]any{"tls_certificate": "some-cert"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "both tls_certificate and tls_key are required")

		_, err = dbtlsutil.Decode(map[string]any{"tls_key": "some-key"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "both tls_certificate and tls_key are required")
	})

	t.Run("invalid tls_ca pem returns error", func(t *testing.T) {
		cfg := &igniteConfig{Host: "ignite.example.com", tls: dbtlsutil.Config{CA: "not-a-valid-pem"}}
		_, err := buildTLSConfig(cfg)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to parse tls_ca PEM")
	})

	t.Run("non-existent tls_ca_path returns error", func(t *testing.T) {
		cfg := &igniteConfig{Host: "ignite.example.com", tls: dbtlsutil.Config{CAPath: "/nonexistent/ca.pem"}}
		_, err := buildTLSConfig(cfg)
		require.Error(t, err)
		require.Contains(t, err.Error(), "read tls_ca_path")
	})
}
