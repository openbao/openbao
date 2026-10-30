// Copyright (c) AppsCode Inc.
// SPDX-License-Identifier: MPL-2.0

package rabbitmq

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"reflect"
	"testing"
	"time"

	rabbithole "github.com/michaelklishin/rabbit-hole/v3"
	dbplugin "github.com/openbao/openbao/sdk/v2/database/dbplugin/v5"
	"github.com/openbao/openbao/v2/internal/helper/dbtlsutil"
	"github.com/stretchr/testify/require"
)

func TestRMQ_TypeAndVersion(t *testing.T) {
	db := newRabbitMQ()
	typ, err := db.Type()
	require.NoError(t, err)
	require.Equal(t, rabbitmqTypeName, typ)
	require.Equal(t, ReportedVersion, db.PluginVersion().Version)
}

func TestRMQ_ParseTags(t *testing.T) {
	cases := map[string]rabbithole.UserTags{
		"":                           nil,
		"administrator":              {"administrator"},
		"administrator,monitoring":   {"administrator", "monitoring"},
		" management , policymaker ": {"management", "policymaker"},
	}
	for in, want := range cases {
		t.Run(in, func(t *testing.T) {
			got := parseTags(in)
			require.True(t, reflect.DeepEqual(got, want), "got %#v want %#v", got, want)
		})
	}
}

func TestRMQ_StatementParsing(t *testing.T) {
	raw := `{"tags":"administrator","vhosts":{"/":{"configure":".*","write":".*","read":".*"}}}`
	var s rmqStatement
	require.NoError(t, json.Unmarshal([]byte(raw), &s))
	require.Equal(t, "administrator", s.Tags)
	require.Equal(t, ".*", s.VHosts["/"].Configure)
}

func TestRMQ_UpdateUser_Validation(t *testing.T) {
	db := newRabbitMQ()
	_, err := db.UpdateUser(context.Background(), dbplugin.UpdateUserRequest{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "missing username")

	_, err = db.UpdateUser(context.Background(), dbplugin.UpdateUserRequest{Username: "u"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "no changes requested")
}

func TestRMQ_NewUser_EmptyStatements(t *testing.T) {
	db := newRabbitMQ()
	// Initialize a producer so NewUser reaches the statements check.
	_, err := db.Initialize(context.Background(), dbplugin.InitializeRequest{
		Config: map[string]any{
			"connection_uri": "http://localhost:15672",
			"username":       "guest",
			"password":       "guest",
		},
		VerifyConnection: false,
	})
	require.NoError(t, err)

	_, err = db.NewUser(context.Background(), dbplugin.NewUserRequest{
		UsernameConfig: dbplugin.UsernameMetadata{DisplayName: "t", RoleName: "t"},
	})
	require.Error(t, err)
}

// generateTestCert returns a self-signed PEM-encoded certificate and its
// PEM-encoded private key, for use as tls_ca/tls_certificate/tls_key test
// fixtures.
func generateTestCert(t *testing.T) (certPEM, keyPEM string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "rabbitmq-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:         true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	certBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	keyBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return string(certBytes), string(keyBytes)
}

func TestRMQ_MakeTLSConfig(t *testing.T) {
	certPEM, keyPEM := generateTestCert(t)

	t.Run("no TLS fields set returns nil config", func(t *testing.T) {
		tlsConfig, err := makeTLSConfig(&rmqConfig{})
		require.NoError(t, err)
		require.Nil(t, tlsConfig)
	})

	t.Run("tls_skip_verify alone builds an InsecureSkipVerify config", func(t *testing.T) {
		tlsConfig, err := makeTLSConfig(&rmqConfig{tls: dbtlsutil.Config{SkipVerify: true}})
		require.NoError(t, err)
		require.NotNil(t, tlsConfig)
		require.True(t, tlsConfig.InsecureSkipVerify)
	})

	t.Run("valid tls_ca is parsed into RootCAs", func(t *testing.T) {
		tlsConfig, err := makeTLSConfig(&rmqConfig{tls: dbtlsutil.Config{CA: certPEM}})
		require.NoError(t, err)
		require.NotNil(t, tlsConfig)
		require.NotNil(t, tlsConfig.RootCAs)
	})

	t.Run("invalid tls_ca PEM errors", func(t *testing.T) {
		_, err := makeTLSConfig(&rmqConfig{tls: dbtlsutil.Config{CA: "not a pem bundle"}})
		require.Error(t, err)
	})

	t.Run("valid tls_certificate/tls_key pair is parsed", func(t *testing.T) {
		tlsConfig, err := makeTLSConfig(&rmqConfig{tls: dbtlsutil.Config{Certificate: certPEM, Key: keyPEM}})
		require.NoError(t, err)
		require.NotNil(t, tlsConfig)
		require.Len(t, tlsConfig.Certificates, 1)
	})

	t.Run("tls_certificate without tls_key errors", func(t *testing.T) {
		_, err := dbtlsutil.Decode(map[string]any{"tls_certificate": certPEM})
		require.Error(t, err)
	})

	t.Run("tls_key without tls_certificate errors", func(t *testing.T) {
		_, err := dbtlsutil.Decode(map[string]any{"tls_key": keyPEM})
		require.Error(t, err)
	})

	t.Run("mismatched tls_certificate/tls_key errors", func(t *testing.T) {
		_, otherKeyPEM := generateTestCert(t)
		_, err := makeTLSConfig(&rmqConfig{tls: dbtlsutil.Config{Certificate: certPEM, Key: otherKeyPEM}})
		require.Error(t, err)
	})
}

func TestRMQ_Acceptance(t *testing.T) {
	if os.Getenv("BAO_ACC") != "1" || os.Getenv("RABBITMQ_URL") == "" {
		t.Skip("set BAO_ACC=1 and RABBITMQ_URL (management URL, e.g. http://guest:guest@localhost:15672) to run RabbitMQ acceptance tests")
	}
	// Manual flow lives in TEST.md.
}
