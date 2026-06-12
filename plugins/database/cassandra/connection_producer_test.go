// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package cassandra

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gocql/gocql"
	"github.com/openbao/openbao/helper/testhelpers/cassandra"
	"github.com/openbao/openbao/sdk/v2/database/dbplugin/v5"
	dbtesting "github.com/openbao/openbao/sdk/v2/database/dbplugin/v5/testing"
	"github.com/openbao/openbao/sdk/v2/helper/certutil"
	"github.com/stretchr/testify/require"
	"github.com/tsaarni/certyaml"
)

var insecureFileMounts = map[string]string{
	"test-fixtures/no_tls/cassandra.yaml": "/etc/cassandra/cassandra.yaml",
}

func TestSelfSignedCA(t *testing.T) {
	ca := certyaml.Certificate{
		Subject: "cn=ca",
	}

	server := certyaml.Certificate{
		Subject:         "cn=cassandra",
		SubjectAltNames: []string{"DNS:cassandra"},
		Issuer:          &ca,
	}

	badCA := certyaml.Certificate{
		Subject: "cn=badca",
	}

	// Write PEM files that will be mounted into the container.
	dir := t.TempDir()
	serverPEM := filepath.Join(dir, "server.pem")
	caPEM := filepath.Join(dir, "ca.pem")
	require.NoError(t, os.WriteFile(serverPEM, append(server.KeyPEM(), server.CertPEM()...), 0o600))
	require.NoError(t, os.WriteFile(caPEM, ca.CertPEM(), 0o644))

	copyFromTo := map[string]string{
		"test-fixtures/with_tls/cassandra.yaml": "/etc/cassandra/cassandra.yaml",
		"test-fixtures/with_tls/cqlshrc":        "/etc/cassandra/cqlshrc",
		serverPEM:                               "/etc/cassandra/server.pem",
		caPEM:                                   "/etc/cassandra/ca.pem",
	}

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(ca.CertPEM())
	tlsConfig := &tls.Config{RootCAs: caPool}
	// Note about CI behavior: when running these tests locally, they seem to pass without issue. However, if the
	// ServerName is not set, the tests fail within CI. It's not entirely clear to me why they are failing in CI
	// however by manually setting the ServerName we can get around the hostname/DNS issue and get them passing.
	// Setting the ServerName isn't the ideal solution, but it was the only reliable one I was able to find
	tlsConfig.ServerName = "cassandra"
	sslOpts := &gocql.SslOptions{
		Config:                 tlsConfig,
		EnableHostVerification: true,
	}

	host, cleanup := cassandra.PrepareTestContainer(t,
		cassandra.CopyFromTo(copyFromTo),
		cassandra.SslOpts(sslOpts),
	)
	t.Cleanup(cleanup)

	type testCase struct {
		config    map[string]interface{}
		expectErr bool
	}

	tests := map[string]testCase{
		// ///////////////////////
		// pem_json tests
		"pem_json/ca only": {
			config: map[string]interface{}{
				"pem_json": toJSON(t, certutil.CertBundle{
					CAChain: []string{string(ca.CertPEM())},
				}),
			},
			expectErr: false,
		},
		"pem_json/bad ca": {
			config: map[string]interface{}{
				"pem_json": toJSON(t, certutil.CertBundle{
					CAChain: []string{string(badCA.CertPEM())},
				}),
			},
			expectErr: true,
		},
		"pem_json/missing ca": {
			config: map[string]interface{}{
				"pem_json": "",
			},
			expectErr: true,
		},

		// ///////////////////////
		// pem_bundle tests
		"pem_bundle/ca only": {
			config: map[string]interface{}{
				"pem_bundle": ca.CertPEM(),
			},
			expectErr: false,
		},
		"pem_bundle/unrecognized CA": {
			config: map[string]interface{}{
				"pem_bundle": badCA.CertPEM(),
			},
			expectErr: true,
		},
		"pem_bundle/missing ca": {
			config: map[string]interface{}{
				"pem_bundle": "",
			},
			expectErr: true,
		},

		// ///////////////////////
		// no cert data provided
		"no cert data/tls=true": {
			config: map[string]interface{}{
				"tls": "true",
			},
			expectErr: true,
		},
		"no cert data/tls=false": {
			config: map[string]interface{}{
				"tls": "false",
			},
			expectErr: true,
		},
		"no cert data/insecure_tls": {
			config: map[string]interface{}{
				"insecure_tls": "true",
			},
			expectErr: false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			// Set values that we don't know until the cassandra container is started
			config := map[string]interface{}{
				"hosts":            host.Name,
				"port":             host.Port,
				"username":         "cassandra",
				"password":         "cassandra",
				"protocol_version": "4",
				"connect_timeout":  "30s",
				"tls":              "true",

				// Note about CI behavior: when running these tests locally, they seem to pass without issue. However, if the
				// tls_server_name is not set, the tests fail within CI. It's not entirely clear to me why they are failing in CI
				// however by manually setting the tls_server_name we can get around the hostname/DNS issue and get them passing.
				// Setting the tls_server_name isn't the ideal solution, but it was the only reliable one I was able to find
				"tls_server_name": "cassandra",
			}

			// Apply the generated & common fields to the config to be sent to the DB
			for k, v := range test.config {
				config[k] = v
			}

			db := new()
			initReq := dbplugin.InitializeRequest{
				Config:           config,
				VerifyConnection: true,
			}

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			_, err := db.Initialize(ctx, initReq)
			if test.expectErr && err == nil {
				t.Fatal("err expected, got nil")
			}
			if !test.expectErr && err != nil {
				t.Fatalf("no error expected, got: %s", err)
			}

			// If no error expected, run a NewUser query to make sure the connection
			// actually works in case Initialize doesn't catch it
			if !test.expectErr {
				assertNewUser(t, db, sslOpts)
			}
		})
	}
}

func assertNewUser(t *testing.T, db *Cassandra, sslOpts *gocql.SslOptions) {
	newUserReq := dbplugin.NewUserRequest{
		UsernameConfig: dbplugin.UsernameMetadata{
			DisplayName: "dispname",
			RoleName:    "rolename",
		},
		Statements: dbplugin.Statements{
			Commands: []string{
				"create user '{{username}}' with password '{{password}}'",
			},
		},
		RollbackStatements: dbplugin.Statements{},
		Password:           "gh8eruajASDFAsgy89svn",
		Expiration:         time.Now().Add(5 * time.Second),
	}

	newUserResp := dbtesting.AssertNewUser(t, db, newUserReq)
	t.Logf("Username: %s", newUserResp.Username)

	assertCreds(t, db.Hosts, db.Port, newUserResp.Username, newUserReq.Password, sslOpts, 5*time.Second)
}

func toJSON(t *testing.T, val interface{}) string {
	t.Helper()
	b, err := json.Marshal(val)
	require.NoError(t, err)
	return string(b)
}
