// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package mysql

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path"
	"reflect"
	"testing"
	"time"

	"github.com/openbao/openbao/helper/testhelpers/certhelpers"
	"github.com/openbao/openbao/sdk/v2/database/helper/dbutil"
	"github.com/ory/dockertest/v4"
)

func TestInit_clientTLS(t *testing.T) {
	// Create certificates for MySQL authentication
	caCert := certhelpers.NewCert(
		t,
		certhelpers.CommonName("test certificate authority"),
		certhelpers.IsCA(true),
		certhelpers.SelfSign(),
	)
	serverCert := certhelpers.NewCert(
		t,
		certhelpers.CommonName("server"),
		certhelpers.DNS("localhost"),
		certhelpers.Parent(caCert),
	)
	clientCert := certhelpers.NewCert(
		t,
		certhelpers.CommonName("client"),
		certhelpers.DNS("client"),
		certhelpers.Parent(caCert),
	)

	// Set up temp directory so we can mount it to the docker container
	confDir := t.TempDir()
	writeFile(t, path.Join(confDir, "ca.pem"), caCert.CombinedPEM(), 0o644)
	writeFile(t, path.Join(confDir, "server-cert.pem"), serverCert.Pem, 0o644)
	writeFile(t, path.Join(confDir, "server-key.pem"), serverCert.PrivateKeyPEM(), 0o644)
	writeFile(t, path.Join(confDir, "client.pem"), clientCert.CombinedPEM(), 0o644)

	// //////////////////////////////////////////////////////
	// Set up MySQL config file
	rawConf := `
[mysqld]
ssl-ca=/etc/mysql/certs/ca.pem
ssl-cert=/etc/mysql/certs/server-cert.pem
ssl-key=/etc/mysql/certs/server-key.pem`

	writeFile(t, path.Join(confDir, "my.cnf"), []byte(rawConf), 0o644)

	// //////////////////////////////////////////////////////
	// Start MySQL container
	retURL := startMySQLWithTLS(t, "8.0", confDir)

	// //////////////////////////////////////////////////////
	// Set up x509 user
	mClient := connect(t, retURL)

	username := setUpX509User(t, mClient, clientCert)

	// //////////////////////////////////////////////////////
	// Test
	mysql := newMySQL(DefaultUserNameTemplate)

	conf := map[string]interface{}{
		"connection_url":      retURL,
		"username":            username,
		"tls_certificate_key": clientCert.CombinedPEM(),
		"tls_ca":              caCert.Pem,
	}

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	_, err := mysql.Init(ctx, conf, true)
	if err != nil {
		t.Fatalf("Unable to initialize mysql engine: %s", err)
	}

	// Initialization complete. The connection was established, but we need to ensure
	// that we're connected as the right user
	whoamiCmd := "SELECT CURRENT_USER()"

	client, err := mysql.getConnection(ctx)
	if err != nil {
		t.Fatalf("Unable to make connection to MySQL: %s", err)
	}
	stmt, err := client.Prepare(whoamiCmd)
	if err != nil {
		t.Fatalf("Unable to prepare MySQL statementL %s", err)
	}

	results := stmt.QueryRow()

	expected := fmt.Sprintf("%s@%%", username)

	var result string
	if err := results.Scan(&result); err != nil {
		t.Fatalf("result could not be scanned from result set: %s", err)
	}

	if !reflect.DeepEqual(result, expected) {
		t.Fatalf("Actual:%#v\nExpected:\n%#v", result, expected)
	}
}

func startMySQLWithTLS(t *testing.T, version, confDir string) string {
	if os.Getenv("MYSQL_URL") != "" {
		return os.Getenv("MYSQL_URL")
	}

	pool := dockertest.NewPoolT(t, "", dockertest.WithMaxWait(30*time.Second))
	username := "root"
	password := "x509test"

	resource := pool.RunT(
		t,
		"docker.mirror.hashicorp.services/library/mysql",
		dockertest.WithTag(version),
		dockertest.WithCmd([]string{"--auto-generate-certs=OFF"}),
		dockertest.WithEnv([]string{fmt.Sprintf("MYSQL_ROOT_PASSWORD=%s", password)}),
		// Mount certs and config from local filesystem into the container.
		dockertest.WithMounts([]string{
			fmt.Sprintf("%s:/etc/mysql/conf.d/my.cnf", path.Join(confDir, "my.cnf")),
			fmt.Sprintf("%s:/etc/mysql/certs", confDir),
		}),
	)

	dsn := fmt.Sprintf("{{username}}:{{password}}@tcp(localhost:%s)/mysql", resource.GetPort("3306/tcp"))
	url := dbutil.QueryHelper(dsn, map[string]string{
		"username": username,
		"password": password,
	})
	// exponential backoff-retry
	err := pool.Retry(t.Context(), 15*time.Second, func() error {
		db, err := sql.Open("mysql", url)
		if err != nil {
			t.Logf("err: %s", err)
			return err
		}
		defer db.Close()
		return db.Ping()
	})
	if err != nil {
		t.Fatalf("Could not connect to mysql docker container: %s", err)
	}

	return dsn
}

func connect(t *testing.T, dsn string) (db *sql.DB) {
	url := dbutil.QueryHelper(dsn, map[string]string{
		"username": "root",
		"password": "x509test",
	})

	db, err := sql.Open("mysql", url)
	if err != nil {
		t.Fatalf("Unable to make connection to MySQL: %s", err)
	}

	err = db.Ping()
	if err != nil {
		t.Fatalf("Failed to ping MySQL server: %s", err)
	}

	return db
}

func setUpX509User(t *testing.T, db *sql.DB, cert certhelpers.Certificate) (username string) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	username = cert.Template.Subject.CommonName

	cmds := []string{
		fmt.Sprintf("CREATE USER %s IDENTIFIED BY '' REQUIRE X509", username),
		fmt.Sprintf("GRANT ALL ON mysql.* TO '%s'@'%%'", username),
	}

	for _, cmd := range cmds {
		stmt, err := db.PrepareContext(ctx, cmd)
		if err != nil {
			t.Fatalf("Failed to prepare query: %s", err)
		}

		_, err = stmt.ExecContext(ctx)
		if err != nil {
			t.Fatalf("Failed to create x509 user in database: %s", err)
		}
		err = stmt.Close()
		if err != nil {
			t.Fatalf("Failed to close prepared statement: %s", err)
		}
	}

	return username
}

// ////////////////////////////////////////////////////////////////////////////
// Writing to file
// ////////////////////////////////////////////////////////////////////////////
func writeFile(t *testing.T, filename string, data []byte, perms os.FileMode) {
	t.Helper()

	err := os.WriteFile(filename, data, perms)
	if err != nil {
		t.Fatalf("Unable to write to file [%s]: %s", filename, err)
	}
}

func Test_parseMultiHostDSN(t *testing.T) {
	type testCase struct {
		connectionURL         string
		expectedHosts         []string
		expectedConnectionURL string
	}

	tests := map[string]testCase{
		"single host": {
			connectionURL:         "user:password@tcp(localhost:3306)/test",
			expectedHosts:         []string{"localhost:3306"},
			expectedConnectionURL: "user:password@tcp(localhost:3306)/test",
		},
		"multiple hosts": {
			connectionURL:         "user:password@tcp(host1:3306,host2:3307)/test",
			expectedHosts:         []string{"host1:3306", "host2:3307"},
			expectedConnectionURL: "user:password@tcp(host1:3306)/test",
		},
		"multiple hosts without ports": {
			connectionURL:         "user:password@tcp(host1,host2)/test",
			expectedHosts:         []string{"host1:3306", "host2:3306"},
			expectedConnectionURL: "user:password@tcp(host1:3306)/test",
		},
		"unix socket": {
			connectionURL:         "user:password@unix(/var/run/mysqld/mysqld.sock)/test",
			expectedHosts:         nil,
			expectedConnectionURL: "user:password@unix(/var/run/mysqld/mysqld.sock)/test",
		},
		"multiple hosts with tls param": {
			connectionURL:         "user:password@tcp(host1:3306,host2:3307)/test?tls=skip-verify",
			expectedHosts:         []string{"host1:3306", "host2:3307"},
			expectedConnectionURL: "user:password@tcp(host1:3306)/test?tls=skip-verify",
		},
		"ipv6 single host": {
			connectionURL:         "user:password@tcp([::1]:3306)/test",
			expectedHosts:         []string{"[::1]:3306"},
			expectedConnectionURL: "user:password@tcp([::1]:3306)/test",
		},
		"ipv6 without port": {
			connectionURL:         "user:password@tcp([::1])/test",
			expectedHosts:         []string{"[::1]:3306"},
			expectedConnectionURL: "user:password@tcp([::1])/test",
		},
		"ipv6 multiple hosts": {
			connectionURL:         "user:password@tcp([::1]:3306,[::2]:3307)/test",
			expectedHosts:         []string{"[::1]:3306", "[::2]:3307"},
			expectedConnectionURL: "user:password@tcp([::1]:3306)/test",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			producer := &mySQLConnectionProducer{
				ConnectionURL: test.connectionURL,
			}

			err := producer.parseMultiHostDSN()
			if err != nil {
				t.Fatalf("unexpected error: %s", err)
			}

			if !reflect.DeepEqual(producer.hosts, test.expectedHosts) {
				t.Fatalf("hosts: got %v, expected %v", producer.hosts, test.expectedHosts)
			}

			if producer.ConnectionURL != test.expectedConnectionURL {
				t.Fatalf("connectionURL: got %s, expected %s", producer.ConnectionURL, test.expectedConnectionURL)
			}
		})
	}
}

func Test_dialWithFailover(t *testing.T) {
	producer := &mySQLConnectionProducer{
		hosts: []string{"invalid-host-1:3306", "invalid-host-2:3306"},
	}

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()

	_, err := producer.dialWithFailover(ctx, "tcp", "ignored")
	if err == nil {
		t.Fatal("expected error when connecting to invalid hosts")
	}
}
