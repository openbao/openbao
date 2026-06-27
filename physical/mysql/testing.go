// Copyright (c) 2024 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

// Adapted from physical/postgresql/testing.go for MySQL/OceanBase.
//
// Unlike the PostgreSQL backend there is no docker testcontainer helper wired
// up for MySQL here; the DB-backed tests are gated on a connection string
// supplied via the MYSQL_URL or OCEANBASE_URL environment variable (a
// go-sql-driver/mysql DSN). When neither is set the caller is expected to skip.

package mysql

import (
	"database/sql"
	"fmt"
	"os"
	"testing"

	_ "github.com/go-sql-driver/mysql"
	log "github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/sdk/v2/physical"
	"github.com/stretchr/testify/require"
)

// mysqlTestDSN returns the DSN to use for DB-backed tests, or an empty string
// if none was configured. OCEANBASE_URL takes precedence over MYSQL_URL so a
// single test run can be targeted at an OceanBase instance.
func mysqlTestDSN() string {
	if url := os.Getenv("OCEANBASE_URL"); url != "" {
		return url
	}
	return os.Getenv("MYSQL_URL")
}

func SetupDatabaseObjects(t *testing.T, m *MySQLBackend) {
	var haTable string
	if m.haEnabled {
		haTable = m.haTable
	}

	err := SetupDatabaseObjectsWithClient(m.client, m.table, m.index, haTable)
	if err != nil {
		t.Fatalf("failed to setup database: %v", err)
	}
}

func SetupDatabaseObjectsWithClient(client *sql.DB, table string, index string, haTable string) error {
	createTableSQL := fmt.Sprintf(
		"CREATE TABLE IF NOT EXISTS %v ( "+
			"  parent_path VARBINARY(512) NOT NULL, "+
			"  path        VARBINARY(512) NOT NULL, "+
			"  `key`       VARBINARY(512) NOT NULL, "+
			"  `value`     LONGBLOB, "+
			"  PRIMARY KEY (path, `key`), "+
			"  KEY %v (parent_path) "+
			") ENGINE=InnoDB; ", table, index,
	)

	if _, err := client.Exec(createTableSQL); err != nil {
		return fmt.Errorf("failed to create table: %v", err)
	}

	if haTable != "" {
		createHaTableSQL := fmt.Sprintf(
			"CREATE TABLE IF NOT EXISTS %v ( "+
				"  ha_key      VARBINARY(512) NOT NULL, "+
				"  ha_identity VARBINARY(512) NOT NULL, "+
				"  ha_value    VARBINARY(512), "+
				"  valid_until DATETIME NOT NULL, "+
				"  PRIMARY KEY (ha_key) "+
				") ENGINE=InnoDB; ", haTable,
		)

		if _, err := client.Exec(createHaTableSQL); err != nil {
			return fmt.Errorf("failed to create ha table: %v", err)
		}
	}

	return nil
}

// GetTestMySQLBackend returns a MySQL backend wired up to the DSN given by
// MYSQL_URL/OCEANBASE_URL. The test is skipped when neither is set.
func GetTestMySQLBackend(t *testing.T, logger log.Logger) (physical.Backend, func()) {
	dsn := mysqlTestDSN()
	if dsn == "" {
		t.Skip("skipping MySQL backend test: set MYSQL_URL or OCEANBASE_URL to a go-sql-driver DSN to run")
	}

	m, err := NewMySQLBackend(map[string]string{
		"connection_url": dsn,
		"ha_enabled":     "true",
	}, logger)
	require.NoError(t, err, "failed initializing mysql database")

	SetupDatabaseObjects(t, m.(*MySQLBackend))

	cleanup := func() {
		mb := m.(*MySQLBackend)
		_, _ = mb.client.Exec(fmt.Sprintf("TRUNCATE TABLE %v", mb.table))
		if mb.haEnabled {
			_, _ = mb.client.Exec(fmt.Sprintf("TRUNCATE TABLE %v", mb.haTable))
		}
	}

	return m, cleanup
}
