// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package postgresql

import (
	"database/sql"
	"fmt"
	"testing"

	log "github.com/hashicorp/go-hclog"
	_ "github.com/jackc/pgx/v5/stdlib"
	thpsql "github.com/openbao/openbao/sdk/v2/helper/testhelpers/postgresql"
	"github.com/openbao/openbao/sdk/v2/physical"
	"github.com/stretchr/testify/require"
)

func SetupDatabaseObjects(t *testing.T, pg *PostgreSQLBackend) {
	var haTable string
	if pg.haEnabled {
		haTable = pg.haTable
	}

	err := SetupDatabaseObjectsWithClient(pg.client, pg.table, pg.tableConstraint, pg.index, haTable, pg.haTableConstraint)
	if err != nil {
		t.Fatalf("failed to setup database: %v", err)
	}
}

func SetupDatabaseObjectsWithClient(client *sql.DB, table string, constraint string, index string, haTable string, haTableConstraint string) error {
	var err error
	// Setup tables and indexes if not exists.
	createTableSQL := fmt.Sprintf(
		"  CREATE TABLE IF NOT EXISTS %v ( "+
			"  parent_path TEXT COLLATE \"C\" NOT NULL, "+
			"  path        TEXT COLLATE \"C\", "+
			"  key         TEXT COLLATE \"C\", "+
			"  value       BYTEA, "+
			"  CONSTRAINT %v PRIMARY KEY (path, key) "+
			" ); ", table, constraint)

	_, err = client.Exec(createTableSQL)
	if err != nil {
		return fmt.Errorf("failed to create table: %v", err)
	}

	createIndexSQL := fmt.Sprintf(" CREATE INDEX IF NOT EXISTS %v ON %v (parent_path); ", index, table)

	_, err = client.Exec(createIndexSQL)
	if err != nil {
		return fmt.Errorf("failed to create index: %v", err)
	}

	if haTable != "" {
		createHaTableSQL := fmt.Sprintf(
			" CREATE TABLE IF NOT EXISTS %v ( "+
				" ha_key                                      TEXT COLLATE \"C\" NOT NULL, "+
				" ha_identity                                 TEXT COLLATE \"C\" NOT NULL, "+
				" ha_value                                    TEXT COLLATE \"C\", "+
				" valid_until                                 TIMESTAMP WITH TIME ZONE NOT NULL, "+
				" CONSTRAINT %v PRIMARY KEY (ha_key) "+
				" ); ", haTable, haTableConstraint)

		_, err = client.Exec(createHaTableSQL)
		if err != nil {
			return fmt.Errorf("failed to create hatable: %v", err)
		}
	}

	return nil
}

func GetTestPostgreSQLBackend(t *testing.T, logger log.Logger) (physical.Backend, func()) {
	cleanup, url := thpsql.PrepareTestContainer(t, "11.1")

	pg, err := NewPostgreSQLBackend(map[string]string{
		"connection_url": url,
		"ha_enable":      "true",
	}, logger)
	require.NoError(t, err, "failed initializing postgres database")

	SetupDatabaseObjects(t, pg.(*PostgreSQLBackend))

	return pg, cleanup
}
