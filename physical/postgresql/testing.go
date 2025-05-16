// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package postgresql

import (
	"fmt"
	"testing"

	log "github.com/hashicorp/go-hclog"
	_ "github.com/jackc/pgx/v5/stdlib"
	thpsql "github.com/openbao/openbao/helper/testhelpers/postgresql"
	"github.com/openbao/openbao/sdk/v2/physical"
	"github.com/stretchr/testify/require"
)

func SetupDatabaseObjects(t *testing.T, pg *PostgreSQLBackend) {
	var err error
	// Setup tables and indexes if not exists.
	createTableSQL := fmt.Sprintf(
		"  CREATE TABLE IF NOT EXISTS %v ( "+
			"  parent_path TEXT COLLATE \"C\" NOT NULL, "+
			"  path        TEXT COLLATE \"C\", "+
			"  key         TEXT COLLATE \"C\", "+
			"  value       BYTEA, "+
			"  CONSTRAINT pkey PRIMARY KEY (path, key) "+
			" ); ", pg.table)

	_, err = pg.client.Exec(createTableSQL)
	if err != nil {
		t.Fatalf("Failed to create table: %v", err)
	}

	createIndexSQL := fmt.Sprintf(" CREATE INDEX IF NOT EXISTS parent_path_idx ON %v (parent_path); ", pg.table)

	_, err = pg.client.Exec(createIndexSQL)
	if err != nil {
		t.Fatalf("Failed to create index: %v", err)
	}

	createHaTableSQL := fmt.Sprintf(
		" CREATE TABLE IF NOT EXISTS %v ( "+
			" ha_key                                      TEXT COLLATE \"C\" NOT NULL, "+
			" ha_identity                                 TEXT COLLATE \"C\" NOT NULL, "+
			" ha_value                                    TEXT COLLATE \"C\", "+
			" valid_until                                 TIMESTAMP WITH TIME ZONE NOT NULL, "+
			" CONSTRAINT ha_key PRIMARY KEY (ha_key) "+
			" ); ", pg.ha_table)

	_, err = pg.client.Exec(createHaTableSQL)
	if err != nil {
		t.Fatalf("Failed to create hatable: %v", err)
	}
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
