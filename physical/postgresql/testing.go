// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package postgresql

import (
	"fmt"
	"testing"

	log "github.com/hashicorp/go-hclog"
	_ "github.com/jackc/pgx/v4/stdlib"
)

func SetupDatabaseObjects(t *testing.T, logger log.Logger, pg *PostgreSQLBackend) {
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

	createHaTableSQL := " CREATE TABLE IF NOT EXISTS openbao_ha_locks ( " +
		" ha_key                                      TEXT COLLATE \"C\" NOT NULL, " +
		" ha_identity                                 TEXT COLLATE \"C\" NOT NULL, " +
		" ha_value                                    TEXT COLLATE \"C\", " +
		" valid_until                                 TIMESTAMP WITH TIME ZONE NOT NULL, " +
		" CONSTRAINT ha_key PRIMARY KEY (ha_key) " +
		" ); "

	_, err = pg.client.Exec(createHaTableSQL)
	if err != nil {
		t.Fatalf("Failed to create hatable: %v", err)
	}
}
