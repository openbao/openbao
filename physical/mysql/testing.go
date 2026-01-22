// Copyright (c) HashiCorp, Inc.
// Copyright (c) 2024 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package mysql

import (
	"os"
	"testing"

	log "github.com/hashicorp/go-hclog"
)

// MakeMySQLTestBackend creates a MySQL backend for testing purposes.
// It returns the backend, a cleanup function, and an error.
func MakeMySQLTestBackend(t *testing.T, logger log.Logger) (*MySQLBackend, func(), error) {
	address := os.Getenv("MYSQL_ADDR")
	if address == "" {
		address = "127.0.0.1:3306"
	}

	username := os.Getenv("MYSQL_USERNAME")
	if username == "" {
		username = "root"
	}

	password := os.Getenv("MYSQL_PASSWORD")
	if password == "" {
		password = "password"
	}

	database := os.Getenv("MYSQL_DATABASE")
	if database == "" {
		database = "test_vault"
	}

	table := os.Getenv("MYSQL_TABLE")
	if table == "" {
		table = "test_vault"
	}

	conf := map[string]string{
		"address":                      address,
		"username":                     username,
		"password":                     password,
		"database":                     database,
		"table":                        table,
		"ha_enabled":                   "true",
		"plaintext_connection_allowed": "true",
	}

	backend, err := NewMySQLBackend(conf, logger)
	if err != nil {
		return nil, nil, err
	}

	mysqlBackend, ok := backend.(*MySQLBackend)
	if !ok {
		return nil, nil, err
	}

	// Create cleanup function
	cleanup := func() {
		// Drop tables
		_, _ = mysqlBackend.client.Exec("DROP TABLE IF EXISTS `" + database + "`.`" + table + "`")
		_, _ = mysqlBackend.client.Exec("DROP TABLE IF EXISTS `" + database + "`.`" + table + "_lock`")
		mysqlBackend.client.Close()
	}

	return mysqlBackend, cleanup, nil
}
