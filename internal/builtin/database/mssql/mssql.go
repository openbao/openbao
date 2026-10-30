// Copyright (c) HashiCorp, Inc.
// Copyright (c) AppsCode Inc.
// SPDX-License-Identifier: MPL-2.0

package mssql

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"github.com/hashicorp/go-secure-stdlib/strutil"
	mssql "github.com/microsoft/go-mssqldb"
	"github.com/microsoft/go-mssqldb/msdsn"
	dbplugin "github.com/openbao/openbao/sdk/v2/database/dbplugin/v5"
	"github.com/openbao/openbao/sdk/v2/database/helper/connutil"
	"github.com/openbao/openbao/sdk/v2/database/helper/dbutil"
	"github.com/openbao/openbao/sdk/v2/helper/dbtxn"
	"github.com/openbao/openbao/sdk/v2/helper/template"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/v2/internal/helper/dbtlsutil"
)

const (
	msSQLTypeName = "mssql"

	defaultUserNameTemplate = `{{ printf "v-%s-%s-%s-%s" (.DisplayName | truncate 20) (.RoleName | truncate 20) (random 20) (unix_time) | truncate 128 }}`
)

// ReportedVersion is overridable at build time so the plugin version surfaces
// in plugin-info responses.
var ReportedVersion = ""

// MSSQL implements the v5 dbplugin contract against Microsoft SQL Server.
// Embeds connutil.SQLConnectionProducer for shared connection_url, root
// rotation, and namespace lifecycle plumbing.
type MSSQL struct {
	*connutil.SQLConnectionProducer

	usernameProducer template.StringTemplate

	// containedDB toggles between server-login + db-user revoke and
	// db-user-only revoke. Set via the contained_db config field.
	containedDB bool
}

var (
	_ dbplugin.Database       = (*MSSQL)(nil)
	_ logical.PluginVersioner = (*MSSQL)(nil)
)

func New() (any, error) {
	db := newMSSQL()
	dbType := dbplugin.NewDatabaseErrorSanitizerMiddleware(db, db.secretValues)
	return dbType, nil
}

func newMSSQL() *MSSQL {
	connProducer := &connutil.SQLConnectionProducer{}
	connProducer.Type = msSQLTypeName
	return &MSSQL{SQLConnectionProducer: connProducer}
}

func (m *MSSQL) Type() (string, error) {
	return msSQLTypeName, nil
}

func (m *MSSQL) PluginVersion() logical.PluginVersion {
	return logical.PluginVersion{Version: ReportedVersion}
}

func (m *MSSQL) secretValues() map[string]string {
	return map[string]string{
		m.Password: "[password]",
	}
}

func (m *MSSQL) getConnection(ctx context.Context) (*sql.DB, error) {
	db, err := m.Connection(ctx)
	if err != nil {
		return nil, err
	}
	return db.(*sql.DB), nil
}

func (m *MSSQL) Initialize(ctx context.Context, req dbplugin.InitializeRequest) (dbplugin.InitializeResponse, error) {
	tlsSettings, err := dbtlsutil.Decode(req.Config)
	if err != nil {
		return dbplugin.InitializeResponse{}, fmt.Errorf("invalid TLS configuration: %w", err)
	}
	if tlsSettings.Configured() {
		m.OpenDB = func(_ string, dataSourceName string) (*sql.DB, error) {
			config, err := msdsn.Parse(dataSourceName)
			if err != nil {
				return nil, fmt.Errorf("failed to parse MSSQL connection URL: %w", err)
			}
			tlsConfig, err := tlsSettings.Build(config.Host)
			if err != nil {
				return nil, err
			}
			config.Encryption = msdsn.EncryptionRequired
			config.TLSConfig = tlsConfig
			config.TrustServerCertificate = tlsSettings.SkipVerify
			config.HostInCertificateProvided = tlsSettings.ServerName != ""
			return sql.OpenDB(mssql.NewConnectorConfig(config)), nil
		}
	} else {
		m.OpenDB = nil
	}

	newConf, err := m.Init(ctx, req.Config, req.VerifyConnection)
	if err != nil {
		return dbplugin.InitializeResponse{}, err
	}

	usernameTemplate, err := strutil.GetString(req.Config, "username_template")
	if err != nil {
		return dbplugin.InitializeResponse{}, fmt.Errorf("failed to retrieve username_template: %w", err)
	}
	if usernameTemplate == "" {
		usernameTemplate = defaultUserNameTemplate
	}

	up, err := template.NewTemplate(template.Template(usernameTemplate))
	if err != nil {
		return dbplugin.InitializeResponse{}, fmt.Errorf("unable to initialize username template: %w", err)
	}
	m.usernameProducer = up

	if _, err := m.usernameProducer.Generate(dbplugin.UsernameMetadata{}); err != nil {
		return dbplugin.InitializeResponse{}, fmt.Errorf("invalid username template - did you reference a field that isn't available? : %w", err)
	}

	if v, ok := req.Config["contained_db"]; ok {
		containedDB, err := parseutil.ParseBool(v)
		if err != nil {
			return dbplugin.InitializeResponse{}, fmt.Errorf(`invalid value for "contained_db": %w`, err)
		}
		m.containedDB = containedDB
	}

	return dbplugin.InitializeResponse{Config: newConf}, nil
}

// NewUser executes creation_statements in one transaction. MSSQL does not
// enforce expiration server-side, so OpenBao's lease + DeleteUser are
// what bound the credential's lifetime.
func (m *MSSQL) NewUser(ctx context.Context, req dbplugin.NewUserRequest) (dbplugin.NewUserResponse, error) {
	m.Lock()
	defer m.Unlock()

	db, err := m.getConnection(ctx)
	if err != nil {
		return dbplugin.NewUserResponse{}, fmt.Errorf("unable to get connection: %w", err)
	}

	if len(req.Statements.Commands) == 0 {
		return dbplugin.NewUserResponse{}, dbutil.ErrEmptyCreationStatement
	}

	username, err := m.usernameProducer.Generate(req.UsernameConfig)
	if err != nil {
		return dbplugin.NewUserResponse{}, err
	}

	expirationStr := req.Expiration.Format("2006-01-02 15:04:05-0700")

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return dbplugin.NewUserResponse{}, err
	}
	defer tx.Rollback() //nolint:errcheck

	for _, stmt := range req.Statements.Commands {
		for _, query := range strutil.ParseArbitraryStringSlice(stmt, ";") {
			query = strings.TrimSpace(query)
			if query == "" {
				continue
			}

			m := map[string]string{
				"name":       username,
				"password":   req.Password,
				"expiration": expirationStr,
			}

			if err := dbtxn.ExecuteTxQueryDirect(ctx, tx, m, query); err != nil {
				return dbplugin.NewUserResponse{}, err
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return dbplugin.NewUserResponse{}, err
	}

	return dbplugin.NewUserResponse{Username: username}, nil
}

// DeleteUser disables the login, kills the user's sessions, drops their
// per-database users, then drops the login itself. If contained_db is set,
// runs a simpler DROP USER IF EXISTS against the current database.
func (m *MSSQL) DeleteUser(ctx context.Context, req dbplugin.DeleteUserRequest) (dbplugin.DeleteUserResponse, error) {
	if len(req.Statements.Commands) == 0 {
		return dbplugin.DeleteUserResponse{}, m.revokeUserDefault(ctx, req.Username)
	}

	db, err := m.getConnection(ctx)
	if err != nil {
		return dbplugin.DeleteUserResponse{}, fmt.Errorf("unable to get connection: %w", err)
	}

	merr := &multierror.Error{}
	for _, stmt := range req.Statements.Commands {
		for _, query := range strutil.ParseArbitraryStringSlice(stmt, ";") {
			query = strings.TrimSpace(query)
			if query == "" {
				continue
			}

			m := map[string]string{"name": req.Username}
			if err := dbtxn.ExecuteDBQueryDirect(ctx, db, m, query); err != nil {
				merr = multierror.Append(merr, err)
			}
		}
	}

	return dbplugin.DeleteUserResponse{}, merr.ErrorOrNil()
}

func (m *MSSQL) revokeUserDefault(ctx context.Context, username string) error {
	db, err := m.getConnection(ctx)
	if err != nil {
		return err
	}

	if m.containedDB {
		// Contained DBs only have a DB user, no server-level login.
		revokeQuery := `DECLARE @stmt nvarchar(max);
			SET @stmt = 'DROP USER IF EXISTS ' + QuoteName(@username);
			EXEC(@stmt);`
		revokeStmt, err := db.PrepareContext(ctx, revokeQuery)
		if err != nil {
			return err
		}
		defer revokeStmt.Close() //nolint:errcheck
		if _, err := revokeStmt.ExecContext(ctx, sql.Named("username", username)); err != nil {
			return err
		}
		return nil
	}

	// Disable server login first so no new sessions can start.
	disableQuery := `DECLARE @stmt nvarchar(max);
		SET @stmt = 'ALTER LOGIN ' + QuoteName(@username) + ' DISABLE';
		EXEC(@stmt);`
	disableStmt, err := db.PrepareContext(ctx, disableQuery)
	if err != nil {
		return err
	}
	defer disableStmt.Close() //nolint:errcheck
	if _, err := disableStmt.ExecContext(ctx, sql.Named("username", username)); err != nil {
		return err
	}

	// Collect active sessions; we'll KILL them below.
	sessionStmt, err := db.PrepareContext(ctx,
		"SELECT session_id FROM sys.dm_exec_sessions WHERE login_name = @p1;")
	if err != nil {
		return err
	}
	defer sessionStmt.Close() //nolint:errcheck

	sessionRows, err := sessionStmt.QueryContext(ctx, username)
	if err != nil {
		return err
	}
	defer sessionRows.Close() //nolint:errcheck

	var revokeStmts []string
	for sessionRows.Next() {
		var sessionID int
		if err := sessionRows.Scan(&sessionID); err != nil {
			return err
		}
		revokeStmts = append(revokeStmts, fmt.Sprintf("KILL %d;", sessionID))
	}

	// sp_msloginmappings is undocumented but it's the simplest way to enum
	// per-DB users mapped to a login. Drop those before dropping the login.
	stmt, err := db.PrepareContext(ctx, "EXEC master.dbo.sp_msloginmappings @p1;")
	if err != nil {
		return err
	}
	defer stmt.Close() //nolint:errcheck

	rows, err := stmt.QueryContext(ctx, username)
	if err != nil {
		return err
	}
	defer rows.Close() //nolint:errcheck

	for rows.Next() {
		var loginName, dbName, qUsername, aliasName sql.NullString
		if err := rows.Scan(&loginName, &dbName, &qUsername, &aliasName); err != nil {
			return err
		}
		if !dbName.Valid {
			continue
		}
		revokeStmts = append(revokeStmts, fmt.Sprintf(dropUserSQL, dbName.String, username, username))
	}

	// Best-effort drop: keep going on individual failures so we remove as
	// much access as possible before giving up.
	var lastStmtError error
	for _, query := range revokeStmts {
		if err := dbtxn.ExecuteDBQueryDirect(ctx, db, nil, query); err != nil {
			lastStmtError = err
		}
	}

	if rows.Err() != nil {
		return fmt.Errorf("could not generate sql statements for all rows: %w", rows.Err())
	}
	if lastStmtError != nil {
		return fmt.Errorf("could not perform all sql statements: %w", lastStmtError)
	}

	stmt, err = db.PrepareContext(ctx, dropLoginSQL)
	if err != nil {
		return err
	}
	defer stmt.Close() //nolint:errcheck
	if _, err := stmt.ExecContext(ctx, sql.Named("username", username)); err != nil {
		return err
	}

	return nil
}

func (m *MSSQL) UpdateUser(ctx context.Context, req dbplugin.UpdateUserRequest) (dbplugin.UpdateUserResponse, error) {
	if req.Password == nil && req.Expiration == nil {
		return dbplugin.UpdateUserResponse{}, errors.New("no changes requested")
	}
	if req.Password != nil {
		return dbplugin.UpdateUserResponse{}, m.updateUserPass(ctx, req.Username, req.Password)
	}
	// MSSQL has no native expiration on logins; OpenBao + DeleteUser bound it.
	return dbplugin.UpdateUserResponse{}, nil
}

func (m *MSSQL) updateUserPass(ctx context.Context, username string, changePass *dbplugin.ChangePassword) error {
	stmts := changePass.Statements.Commands
	if len(stmts) == 0 && !m.containedDB {
		stmts = []string{alterLoginSQL}
	}

	password := changePass.NewPassword
	if username == "" || password == "" {
		return errors.New("must provide both username and password")
	}

	m.Lock()
	defer m.Unlock()

	db, err := m.getConnection(ctx)
	if err != nil {
		return err
	}

	// Contained DB users don't have server logins, so only check
	// server_principals on the non-contained path.
	if !m.containedDB {
		var exists bool
		err = db.QueryRowContext(ctx, "SELECT 1 FROM master.sys.server_principals where name = @p1", username).Scan(&exists)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	for _, stmt := range stmts {
		for _, query := range strutil.ParseArbitraryStringSlice(stmt, ";") {
			query = strings.TrimSpace(query)
			if query == "" {
				continue
			}

			m := map[string]string{
				"name":     username,
				"username": username,
				"password": password,
			}
			if err := dbtxn.ExecuteTxQueryDirect(ctx, tx, m, query); err != nil {
				return fmt.Errorf("failed to execute query: %w", err)
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

const dropUserSQL = `
USE [%s]
IF EXISTS
  (SELECT name
   FROM sys.database_principals
   WHERE name = N'%s')
BEGIN
  DROP USER [%s]
END
`

const dropLoginSQL = `
DECLARE @stmt nvarchar(max)
SET @stmt = 'IF EXISTS (SELECT name FROM [master].[sys].[server_principals] WHERE [name] = ' + QuoteName(@username, '''') + ') ' +
	'BEGIN ' +
		'DROP LOGIN ' + QuoteName(@username) + ' ' +
	'END'
EXEC (@stmt)`

const alterLoginSQL = `
ALTER LOGIN [{{username}}] WITH PASSWORD = '{{password}}'
`
