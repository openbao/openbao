// Copyright (c) AppsCode Inc.
// SPDX-License-Identifier: MPL-2.0

// Package oracle implements the v5 OpenBao database secrets-engine plugin
// for Oracle Database. The plugin uses the pure-Go driver
// github.com/sijms/go-ora/v2, which speaks the Oracle TNS protocol without
// requiring the Oracle Instant Client. CGO is not required.
//
// Oracle identifier rules:
//   - Identifiers are case-folded to upper-case unless double-quoted.
//   - The default username template emits a quoted-safe upper-case name
//     of the form V_<DISPLAY>_<ROLE>_<RANDOM>_<UNIX> truncated to 30
//     characters (the historical Oracle identifier limit) — newer
//     Oracle versions allow 128 but truncating gives the widest
//     compatibility window.
//
// The default revoke path runs `REVOKE`/`DROP USER ... CASCADE` against
// identifiers quoted via dbutil.QuoteIdentifier, so a username containing
// `"` is rejected at the DB layer rather than allowing SQL injection.
package oracle

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/go-secure-stdlib/strutil"
	dbplugin "github.com/openbao/openbao/sdk/v2/database/dbplugin/v5"
	"github.com/openbao/openbao/sdk/v2/database/helper/connutil"
	"github.com/openbao/openbao/sdk/v2/database/helper/dbutil"
	"github.com/openbao/openbao/sdk/v2/helper/dbtxn"
	"github.com/openbao/openbao/sdk/v2/helper/template"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/v2/internal/helper/dbtlsutil"
	go_ora "github.com/sijms/go-ora/v2"
)

const (
	oracleTypeName = "oracle"

	// 30 characters is the historical Oracle identifier limit.
	defaultUserNameTemplate = `{{ printf "V_%s_%s_%s_%s" (.DisplayName | truncate 8) (.RoleName | truncate 8) (random 8) (unix_time) | truncate 30 | replace "-" "_" | replace "." "_" | uppercase }}`

	defaultChangePasswordStatement = `ALTER USER {{username}} IDENTIFIED BY "{{password}}";`
)

// ReportedVersion is overridable at build time.
var ReportedVersion = ""

// Oracle implements the v5 dbplugin.Database contract against Oracle.
// Embeds connutil.SQLConnectionProducer for shared connection_url
// plumbing, root rotation, and per-namespace mount lifecycle.
type Oracle struct {
	*connutil.SQLConnectionProducer

	usernameProducer template.StringTemplate
}

var (
	_ dbplugin.Database       = (*Oracle)(nil)
	_ logical.PluginVersioner = (*Oracle)(nil)
)

func New() (any, error) {
	db := newOracle()
	dbType := dbplugin.NewDatabaseErrorSanitizerMiddleware(db, db.secretValues)
	return dbType, nil
}

func newOracle() *Oracle {
	connProducer := &connutil.SQLConnectionProducer{}
	connProducer.Type = oracleTypeName
	return &Oracle{SQLConnectionProducer: connProducer}
}

func (o *Oracle) secretValues() map[string]string {
	return map[string]string{
		o.Password: "[password]",
	}
}

func (o *Oracle) Initialize(ctx context.Context, req dbplugin.InitializeRequest) (dbplugin.InitializeResponse, error) {
	tlsSettings, err := dbtlsutil.Decode(req.Config)
	if err != nil {
		return dbplugin.InitializeResponse{}, fmt.Errorf("invalid TLS configuration: %w", err)
	}
	if tlsSettings.Configured() {
		o.OpenDB = func(_ string, dataSourceName string) (*sql.DB, error) {
			parsed, err := url.Parse(dataSourceName)
			if err != nil {
				return nil, fmt.Errorf("failed to parse Oracle connection URL: %w", err)
			}
			tlsConfig, err := tlsSettings.Build(parsed.Hostname())
			if err != nil {
				return nil, err
			}
			query := parsed.Query()
			query.Set("SSL", "enabled")
			query.Set("SSL VERIFY", fmt.Sprintf("%t", !tlsSettings.SkipVerify))
			parsed.RawQuery = query.Encode()

			connector := go_ora.NewConnector(parsed.String()).(*go_ora.OracleConnector)
			connector.WithTLSConfig(tlsConfig)
			return sql.OpenDB(connector), nil
		}
	} else {
		o.OpenDB = nil
	}

	newConf, err := o.Init(ctx, req.Config, req.VerifyConnection)
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
	o.usernameProducer = up

	if _, err := o.usernameProducer.Generate(dbplugin.UsernameMetadata{}); err != nil {
		return dbplugin.InitializeResponse{}, fmt.Errorf("invalid username template: %w", err)
	}

	return dbplugin.InitializeResponse{Config: newConf}, nil
}

func (o *Oracle) Type() (string, error) {
	return oracleTypeName, nil
}

func (o *Oracle) PluginVersion() logical.PluginVersion {
	return logical.PluginVersion{Version: ReportedVersion}
}

func (o *Oracle) getConnection(ctx context.Context) (*sql.DB, error) {
	db, err := o.Connection(ctx)
	if err != nil {
		return nil, err
	}
	return db.(*sql.DB), nil
}

// NewUser executes creation_statements in a single Oracle session. Oracle
// does not support multi-statement transactions over DDL (CREATE USER is
// auto-committed) so the "transaction" here is logical; failures past the
// first statement leave a partially-created user, which the lease revoke
// will clean up.
func (o *Oracle) NewUser(ctx context.Context, req dbplugin.NewUserRequest) (dbplugin.NewUserResponse, error) {
	o.Lock()
	defer o.Unlock()

	if len(req.Statements.Commands) == 0 {
		return dbplugin.NewUserResponse{}, dbutil.ErrEmptyCreationStatement
	}

	db, err := o.getConnection(ctx)
	if err != nil {
		return dbplugin.NewUserResponse{}, fmt.Errorf("unable to get connection: %w", err)
	}

	username, err := o.usernameProducer.Generate(req.UsernameConfig)
	if err != nil {
		return dbplugin.NewUserResponse{}, err
	}

	// Oracle identifiers without quotes are case-folded to upper. Replace
	// punctuation that can come from OpenBao/KubeVault role names but is
	// illegal in unquoted Oracle identifiers.
	username = strings.NewReplacer("-", "_", ".", "_").Replace(username)
	username = strings.ToUpper(username)

	expirationStr := req.Expiration.UTC().Format("2006-01-02 15:04:05")

	merr := &multierror.Error{}
	for _, stmt := range req.Statements.Commands {
		for _, query := range strutil.ParseArbitraryStringSlice(stmt, ";") {
			query = strings.TrimSpace(query)
			if query == "" {
				continue
			}

			m := map[string]string{
				"name":       username,
				"username":   username,
				"password":   req.Password,
				"expiration": expirationStr,
			}

			if err := dbtxn.ExecuteDBQueryDirect(ctx, db, m, query); err != nil {
				merr = multierror.Append(merr, fmt.Errorf("failed to execute query: %w", err))
				return dbplugin.NewUserResponse{Username: username}, merr.ErrorOrNil()
			}
		}
	}

	return dbplugin.NewUserResponse{Username: username}, nil
}

// UpdateUser supports password change. Oracle has no native VALID UNTIL on
// users, so Expiration is informational only.
func (o *Oracle) UpdateUser(ctx context.Context, req dbplugin.UpdateUserRequest) (dbplugin.UpdateUserResponse, error) {
	if req.Username == "" {
		return dbplugin.UpdateUserResponse{}, errors.New("missing username")
	}
	if req.Password == nil && req.Expiration == nil {
		return dbplugin.UpdateUserResponse{}, errors.New("no changes requested")
	}

	if req.Password != nil {
		if err := o.changeUserPassword(ctx, req.Username, req.Password); err != nil {
			return dbplugin.UpdateUserResponse{}, err
		}
	}
	return dbplugin.UpdateUserResponse{}, nil
}

func (o *Oracle) changeUserPassword(ctx context.Context, username string, req *dbplugin.ChangePassword) error {
	password := req.NewPassword
	if username == "" || password == "" {
		return errors.New("must provide both username and password")
	}

	stmts := req.Statements.Commands
	if len(stmts) == 0 {
		stmts = []string{defaultChangePasswordStatement}
	}

	o.Lock()
	defer o.Unlock()

	db, err := o.getConnection(ctx)
	if err != nil {
		return err
	}

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
			if err := dbtxn.ExecuteDBQueryDirect(ctx, db, m, query); err != nil {
				return fmt.Errorf("failed to execute query: %w", err)
			}
		}
	}

	return nil
}

// DeleteUser runs custom revocation_statements if provided, otherwise the
// default revoke (drop the user with CASCADE) against a quoted identifier.
func (o *Oracle) DeleteUser(ctx context.Context, req dbplugin.DeleteUserRequest) (dbplugin.DeleteUserResponse, error) {
	o.Lock()
	defer o.Unlock()

	if len(req.Statements.Commands) == 0 {
		return dbplugin.DeleteUserResponse{}, o.defaultRevoke(ctx, req.Username)
	}

	db, err := o.getConnection(ctx)
	if err != nil {
		return dbplugin.DeleteUserResponse{}, err
	}

	merr := &multierror.Error{}
	for _, stmt := range req.Statements.Commands {
		for _, query := range strutil.ParseArbitraryStringSlice(stmt, ";") {
			query = strings.TrimSpace(query)
			if query == "" {
				continue
			}

			m := map[string]string{"name": req.Username, "username": req.Username}
			if err := dbtxn.ExecuteDBQueryDirect(ctx, db, m, query); err != nil {
				merr = multierror.Append(merr, err)
			}
		}
	}

	return dbplugin.DeleteUserResponse{}, merr.ErrorOrNil()
}

func (o *Oracle) defaultRevoke(ctx context.Context, username string) error {
	db, err := o.getConnection(ctx)
	if err != nil {
		return err
	}

	// Identifier interpolation is unavoidable for Oracle DDL; quote first.
	quoted := dbutil.QuoteIdentifier(username)

	// Kill any active sessions first so DROP USER doesn't fail with
	// ORA-01940 ("cannot drop a user that is currently connected").
	rows, err := db.QueryContext(ctx,
		`SELECT sid, serial# FROM v$session WHERE username = :1`, strings.ToUpper(username))
	if err == nil {
		defer rows.Close() //nolint:errcheck
		for rows.Next() {
			var sid, serial int
			if err := rows.Scan(&sid, &serial); err == nil {
				_, _ = db.ExecContext(ctx, fmt.Sprintf("ALTER SYSTEM KILL SESSION '%d,%d' IMMEDIATE", sid, serial))
			}
		}
	}
	// If the query failed (e.g. caller lacks SELECT on v$session), fall
	// through to DROP USER and let Oracle surface a clean error.

	if _, err := db.ExecContext(ctx, fmt.Sprintf("DROP USER %s CASCADE", quoted)); err != nil {
		return fmt.Errorf("failed to drop user: %w", err)
	}
	return nil
}
