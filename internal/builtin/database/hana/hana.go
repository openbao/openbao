// Copyright (c) HashiCorp, Inc.
// Copyright (c) AppsCode Inc.
// SPDX-License-Identifier: MPL-2.0

package hana

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"

	hdbdriver "github.com/SAP/go-hdb/driver"
	"github.com/hashicorp/go-secure-stdlib/strutil"
	"github.com/openbao/openbao/sdk/v2/database/dbplugin/v5"
	"github.com/openbao/openbao/sdk/v2/database/helper/connutil"
	"github.com/openbao/openbao/sdk/v2/database/helper/dbutil"
	"github.com/openbao/openbao/sdk/v2/helper/dbtxn"
	"github.com/openbao/openbao/sdk/v2/helper/template"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/v2/internal/helper/dbtlsutil"
)

const (
	hanaTypeName = "hdb"

	defaultUserNameTemplate = `{{ printf "v_%s_%s_%s_%s" (.DisplayName | truncate 32) (.RoleName | truncate 20) (random 20) (unix_time) | truncate 127 | replace "-" "_" | uppercase }}`
)

// ReportedVersion is wired in at build time so the plugin version surfaces in
// plugin-info responses. Matches the pattern other built-in DB plugins use.
var ReportedVersion = ""

// HANA implements the v5 dbplugin.Database contract against SAP HANA. It
// embeds connutil.SQLConnectionProducer so every connection_url, root
// rotation, and namespace-scoped mount lifecycle gets the same plumbing the
// rest of OpenBao's built-in SQL plugins use.
type HANA struct {
	*connutil.SQLConnectionProducer

	usernameProducer template.StringTemplate
}

var (
	_ dbplugin.Database       = (*HANA)(nil)
	_ logical.PluginVersioner = (*HANA)(nil)
)

// New is the factory entry point referenced from helper/builtinplugins/registry.go.
func New() (any, error) {
	db := newHANA()
	dbType := dbplugin.NewDatabaseErrorSanitizerMiddleware(db, db.secretValues)
	return dbType, nil
}

func newHANA() *HANA {
	connProducer := &connutil.SQLConnectionProducer{}
	connProducer.Type = hanaTypeName
	return &HANA{SQLConnectionProducer: connProducer}
}

func (h *HANA) secretValues() map[string]string {
	return map[string]string{
		h.Password: "[password]",
	}
}

func (h *HANA) Initialize(ctx context.Context, req dbplugin.InitializeRequest) (dbplugin.InitializeResponse, error) {
	tlsSettings, err := dbtlsutil.Decode(req.Config)
	if err != nil {
		return dbplugin.InitializeResponse{}, fmt.Errorf("invalid TLS configuration: %w", err)
	}
	if tlsSettings.Configured() {
		h.OpenDB = func(_ string, dataSourceName string) (*sql.DB, error) {
			parsed, err := url.Parse(dataSourceName)
			if err != nil {
				return nil, fmt.Errorf("failed to parse HANA connection URL: %w", err)
			}
			tlsConfig, err := tlsSettings.Build(parsed.Hostname())
			if err != nil {
				return nil, err
			}
			connector, err := hdbdriver.NewDSNConnector(dataSourceName)
			if err != nil {
				return nil, fmt.Errorf("failed to create HANA connector: %w", err)
			}
			connector.SetTLSConfig(tlsConfig)
			return sql.OpenDB(connector), nil
		}
	} else {
		h.OpenDB = nil
	}

	conf, err := h.Init(ctx, req.Config, req.VerifyConnection)
	if err != nil {
		return dbplugin.InitializeResponse{}, fmt.Errorf("error initializing db: %w", err)
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
	h.usernameProducer = up

	if _, err := h.usernameProducer.Generate(dbplugin.UsernameMetadata{}); err != nil {
		return dbplugin.InitializeResponse{}, fmt.Errorf("invalid username template: %w", err)
	}

	return dbplugin.InitializeResponse{Config: conf}, nil
}

func (h *HANA) Type() (string, error) {
	return hanaTypeName, nil
}

func (h *HANA) PluginVersion() logical.PluginVersion {
	return logical.PluginVersion{Version: ReportedVersion}
}

func (h *HANA) getConnection(ctx context.Context) (*sql.DB, error) {
	db, err := h.Connection(ctx)
	if err != nil {
		return nil, err
	}
	return db.(*sql.DB), nil
}

// NewUser executes the configured creation_statements against HANA in one
// transaction. The generated username is uppercased and has hyphens replaced
// with underscores because HANA identifiers are case-folded and reject
// hyphens.
func (h *HANA) NewUser(ctx context.Context, req dbplugin.NewUserRequest) (dbplugin.NewUserResponse, error) {
	h.Lock()
	defer h.Unlock()

	db, err := h.getConnection(ctx)
	if err != nil {
		return dbplugin.NewUserResponse{}, err
	}

	if len(req.Statements.Commands) == 0 {
		return dbplugin.NewUserResponse{}, dbutil.ErrEmptyCreationStatement
	}

	username, err := h.usernameProducer.Generate(req.UsernameConfig)
	if err != nil {
		return dbplugin.NewUserResponse{}, err
	}

	// HANA user names must be undelimited identifiers. Metadata supplied by
	// orchestrators commonly contains dots and hyphens, so normalize all SQL
	// punctuation to underscores before storing the username in the lease.
	username = strings.Map(func(r rune) rune {
		if r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r) {
			return unicode.ToUpper(r)
		}
		return '_'
	}, username)
	if err := validateUsername(username); err != nil {
		return dbplugin.NewUserResponse{}, err
	}

	// HANA enforces the VALID UNTIL clause server-side, so the role-supplied
	// SQL alone is enough to deactivate the user even if OpenBao never sends
	// a revoke.
	expirationStr := req.Expiration.UTC().Format("2006-01-02 15:04:05")

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

func (h *HANA) UpdateUser(ctx context.Context, req dbplugin.UpdateUserRequest) (dbplugin.UpdateUserResponse, error) {
	h.Lock()
	defer h.Unlock()

	if req.Username == "" {
		return dbplugin.UpdateUserResponse{}, errors.New("missing username")
	}
	if err := validateUsername(req.Username); err != nil {
		return dbplugin.UpdateUserResponse{}, err
	}
	if req.Password == nil && req.Expiration == nil {
		return dbplugin.UpdateUserResponse{}, nil
	}

	db, err := h.getConnection(ctx)
	if err != nil {
		return dbplugin.UpdateUserResponse{}, err
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return dbplugin.UpdateUserResponse{}, err
	}
	defer tx.Rollback() //nolint:errcheck

	if req.Password != nil {
		if err := h.updateUserPassword(ctx, tx, req.Username, req.Password); err != nil {
			return dbplugin.UpdateUserResponse{}, err
		}
	}

	if req.Expiration != nil {
		if err := h.updateUserExpiration(ctx, tx, req.Username, req.Expiration); err != nil {
			return dbplugin.UpdateUserResponse{}, err
		}
	}

	if err := tx.Commit(); err != nil {
		return dbplugin.UpdateUserResponse{}, err
	}
	return dbplugin.UpdateUserResponse{}, nil
}

func (h *HANA) updateUserPassword(ctx context.Context, tx *sql.Tx, username string, req *dbplugin.ChangePassword) error {
	password := req.NewPassword
	if username == "" || password == "" {
		return errors.New("must provide both username and password")
	}

	stmts := req.Statements.Commands
	if len(stmts) == 0 {
		stmts = []string{`ALTER USER {{username}} PASSWORD "{{password}}" NO FORCE_FIRST_PASSWORD_CHANGE`}
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

			if err := dbtxn.ExecuteTxQueryDirect(ctx, tx, m, query); err != nil {
				return fmt.Errorf("failed to execute query: %w", err)
			}
		}
	}

	return nil
}

func (h *HANA) updateUserExpiration(ctx context.Context, tx *sql.Tx, username string, req *dbplugin.ChangeExpiration) error {
	expirationStr := req.NewExpiration.UTC().Format("2006-01-02 15:04:05")
	if username == "" || expirationStr == "" {
		return errors.New("must provide both username and expiration")
	}

	stmts := req.Statements.Commands
	if len(stmts) == 0 {
		stmts = []string{`ALTER USER {{username}} VALID UNTIL '{{expiration}}'`}
	}

	for _, stmt := range stmts {
		for _, query := range strutil.ParseArbitraryStringSlice(stmt, ";") {
			query = strings.TrimSpace(query)
			if query == "" {
				continue
			}

			m := map[string]string{
				"name":       username,
				"username":   username,
				"expiration": expirationStr,
			}

			if err := dbtxn.ExecuteTxQueryDirect(ctx, tx, m, query); err != nil {
				return fmt.Errorf("failed to execute query: %w", err)
			}
		}
	}

	return nil
}

// DeleteUser revokes the user. With no custom revocation_statements, runs
// the default soft-drop: deactivate the user, then DROP USER ... RESTRICT
// (drops only if no dependencies remain — same semantics as the upstream
// Vault plugin. HANA requires user names to be undelimited identifiers, so
// names are validated before interpolation instead of being quoted.
func (h *HANA) DeleteUser(ctx context.Context, req dbplugin.DeleteUserRequest) (dbplugin.DeleteUserResponse, error) {
	h.Lock()
	defer h.Unlock()
	if err := validateUsername(req.Username); err != nil {
		return dbplugin.DeleteUserResponse{}, err
	}

	if len(req.Statements.Commands) == 0 {
		return h.revokeUserDefault(ctx, req)
	}

	db, err := h.getConnection(ctx)
	if err != nil {
		return dbplugin.DeleteUserResponse{}, err
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return dbplugin.DeleteUserResponse{}, err
	}
	defer tx.Rollback() //nolint:errcheck

	for _, stmt := range req.Statements.Commands {
		for _, query := range strutil.ParseArbitraryStringSlice(stmt, ";") {
			query = strings.TrimSpace(query)
			if query == "" {
				continue
			}

			m := map[string]string{"name": req.Username}
			if err := dbtxn.ExecuteTxQueryDirect(ctx, tx, m, query); err != nil {
				return dbplugin.DeleteUserResponse{}, err
			}
		}
	}

	return dbplugin.DeleteUserResponse{}, tx.Commit()
}

func (h *HANA) revokeUserDefault(ctx context.Context, req dbplugin.DeleteUserRequest) (dbplugin.DeleteUserResponse, error) {
	db, err := h.getConnection(ctx)
	if err != nil {
		return dbplugin.DeleteUserResponse{}, err
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return dbplugin.DeleteUserResponse{}, err
	}
	defer tx.Rollback() //nolint:errcheck

	// HANA requires user names to be undelimited identifiers. DeleteUser
	// validates the name before it reaches this interpolation point.
	disable := fmt.Sprintf("ALTER USER %s DEACTIVATE USER NOW", req.Username)
	disableStmt, err := tx.PrepareContext(ctx, disable)
	if err != nil {
		return dbplugin.DeleteUserResponse{}, err
	}
	defer disableStmt.Close() //nolint:errcheck
	if _, err := disableStmt.ExecContext(ctx); err != nil {
		return dbplugin.DeleteUserResponse{}, err
	}

	drop := fmt.Sprintf("DROP USER %s RESTRICT", req.Username)
	dropStmt, err := tx.PrepareContext(ctx, drop)
	if err != nil {
		return dbplugin.DeleteUserResponse{}, err
	}
	defer dropStmt.Close() //nolint:errcheck
	if _, err := dropStmt.ExecContext(ctx); err != nil {
		return dbplugin.DeleteUserResponse{}, err
	}

	if err := tx.Commit(); err != nil {
		return dbplugin.DeleteUserResponse{}, err
	}

	return dbplugin.DeleteUserResponse{}, nil
}

// validateUsername restricts generated HANA users to identifiers that are
// safe to interpolate into user-management statements. HANA does not permit
// quoted (delimited) user names, and DDL identifiers cannot be parameters.
func validateUsername(username string) error {
	if username == "" {
		return errors.New("missing username")
	}
	if utf8.RuneCountInString(username) > 127 {
		return errors.New("username exceeds HANA's 127-character limit")
	}

	for i, r := range username {
		if (i == 0 && r != '_' && !unicode.IsLetter(r)) ||
			(i > 0 && r != '_' && !unicode.IsLetter(r) && !unicode.IsDigit(r)) {
			return fmt.Errorf("username %q is not a valid undelimited HANA identifier", username)
		}
	}
	return nil
}
