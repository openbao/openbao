// Copyright (c) AppsCode Inc.
// SPDX-License-Identifier: MPL-2.0

// Package ignite implements an OpenBao v5 database plugin for Apache
// Ignite using the thin client binary protocol (port 10800). Dynamic
// credentials become native SQL users created via CREATE USER / ALTER
// USER / DROP USER, which Ignite 2.5+ supports when persistence is
// enabled and `authenticationEnabled=true` is set on the cluster.
package ignite

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	ignite "github.com/amsokol/ignite-go-client/binary/v1"
	"github.com/hashicorp/go-secure-stdlib/strutil"
	"github.com/mitchellh/mapstructure"
	dbplugin "github.com/openbao/openbao/sdk/v2/database/dbplugin/v5"
	"github.com/openbao/openbao/sdk/v2/database/helper/dbutil"
	"github.com/openbao/openbao/sdk/v2/helper/template"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/v2/internal/helper/dbtlsutil"
)

const (
	igniteTypeName = "ignite"

	defaultPort = 10800

	// Ignite identifiers are case-folded and capped. Cap at 32 for safety.
	defaultUserNameTemplate = `{{ printf "v_%s_%s_%s" (.DisplayName | truncate 8) (.RoleName | truncate 8) (random 8) | replace "-" "_" | uppercase | truncate 32 }}`

	dialTimeout = 10 * time.Second
	queryLimit  = 30 * time.Second
)

// ReportedVersion is overridable at build time.
var ReportedVersion = ""

// Ignite implements dbplugin.Database over the Ignite thin client
// binary protocol. Statements run through OP_QUERY_SQL_FIELDS with no
// bound cache, so user-management DDL does not require any cache to
// exist on the cluster.
type Ignite struct {
	mu sync.Mutex

	config           *igniteConfig
	usernameProducer template.StringTemplate
}

type igniteConfig struct {
	// URL is accepted for backwards compatibility with configs written
	// for the REST-based plugin; only host and port are used.
	URL string `mapstructure:"url"`
	// Host and Port override whatever URL provides.
	Host string `mapstructure:"host"`
	Port int    `mapstructure:"port"`

	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`

	tls dbtlsutil.Config
}

var (
	_ dbplugin.Database       = (*Ignite)(nil)
	_ logical.PluginVersioner = (*Ignite)(nil)
)

func New() (any, error) {
	db := newIgnite()
	return dbplugin.NewDatabaseErrorSanitizerMiddleware(db, db.secretValues), nil
}

func newIgnite() *Ignite {
	return &Ignite{}
}

func (i *Ignite) secretValues() map[string]string {
	if i.config == nil {
		return map[string]string{}
	}
	return map[string]string{i.config.Password: "[password]"}
}

func (i *Ignite) Type() (string, error) {
	return igniteTypeName, nil
}

func (i *Ignite) PluginVersion() logical.PluginVersion {
	return logical.PluginVersion{Version: ReportedVersion}
}

func (i *Ignite) Close() error {
	return nil
}

func (i *Ignite) Initialize(ctx context.Context, req dbplugin.InitializeRequest) (dbplugin.InitializeResponse, error) {
	i.mu.Lock()
	defer i.mu.Unlock()

	cfg := &igniteConfig{}
	if err := mapstructure.WeakDecode(req.Config, cfg); err != nil {
		return dbplugin.InitializeResponse{}, err
	}
	tlsSettings, err := dbtlsutil.Decode(req.Config)
	if err != nil {
		return dbplugin.InitializeResponse{}, err
	}
	cfg.tls = tlsSettings
	if err := normalizeTarget(cfg); err != nil {
		return dbplugin.InitializeResponse{}, err
	}
	if cfg.Username == "" || cfg.Password == "" {
		return dbplugin.InitializeResponse{}, errors.New("username and password are required")
	}

	if _, err := buildTLSConfig(cfg); err != nil {
		return dbplugin.InitializeResponse{}, err
	}

	usernameTemplate, err := strutil.GetString(req.Config, "username_template")
	if err != nil {
		return dbplugin.InitializeResponse{}, err
	}
	if usernameTemplate == "" {
		usernameTemplate = defaultUserNameTemplate
	}
	up, err := template.NewTemplate(template.Template(usernameTemplate))
	if err != nil {
		return dbplugin.InitializeResponse{}, fmt.Errorf("invalid username_template: %w", err)
	}
	if _, err := up.Generate(dbplugin.UsernameMetadata{}); err != nil {
		return dbplugin.InitializeResponse{}, fmt.Errorf("invalid username template: %w", err)
	}

	i.config = cfg
	i.usernameProducer = up

	if req.VerifyConnection {
		if err := i.withClient(ctx, func(c ignite.Client) error { return nil }); err != nil {
			return dbplugin.InitializeResponse{}, fmt.Errorf("failed to verify connection: %w", err)
		}
	}

	return dbplugin.InitializeResponse{Config: req.Config}, nil
}

// NewUser runs every command in creation_statements through the Ignite
// thin client protocol. Statements are not parameterized because
// Ignite's CREATE USER DDL doesn't accept bind parameters; instead, the
// username is uppercased + underscored and validated to a safe
// identifier set (rejects single quotes, semicolons, and double quotes).
func (i *Ignite) NewUser(ctx context.Context, req dbplugin.NewUserRequest) (dbplugin.NewUserResponse, error) {
	if len(req.Statements.Commands) == 0 {
		return dbplugin.NewUserResponse{}, dbutil.ErrEmptyCreationStatement
	}

	i.mu.Lock()
	defer i.mu.Unlock()

	username, err := i.usernameProducer.Generate(req.UsernameConfig)
	if err != nil {
		return dbplugin.NewUserResponse{}, err
	}
	username = strings.ToUpper(strings.ReplaceAll(username, "-", "_"))
	if err := safeIdentifier(username); err != nil {
		return dbplugin.NewUserResponse{}, err
	}
	if err := safePassword(req.Password); err != nil {
		return dbplugin.NewUserResponse{}, err
	}

	bindings := map[string]string{
		"name":     username,
		"username": username,
		"password": req.Password,
	}

	for _, stmt := range req.Statements.Commands {
		for _, q := range strutil.ParseArbitraryStringSlice(stmt, ";") {
			q = strings.TrimSpace(q)
			if q == "" {
				continue
			}
			rendered := renderTemplate(q, bindings)
			if err := i.execSQL(ctx, rendered); err != nil {
				return dbplugin.NewUserResponse{}, fmt.Errorf("execute creation statement: %w", err)
			}
		}
	}

	return dbplugin.NewUserResponse{Username: username}, nil
}

func (i *Ignite) UpdateUser(ctx context.Context, req dbplugin.UpdateUserRequest) (dbplugin.UpdateUserResponse, error) {
	if req.Username == "" {
		return dbplugin.UpdateUserResponse{}, errors.New("missing username")
	}
	if req.Password == nil && req.Expiration == nil {
		return dbplugin.UpdateUserResponse{}, errors.New("no changes requested")
	}
	if req.Password == nil {
		return dbplugin.UpdateUserResponse{}, nil
	}
	if err := safeIdentifier(req.Username); err != nil {
		return dbplugin.UpdateUserResponse{}, err
	}
	if err := safePassword(req.Password.NewPassword); err != nil {
		return dbplugin.UpdateUserResponse{}, err
	}

	i.mu.Lock()
	defer i.mu.Unlock()

	stmt := fmt.Sprintf(`ALTER USER "%s" WITH PASSWORD '%s'`, req.Username, req.Password.NewPassword)
	if err := i.execSQL(ctx, stmt); err != nil {
		return dbplugin.UpdateUserResponse{}, fmt.Errorf("alter user: %w", err)
	}
	return dbplugin.UpdateUserResponse{}, nil
}

func (i *Ignite) DeleteUser(ctx context.Context, req dbplugin.DeleteUserRequest) (dbplugin.DeleteUserResponse, error) {
	if err := safeIdentifier(req.Username); err != nil {
		return dbplugin.DeleteUserResponse{}, err
	}

	i.mu.Lock()
	defer i.mu.Unlock()

	stmts := req.Statements.Commands
	if len(stmts) == 0 {
		stmts = []string{fmt.Sprintf(`DROP USER "%s"`, req.Username)}
	}
	bindings := map[string]string{"name": req.Username, "username": req.Username}
	for _, s := range stmts {
		for _, q := range strutil.ParseArbitraryStringSlice(s, ";") {
			q = strings.TrimSpace(q)
			if q == "" {
				continue
			}
			rendered := renderTemplate(q, bindings)
			if err := i.execSQL(ctx, rendered); err != nil {
				return dbplugin.DeleteUserResponse{}, fmt.Errorf("execute revocation statement: %w", err)
			}
		}
	}
	return dbplugin.DeleteUserResponse{}, nil
}

// --- thin client helpers ----------------------------------------------------

// normalizeTarget resolves the host/port to dial. Explicit host/port
// fields win; otherwise they are parsed from url (scheme ignored), so
// configs written for the old REST plugin keep working.
func normalizeTarget(cfg *igniteConfig) error {
	host, port := cfg.Host, cfg.Port
	if host == "" && cfg.URL != "" {
		u, err := url.Parse(cfg.URL)
		if err != nil {
			return fmt.Errorf("unable to parse url: %w", err)
		}
		host = u.Hostname()
		if p := u.Port(); p != "" {
			var err error
			port, err = strconv.Atoi(p)
			if err != nil {
				return fmt.Errorf("unable to parse port in url: %w", err)
			}
		}
	}
	if host == "" {
		return errors.New("host or url is required")
	}
	if port == 0 {
		port = defaultPort
	}
	cfg.Host, cfg.Port = host, port
	return nil
}

func (cfg *igniteConfig) tlsConfigured() bool {
	return cfg != nil && cfg.tls.Configured()
}

func buildTLSConfig(cfg *igniteConfig) (*tls.Config, error) {
	if cfg == nil || !cfg.tlsConfigured() {
		return nil, nil
	}
	return cfg.tls.Build(cfg.Host)
}

// withClient opens a thin client connection, runs fn, and closes it.
// A fresh connection per call keeps reconnect logic trivial; credential
// operations are infrequent enough that the handshake cost is fine.
func (i *Ignite) withClient(ctx context.Context, fn func(c ignite.Client) error) error {
	cfg := i.config
	tlsCfg, err := buildTLSConfig(cfg)
	if err != nil {
		return err
	}

	dialer := net.Dialer{Timeout: dialTimeout}
	if deadline, ok := ctx.Deadline(); ok {
		dialer.Deadline = deadline
	}

	c, err := ignite.Connect(ignite.ConnInfo{
		Network:   "tcp",
		Host:      cfg.Host,
		Port:      cfg.Port,
		Major:     1,
		Minor:     1,
		Patch:     0,
		Username:  cfg.Username,
		Password:  cfg.Password,
		Dialer:    dialer,
		TLSConfig: tlsCfg,
	})
	if err != nil {
		return fmt.Errorf("failed to connect to %s:%d: %w", cfg.Host, cfg.Port, err)
	}
	defer c.Close() //nolint:errcheck

	return fn(c)
}

func (i *Ignite) execSQL(ctx context.Context, statement string) error {
	return i.withClient(ctx, func(c ignite.Client) error {
		timeout := queryLimit
		if deadline, ok := ctx.Deadline(); ok {
			timeout = time.Until(deadline)
			if timeout <= 0 {
				return ctx.Err()
			}
		}
		// The wire format carries a cache id derived from the Java string
		// hash of the cache name; 0 means "no cache". The library maps an
		// empty name to hash 1, so hand it a NUL string whose hash is 0.
		const noCache = "\x00\x00"
		_, err := c.QuerySQLFields(noCache, false, ignite.QuerySQLFieldsData{
			Schema:        "PUBLIC",
			Query:         statement,
			PageSize:      1,
			StatementType: ignite.StatementTypeAny,
			Timeout:       timeout.Milliseconds(),
		})
		return err
	})
}

// renderTemplate replaces {{key}} with bindings[key]. We deliberately do
// not use html/template here because Ignite DDL needs the values
// inserted literally (already validated by safeIdentifier/safePassword).
func renderTemplate(in string, bindings map[string]string) string {
	for k, v := range bindings {
		in = strings.ReplaceAll(in, "{{"+k+"}}", v)
	}
	return in
}

// safeIdentifier rejects identifiers that would break DDL string escaping.
func safeIdentifier(s string) error {
	if s == "" {
		return errors.New("empty identifier")
	}
	for _, r := range s {
		switch r {
		case '"', '\'', ';', '`':
			return fmt.Errorf("identifier %q contains forbidden character %q", s, r)
		}
	}
	return nil
}

// safePassword rejects passwords that would terminate the SQL string we
// build (single quote) — we don't want to introduce SQL injection in DDL.
func safePassword(p string) error {
	if p == "" {
		return errors.New("empty password")
	}
	if strings.ContainsRune(p, '\'') {
		return errors.New("password contains a single quote, which Ignite DDL can't escape safely")
	}
	return nil
}
