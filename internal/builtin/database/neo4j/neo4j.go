// Copyright (c) AppsCode Inc.
// SPDX-License-Identifier: MPL-2.0

// Package neo4j implements an OpenBao v5 database plugin for Neo4j 4+.
// Dynamic credentials become native users created via Cypher's
// CREATE USER syntax against the `system` database; permissions come from
// pre-existing roles named in creation_statements.
package neo4j

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sync"

	"github.com/hashicorp/go-secure-stdlib/strutil"
	"github.com/mitchellh/mapstructure"
	neo4j "github.com/neo4j/neo4j-go-driver/v5/neo4j"
	neo4jconfig "github.com/neo4j/neo4j-go-driver/v5/neo4j/config"
	dbplugin "github.com/openbao/openbao/sdk/v2/database/dbplugin/v5"
	"github.com/openbao/openbao/sdk/v2/database/helper/dbutil"
	"github.com/openbao/openbao/sdk/v2/helper/template"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/v2/internal/helper/dbtlsutil"
)

const (
	neo4jTypeName = "neo4j"

	// Neo4j allows long identifiers but the practical convention is short
	// lower-case names. Cap at 60 to stay well under any server limit.
	defaultUserNameTemplate = `{{ printf "v-%s-%s-%s-%s" (.DisplayName | truncate 10) (.RoleName | truncate 10) (random 15) (unix_time) | replace "." "-" | truncate 60 }}`
)

// ReportedVersion is overridable at build time.
var ReportedVersion = ""

// Neo4j implements dbplugin.Database. creation_statements is a JSON
// document `{"roles":["role1","role2"]}` listing pre-existing Neo4j
// roles to grant the new user.
type Neo4j struct {
	mu sync.Mutex

	config           *neo4jConfig
	driver           neo4j.DriverWithContext
	usernameProducer template.StringTemplate
}

type neo4jConfig struct {
	URI      string `mapstructure:"uri"`
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
	Database string `mapstructure:"database"` // defaults to "system"
}

type neo4jStatement struct {
	Roles []string `json:"roles"`
}

var (
	_ dbplugin.Database       = (*Neo4j)(nil)
	_ logical.PluginVersioner = (*Neo4j)(nil)
)

func New() (any, error) {
	db := newNeo4j()
	return dbplugin.NewDatabaseErrorSanitizerMiddleware(db, db.secretValues), nil
}

func newNeo4j() *Neo4j {
	return &Neo4j{}
}

func (n *Neo4j) secretValues() map[string]string {
	if n.config == nil {
		return map[string]string{}
	}
	return map[string]string{n.config.Password: "[password]"}
}

func (n *Neo4j) Type() (string, error) {
	return neo4jTypeName, nil
}

func (n *Neo4j) PluginVersion() logical.PluginVersion {
	return logical.PluginVersion{Version: ReportedVersion}
}

func (n *Neo4j) Close() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.driver != nil {
		_ = n.driver.Close(context.Background())
	}
	n.driver = nil
	return nil
}

func (n *Neo4j) Initialize(ctx context.Context, req dbplugin.InitializeRequest) (dbplugin.InitializeResponse, error) {
	n.mu.Lock()
	defer n.mu.Unlock()

	cfg := &neo4jConfig{}
	if err := mapstructure.WeakDecode(req.Config, cfg); err != nil {
		return dbplugin.InitializeResponse{}, err
	}
	if cfg.URI == "" {
		return dbplugin.InitializeResponse{}, errors.New("uri is required")
	}
	if cfg.Username == "" || cfg.Password == "" {
		return dbplugin.InitializeResponse{}, errors.New("username and password are required")
	}
	if cfg.Database == "" {
		cfg.Database = "system"
	}

	tlsSettings, err := dbtlsutil.Decode(req.Config)
	if err != nil {
		return dbplugin.InitializeResponse{}, fmt.Errorf("invalid TLS configuration: %w", err)
	}
	parsedURI, err := url.Parse(cfg.URI)
	if err != nil {
		return dbplugin.InitializeResponse{}, fmt.Errorf("invalid Neo4j URI: %w", err)
	}
	if tlsSettings.Configured() || parsedURI.Scheme == "bolt+ssc" || parsedURI.Scheme == "neo4j+ssc" {
		parsedURI.Scheme, err = secureScheme(parsedURI.Scheme, tlsSettings.SkipVerify)
		if err != nil {
			return dbplugin.InitializeResponse{}, err
		}
		cfg.URI = parsedURI.String()
	}

	var configurers []func(*neo4jconfig.Config)
	if tlsSettings.Configured() {
		tlsConfig, err := tlsSettings.Build(parsedURI.Hostname())
		if err != nil {
			return dbplugin.InitializeResponse{}, err
		}
		configurers = append(configurers, func(config *neo4jconfig.Config) {
			config.TlsConfig = tlsConfig
		})
	}
	driver, err := neo4j.NewDriverWithContext(cfg.URI, neo4j.BasicAuth(cfg.Username, cfg.Password, ""), configurers...)
	if err != nil {
		return dbplugin.InitializeResponse{}, fmt.Errorf("neo4j driver: %w", err)
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

	n.config = cfg
	n.driver = driver
	n.usernameProducer = up

	if req.VerifyConnection {
		if err := driver.VerifyConnectivity(ctx); err != nil {
			return dbplugin.InitializeResponse{}, fmt.Errorf("verify neo4j connectivity: %w", err)
		}
	}

	return dbplugin.InitializeResponse{Config: req.Config}, nil
}

func secureScheme(scheme string, insecure bool) (string, error) {
	suffix := "+s"
	if insecure {
		suffix = "+ssc"
	}
	switch scheme {
	case "bolt", "bolt+s", "bolt+ssc":
		return "bolt" + suffix, nil
	case "neo4j", "neo4j+s", "neo4j+ssc":
		return "neo4j" + suffix, nil
	default:
		return "", fmt.Errorf("unsupported Neo4j URI scheme %q", scheme)
	}
}

// NewUser creates a user via Cypher and grants each role in the statement.
// CREATE USER is non-transactional in Neo4j, so on a per-role grant failure
// we attempt to DROP the user before returning so partial state doesn't
// linger.
func (n *Neo4j) NewUser(ctx context.Context, req dbplugin.NewUserRequest) (dbplugin.NewUserResponse, error) {
	if len(req.Statements.Commands) == 0 {
		return dbplugin.NewUserResponse{}, dbutil.ErrEmptyCreationStatement
	}

	var stmt neo4jStatement
	if err := json.Unmarshal([]byte(req.Statements.Commands[0]), &stmt); err != nil {
		return dbplugin.NewUserResponse{}, fmt.Errorf("creation_statements must be a JSON role doc: %w", err)
	}

	n.mu.Lock()
	defer n.mu.Unlock()

	if n.driver == nil || n.config == nil {
		return dbplugin.NewUserResponse{}, errors.New("database not initialized")
	}

	username, err := n.usernameProducer.Generate(req.UsernameConfig)
	if err != nil {
		return dbplugin.NewUserResponse{}, err
	}

	sess := n.driver.NewSession(ctx, neo4j.SessionConfig{DatabaseName: n.config.Database})
	defer sess.Close(ctx) //nolint:errcheck

	if _, err := sess.Run(
		ctx,
		"CREATE USER $name SET PASSWORD $password CHANGE NOT REQUIRED",
		map[string]any{"name": username, "password": req.Password},
	); err != nil {
		return dbplugin.NewUserResponse{}, fmt.Errorf("create neo4j user: %w", err)
	}

	cleanup := func(opErr error) (dbplugin.NewUserResponse, error) {
		_, _ = sess.Run(ctx, "DROP USER $name", map[string]any{"name": username})
		return dbplugin.NewUserResponse{}, opErr
	}

	for _, role := range stmt.Roles {
		if role == "" {
			continue
		}
		// Role identifiers can't be parameterized in Cypher; quote with
		// backticks and reject role names that contain backticks themselves.
		if containsBacktick(role) {
			return cleanup(fmt.Errorf("role name %q contains a backtick", role))
		}
		query := fmt.Sprintf("GRANT ROLE `%s` TO $name", role)
		if _, err := sess.Run(ctx, query, map[string]any{"name": username}); err != nil {
			return cleanup(fmt.Errorf("grant role %q: %w", role, err))
		}
	}

	return dbplugin.NewUserResponse{Username: username}, nil
}

func (n *Neo4j) UpdateUser(ctx context.Context, req dbplugin.UpdateUserRequest) (dbplugin.UpdateUserResponse, error) {
	if req.Username == "" {
		return dbplugin.UpdateUserResponse{}, errors.New("missing username")
	}
	if req.Password == nil && req.Expiration == nil {
		return dbplugin.UpdateUserResponse{}, errors.New("no changes requested")
	}
	if req.Password == nil {
		return dbplugin.UpdateUserResponse{}, nil
	}

	n.mu.Lock()
	defer n.mu.Unlock()

	if n.driver == nil || n.config == nil {
		return dbplugin.UpdateUserResponse{}, errors.New("database not initialized")
	}

	sess := n.driver.NewSession(ctx, neo4j.SessionConfig{DatabaseName: n.config.Database})
	defer sess.Close(ctx) //nolint:errcheck

	if _, err := sess.Run(
		ctx,
		"ALTER USER $name SET PASSWORD $password CHANGE NOT REQUIRED",
		map[string]any{"name": req.Username, "password": req.Password.NewPassword},
	); err != nil {
		return dbplugin.UpdateUserResponse{}, fmt.Errorf("alter neo4j user: %w", err)
	}
	return dbplugin.UpdateUserResponse{}, nil
}

func (n *Neo4j) DeleteUser(ctx context.Context, req dbplugin.DeleteUserRequest) (dbplugin.DeleteUserResponse, error) {
	if req.Username == "" {
		return dbplugin.DeleteUserResponse{}, errors.New("missing username")
	}

	n.mu.Lock()
	defer n.mu.Unlock()

	if n.driver == nil || n.config == nil {
		return dbplugin.DeleteUserResponse{}, errors.New("database not initialized")
	}

	sess := n.driver.NewSession(ctx, neo4j.SessionConfig{DatabaseName: n.config.Database})
	defer sess.Close(ctx) //nolint:errcheck

	if _, err := sess.Run(
		ctx,
		"DROP USER $name IF EXISTS",
		map[string]any{"name": req.Username},
	); err != nil {
		return dbplugin.DeleteUserResponse{}, fmt.Errorf("drop neo4j user: %w", err)
	}
	return dbplugin.DeleteUserResponse{}, nil
}

func containsBacktick(s string) bool {
	for _, r := range s {
		if r == '`' {
			return true
		}
	}
	return false
}
