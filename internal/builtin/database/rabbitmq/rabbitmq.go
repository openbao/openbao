// Copyright (c) AppsCode Inc.
// SPDX-License-Identifier: MPL-2.0

// Package rabbitmq implements OpenBao's builtin v5 database plugin for
// RabbitMQ, using the management HTTP API via the rabbit-hole client.
// Dynamic credentials become RabbitMQ internal-realm users with per-vhost
// configure/write/read regex permissions plus optional vhost-topic
// permissions.
//
// This supersedes OpenBao's former standalone `rabbitmq/` secrets engine:
// same user-management semantics, but exposed through the dbplugin v5
// contract so it shares roles, lease tracking, and remote-db-plugin support
// with the rest of the database plugins.
package rabbitmq

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"

	cleanhttp "github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/go-secure-stdlib/strutil"
	rabbithole "github.com/michaelklishin/rabbit-hole/v3"
	"github.com/mitchellh/mapstructure"
	dbplugin "github.com/openbao/openbao/sdk/v2/database/dbplugin/v5"
	"github.com/openbao/openbao/sdk/v2/database/helper/dbutil"
	"github.com/openbao/openbao/sdk/v2/helper/template"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/v2/internal/helper/dbtlsutil"
)

const (
	rabbitmqTypeName = "rabbitmq"

	defaultUserNameTemplate = `{{ printf "v-%s-%s-%s-%s" (.DisplayName | truncate 15) (.RoleName | truncate 15) (random 20) (unix_time) | replace "." "-" | truncate 100 }}`
)

// ReportedVersion is overridable at build time.
var ReportedVersion = ""

// RabbitMQ implements dbplugin.Database against the RabbitMQ management
// HTTP API. creation_statements carry a JSON role document with optional
// tags, vhost permissions, and vhost-topic permissions.
type RabbitMQ struct {
	mu sync.Mutex

	config           *rmqConfig
	client           *rabbithole.Client
	usernameProducer template.StringTemplate
}

type rmqConfig struct {
	ConnectionURI    string `mapstructure:"connection_uri"`
	Username         string `mapstructure:"username"`
	Password         string `mapstructure:"password"`
	VerifyConnection bool   `mapstructure:"verify_connection"`

	// TLS fields are config-level, not part of creation_statements.
	tls dbtlsutil.Config
}

// rmqStatement is the role document an operator puts in
// `creation_statements`. The shape mirrors OpenBao's former standalone
// `rabbitmq/roles/...` schema so operators familiar with it can reuse what
// they know.
type rmqStatement struct {
	Tags        string                             `json:"tags"`
	VHosts      map[string]rmqPerm                 `json:"vhosts"`
	VHostTopics map[string]map[string]rmqTopicPerm `json:"vhost_topics"`
}

type rmqPerm struct {
	Configure string `json:"configure"`
	Write     string `json:"write"`
	Read      string `json:"read"`
}

type rmqTopicPerm struct {
	Write string `json:"write"`
	Read  string `json:"read"`
}

var (
	_ dbplugin.Database       = (*RabbitMQ)(nil)
	_ logical.PluginVersioner = (*RabbitMQ)(nil)
)

func New() (any, error) {
	db := newRabbitMQ()
	return dbplugin.NewDatabaseErrorSanitizerMiddleware(db, db.secretValues), nil
}

func newRabbitMQ() *RabbitMQ {
	return &RabbitMQ{}
}

func (r *RabbitMQ) secretValues() map[string]string {
	if r.config == nil {
		return map[string]string{}
	}
	return map[string]string{r.config.Password: "[password]"}
}

func (r *RabbitMQ) Type() (string, error) {
	return rabbitmqTypeName, nil
}

func (r *RabbitMQ) PluginVersion() logical.PluginVersion {
	return logical.PluginVersion{Version: ReportedVersion}
}

func (r *RabbitMQ) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.client = nil
	return nil
}

func (r *RabbitMQ) Initialize(ctx context.Context, req dbplugin.InitializeRequest) (dbplugin.InitializeResponse, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	cfg := &rmqConfig{}
	if err := mapstructure.WeakDecode(req.Config, cfg); err != nil {
		return dbplugin.InitializeResponse{}, err
	}
	tlsSettings, err := dbtlsutil.Decode(req.Config)
	if err != nil {
		return dbplugin.InitializeResponse{}, err
	}
	cfg.tls = tlsSettings
	if cfg.ConnectionURI == "" {
		return dbplugin.InitializeResponse{}, errors.New("connection_uri is required")
	}
	if cfg.Username == "" || cfg.Password == "" {
		return dbplugin.InitializeResponse{}, errors.New("username and password are required")
	}

	tlsConfig, err := makeTLSConfig(cfg)
	if err != nil {
		return dbplugin.InitializeResponse{}, err
	}

	// Use a default pooled transport so there would be no leaked file descriptors.
	transport := cleanhttp.DefaultPooledTransport()
	if tlsConfig != nil {
		transport.TLSClientConfig = tlsConfig
	}

	client, err := rabbithole.NewTLSClient(cfg.ConnectionURI, cfg.Username, cfg.Password, transport)
	if err != nil {
		return dbplugin.InitializeResponse{}, fmt.Errorf("rabbitmq client: %w", err)
	}
	client.SetTransport(transport)

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

	if req.VerifyConnection {
		if _, err := client.Overview(); err != nil {
			return dbplugin.InitializeResponse{}, fmt.Errorf("failed to verify connection: %w", err)
		}
	}

	r.config = cfg
	r.client = client
	r.usernameProducer = up

	return dbplugin.InitializeResponse{Config: req.Config}, nil
}

func (r *RabbitMQ) NewUser(ctx context.Context, req dbplugin.NewUserRequest) (dbplugin.NewUserResponse, error) {
	if len(req.Statements.Commands) == 0 {
		return dbplugin.NewUserResponse{}, dbutil.ErrEmptyCreationStatement
	}

	var stmt rmqStatement
	if err := json.Unmarshal([]byte(req.Statements.Commands[0]), &stmt); err != nil {
		return dbplugin.NewUserResponse{}, fmt.Errorf("creation_statements must be a JSON role doc: %w", err)
	}
	if len(stmt.VHosts) == 0 && stmt.Tags == "" {
		return dbplugin.NewUserResponse{}, errors.New("creation_statements requires at least one of: vhosts, tags")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	username, err := r.usernameProducer.Generate(req.UsernameConfig)
	if err != nil {
		return dbplugin.NewUserResponse{}, err
	}

	settings := rabbithole.UserSettings{
		Password: req.Password,
		Tags:     parseTags(stmt.Tags),
	}
	if _, err := r.client.PutUser(username, settings); err != nil {
		return dbplugin.NewUserResponse{}, fmt.Errorf("create rabbitmq user: %w", err)
	}

	// Best-effort cleanup on partial failure: if a permission update fails,
	// delete the user so we don't leave a half-configured account behind.
	cleanup := func(opErr error) (dbplugin.NewUserResponse, error) {
		_, _ = r.client.DeleteUser(username)
		return dbplugin.NewUserResponse{}, opErr
	}

	for vhost, perm := range stmt.VHosts {
		if _, err := r.client.UpdatePermissionsIn(vhost, username, rabbithole.Permissions{
			Configure: perm.Configure,
			Write:     perm.Write,
			Read:      perm.Read,
		}); err != nil {
			return cleanup(fmt.Errorf("set permissions on vhost %q: %w", vhost, err))
		}
	}
	for vhost, topics := range stmt.VHostTopics {
		for topic, tp := range topics {
			if _, err := r.client.UpdateTopicPermissionsIn(vhost, username, rabbithole.TopicPermissions{
				Exchange: topic,
				Write:    tp.Write,
				Read:     tp.Read,
			}); err != nil {
				return cleanup(fmt.Errorf("set topic permissions on vhost %q topic %q: %w", vhost, topic, err))
			}
		}
	}

	return dbplugin.NewUserResponse{Username: username}, nil
}

func (r *RabbitMQ) UpdateUser(ctx context.Context, req dbplugin.UpdateUserRequest) (dbplugin.UpdateUserResponse, error) {
	if req.Username == "" {
		return dbplugin.UpdateUserResponse{}, errors.New("missing username")
	}
	if req.Password == nil && req.Expiration == nil {
		return dbplugin.UpdateUserResponse{}, errors.New("no changes requested")
	}
	if req.Password == nil {
		// RabbitMQ has no native VALID UNTIL; expiration is informational.
		return dbplugin.UpdateUserResponse{}, nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// PutUser with an existing username updates the password (and tags).
	// We don't have the tags here, so re-fetch them to preserve. This is
	// also how root-credential rotation (database/rotate-root/:name) picks
	// up a new password for the connection's admin user.
	existing, err := r.client.GetUser(req.Username)
	if err != nil {
		return dbplugin.UpdateUserResponse{}, fmt.Errorf("fetch existing user: %w", err)
	}
	if _, err := r.client.PutUser(req.Username, rabbithole.UserSettings{
		Password: req.Password.NewPassword,
		Tags:     existing.Tags,
	}); err != nil {
		return dbplugin.UpdateUserResponse{}, fmt.Errorf("update password: %w", err)
	}
	return dbplugin.UpdateUserResponse{}, nil
}

func (r *RabbitMQ) DeleteUser(ctx context.Context, req dbplugin.DeleteUserRequest) (dbplugin.DeleteUserResponse, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	resp, err := r.client.DeleteUser(req.Username)
	if err != nil {
		// 404 is idempotent.
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			return dbplugin.DeleteUserResponse{}, nil
		}
		return dbplugin.DeleteUserResponse{}, fmt.Errorf("delete rabbitmq user: %w", err)
	}
	return dbplugin.DeleteUserResponse{}, nil
}

// parseTags splits the comma-separated tag string from a role document
// into the slice form rabbit-hole v3 expects.
func parseTags(s string) rabbithole.UserTags {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make(rabbithole.UserTags, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// makeTLSConfig builds a *tls.Config from the config's TLS fields. It
// returns (nil, nil) when no TLS field is set, so callers fall back to the
// Go default TLS behavior.
func makeTLSConfig(cfg *rmqConfig) (*tls.Config, error) {
	if !cfg.tls.Configured() {
		return nil, nil
	}
	return cfg.tls.Build("")
}
