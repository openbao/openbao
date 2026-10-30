// Copyright (c) AppsCode Inc.
// SPDX-License-Identifier: MPL-2.0

// Package elasticsearch implements the OpenBao v5 database plugin for
// Elasticsearch and OpenSearch. The plugin talks to the native realm
// users API (/_security/user/...) over HTTP. Dynamic credentials map
// directly to native users with operator-specified roles.
package elasticsearch

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-secure-stdlib/strutil"
	"github.com/mitchellh/mapstructure"
	dbplugin "github.com/openbao/openbao/sdk/v2/database/dbplugin/v5"
	"github.com/openbao/openbao/sdk/v2/database/helper/dbutil"
	"github.com/openbao/openbao/sdk/v2/helper/template"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/v2/internal/helper/dbtlsutil"
)

const (
	esTypeName = "elasticsearch"

	defaultUserNameTemplate = `{{ printf "v-%s-%s-%s-%s" (.DisplayName | truncate 15) (.RoleName | truncate 15) (random 20) (unix_time) | replace "." "-" | truncate 100 }}`
)

// ReportedVersion is overridable at build time.
var ReportedVersion = ""

// Elasticsearch implements dbplugin.Database against the native realm
// users API. creation_statements are JSON role documents — a list of role
// names plus an optional full_name and metadata payload.
type Elasticsearch struct {
	mu sync.Mutex

	config           *esConfig
	httpClient       *http.Client
	usernameProducer template.StringTemplate
}

type esConfig struct {
	URL      string `mapstructure:"url"`
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`

	tls dbtlsutil.Config

	// UseOldXPackAPI toggles between the modern /_security/ prefix
	// (default; Elasticsearch 7+ and OpenSearch) and the legacy
	// /_xpack/security/ prefix (Elasticsearch 6).
	UseOldXPackAPI bool `mapstructure:"use_old_xpack"`
}

// esStatement is the role document operators put in creation_statements.
type esStatement struct {
	ElasticsearchRoles []string       `json:"elasticsearch_roles"`
	FullName           string         `json:"full_name"`
	Email              string         `json:"email"`
	Metadata           map[string]any `json:"metadata"`
}

var (
	_ dbplugin.Database       = (*Elasticsearch)(nil)
	_ logical.PluginVersioner = (*Elasticsearch)(nil)
)

func New() (any, error) {
	db := newES()
	return dbplugin.NewDatabaseErrorSanitizerMiddleware(db, db.secretValues), nil
}

func newES() *Elasticsearch {
	return &Elasticsearch{}
}

func (e *Elasticsearch) secretValues() map[string]string {
	if e.config == nil {
		return map[string]string{}
	}
	return map[string]string{e.config.Password: "[password]"}
}

func (e *Elasticsearch) Type() (string, error) {
	return esTypeName, nil
}

func (e *Elasticsearch) PluginVersion() logical.PluginVersion {
	return logical.PluginVersion{Version: ReportedVersion}
}

func (e *Elasticsearch) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.httpClient != nil {
		e.httpClient.CloseIdleConnections()
	}
	e.httpClient = nil
	return nil
}

func (e *Elasticsearch) Initialize(ctx context.Context, req dbplugin.InitializeRequest) (dbplugin.InitializeResponse, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	cfg := &esConfig{}
	if err := mapstructure.WeakDecode(req.Config, cfg); err != nil {
		return dbplugin.InitializeResponse{}, err
	}
	tlsSettings, err := dbtlsutil.Decode(req.Config)
	if err != nil {
		return dbplugin.InitializeResponse{}, err
	}
	cfg.tls = tlsSettings
	if cfg.URL == "" {
		return dbplugin.InitializeResponse{}, errors.New("url is required")
	}
	if cfg.Username == "" || cfg.Password == "" {
		return dbplugin.InitializeResponse{}, errors.New("username and password are required")
	}

	client, err := newHTTPClient(cfg)
	if err != nil {
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
		return dbplugin.InitializeResponse{}, fmt.Errorf("unable to initialize username template: %w", err)
	}
	if _, err := up.Generate(dbplugin.UsernameMetadata{}); err != nil {
		return dbplugin.InitializeResponse{}, fmt.Errorf("invalid username template: %w", err)
	}

	e.config = cfg
	e.httpClient = client
	e.usernameProducer = up

	if req.VerifyConnection {
		if err := e.healthcheck(ctx); err != nil {
			return dbplugin.InitializeResponse{}, fmt.Errorf("failed to verify connection: %w", err)
		}
	}

	return dbplugin.InitializeResponse{Config: req.Config}, nil
}

func (e *Elasticsearch) NewUser(ctx context.Context, req dbplugin.NewUserRequest) (dbplugin.NewUserResponse, error) {
	if len(req.Statements.Commands) == 0 {
		return dbplugin.NewUserResponse{}, dbutil.ErrEmptyCreationStatement
	}

	var stmt esStatement
	if err := json.Unmarshal([]byte(req.Statements.Commands[0]), &stmt); err != nil {
		return dbplugin.NewUserResponse{}, fmt.Errorf("creation_statements must be a JSON role doc: %w", err)
	}
	if len(stmt.ElasticsearchRoles) == 0 {
		return dbplugin.NewUserResponse{}, errors.New("elasticsearch_roles is required in creation_statements")
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	username, err := e.usernameProducer.Generate(req.UsernameConfig)
	if err != nil {
		return dbplugin.NewUserResponse{}, err
	}

	body := map[string]any{
		"password": req.Password,
		"roles":    stmt.ElasticsearchRoles,
	}
	if stmt.FullName != "" {
		body["full_name"] = stmt.FullName
	}
	if stmt.Email != "" {
		body["email"] = stmt.Email
	}
	if stmt.Metadata != nil {
		body["metadata"] = stmt.Metadata
	}

	if err := e.putUser(ctx, username, body); err != nil {
		return dbplugin.NewUserResponse{}, err
	}
	return dbplugin.NewUserResponse{Username: username}, nil
}

func (e *Elasticsearch) UpdateUser(ctx context.Context, req dbplugin.UpdateUserRequest) (dbplugin.UpdateUserResponse, error) {
	if req.Username == "" {
		return dbplugin.UpdateUserResponse{}, errors.New("missing username")
	}
	if req.Password == nil && req.Expiration == nil {
		return dbplugin.UpdateUserResponse{}, errors.New("no changes requested")
	}
	if req.Password == nil {
		// ES has no native VALID UNTIL; expiration updates are a no-op.
		return dbplugin.UpdateUserResponse{}, nil
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	return dbplugin.UpdateUserResponse{}, e.changePassword(ctx, req.Username, req.Password.NewPassword)
}

func (e *Elasticsearch) DeleteUser(ctx context.Context, req dbplugin.DeleteUserRequest) (dbplugin.DeleteUserResponse, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if err := e.deleteUser(ctx, req.Username); err != nil {
		return dbplugin.DeleteUserResponse{}, err
	}
	return dbplugin.DeleteUserResponse{}, nil
}

// --- HTTP helpers -----------------------------------------------------------

func (e *Elasticsearch) securityPath() string {
	if e.config.UseOldXPackAPI {
		return "_xpack/security"
	}
	return "_security"
}

func (e *Elasticsearch) healthcheck(ctx context.Context) error {
	req, err := e.newRequest(ctx, http.MethodGet, "_cluster/health", nil)
	if err != nil {
		return err
	}
	resp, err := e.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("elasticsearch health check failed: %s: %s", resp.Status, string(body))
	}
	return nil
}

func (e *Elasticsearch) putUser(ctx context.Context, username string, body map[string]any) error {
	path := fmt.Sprintf("%s/user/%s", e.securityPath(), url.PathEscape(username))
	return e.doJSON(ctx, http.MethodPut, path, body)
}

func (e *Elasticsearch) changePassword(ctx context.Context, username, newPassword string) error {
	path := fmt.Sprintf("%s/user/%s/_password", e.securityPath(), url.PathEscape(username))
	return e.doJSON(ctx, http.MethodPost, path, map[string]string{"password": newPassword})
}

func (e *Elasticsearch) deleteUser(ctx context.Context, username string) error {
	path := fmt.Sprintf("%s/user/%s", e.securityPath(), url.PathEscape(username))
	req, err := e.newRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return err
	}
	resp, err := e.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode == http.StatusNotFound {
		return nil
	}
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("delete user failed: %s: %s", resp.Status, string(body))
	}
	return nil
}

func (e *Elasticsearch) doJSON(ctx context.Context, method, path string, body any) error {
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			return err
		}
	}
	req, err := e.newRequest(ctx, method, path, &buf)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("%s %s failed: %s: %s", method, path, resp.Status, string(b))
	}
	return nil
}

func (e *Elasticsearch) newRequest(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
	base := strings.TrimRight(e.config.URL, "/")
	full := fmt.Sprintf("%s/%s", base, strings.TrimLeft(path, "/"))
	req, err := http.NewRequestWithContext(ctx, method, full, body)
	if err != nil {
		return nil, err
	}
	auth := base64.StdEncoding.EncodeToString([]byte(e.config.Username + ":" + e.config.Password))
	req.Header.Set("Authorization", "Basic "+auth)
	return req, nil
}

func newHTTPClient(cfg *esConfig) (*http.Client, error) {
	tlsCfg, err := cfg.tls.Build("")
	if err != nil {
		return nil, err
	}

	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsCfg,
		},
	}, nil
}
