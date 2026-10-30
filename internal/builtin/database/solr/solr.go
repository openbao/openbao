// Copyright (c) AppsCode Inc.
// SPDX-License-Identifier: MPL-2.0

// Package solr implements an OpenBao v5 database plugin for Apache Solr
// using the Security Plugin API. Dynamic credentials become entries in
// security.json's Basic Auth Plugin user table, with role bindings
// supplied via creation_statements as a JSON document.
package solr

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
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
	solrTypeName = "solr"

	defaultUserNameTemplate = `{{ printf "v-%s-%s-%s-%s" (.DisplayName | truncate 15) (.RoleName | truncate 15) (random 20) (unix_time) | replace "." "-" | truncate 100 }}`
)

// ReportedVersion is overridable at build time.
var ReportedVersion = ""

// Solr implements dbplugin.Database. creation_statements is a JSON role
// doc `{"roles":["admin","reader"]}` listing roles to bind to the new
// user via set-user-role.
type Solr struct {
	mu sync.Mutex

	config           *solrConfig
	httpClient       *http.Client
	usernameProducer template.StringTemplate
}

type solrConfig struct {
	URL      string `mapstructure:"url"`
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`

	tls dbtlsutil.Config
}

type solrStatement struct {
	Roles []string `json:"roles"`
}

var (
	_ dbplugin.Database       = (*Solr)(nil)
	_ logical.PluginVersioner = (*Solr)(nil)
)

func New() (any, error) {
	db := newSolr()
	return dbplugin.NewDatabaseErrorSanitizerMiddleware(db, db.secretValues), nil
}

func newSolr() *Solr {
	return &Solr{}
}

func (s *Solr) secretValues() map[string]string {
	if s.config == nil {
		return map[string]string{}
	}
	return map[string]string{s.config.Password: "[password]"}
}

func (s *Solr) Type() (string, error) {
	return solrTypeName, nil
}

func (s *Solr) PluginVersion() logical.PluginVersion {
	return logical.PluginVersion{Version: ReportedVersion}
}

func (s *Solr) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.httpClient != nil {
		s.httpClient.CloseIdleConnections()
	}
	s.httpClient = nil
	return nil
}

func (s *Solr) Initialize(ctx context.Context, req dbplugin.InitializeRequest) (dbplugin.InitializeResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cfg := &solrConfig{}
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
		return dbplugin.InitializeResponse{}, fmt.Errorf("invalid username_template: %w", err)
	}
	if _, err := up.Generate(dbplugin.UsernameMetadata{}); err != nil {
		return dbplugin.InitializeResponse{}, fmt.Errorf("invalid username template: %w", err)
	}

	s.config = cfg
	s.httpClient = client
	s.usernameProducer = up

	if req.VerifyConnection {
		if err := s.ping(ctx); err != nil {
			return dbplugin.InitializeResponse{}, fmt.Errorf("failed to verify connection: %w", err)
		}
	}

	return dbplugin.InitializeResponse{Config: req.Config}, nil
}

// NewUser issues a set-user command to the BasicAuth Plugin and, for each
// role in the statement, a set-user-role command to the Authorization
// Plugin. On any failure after the user is created, the plugin deletes
// the half-configured user.
func (s *Solr) NewUser(ctx context.Context, req dbplugin.NewUserRequest) (dbplugin.NewUserResponse, error) {
	if len(req.Statements.Commands) == 0 {
		return dbplugin.NewUserResponse{}, dbutil.ErrEmptyCreationStatement
	}

	var stmt solrStatement
	if err := json.Unmarshal([]byte(req.Statements.Commands[0]), &stmt); err != nil {
		return dbplugin.NewUserResponse{}, fmt.Errorf("creation_statements must be a JSON role doc: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	username, err := s.usernameProducer.Generate(req.UsernameConfig)
	if err != nil {
		return dbplugin.NewUserResponse{}, err
	}

	if err := s.postAuth(ctx, map[string]any{
		"set-user": map[string]string{username: req.Password},
	}); err != nil {
		return dbplugin.NewUserResponse{}, fmt.Errorf("set-user: %w", err)
	}

	cleanup := func(opErr error) (dbplugin.NewUserResponse, error) {
		_ = s.postAuth(ctx, map[string]any{"delete-user": []string{username}})
		return dbplugin.NewUserResponse{}, opErr
	}

	if len(stmt.Roles) > 0 {
		if err := s.postAuthZ(ctx, map[string]any{
			"set-user-role": map[string][]string{username: stmt.Roles},
		}); err != nil {
			return cleanup(fmt.Errorf("set-user-role: %w", err))
		}
	}

	return dbplugin.NewUserResponse{Username: username}, nil
}

func (s *Solr) UpdateUser(ctx context.Context, req dbplugin.UpdateUserRequest) (dbplugin.UpdateUserResponse, error) {
	if req.Username == "" {
		return dbplugin.UpdateUserResponse{}, errors.New("missing username")
	}
	if req.Password == nil && req.Expiration == nil {
		return dbplugin.UpdateUserResponse{}, errors.New("no changes requested")
	}
	if req.Password == nil {
		return dbplugin.UpdateUserResponse{}, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.postAuth(ctx, map[string]any{
		"set-user": map[string]string{req.Username: req.Password.NewPassword},
	}); err != nil {
		return dbplugin.UpdateUserResponse{}, fmt.Errorf("set-user: %w", err)
	}
	return dbplugin.UpdateUserResponse{}, nil
}

func (s *Solr) DeleteUser(ctx context.Context, req dbplugin.DeleteUserRequest) (dbplugin.DeleteUserResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// delete-user is idempotent on the Solr side; missing user yields a
	// 200 with a no-op result, so no special-casing is needed.
	if err := s.postAuth(ctx, map[string]any{"delete-user": []string{req.Username}}); err != nil {
		return dbplugin.DeleteUserResponse{}, fmt.Errorf("delete-user: %w", err)
	}
	return dbplugin.DeleteUserResponse{}, nil
}

// --- HTTP helpers -----------------------------------------------------------

func (s *Solr) ping(ctx context.Context) error {
	req, err := s.newRequest(ctx, http.MethodGet, "admin/info/system?wt=json", nil)
	if err != nil {
		return err
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("solr ping failed: %s: %s", resp.Status, string(body))
	}
	return nil
}

func (s *Solr) postAuth(ctx context.Context, body map[string]any) error {
	return s.doJSON(ctx, http.MethodPost, "admin/authentication", body)
}

func (s *Solr) postAuthZ(ctx context.Context, body map[string]any) error {
	return s.doJSON(ctx, http.MethodPost, "admin/authorization", body)
}

func (s *Solr) doJSON(ctx context.Context, method, path string, body any) error {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(body); err != nil {
		return err
	}
	req, err := s.newRequest(ctx, method, path, &buf)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.httpClient.Do(req)
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

func (s *Solr) newRequest(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
	base := strings.TrimRight(s.config.URL, "/")
	full := fmt.Sprintf("%s/%s", base, strings.TrimLeft(path, "/"))
	req, err := http.NewRequestWithContext(ctx, method, full, body)
	if err != nil {
		return nil, err
	}
	auth := base64.StdEncoding.EncodeToString([]byte(s.config.Username + ":" + s.config.Password))
	req.Header.Set("Authorization", "Basic "+auth)
	return req, nil
}

func newHTTPClient(cfg *solrConfig) (*http.Client, error) {
	tlsCfg, err := cfg.tls.Build("")
	if err != nil {
		return nil, err
	}

	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}, nil
}
