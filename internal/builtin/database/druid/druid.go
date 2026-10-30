// Copyright (c) AppsCode Inc.
// SPDX-License-Identifier: MPL-2.0

// Package druid implements an OpenBao v5 database plugin for Apache Druid
// using the BasicSecurity Coordinator API. The plugin manages internal
// users in the configured authenticator and assigns role bindings in the
// configured authorizer.
package druid

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
	druidTypeName = "druid"

	defaultUserNameTemplate = `{{ printf "v-%s-%s-%s-%s" (.DisplayName | truncate 15) (.RoleName | truncate 15) (random 20) (unix_time) | replace "." "-" | truncate 100 }}`

	defaultAuthenticator = "MyBasicMetadataAuthenticator"
	defaultAuthorizer    = "MyBasicMetadataAuthorizer"
)

// ReportedVersion is overridable at build time.
var ReportedVersion = ""

// Druid implements dbplugin.Database against the Druid coordinator's
// BasicSecurity API. creation_statements is a JSON role doc
// `{"roles":["admin"]}`.
type Druid struct {
	mu sync.Mutex

	config           *druidConfig
	httpClient       *http.Client
	usernameProducer template.StringTemplate
}

type druidConfig struct {
	URL           string `mapstructure:"url"`
	Username      string `mapstructure:"username"`
	Password      string `mapstructure:"password"`
	Authenticator string `mapstructure:"authenticator"`
	Authorizer    string `mapstructure:"authorizer"`

	tls dbtlsutil.Config
}

type druidStatement struct {
	Roles []string `json:"roles"`
}

var (
	_ dbplugin.Database       = (*Druid)(nil)
	_ logical.PluginVersioner = (*Druid)(nil)
)

func New() (any, error) {
	db := newDruid()
	return dbplugin.NewDatabaseErrorSanitizerMiddleware(db, db.secretValues), nil
}

func newDruid() *Druid {
	return &Druid{}
}

func (d *Druid) secretValues() map[string]string {
	if d.config == nil {
		return map[string]string{}
	}
	return map[string]string{d.config.Password: "[password]"}
}

func (d *Druid) Type() (string, error) {
	return druidTypeName, nil
}

func (d *Druid) PluginVersion() logical.PluginVersion {
	return logical.PluginVersion{Version: ReportedVersion}
}

func (d *Druid) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.httpClient != nil {
		d.httpClient.CloseIdleConnections()
	}
	d.httpClient = nil
	return nil
}

func (d *Druid) Initialize(ctx context.Context, req dbplugin.InitializeRequest) (dbplugin.InitializeResponse, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	cfg := &druidConfig{}
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
	if cfg.Authenticator == "" {
		cfg.Authenticator = defaultAuthenticator
	}
	if cfg.Authorizer == "" {
		cfg.Authorizer = defaultAuthorizer
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

	d.config = cfg
	d.httpClient = client
	d.usernameProducer = up

	if req.VerifyConnection {
		if err := d.healthcheck(ctx); err != nil {
			return dbplugin.InitializeResponse{}, fmt.Errorf("failed to verify connection: %w", err)
		}
	}

	return dbplugin.InitializeResponse{Config: req.Config}, nil
}

// NewUser creates the user + credentials in the authenticator, then
// assigns the named roles via the authorizer. On any failure after the
// user is created, the plugin deletes the user.
func (d *Druid) NewUser(ctx context.Context, req dbplugin.NewUserRequest) (dbplugin.NewUserResponse, error) {
	if len(req.Statements.Commands) == 0 {
		return dbplugin.NewUserResponse{}, dbutil.ErrEmptyCreationStatement
	}

	var stmt druidStatement
	if err := json.Unmarshal([]byte(req.Statements.Commands[0]), &stmt); err != nil {
		return dbplugin.NewUserResponse{}, fmt.Errorf("creation_statements must be a JSON role doc: %w", err)
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	username, err := d.usernameProducer.Generate(req.UsernameConfig)
	if err != nil {
		return dbplugin.NewUserResponse{}, err
	}

	// 1. Create the user record in the authenticator.
	if err := d.doJSON(ctx, http.MethodPost, d.authnPath("users", username), nil); err != nil {
		return dbplugin.NewUserResponse{}, fmt.Errorf("create authn user: %w", err)
	}

	cleanup := func(opErr error) (dbplugin.NewUserResponse, error) {
		var errs []error
		if err := d.doJSON(ctx, http.MethodDelete, d.authnPath("users", username), nil); err != nil {
			errs = append(errs, fmt.Errorf("cleanup authn user: %w", err))
		}
		if err := d.doJSON(ctx, http.MethodDelete, d.authzPath("users", username), nil); err != nil {
			errs = append(errs, fmt.Errorf("cleanup authz user: %w", err))
		}
		if len(errs) > 0 {
			return dbplugin.NewUserResponse{}, errors.Join(append([]error{opErr}, errs...)...)
		}
		return dbplugin.NewUserResponse{}, opErr
	}

	// 2. Set the user's credentials.
	if err := d.doJSON(ctx, http.MethodPost, d.authnPath("users", username, "credentials"),
		map[string]string{"password": req.Password}); err != nil {
		return cleanup(fmt.Errorf("set credentials: %w", err))
	}

	// 3. Create the user record in the authorizer + assign roles.
	if err := d.doJSON(ctx, http.MethodPost, d.authzPath("users", username), nil); err != nil {
		return cleanup(fmt.Errorf("create authz user: %w", err))
	}
	for _, role := range stmt.Roles {
		if role == "" {
			continue
		}
		if err := d.doJSON(ctx, http.MethodPost, d.authzPath("users", username, "roles", role), nil); err != nil {
			return cleanup(fmt.Errorf("assign role %q: %w", role, err))
		}
	}

	return dbplugin.NewUserResponse{Username: username}, nil
}

func (d *Druid) UpdateUser(ctx context.Context, req dbplugin.UpdateUserRequest) (dbplugin.UpdateUserResponse, error) {
	if req.Username == "" {
		return dbplugin.UpdateUserResponse{}, errors.New("missing username")
	}
	if req.Password == nil && req.Expiration == nil {
		return dbplugin.UpdateUserResponse{}, errors.New("no changes requested")
	}
	if req.Password == nil {
		return dbplugin.UpdateUserResponse{}, nil
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	if err := d.doJSON(ctx, http.MethodPost, d.authnPath("users", req.Username, "credentials"),
		map[string]string{"password": req.Password.NewPassword}); err != nil {
		return dbplugin.UpdateUserResponse{}, fmt.Errorf("set credentials: %w", err)
	}
	return dbplugin.UpdateUserResponse{}, nil
}

func (d *Druid) DeleteUser(ctx context.Context, req dbplugin.DeleteUserRequest) (dbplugin.DeleteUserResponse, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	errAuthz := d.doJSON(ctx, http.MethodDelete, d.authzPath("users", req.Username), nil)
	errAuthn := d.doJSON(ctx, http.MethodDelete, d.authnPath("users", req.Username), nil)

	if err := errors.Join(errAuthz, errAuthn); err != nil {
		return dbplugin.DeleteUserResponse{}, fmt.Errorf("delete user: %w", err)
	}
	return dbplugin.DeleteUserResponse{}, nil
}

// --- HTTP helpers -----------------------------------------------------------

func (d *Druid) authnPath(parts ...string) string {
	bits := append(
		[]string{"druid-ext", "basic-security", "authentication", "db", d.config.Authenticator},
		parts...,
	)
	for i, b := range bits {
		bits[i] = url.PathEscape(b)
	}
	return strings.Join(bits, "/")
}

func (d *Druid) authzPath(parts ...string) string {
	bits := append(
		[]string{"druid-ext", "basic-security", "authorization", "db", d.config.Authorizer},
		parts...,
	)
	for i, b := range bits {
		bits[i] = url.PathEscape(b)
	}
	return strings.Join(bits, "/")
}

func (d *Druid) healthcheck(ctx context.Context) error {
	req, err := d.newRequest(ctx, http.MethodGet, "status", nil)
	if err != nil {
		return err
	}
	resp, err := d.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("druid status failed: %s: %s", resp.Status, string(body))
	}
	return nil
}

func (d *Druid) doJSON(ctx context.Context, method, path string, body any) error {
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			return err
		}
	}
	req, err := d.newRequest(ctx, method, path, &buf)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := d.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode == http.StatusNotFound && method == http.MethodDelete {
		return nil
	}
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("%s %s failed: %s: %s", method, path, resp.Status, string(b))
	}
	return nil
}

func (d *Druid) newRequest(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
	base := strings.TrimRight(d.config.URL, "/")
	full := fmt.Sprintf("%s/%s", base, strings.TrimLeft(path, "/"))
	req, err := http.NewRequestWithContext(ctx, method, full, body)
	if err != nil {
		return nil, err
	}
	auth := base64.StdEncoding.EncodeToString([]byte(d.config.Username + ":" + d.config.Password))
	req.Header.Set("Authorization", "Basic "+auth)
	return req, nil
}

func newHTTPClient(cfg *druidConfig) (*http.Client, error) {
	tlsCfg, err := cfg.tls.Build("")
	if err != nil {
		return nil, err
	}

	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}, nil
}
