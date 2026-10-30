// Copyright (c) AppsCode Inc.
// SPDX-License-Identifier: MPL-2.0

// Package weaviate implements an OpenBao v5 database plugin for the
// Weaviate vector database.
//
// For Weaviate v1.30+ with AUTHENTICATION_DB_USERS_ENABLED=true and
// AUTHORIZATION_ENABLE_RBAC=true, this plugin supports dynamic credentials
// via Weaviate's User Management and RBAC REST APIs:
//   - Initialize parses config and (with VerifyConnection=true) calls
//     `/v1/.well-known/ready` with the configured API key as a Bearer token.
//   - NewUser generates a unique username, creates the user via
//     `POST /v1/users/db/{user_id}`, assigns roles configured in the role's
//     creation statements via `POST /v1/authz/users/{id}/assign`, and returns
//     Weaviate's generated API key in NewUserResponse.Password.
//   - UpdateUser rotates the user's API key via
//     `POST /v1/users/db/{user_id}/rotate-key`.
//   - DeleteUser deletes the database user via `DELETE /v1/users/db/{user_id}`.
package weaviate

import (
	"bytes"
	"context"
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
	"github.com/openbao/openbao/sdk/v2/helper/template"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/v2/internal/helper/dbtlsutil"
)

const (
	weaviateTypeName        = "weaviate"
	defaultUserNameTemplate = `{{ printf "v-%s-%s-%s-%s" (.DisplayName | truncate 8) (.RoleName | truncate 8) (random 20) (unix_time) | truncate 63 }}`
)

// ReportedVersion is overridable at build time.
var ReportedVersion = ""

// Weaviate implements dbplugin.Database for Weaviate.
type Weaviate struct {
	mu               sync.Mutex
	config           *weaviateConfig
	client           *http.Client
	usernameProducer template.StringTemplate
}

type weaviateConfig struct {
	URL    string `mapstructure:"url"`
	APIKey string `mapstructure:"api_key"`

	tls dbtlsutil.Config
}

var (
	_ dbplugin.Database       = (*Weaviate)(nil)
	_ logical.PluginVersioner = (*Weaviate)(nil)
)

func New() (any, error) {
	db := newWeaviate()
	return dbplugin.NewDatabaseErrorSanitizerMiddleware(db, db.secretValues), nil
}

func newWeaviate() *Weaviate {
	return &Weaviate{}
}

func (w *Weaviate) secretValues() map[string]string {
	if w.config == nil {
		return map[string]string{}
	}
	return map[string]string{w.config.APIKey: "[api_key]"}
}

func (w *Weaviate) Type() (string, error) {
	return weaviateTypeName, nil
}

func (w *Weaviate) PluginVersion() logical.PluginVersion {
	return logical.PluginVersion{Version: ReportedVersion}
}

func (w *Weaviate) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.client != nil {
		w.client.CloseIdleConnections()
	}
	w.client = nil
	return nil
}

func (w *Weaviate) Initialize(ctx context.Context, req dbplugin.InitializeRequest) (dbplugin.InitializeResponse, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	cfg := &weaviateConfig{}
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
	w.usernameProducer = up

	_, err = w.usernameProducer.Generate(dbplugin.UsernameMetadata{})
	if err != nil {
		return dbplugin.InitializeResponse{}, fmt.Errorf("invalid username template: %w", err)
	}

	client, err := newHTTPClient(cfg)
	if err != nil {
		return dbplugin.InitializeResponse{}, err
	}
	w.config = cfg
	w.client = client

	if req.VerifyConnection {
		if err := w.healthcheck(ctx); err != nil {
			return dbplugin.InitializeResponse{}, fmt.Errorf("failed to verify connection: %w", err)
		}
	}

	return dbplugin.InitializeResponse{Config: req.Config}, nil
}

// NewUser generates a dynamic database user in Weaviate, assigns roles from
// creation statements, and returns the generated API key.
func (w *Weaviate) NewUser(ctx context.Context, req dbplugin.NewUserRequest) (dbplugin.NewUserResponse, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.client == nil || w.config == nil {
		return dbplugin.NewUserResponse{}, errors.New("database not initialized")
	}

	username, err := w.usernameProducer.Generate(req.UsernameConfig)
	if err != nil {
		return dbplugin.NewUserResponse{}, err
	}

	escapedUser := url.PathEscape(username)
	path := "/v1/users/db/" + escapedUser

	resp, body, err := w.doRequest(ctx, http.MethodPost, path, nil)
	if err != nil {
		return dbplugin.NewUserResponse{}, fmt.Errorf("failed to create user %q: %w", username, err)
	}
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return dbplugin.NewUserResponse{}, fmt.Errorf("failed to create user %q: %w", username, formatWeaviateError(resp.Status, body))
	}

	var keyResp struct {
		APIKey string `json:"apikey"`
	}
	if err := json.Unmarshal(body, &keyResp); err != nil {
		_ = w.deleteUser(ctx, username)
		return dbplugin.NewUserResponse{}, fmt.Errorf("failed to parse user api key response: %w", err)
	}
	if keyResp.APIKey == "" {
		_ = w.deleteUser(ctx, username)
		return dbplugin.NewUserResponse{}, errors.New("empty api key returned by weaviate")
	}

	var rolesToAssign []string
	for _, cmd := range req.Statements.Commands {
		cmd = strings.TrimSpace(cmd)
		if cmd == "" {
			continue
		}

		// Structured JSON statement: {"roles": [...], "custom_roles": [...]}
		if strings.HasPrefix(cmd, "{") {
			var stmt weaviateStatement
			if err := json.Unmarshal([]byte(cmd), &stmt); err == nil && (len(stmt.Roles) > 0 || len(stmt.CustomRoles) > 0) {
				for _, r := range stmt.Roles {
					if r = strings.TrimSpace(r); r != "" {
						rolesToAssign = append(rolesToAssign, r)
					}
				}
				for _, cr := range stmt.CustomRoles {
					if cr.Name == "" {
						_ = w.deleteUser(ctx, username)
						return dbplugin.NewUserResponse{}, errors.New("custom role definition missing name")
					}
					if err := w.ensureRole(ctx, cr); err != nil {
						_ = w.deleteUser(ctx, username)
						return dbplugin.NewUserResponse{}, err
					}
					rolesToAssign = append(rolesToAssign, cr.Name)
				}
				continue
			}

			// Backwards compatibility: Single custom role JSON definition
			var roleDef weaviateRoleDef
			if err := json.Unmarshal([]byte(cmd), &roleDef); err == nil && roleDef.Name != "" {
				if err := w.ensureRole(ctx, roleDef); err != nil {
					_ = w.deleteUser(ctx, username)
					return dbplugin.NewUserResponse{}, err
				}
				rolesToAssign = append(rolesToAssign, roleDef.Name)
				continue
			}

			_ = w.deleteUser(ctx, username)
			return dbplugin.NewUserResponse{}, fmt.Errorf("failed to parse role statement JSON: %q", cmd)
		}

		// Array of roles or custom role definitions: ["viewer"] or [{"name": "..."}]
		if strings.HasPrefix(cmd, "[") {
			var strRoles []string
			if err := json.Unmarshal([]byte(cmd), &strRoles); err == nil && len(strRoles) > 0 {
				for _, r := range strRoles {
					if r = strings.TrimSpace(r); r != "" {
						rolesToAssign = append(rolesToAssign, r)
					}
				}
				continue
			}

			var roleDefs []weaviateRoleDef
			if err := json.Unmarshal([]byte(cmd), &roleDefs); err == nil && len(roleDefs) > 0 {
				for _, rd := range roleDefs {
					if rd.Name == "" {
						_ = w.deleteUser(ctx, username)
						return dbplugin.NewUserResponse{}, errors.New("custom role definition missing name")
					}
					if err := w.ensureRole(ctx, rd); err != nil {
						_ = w.deleteUser(ctx, username)
						return dbplugin.NewUserResponse{}, err
					}
					rolesToAssign = append(rolesToAssign, rd.Name)
				}
				continue
			}

			_ = w.deleteUser(ctx, username)
			return dbplugin.NewUserResponse{}, fmt.Errorf("failed to parse role statement JSON array: %q", cmd)
		}

		// Plain role name string (e.g. "viewer", or comma-separated "viewer, admin")
		if strings.Contains(cmd, ",") {
			for _, part := range strings.Split(cmd, ",") {
				if part = strings.TrimSpace(part); part != "" {
					rolesToAssign = append(rolesToAssign, part)
				}
			}
		} else {
			rolesToAssign = append(rolesToAssign, cmd)
		}
	}

	rolesToAssign = deduplicateStrings(rolesToAssign)
	if len(rolesToAssign) > 0 {
		assignReq := struct {
			Roles    []string `json:"roles"`
			UserType string   `json:"userType"`
		}{
			Roles:    rolesToAssign,
			UserType: "db",
		}
		assignPath := "/v1/authz/users/" + escapedUser + "/assign"
		aResp, aBody, err := w.doRequest(ctx, http.MethodPost, assignPath, assignReq)
		if err != nil {
			_ = w.deleteUser(ctx, username)
			return dbplugin.NewUserResponse{}, fmt.Errorf("failed to assign roles to user %q: %w", username, err)
		}
		if aResp.StatusCode != http.StatusOK && aResp.StatusCode != http.StatusNoContent {
			_ = w.deleteUser(ctx, username)
			return dbplugin.NewUserResponse{}, fmt.Errorf("failed to assign roles to user %q: %w", username, formatWeaviateError(aResp.Status, aBody))
		}
	}

	return dbplugin.NewUserResponse{
		Username: username,
		Password: keyResp.APIKey,
	}, nil
}

// UpdateUser handles user updates. Weaviate generates dynamic database user API keys
// and does not support password updates or static credentials because server-generated
// keys cannot be returned via the v5 update response.
func (w *Weaviate) UpdateUser(ctx context.Context, req dbplugin.UpdateUserRequest) (dbplugin.UpdateUserResponse, error) {
	if req.Username == "" {
		return dbplugin.UpdateUserResponse{}, errors.New("missing username")
	}
	if req.Password == nil && req.Expiration == nil {
		return dbplugin.UpdateUserResponse{}, errors.New("no changes requested")
	}
	if req.Password != nil {
		return dbplugin.UpdateUserResponse{}, errors.New("weaviate does not support updating user credentials or static roles")
	}
	return dbplugin.UpdateUserResponse{}, nil
}

// DeleteUser deletes the database user in Weaviate.
func (w *Weaviate) DeleteUser(ctx context.Context, req dbplugin.DeleteUserRequest) (dbplugin.DeleteUserResponse, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if req.Username == "" {
		return dbplugin.DeleteUserResponse{}, errors.New("missing username")
	}
	if err := w.deleteUser(ctx, req.Username); err != nil {
		return dbplugin.DeleteUserResponse{}, err
	}
	return dbplugin.DeleteUserResponse{}, nil
}

func (w *Weaviate) deleteUser(ctx context.Context, username string) error {
	if w.client == nil || w.config == nil {
		return errors.New("database not initialized")
	}
	path := "/v1/users/db/" + url.PathEscape(username)
	resp, body, err := w.doRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return fmt.Errorf("failed to delete user %q: %w", username, err)
	}
	if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNotFound {
		return nil
	}
	return fmt.Errorf("failed to delete user %q: %w", username, formatWeaviateError(resp.Status, body))
}

// weaviateStatement represents a structured creation statement containing
// built-in/existing roles and/or custom role definitions.
type weaviateStatement struct {
	Roles       []string          `json:"roles"`
	CustomRoles []weaviateRoleDef `json:"custom_roles"`
}

func (s *weaviateStatement) UnmarshalJSON(data []byte) error {
	type Alias weaviateStatement
	aux := &struct {
		*Alias
		SingleRole     string            `json:"role"`
		AltCustomRoles []weaviateRoleDef `json:"customRoles"`
	}{
		Alias: (*Alias)(s),
	}
	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}
	if len(s.Roles) == 0 && aux.SingleRole != "" {
		s.Roles = []string{aux.SingleRole}
	}
	if len(s.CustomRoles) == 0 && len(aux.AltCustomRoles) > 0 {
		s.CustomRoles = aux.AltCustomRoles
	}
	return nil
}

// weaviateRoleDef represents a custom role definition in Weaviate.
type weaviateRoleDef struct {
	Name        string `json:"name"`
	Permissions any    `json:"permissions"`
}

func (w *Weaviate) ensureRole(ctx context.Context, role weaviateRoleDef) error {
	path := "/v1/authz/roles"
	resp, body, err := w.doRequest(ctx, http.MethodPost, path, role)
	if err != nil {
		return fmt.Errorf("failed to create role %q: %w", role.Name, err)
	}
	// 201 Created or 200 OK means role was created.
	if resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusOK {
		return nil
	}
	// 409 Conflict means role already exists.
	if resp.StatusCode == http.StatusConflict {
		// If permissions were supplied, append them to the existing role
		if role.Permissions != nil {
			addPermPath := "/v1/authz/roles/" + url.PathEscape(role.Name) + "/add-permissions"
			addBody := struct {
				Permissions any `json:"permissions"`
			}{
				Permissions: role.Permissions,
			}
			pResp, pBody, pErr := w.doRequest(ctx, http.MethodPost, addPermPath, addBody)
			if pErr != nil {
				return fmt.Errorf("failed to add permissions to role %q: %w", role.Name, pErr)
			}
			if pResp.StatusCode == http.StatusOK || pResp.StatusCode == http.StatusNoContent || pResp.StatusCode == http.StatusConflict {
				return nil
			}
			return fmt.Errorf("failed to add permissions to role %q: %w", role.Name, formatWeaviateError(pResp.Status, pBody))
		}
		return nil
	}
	return fmt.Errorf("failed to create role %q: %w", role.Name, formatWeaviateError(resp.Status, body))
}

func deduplicateStrings(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	var out []string
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}

func (w *Weaviate) healthcheck(ctx context.Context) error {
	resp, body, err := w.doRequest(ctx, http.MethodGet, "/v1/.well-known/ready", nil)
	if err != nil {
		return err
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("weaviate /v1/.well-known/ready failed: %s: %s", resp.Status, string(body))
	}
	return nil
}

func (w *Weaviate) doRequest(ctx context.Context, method, path string, reqBody any) (*http.Response, []byte, error) {
	base := strings.TrimRight(w.config.URL, "/")
	var r io.Reader
	if reqBody != nil {
		b, err := json.Marshal(reqBody)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		r = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, base+path, r)
	if err != nil {
		return nil, nil, err
	}
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if w.config.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+w.config.APIKey)
	}

	resp, err := w.client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close() //nolint:errcheck

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read response body: %w", err)
	}
	return resp, body, nil
}

func formatWeaviateError(status string, body []byte) error {
	var we struct {
		Error []struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &we); err == nil && len(we.Error) > 0 {
		var msgs []string
		for _, e := range we.Error {
			if e.Message != "" {
				msgs = append(msgs, e.Message)
			}
		}
		if len(msgs) > 0 {
			return fmt.Errorf("%s: %s", status, strings.Join(msgs, "; "))
		}
	}
	if len(body) > 0 {
		return fmt.Errorf("%s: %s", status, string(body))
	}
	return fmt.Errorf("%s", status)
}

func newHTTPClient(cfg *weaviateConfig) (*http.Client, error) {
	tlsCfg, err := cfg.tls.Build("")
	if err != nil {
		return nil, err
	}

	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = tlsCfg

	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: tr,
	}, nil
}
