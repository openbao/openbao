// Copyright (c) AppsCode Inc.
// SPDX-License-Identifier: MPL-2.0

// Package milvus implements an OpenBao v5 database plugin for Milvus 2.x
// using the Milvus Go SDK (v2) over gRPC.
package milvus

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/hashicorp/go-secure-stdlib/strutil"
	"github.com/milvus-io/milvus-proto/go-api/v2/commonpb"
	milvusclient "github.com/milvus-io/milvus-sdk-go/v2/client"
	"github.com/milvus-io/milvus-sdk-go/v2/entity"
	"github.com/mitchellh/mapstructure"
	dbplugin "github.com/openbao/openbao/sdk/v2/database/dbplugin/v5"
	"github.com/openbao/openbao/sdk/v2/database/helper/dbutil"
	"github.com/openbao/openbao/sdk/v2/helper/template"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/v2/internal/helper/dbtlsutil"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const (
	milvusTypeName = "milvus"

	// Milvus usernames are limited to 32 characters in 2.4+. Cap the
	// template at 32 to avoid the server-side rejection.
	defaultUserNameTemplate = `{{ printf "v-%s-%s-%s" (.DisplayName | truncate 8) (.RoleName | truncate 8) (random 10) | replace "." "-" | truncate 32 }}`
)

// ReportedVersion is overridable at build time.
var ReportedVersion = ""

// Milvus implements dbplugin.Database via the Milvus Go SDK over gRPC.
// creation_statements is a JSON role doc `{"roles":["role1"]}` listing
// pre-existing roles to grant.
type Milvus struct {
	mu sync.Mutex

	config           *milvusConfig
	client           milvusclient.Client
	usernameProducer template.StringTemplate
}
type milvusConfig struct {
	URL      string `mapstructure:"url"`
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
	Token    string `mapstructure:"token"`
	DBName   string `mapstructure:"db_name"`

	tls dbtlsutil.Config
}

// milvusStatement represents a structured creation statement containing
// built-in/existing roles and/or custom role definitions.
type milvusStatement struct {
	Roles       []string        `json:"roles"`
	CustomRoles []milvusRoleDef `json:"custom_roles"`
}

func (s *milvusStatement) UnmarshalJSON(data []byte) error {
	type Alias milvusStatement
	aux := &struct {
		*Alias
		SingleRole     string          `json:"role"`
		AltCustomRoles []milvusRoleDef `json:"customRoles"`
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

// milvusRoleDef represents a custom role definition in Milvus.
type milvusRoleDef struct {
	Name       string            `json:"name"`
	Privileges []milvusPrivilege `json:"privileges"`
}

func (r *milvusRoleDef) UnmarshalJSON(data []byte) error {
	type Alias milvusRoleDef
	aux := &struct {
		*Alias
		AltPrivileges []milvusPrivilege `json:"permissions"`
	}{
		Alias: (*Alias)(r),
	}
	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}
	if len(r.Privileges) == 0 && len(aux.AltPrivileges) > 0 {
		r.Privileges = aux.AltPrivileges
	}
	return nil
}

// milvusPrivilege represents a privilege grant for a custom role in Milvus.
type milvusPrivilege struct {
	ObjectType string `json:"object_type"`
	ObjectName string `json:"object_name"`
	Privilege  string `json:"privilege"`
	DBName     string `json:"db_name"`
}

func (p *milvusPrivilege) UnmarshalJSON(data []byte) error {
	type Alias milvusPrivilege
	aux := &struct {
		*Alias
		AltObjectType string `json:"objectType"`
		Type          string `json:"type"`
		AltObjectName string `json:"objectName"`
		Object        string `json:"object"`
		Collection    string `json:"collection"`
		Action        string `json:"action"`
		Permission    string `json:"permission"`
		AltDBName     string `json:"dbName"`
		Database      string `json:"database"`
	}{
		Alias: (*Alias)(p),
	}
	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}
	if p.ObjectType == "" {
		if aux.AltObjectType != "" {
			p.ObjectType = aux.AltObjectType
		} else if aux.Type != "" {
			p.ObjectType = aux.Type
		}
	}
	if p.ObjectName == "" {
		if aux.AltObjectName != "" {
			p.ObjectName = aux.AltObjectName
		} else if aux.Object != "" {
			p.ObjectName = aux.Object
		} else if aux.Collection != "" {
			p.ObjectName = aux.Collection
		}
	}
	if p.Privilege == "" {
		if aux.Action != "" {
			p.Privilege = aux.Action
		} else if aux.Permission != "" {
			p.Privilege = aux.Permission
		}
	}
	if p.DBName == "" {
		if aux.AltDBName != "" {
			p.DBName = aux.AltDBName
		} else if aux.Database != "" {
			p.DBName = aux.Database
		}
	}
	return nil
}

var (
	_ dbplugin.Database       = (*Milvus)(nil)
	_ logical.PluginVersioner = (*Milvus)(nil)
)

func New() (any, error) {
	db := newMilvus()
	return dbplugin.NewDatabaseErrorSanitizerMiddleware(db, db.secretValues), nil
}

func newMilvus() *Milvus {
	return &Milvus{}
}

func (m *Milvus) secretValues() map[string]string {
	if m.config == nil {
		return map[string]string{}
	}
	out := map[string]string{}
	if m.config.Password != "" {
		out[m.config.Password] = "[password]"
	}
	if m.config.Token != "" {
		out[m.config.Token] = "[token]"
	}
	return out
}

func (m *Milvus) Type() (string, error) {
	return milvusTypeName, nil
}

func (m *Milvus) PluginVersion() logical.PluginVersion {
	return logical.PluginVersion{Version: ReportedVersion}
}

func (m *Milvus) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.client != nil {
		if err := m.client.Close(); err != nil {
			return err
		}
	}
	m.client = nil
	return nil
}

func (m *Milvus) Initialize(ctx context.Context, req dbplugin.InitializeRequest) (dbplugin.InitializeResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	cfg := &milvusConfig{}
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
	if cfg.Token == "" && (cfg.Username == "" || cfg.Password == "") {
		return dbplugin.InitializeResponse{}, errors.New("either token, or both username and password are required")
	}

	clientConfig, err := newMilvusClientConfig(cfg)
	if err != nil {
		return dbplugin.InitializeResponse{}, err
	}
	clientConfig.DisableConn = !req.VerifyConnection

	client, err := milvusclient.NewClient(ctx, *clientConfig)
	if err != nil {
		return dbplugin.InitializeResponse{}, fmt.Errorf("create Milvus client: %w", err)
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

	m.config = cfg
	m.client = client
	m.usernameProducer = up

	if req.VerifyConnection {
		if _, err := m.client.GetVersion(ctx); err != nil {
			_ = m.client.Close()
			m.client = nil
			return dbplugin.InitializeResponse{}, fmt.Errorf("failed to verify connection: %w", err)
		}
	}

	return dbplugin.InitializeResponse{Config: req.Config}, nil
}

func newMilvusClientConfig(cfg *milvusConfig) (*milvusclient.Config, error) {
	clientConfig := &milvusclient.Config{
		Address:  cfg.URL,
		Username: cfg.Username,
		Password: cfg.Password,
		APIKey:   cfg.Token,
		DBName:   cfg.DBName,
	}

	if !cfg.tls.Configured() {
		return clientConfig, nil
	}

	tlsConfig, err := cfg.tls.Build("")
	if err != nil {
		return nil, err
	}

	clientConfig.EnableTLSAuth = true
	clientConfig.DialOptions = append(
		append([]grpc.DialOption{}, milvusclient.DefaultGrpcOpts...),
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
	)
	return clientConfig, nil
}

// NewUser creates the user, ensures custom roles and their privileges exist,
// and then grants each role from the statement(s) to the user. If
// any grant fails the plugin drops the half-configured user.
func (m *Milvus) NewUser(ctx context.Context, req dbplugin.NewUserRequest) (dbplugin.NewUserResponse, error) {
	if len(req.Statements.Commands) == 0 {
		return dbplugin.NewUserResponse{}, dbutil.ErrEmptyCreationStatement
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.client == nil {
		return dbplugin.NewUserResponse{}, errors.New("database not initialized")
	}

	var rolesToAssign []string
	for _, cmd := range req.Statements.Commands {
		cmd = strings.TrimSpace(cmd)
		if cmd == "" {
			continue
		}

		// Structured JSON statement: {"roles": [...], "custom_roles": [...]}
		if strings.HasPrefix(cmd, "{") {
			var stmt milvusStatement
			if err := json.Unmarshal([]byte(cmd), &stmt); err == nil && (len(stmt.Roles) > 0 || len(stmt.CustomRoles) > 0 || strings.Contains(cmd, `"roles"`) || strings.Contains(cmd, `"custom_roles"`)) {
				for _, r := range stmt.Roles {
					if r = strings.TrimSpace(r); r != "" {
						rolesToAssign = append(rolesToAssign, r)
					}
				}
				for _, cr := range stmt.CustomRoles {
					if cr.Name == "" {
						return dbplugin.NewUserResponse{}, errors.New("custom role definition missing name")
					}
					if err := m.ensureRole(ctx, cr); err != nil {
						return dbplugin.NewUserResponse{}, err
					}
					rolesToAssign = append(rolesToAssign, cr.Name)
				}
				continue
			}

			// Single custom role JSON definition: {"name": "...", "privileges": [...]}
			var roleDef milvusRoleDef
			if err := json.Unmarshal([]byte(cmd), &roleDef); err == nil && roleDef.Name != "" {
				if err := m.ensureRole(ctx, roleDef); err != nil {
					return dbplugin.NewUserResponse{}, err
				}
				rolesToAssign = append(rolesToAssign, roleDef.Name)
				continue
			}

			return dbplugin.NewUserResponse{}, fmt.Errorf("failed to parse role statement JSON: %q", cmd)
		}

		// Array of roles or custom role definitions: ["public"] or [{"name": "..."}]
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

			var roleDefs []milvusRoleDef
			if err := json.Unmarshal([]byte(cmd), &roleDefs); err == nil && len(roleDefs) > 0 {
				for _, rd := range roleDefs {
					if rd.Name == "" {
						return dbplugin.NewUserResponse{}, errors.New("custom role definition missing name")
					}
					if err := m.ensureRole(ctx, rd); err != nil {
						return dbplugin.NewUserResponse{}, err
					}
					rolesToAssign = append(rolesToAssign, rd.Name)
				}
				continue
			}

			return dbplugin.NewUserResponse{}, fmt.Errorf("failed to parse role statement JSON array: %q", cmd)
		}

		// Plain role name string (e.g. "public", or comma-separated "public, admin")
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

	username, err := m.usernameProducer.Generate(req.UsernameConfig)
	if err != nil {
		return dbplugin.NewUserResponse{}, err
	}

	if err := m.client.CreateCredential(ctx, username, req.Password); err != nil {
		return dbplugin.NewUserResponse{}, fmt.Errorf("failed to create Milvus user: %w", err)
	}

	for _, role := range rolesToAssign {
		if err := m.client.AddUserRole(ctx, username, role); err != nil {
			if cleanupErr := m.client.DeleteCredential(ctx, username); cleanupErr != nil {
				return dbplugin.NewUserResponse{}, fmt.Errorf("failed to grant role %q: %w; failed to remove partially created user: %v", role, err, cleanupErr)
			}
			return dbplugin.NewUserResponse{}, fmt.Errorf("failed to grant role %q: %w", role, err)
		}
	}

	return dbplugin.NewUserResponse{Username: username}, nil
}

// UpdateUser handles user updates. Milvus requires the user's old password to
// update credentials unless common.security.superUsers is configured. Because
// OpenBao does not retain previously-generated dynamic passwords, password
// updates and static roles are unsupported.
func (m *Milvus) UpdateUser(_ context.Context, req dbplugin.UpdateUserRequest) (dbplugin.UpdateUserResponse, error) {
	if req.Username == "" {
		return dbplugin.UpdateUserResponse{}, errors.New("missing username")
	}
	if req.Password == nil && req.Expiration == nil {
		return dbplugin.UpdateUserResponse{}, errors.New("no changes requested")
	}
	if req.Password != nil {
		return dbplugin.UpdateUserResponse{}, errors.New("milvus does not support updating user credentials or static roles")
	}
	return dbplugin.UpdateUserResponse{}, nil
}

func (m *Milvus) DeleteUser(ctx context.Context, req dbplugin.DeleteUserRequest) (dbplugin.DeleteUserResponse, error) {
	if req.Username == "" {
		return dbplugin.DeleteUserResponse{}, errors.New("missing username")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.client == nil {
		return dbplugin.DeleteUserResponse{}, errors.New("database not initialized")
	}

	if err := m.client.DeleteCredential(ctx, req.Username); err != nil {
		return dbplugin.DeleteUserResponse{}, fmt.Errorf("failed to delete Milvus user: %w", err)
	}
	return dbplugin.DeleteUserResponse{}, nil
}

func (m *Milvus) ensureRole(ctx context.Context, role milvusRoleDef) error {
	role.Name = strings.TrimSpace(role.Name)
	if role.Name == "" {
		return errors.New("custom role definition missing name")
	}

	if err := m.client.CreateRole(ctx, role.Name); err != nil {
		if !strings.Contains(strings.ToLower(err.Error()), "already exist") {
			return fmt.Errorf("failed to create role %q: %w", role.Name, err)
		}
	}

	for _, p := range role.Privileges {
		privilege := strings.TrimSpace(p.Privilege)
		if privilege == "" {
			return fmt.Errorf("role %q privilege missing privilege/action name", role.Name)
		}

		objName := strings.TrimSpace(p.ObjectName)
		objType, err := parseObjectType(p.ObjectType, objName)
		if err != nil {
			return fmt.Errorf("role %q: %w", role.Name, err)
		}

		if objName == "" {
			objName = "*"
		}

		var opts []entity.OperatePrivilegeOption
		dbName := strings.TrimSpace(p.DBName)
		if dbName != "" {
			opts = append(opts, entity.WithOperatePrivilegeDatabase(dbName))
		}

		if err := m.client.Grant(ctx, role.Name, objType, objName, privilege, opts...); err != nil {
			errStr := strings.ToLower(err.Error())
			if !strings.Contains(errStr, "already exist") && !strings.Contains(errStr, "already granted") {
				return fmt.Errorf("failed to grant privilege %q on %s %q to role %q: %w", privilege, commonpb.ObjectType_name[int32(objType)], objName, role.Name, err)
			}
		}
	}
	return nil
}

func parseObjectType(raw string, objectName string) (entity.PriviledgeObjectType, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "global":
		return entity.PriviledegeObjectTypeGlobal, nil
	case "collection", "collections":
		return entity.PriviledegeObjectTypeCollection, nil
	case "user", "users":
		return entity.PriviledegeObjectTypeUser, nil
	case "":
		if objectName == "*" || objectName == "" {
			return entity.PriviledegeObjectTypeGlobal, nil
		}
		return entity.PriviledegeObjectTypeCollection, nil
	default:
		return 0, fmt.Errorf("unknown privilege object type: %q (expected Global, Collection, or User)", raw)
	}
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
