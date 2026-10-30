// Copyright (c) AppsCode Inc.
// SPDX-License-Identifier: MPL-2.0

// Package etcd implements an OpenBao v5 database plugin for etcd's built-in
// auth store. Dynamic credentials become native etcd users created via the
// v3 Auth API, with permissions coming from pre-existing roles and/or inline
// custom roles defined in creation_statements.
package etcd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"github.com/hashicorp/go-secure-stdlib/strutil"
	"github.com/mitchellh/mapstructure"
	dbplugin "github.com/openbao/openbao/sdk/v2/database/dbplugin/v5"
	"github.com/openbao/openbao/sdk/v2/database/helper/dbutil"
	"github.com/openbao/openbao/sdk/v2/helper/template"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/v2/internal/helper/dbtlsutil"
	"go.etcd.io/etcd/api/v3/v3rpc/rpctypes"
	clientv3 "go.etcd.io/etcd/client/v3"
)

const (
	etcdTypeName = "etcd"

	defaultUserNameTemplate = `{{ printf "v-%s-%s-%s-%s" (.DisplayName | truncate 10) (.RoleName | truncate 10) (random 15) (unix_time) | replace "." "-" | truncate 60 }}`

	defaultDialTimeout = 5 * time.Second
)

// ReportedVersion is overridable at build time.
var ReportedVersion = ""

// Etcd implements dbplugin.Database against etcd's v3 Auth API.
// creation_statements is a JSON document `{"roles":["role1","role2"]}`
// listing pre-existing etcd roles to grant the new user.
type Etcd struct {
	mu sync.Mutex

	config           *etcdConfig
	client           *clientv3.Client
	usernameProducer template.StringTemplate
}

type etcdConfig struct {
	Endpoints   []string `mapstructure:"endpoints"`
	Username    string   `mapstructure:"username"`
	Password    string   `mapstructure:"password"`
	DialTimeout string   `mapstructure:"dial_timeout"`
}

// etcdStatement represents a structured creation statement containing
// pre-existing roles and/or custom role definitions.
type etcdStatement struct {
	Roles       []string      `json:"roles"`
	CustomRoles []etcdRoleDef `json:"custom_roles"`
}

func (s *etcdStatement) UnmarshalJSON(data []byte) error {
	type Alias etcdStatement
	aux := &struct {
		*Alias
		SingleRole     string        `json:"role"`
		AltCustomRoles []etcdRoleDef `json:"customRoles"`
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

// etcdRoleDef represents a custom role definition in etcd.
type etcdRoleDef struct {
	Name        string           `json:"name"`
	Permissions []etcdPermission `json:"permissions"`
}

func (r *etcdRoleDef) UnmarshalJSON(data []byte) error {
	type Alias etcdRoleDef
	aux := &struct {
		*Alias
		AltPermissions []etcdPermission `json:"privileges"`
	}{
		Alias: (*Alias)(r),
	}
	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}
	if len(r.Permissions) == 0 && len(aux.AltPermissions) > 0 {
		r.Permissions = aux.AltPermissions
	}
	return nil
}

// etcdPermission represents a key permission grant for an etcd role.
type etcdPermission struct {
	Permission string `json:"permission"`
	Key        string `json:"key"`
	RangeEnd   string `json:"range_end"`
	Prefix     bool   `json:"prefix"`
}

func (p *etcdPermission) UnmarshalJSON(data []byte) error {
	type Alias etcdPermission
	aux := &struct {
		*Alias
		AltPerm     string `json:"perm"`
		Type        string `json:"type"`
		AltKey      string `json:"path"`
		AltRangeEnd string `json:"rangeEnd"`
		AltPrefix   bool   `json:"isPrefix"`
	}{
		Alias: (*Alias)(p),
	}
	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}
	if p.Permission == "" {
		if aux.AltPerm != "" {
			p.Permission = aux.AltPerm
		} else if aux.Type != "" {
			p.Permission = aux.Type
		}
	}
	if p.Key == "" && aux.AltKey != "" {
		p.Key = aux.AltKey
	}
	if p.RangeEnd == "" && aux.AltRangeEnd != "" {
		p.RangeEnd = aux.AltRangeEnd
	}
	if !p.Prefix && aux.AltPrefix {
		p.Prefix = true
	}
	return nil
}

var (
	_ dbplugin.Database       = (*Etcd)(nil)
	_ logical.PluginVersioner = (*Etcd)(nil)
)

func New() (any, error) {
	db := newEtcd()
	return dbplugin.NewDatabaseErrorSanitizerMiddleware(db, db.secretValues), nil
}

func newEtcd() *Etcd {
	return &Etcd{}
}

func (e *Etcd) secretValues() map[string]string {
	if e.config == nil {
		return map[string]string{}
	}
	return map[string]string{e.config.Password: "[password]"}
}

func (e *Etcd) Type() (string, error) {
	return etcdTypeName, nil
}

func (e *Etcd) PluginVersion() logical.PluginVersion {
	return logical.PluginVersion{Version: ReportedVersion}
}

func (e *Etcd) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.client != nil {
		_ = e.client.Close()
	}
	e.client = nil
	return nil
}

func (e *Etcd) Initialize(ctx context.Context, req dbplugin.InitializeRequest) (dbplugin.InitializeResponse, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	cfg := &etcdConfig{}
	if err := mapstructure.WeakDecode(req.Config, cfg); err != nil {
		return dbplugin.InitializeResponse{}, err
	}
	cfg.Endpoints = sanitizeEndpoints(cfg.Endpoints)
	if len(cfg.Endpoints) == 0 {
		return dbplugin.InitializeResponse{}, errors.New("endpoints is required")
	}

	dialTimeout := defaultDialTimeout
	if cfg.DialTimeout != "" {
		d, err := parseutil.ParseDurationSecond(cfg.DialTimeout)
		if err != nil {
			return dbplugin.InitializeResponse{}, fmt.Errorf("invalid dial_timeout: %w", err)
		}
		dialTimeout = d
	}

	tlsSettings, err := dbtlsutil.Decode(req.Config)
	if err != nil {
		return dbplugin.InitializeResponse{}, fmt.Errorf("invalid TLS configuration: %w", err)
	}

	clientCfg := clientv3.Config{
		Endpoints:   cfg.Endpoints,
		DialTimeout: dialTimeout,
		Username:    cfg.Username,
		Password:    cfg.Password,
		Context:     ctx,
	}
	if tlsSettings.Configured() {
		tlsConfig, err := tlsSettings.Build("")
		if err != nil {
			return dbplugin.InitializeResponse{}, err
		}
		clientCfg.TLS = tlsConfig
	}

	cli, err := clientv3.New(clientCfg)
	if err != nil {
		return dbplugin.InitializeResponse{}, fmt.Errorf("etcd client: %w", err)
	}

	usernameTemplate, err := strutil.GetString(req.Config, "username_template")
	if err != nil {
		_ = cli.Close()
		return dbplugin.InitializeResponse{}, err
	}
	if usernameTemplate == "" {
		usernameTemplate = defaultUserNameTemplate
	}
	up, err := template.NewTemplate(template.Template(usernameTemplate))
	if err != nil {
		_ = cli.Close()
		return dbplugin.InitializeResponse{}, fmt.Errorf("invalid username_template: %w", err)
	}
	if _, err := up.Generate(dbplugin.UsernameMetadata{}); err != nil {
		_ = cli.Close()
		return dbplugin.InitializeResponse{}, fmt.Errorf("invalid username template: %w", err)
	}

	if e.client != nil {
		_ = e.client.Close()
	}
	e.config = cfg
	e.client = cli
	e.usernameProducer = up

	if req.VerifyConnection {
		verifyCtx, cancel := context.WithTimeout(ctx, dialTimeout)
		defer cancel()
		if _, err := cli.AuthStatus(verifyCtx); err != nil {
			_ = cli.Close()
			e.client = nil
			return dbplugin.InitializeResponse{}, fmt.Errorf("failed to verify connection: %w", err)
		}
	}

	return dbplugin.InitializeResponse{Config: req.Config}, nil
}

// NewUser creates an etcd user via UserAdd, ensuring any custom roles exist
// and granting each role in the statement via UserGrantRole. Custom-role
// permissions are additive-only: omitted permissions are not revoked. If a
// role grant fails, the just-created user is deleted so no half-configured user
// is left behind. Custom roles are preserved on user revocation.
func (e *Etcd) NewUser(ctx context.Context, req dbplugin.NewUserRequest) (dbplugin.NewUserResponse, error) {
	if len(req.Statements.Commands) == 0 {
		return dbplugin.NewUserResponse{}, dbutil.ErrEmptyCreationStatement
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	if e.client == nil {
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
			var stmt etcdStatement
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
					if err := e.ensureRole(ctx, cr); err != nil {
						return dbplugin.NewUserResponse{}, err
					}
					rolesToAssign = append(rolesToAssign, cr.Name)
				}
				continue
			}

			// Single custom role JSON definition: {"name": "...", "permissions": [...]}
			var roleDef etcdRoleDef
			if err := json.Unmarshal([]byte(cmd), &roleDef); err == nil && roleDef.Name != "" {
				if err := e.ensureRole(ctx, roleDef); err != nil {
					return dbplugin.NewUserResponse{}, err
				}
				rolesToAssign = append(rolesToAssign, roleDef.Name)
				continue
			}

			return dbplugin.NewUserResponse{}, fmt.Errorf("failed to parse role statement JSON: %q", cmd)
		}

		// Array of roles or custom role definitions: ["reader"] or [{"name": "..."}]
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

			var roleDefs []etcdRoleDef
			if err := json.Unmarshal([]byte(cmd), &roleDefs); err == nil && len(roleDefs) > 0 {
				for _, rd := range roleDefs {
					if rd.Name == "" {
						return dbplugin.NewUserResponse{}, errors.New("custom role definition missing name")
					}
					if err := e.ensureRole(ctx, rd); err != nil {
						return dbplugin.NewUserResponse{}, err
					}
					rolesToAssign = append(rolesToAssign, rd.Name)
				}
				continue
			}

			return dbplugin.NewUserResponse{}, fmt.Errorf("failed to parse role statement JSON array: %q", cmd)
		}

		// Plain role name string (e.g. "reader", or comma-separated "reader, writer")
		if strings.Contains(cmd, ",") {
			for part := range strings.SplitSeq(cmd, ",") {
				if part = strings.TrimSpace(part); part != "" {
					rolesToAssign = append(rolesToAssign, part)
				}
			}
		} else {
			rolesToAssign = append(rolesToAssign, cmd)
		}
	}

	rolesToAssign = deduplicateStrings(rolesToAssign)

	username, err := e.usernameProducer.Generate(req.UsernameConfig)
	if err != nil {
		return dbplugin.NewUserResponse{}, err
	}

	if _, err := e.client.UserAdd(ctx, username, req.Password); err != nil {
		return dbplugin.NewUserResponse{}, fmt.Errorf("create etcd user: %w", err)
	}

	cleanup := func(opErr error) (dbplugin.NewUserResponse, error) {
		_, _ = e.client.UserDelete(ctx, username)
		return dbplugin.NewUserResponse{}, opErr
	}

	for _, role := range rolesToAssign {
		if _, err := e.client.UserGrantRole(ctx, username, role); err != nil {
			errStr := strings.ToLower(err.Error())
			if !strings.Contains(errStr, "already exist") && !strings.Contains(errStr, "already granted") {
				return cleanup(fmt.Errorf("grant role %q: %w", role, err))
			}
		}
	}

	return dbplugin.NewUserResponse{Username: username}, nil
}

func (e *Etcd) UpdateUser(ctx context.Context, req dbplugin.UpdateUserRequest) (dbplugin.UpdateUserResponse, error) {
	if req.Username == "" {
		return dbplugin.UpdateUserResponse{}, errors.New("missing username")
	}
	if req.Password == nil && req.Expiration == nil {
		return dbplugin.UpdateUserResponse{}, errors.New("no changes requested")
	}
	if req.Password == nil {
		return dbplugin.UpdateUserResponse{}, nil
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	if e.client == nil {
		return dbplugin.UpdateUserResponse{}, errors.New("database not initialized")
	}

	if _, err := e.client.UserChangePassword(ctx, req.Username, req.Password.NewPassword); err != nil {
		return dbplugin.UpdateUserResponse{}, fmt.Errorf("change etcd user password: %w", err)
	}
	return dbplugin.UpdateUserResponse{}, nil
}

func (e *Etcd) DeleteUser(ctx context.Context, req dbplugin.DeleteUserRequest) (dbplugin.DeleteUserResponse, error) {
	if req.Username == "" {
		return dbplugin.DeleteUserResponse{}, errors.New("missing username")
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	if e.client == nil {
		return dbplugin.DeleteUserResponse{}, errors.New("database not initialized")
	}

	if _, err := e.client.UserDelete(ctx, req.Username); err != nil {
		if isUserNotFound(err) {
			return dbplugin.DeleteUserResponse{}, nil
		}
		return dbplugin.DeleteUserResponse{}, fmt.Errorf("delete etcd user: %w", err)
	}
	return dbplugin.DeleteUserResponse{}, nil
}

// --- helpers ---------------------------------------------------------------

func isUserNotFound(err error) bool {
	return err != nil && strings.Contains(err.Error(), "user name not found")
}

func sanitizeEndpoints(endpoints []string) []string {
	var clean []string
	for _, e := range endpoints {
		for part := range strings.SplitSeq(e, ",") {
			part = strings.TrimSpace(part)
			if part != "" {
				clean = append(clean, part)
			}
		}
	}
	return clean
}

func (e *Etcd) ensureRole(ctx context.Context, role etcdRoleDef) error {
	role.Name = strings.TrimSpace(role.Name)
	if role.Name == "" {
		return errors.New("custom role definition missing name")
	}

	if _, err := e.client.RoleAdd(ctx, role.Name); err != nil {
		if !isRoleAlreadyExists(err) {
			return fmt.Errorf("failed to create role %q: %w", role.Name, err)
		}
	}

	for _, p := range role.Permissions {
		permType, err := parseEtcdPermissionType(p.Permission)
		if err != nil {
			return fmt.Errorf("role %q: %w", role.Name, err)
		}

		key := p.Key
		rangeEnd := strings.TrimSpace(p.RangeEnd)
		if p.Prefix && rangeEnd == "" {
			rangeEnd = clientv3.GetPrefixRangeEnd(key)
		} else if key == "" && rangeEnd == "" {
			return fmt.Errorf("role %q permission requires a non-empty key (or prefix: true)", role.Name)
		}

		if _, err := e.client.RoleGrantPermission(ctx, role.Name, key, rangeEnd, permType); err != nil {
			errStr := strings.ToLower(err.Error())
			if !strings.Contains(errStr, "already exist") && !strings.Contains(errStr, "already granted") {
				return fmt.Errorf("failed to grant permission to role %q: %w", role.Name, err)
			}
		}
	}
	return nil
}

func parseEtcdPermissionType(s string) (clientv3.PermissionType, error) {
	norm := strings.ToUpper(strings.TrimSpace(s))
	norm = strings.ReplaceAll(norm, "-", "")
	norm = strings.ReplaceAll(norm, "_", "")
	switch norm {
	case "READ":
		return clientv3.PermissionType(clientv3.PermRead), nil
	case "WRITE":
		return clientv3.PermissionType(clientv3.PermWrite), nil
	case "READWRITE":
		return clientv3.PermissionType(clientv3.PermReadWrite), nil
	default:
		return clientv3.StrToPermissionType(s)
	}
}

func isRoleAlreadyExists(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, rpctypes.ErrRoleAlreadyExist) || errors.Is(err, rpctypes.ErrGRPCRoleAlreadyExist) {
		return true
	}
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "role name already exists") || strings.Contains(errStr, "role already exist")
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
