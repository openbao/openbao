// Package qdrant implements an OpenBao v5 database plugin for the
// Qdrant vector database.
//
// Qdrant supports granular access control (RBAC) via JSON Web Tokens (JWT)
// signed with the instance's admin API key using HS256:
//   - Initialize parses config and verifies the API key against `/readyz`.
//   - NewUser generates a unique username, inserts a validation point into the
//     validation collection (default: "openbao_users"), signs an HS256 JWT
//     containing permissions, lease expiry (exp), and a value_exists claim,
//     and returns the signed JWT in NewUserResponse.Password.
//   - UpdateUser handles credential updates.
//   - DeleteUser revokes the user's token by deleting its validation point from
//     the validation collection, immediately invalidating the token via value_exists.
package qdrant

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

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/mitchellh/mapstructure"
	dbplugin "github.com/openbao/openbao/sdk/v2/database/dbplugin/v5"
	"github.com/openbao/openbao/sdk/v2/helper/template"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/v2/internal/helper/dbtlsutil"
)

const (
	qdrantTypeName              = "qdrant"
	defaultUserNameTemplate     = `{{ printf "v-%s-%s-%s-%s" (.DisplayName | truncate 8) (.RoleName | truncate 8) (random 20) (unix_time) | truncate 63 }}`
	defaultValidationCollection = "openbao_users"
)

// ReportedVersion is overridable at build time.
var ReportedVersion = ""

// Qdrant implements dbplugin.Database for Qdrant.
type Qdrant struct {
	mu               sync.Mutex
	config           *qdrantConfig
	client           *http.Client
	usernameProducer template.StringTemplate
}

type qdrantConfig struct {
	URL                  string `mapstructure:"url"`
	APIKey               string `mapstructure:"api_key"`
	ValidationCollection string `mapstructure:"validation_collection"`

	tls dbtlsutil.Config
}

var (
	_ dbplugin.Database       = (*Qdrant)(nil)
	_ logical.PluginVersioner = (*Qdrant)(nil)
)

func New() (any, error) {
	db := newQdrant()
	return dbplugin.NewDatabaseErrorSanitizerMiddleware(db, db.secretValues), nil
}

func newQdrant() *Qdrant {
	up, _ := template.NewTemplate(template.Template(defaultUserNameTemplate))
	return &Qdrant{
		usernameProducer: up,
	}
}

func (q *Qdrant) secretValues() map[string]string {
	if q.config == nil {
		return map[string]string{}
	}
	return map[string]string{q.config.APIKey: "[api_key]"}
}

func (q *Qdrant) Type() (string, error) {
	return qdrantTypeName, nil
}

func (q *Qdrant) PluginVersion() logical.PluginVersion {
	return logical.PluginVersion{Version: ReportedVersion}
}

func (q *Qdrant) Close() error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.client != nil {
		q.client.CloseIdleConnections()
	}
	q.client = nil
	return nil
}

func (q *Qdrant) Initialize(ctx context.Context, req dbplugin.InitializeRequest) (dbplugin.InitializeResponse, error) {
	q.mu.Lock()
	defer q.mu.Unlock()

	cfg := &qdrantConfig{}
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

	client, err := newHTTPClient(cfg)
	if err != nil {
		return dbplugin.InitializeResponse{}, err
	}
	q.config = cfg
	q.client = client

	up, err := template.NewTemplate(template.Template(defaultUserNameTemplate))
	if err != nil {
		return dbplugin.InitializeResponse{}, fmt.Errorf("unable to initialize username template: %w", err)
	}
	q.usernameProducer = up

	if req.VerifyConnection {
		if err := q.healthcheck(ctx); err != nil {
			return dbplugin.InitializeResponse{}, fmt.Errorf("failed to verify connection: %w", err)
		}
	}

	return dbplugin.InitializeResponse{Config: req.Config}, nil
}

// NewUser generates a signed HS256 JWT token for Qdrant RBAC.
func (q *Qdrant) NewUser(ctx context.Context, req dbplugin.NewUserRequest) (dbplugin.NewUserResponse, error) {
	q.mu.Lock()
	defer q.mu.Unlock()

	if q.config == nil || q.config.APIKey == "" {
		return dbplugin.NewUserResponse{}, errors.New("qdrant api_key is required in config to sign JWT tokens")
	}

	username, err := q.usernameProducer.Generate(req.UsernameConfig)
	if err != nil {
		return dbplugin.NewUserResponse{}, fmt.Errorf("failed to generate username: %w", err)
	}

	claims := jwt.MapClaims{
		"sub": username,
	}

	if !req.Expiration.IsZero() {
		claims["exp"] = req.Expiration.Unix()
	}

	// Parse creation statements for access permissions.
	var collectionAccessList []any
	var globalAccess string
	hasCommands := false

	for _, cmd := range req.Statements.Commands {
		cmd = strings.TrimSpace(cmd)
		if cmd == "" {
			continue
		}
		hasCommands = true

		// JSON Object
		if strings.HasPrefix(cmd, "{") {
			var obj map[string]any
			if err := json.Unmarshal([]byte(cmd), &obj); err != nil {
				return dbplugin.NewUserResponse{}, fmt.Errorf("malformed JSON in creation statement: %w", err)
			}

			// Validate allowed keys. Only "collection" and "access" are permitted.
			for k := range obj {
				if k != "access" && k != "collection" {
					return dbplugin.NewUserResponse{}, fmt.Errorf("unsupported key %q in creation statement; only access permissions may be specified", k)
				}
			}

			// Single collection access rule: {"collection": "...", "access": "..."}
			if _, hasCol := obj["collection"]; hasCol {
				rule, err := parseCollectionRule(obj)
				if err != nil {
					return dbplugin.NewUserResponse{}, err
				}
				collectionAccessList = append(collectionAccessList, rule)
				continue
			}

			// Access wrapper: {"access": ...}
			if accRaw, hasAcc := obj["access"]; hasAcc {
				switch v := accRaw.(type) {
				case string:
					normalized := strings.ToLower(strings.TrimSpace(v))
					switch normalized {
					case "r", "read":
						globalAccess = "r"
					case "m", "manage":
						globalAccess = "m"
					default:
						return dbplugin.NewUserResponse{}, fmt.Errorf("invalid global access %q in creation statement; expected 'r' or 'm'", v)
					}
				case []any:
					for i, elem := range v {
						elemMap, ok := elem.(map[string]any)
						if !ok {
							return dbplugin.NewUserResponse{}, fmt.Errorf("invalid collection access rule at index %d in creation statement", i)
						}
						rule, err := parseCollectionRule(elemMap)
						if err != nil {
							return dbplugin.NewUserResponse{}, fmt.Errorf("invalid collection rule at index %d: %w", i, err)
						}
						collectionAccessList = append(collectionAccessList, rule)
					}
				default:
					return dbplugin.NewUserResponse{}, errors.New("invalid type for access field: expected string or array of collection rules")
				}
				continue
			}

			return dbplugin.NewUserResponse{}, errors.New("creation statement JSON object must specify 'access' or 'collection'")
		}

		// JSON Array
		if strings.HasPrefix(cmd, "[") {
			var arr []any
			if err := json.Unmarshal([]byte(cmd), &arr); err != nil {
				return dbplugin.NewUserResponse{}, fmt.Errorf("malformed JSON array in creation statement: %w", err)
			}
			for i, elem := range arr {
				elemMap, ok := elem.(map[string]any)
				if !ok {
					return dbplugin.NewUserResponse{}, fmt.Errorf("invalid collection access rule at index %d in creation statement", i)
				}
				rule, err := parseCollectionRule(elemMap)
				if err != nil {
					return dbplugin.NewUserResponse{}, fmt.Errorf("invalid collection rule at index %d: %w", i, err)
				}
				collectionAccessList = append(collectionAccessList, rule)
			}
			continue
		}

		// Plain string shorthand
		switch strings.ToLower(cmd) {
		case "r", "read":
			globalAccess = "r"
		case "m", "manage":
			globalAccess = "m"
		default:
			// "col1:rw, col2:r"
			for _, part := range strings.Split(cmd, ",") {
				part = strings.TrimSpace(part)
				if part == "" {
					continue
				}
				col, acc, found := strings.Cut(part, ":")
				col = strings.TrimSpace(col)
				acc = strings.TrimSpace(acc)
				if !found || col == "" || (acc != "r" && acc != "rw") {
					return dbplugin.NewUserResponse{}, fmt.Errorf("unrecognized creation statement %q; expected 'r', 'm', or 'collection:r|rw'", part)
				}
				collectionAccessList = append(collectionAccessList, map[string]any{
					"collection": col,
					"access":     acc,
				})
			}
		}
	}

	if !hasCommands {
		return dbplugin.NewUserResponse{}, errors.New("at least one creation statement specifying access permissions is required")
	}

	if len(collectionAccessList) > 0 && globalAccess != "" {
		return dbplugin.NewUserResponse{}, errors.New("cannot mix global access ('r'/'m') with collection-specific access rules")
	}

	if len(collectionAccessList) > 0 {
		claims["access"] = collectionAccessList
	} else if globalAccess != "" {
		claims["access"] = globalAccess
	} else {
		return dbplugin.NewUserResponse{}, errors.New("no valid access permissions were defined in creation statements")
	}

	validationCol := q.validationCollection()
	claims["value_exists"] = map[string]any{
		"collection": validationCol,
		"matches": []map[string]any{
			{
				"key":   "user_id",
				"value": username,
			},
		},
	}

	if q.client != nil {
		if err := q.ensureCollection(ctx, validationCol); err != nil {
			return dbplugin.NewUserResponse{}, fmt.Errorf("failed to ensure validation collection: %w", err)
		}
		if err := q.insertValidationPoint(ctx, validationCol, username); err != nil {
			return dbplugin.NewUserResponse{}, fmt.Errorf("failed to insert validation point: %w", err)
		}
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte(q.config.APIKey))
	if err != nil {
		if q.client != nil {
			_ = q.deleteValidationPoints(ctx, validationCol, username)
		}
		return dbplugin.NewUserResponse{}, fmt.Errorf("failed to sign JWT token: %w", err)
	}

	return dbplugin.NewUserResponse{
		Username: username,
		Password: signedToken,
	}, nil
}

// UpdateUser handles user updates. Qdrant generates dynamic JWT credentials
// and does not support password updates or static credentials.
func (q *Qdrant) UpdateUser(ctx context.Context, req dbplugin.UpdateUserRequest) (dbplugin.UpdateUserResponse, error) {
	if req.Username == "" {
		return dbplugin.UpdateUserResponse{}, errors.New("missing username")
	}
	if req.Password == nil && req.Expiration == nil {
		return dbplugin.UpdateUserResponse{}, errors.New("no changes requested")
	}
	if req.Password != nil {
		return dbplugin.UpdateUserResponse{}, errors.New("qdrant does not support updating user credentials or static roles")
	}
	return dbplugin.UpdateUserResponse{}, nil
}

// DeleteUser revokes the user's JWT by deleting its validation point from Qdrant.
func (q *Qdrant) DeleteUser(ctx context.Context, req dbplugin.DeleteUserRequest) (dbplugin.DeleteUserResponse, error) {
	q.mu.Lock()
	defer q.mu.Unlock()

	if req.Username == "" {
		return dbplugin.DeleteUserResponse{}, errors.New("missing username")
	}

	if q.client != nil {
		validationCol := q.validationCollection()
		if err := q.deleteValidationPoints(ctx, validationCol, req.Username); err != nil {
			return dbplugin.DeleteUserResponse{}, err
		}
	}

	return dbplugin.DeleteUserResponse{}, nil
}

func (q *Qdrant) validationCollection() string {
	if q.config != nil && q.config.ValidationCollection != "" {
		return q.config.ValidationCollection
	}
	return defaultValidationCollection
}

func parseCollectionRule(elemMap map[string]any) (map[string]any, error) {
	for k := range elemMap {
		if k != "collection" && k != "access" {
			return nil, fmt.Errorf("unsupported key %q in collection access rule; only 'collection' and 'access' are allowed", k)
		}
	}
	colRaw, hasCol := elemMap["collection"]
	accRaw, hasAcc := elemMap["access"]
	if !hasCol || !hasAcc {
		return nil, errors.New("collection access rule must contain both 'collection' and 'access'")
	}
	col, ok1 := colRaw.(string)
	acc, ok2 := accRaw.(string)
	if !ok1 || strings.TrimSpace(col) == "" {
		return nil, fmt.Errorf("invalid collection name: %v", colRaw)
	}
	if !ok2 || (acc != "r" && acc != "rw") {
		return nil, fmt.Errorf("invalid access level %v for collection %q; expected 'r' or 'rw'", accRaw, col)
	}
	return map[string]any{
		"collection": strings.TrimSpace(col),
		"access":     acc,
	}, nil
}

func (q *Qdrant) doRequest(ctx context.Context, method, path string, reqBody any) (*http.Response, []byte, error) {
	if q.client == nil || q.config == nil {
		return nil, nil, errors.New("qdrant client not initialized")
	}
	base := strings.TrimRight(q.config.URL, "/")
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
	if q.config.APIKey != "" {
		req.Header.Set("api-key", q.config.APIKey)
	}

	resp, err := q.client.Do(req)
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

func (q *Qdrant) ensureCollection(ctx context.Context, collection string) error {
	resp, body, err := q.doRequest(ctx, http.MethodGet, "/collections/"+url.PathEscape(collection), nil)
	if err != nil {
		return fmt.Errorf("check collection %q: %w", collection, err)
	}
	if resp.StatusCode == http.StatusOK {
		return nil
	}
	if resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("check collection %q failed: %s: %s", collection, resp.Status, string(body))
	}

	createPayload := map[string]any{
		"vectors": map[string]any{},
	}
	cResp, cBody, err := q.doRequest(ctx, http.MethodPut, "/collections/"+url.PathEscape(collection), createPayload)
	if err != nil {
		return fmt.Errorf("create validation collection %q: %w", collection, err)
	}
	if cResp.StatusCode != http.StatusOK && cResp.StatusCode != http.StatusCreated {
		return fmt.Errorf("create validation collection %q failed: %s: %s", collection, cResp.Status, string(cBody))
	}
	return nil
}

func (q *Qdrant) insertValidationPoint(ctx context.Context, collection, username string) error {
	pointID := uuid.New().String()
	payload := map[string]any{
		"points": []map[string]any{
			{
				"id":     pointID,
				"vector": map[string]any{},
				"payload": map[string]any{
					"user_id": username,
				},
			},
		},
	}
	resp, body, err := q.doRequest(ctx, http.MethodPut, "/collections/"+url.PathEscape(collection)+"/points?wait=true", payload)
	if err != nil {
		return fmt.Errorf("insert validation point for user %q: %w", username, err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("insert validation point for user %q failed: %s: %s", username, resp.Status, string(body))
	}
	return nil
}

func (q *Qdrant) deleteValidationPoints(ctx context.Context, collection, username string) error {
	deletePayload := map[string]any{
		"filter": map[string]any{
			"must": []map[string]any{
				{
					"key": "user_id",
					"match": map[string]any{
						"value": username,
					},
				},
			},
		},
	}
	resp, body, err := q.doRequest(ctx, http.MethodPost, "/collections/"+url.PathEscape(collection)+"/points/delete?wait=true", deletePayload)
	if err != nil {
		return fmt.Errorf("delete validation points for user %q: %w", username, err)
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("delete validation points for user %q failed: %s: %s", username, resp.Status, string(body))
	}
	return nil
}

func (q *Qdrant) healthcheck(ctx context.Context) error {
	base := strings.TrimRight(q.config.URL, "/")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/readyz", nil)
	if err != nil {
		return err
	}
	if q.config.APIKey != "" {
		req.Header.Set("api-key", q.config.APIKey)
	}
	resp, err := q.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("qdrant /readyz failed: %s: %s", resp.Status, string(b))
	}
	return nil
}

func newHTTPClient(cfg *qdrantConfig) (*http.Client, error) {
	tlsCfg, err := cfg.tls.Build("")
	if err != nil {
		return nil, err
	}
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}, nil
}
