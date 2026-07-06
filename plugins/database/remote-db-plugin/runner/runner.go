// Copyright (c) AppsCode Inc.
// SPDX-License-Identifier: MPL-2.0

// Package runner dispatches incoming requests from the hub to the actual
// built-in database plugins (postgres, mysql, valkey, …) running in-process
// inside the spoke daemon.
//
// PluginRunner holds a long-lived cache of `dbplugin.Database` instances
// keyed by the hub's `instance_id`. The hub generates that id on first
// Initialize and persists it in the database mount's config; every subsequent
// NewUser/UpdateUser/DeleteUser carries it. This fixes the earlier design
// where every request ran as a one-shot subprocess: state (DB connection,
// rotated root credentials, prepared statements) is now preserved between
// calls, which is what the dbplugin v5 contract assumes.
//
// On a cache miss (spoke restart with hub still holding the id), the runner
// transparently re-Initializes from the config carried in the request so
// callers never see the difference.
package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	dbCassandra "github.com/openbao/openbao/plugins/database/cassandra"
	dbInflux "github.com/openbao/openbao/plugins/database/influxdb"
	dbMySQL "github.com/openbao/openbao/plugins/database/mysql"
	dbPostgres "github.com/openbao/openbao/plugins/database/postgresql"
	dbValkey "github.com/openbao/openbao/plugins/database/valkey"
	dbplugin "github.com/openbao/openbao/sdk/v2/database/dbplugin/v5"
)

// PluginRunner holds the cache of long-lived plugin instances. Safe for
// concurrent use: r.mu guards `plugins` and `loading`; once an entry is
// acquired via acquire(), callers operate on its db without holding r.mu.
//
// `loading` carries a per-instance-id mutex used to single-flight Initialize
// and cold-cache loads — without it, two concurrent requests for the same id
// can both call Initialize then install entries, then race on cleanup of the
// displaced one.
type PluginRunner struct {
	mu      sync.Mutex
	plugins map[string]*pluginEntry
	loading map[string]*sync.Mutex

	idleTTL       time.Duration // 0 disables idle eviction
	evictorOnce   sync.Once
	evictorActive bool // set under evictorOnce so tests can detect
}

// pluginEntry wraps one cached dbplugin.Database. The refcount has two
// classes of holder:
//
//  1. The cache slot itself. While the entry is reachable via r.plugins it
//     holds one reference. installOrReplace and remove drop this reference.
//  2. Each in-flight handler. acquire() bumps the count under r.mu, release()
//     drops it.
//
// db.Close() runs exactly once, when refs transitions to 0. This is what
// makes Close, re-Initialize, and idle eviction safe to call while a handler
// is mid-flight: the displaced entry stays usable for its remaining
// handlers, and its connection is closed only after the last one releases.
type pluginEntry struct {
	pluginName string
	db         dbplugin.Database
	lastUsed   time.Time // guarded by PluginRunner.mu
	refs       atomic.Int32
}

func newPluginEntry(name string, db dbplugin.Database) *pluginEntry {
	e := &pluginEntry{pluginName: name, db: db, lastUsed: time.Now()}
	e.refs.Store(1) // initial reference for the cache slot
	return e
}

// release drops one reference. If it was the last, closes the underlying db.
// Safe to call from any goroutine; never blocks on r.mu.
func (e *pluginEntry) release() {
	if e.refs.Add(-1) == 0 {
		if err := e.db.Close(); err != nil {
			log.Printf("[runner] close plugin instance: %v", err)
		}
	}
}

// DefaultIdleTTL is the period of inactivity after which a cached plugin
// instance is closed and removed. Catches the case where the hub forgot to
// send a Close (mount deletion while the spoke was offline, hub crash that
// lost track of the instance_id, ...).
const DefaultIdleTTL = 24 * time.Hour

func NewPluginRunner() *PluginRunner {
	return NewPluginRunnerWithTTL(DefaultIdleTTL)
}

// NewPluginRunnerWithTTL constructs a runner with a custom idle TTL. Set
// idleTTL to 0 to disable eviction (useful for tests).
func NewPluginRunnerWithTTL(idleTTL time.Duration) *PluginRunner {
	return &PluginRunner{
		plugins: make(map[string]*pluginEntry),
		loading: make(map[string]*sync.Mutex),
		idleTTL: idleTTL,
	}
}

// StartIdleEvictor launches a background goroutine that closes plugins whose
// lastUsed is older than idleTTL. Cancellable via ctx; the goroutine returns
// when ctx is done. Idempotent — calling it more than once is a no-op (only
// the first call spawns an evictor).
func (r *PluginRunner) StartIdleEvictor(ctx context.Context) {
	if r.idleTTL <= 0 {
		return
	}
	r.evictorOnce.Do(func() {
		r.evictorActive = true
		go func() {
			// Check at roughly 1/4 the TTL so an idle entry is evicted within
			// a reasonable window past the deadline, without thrashing on a
			// short TTL.
			tick := r.idleTTL / 4
			if tick < time.Minute {
				tick = time.Minute
			}
			t := time.NewTicker(tick)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case now := <-t.C:
					r.evictIdle(now)
				}
			}
		}()
	})
}

func (r *PluginRunner) evictIdle(now time.Time) {
	if r.idleTTL <= 0 {
		return
	}
	r.mu.Lock()
	var toRelease []*pluginEntry
	for id, e := range r.plugins {
		// refs == 1 means only the slot reference: no handler is in flight,
		// so the slot is safe to drop. If a handler is in flight (refs > 1)
		// the entry is skipped — the next tick will catch it after release.
		// The lookup, refs check, and delete all happen under r.mu, which
		// acquire() also takes, so the check is race-free against new
		// acquirers.
		if e.refs.Load() == 1 && now.Sub(e.lastUsed) > r.idleTTL {
			delete(r.plugins, id)
			toRelease = append(toRelease, e)
		}
	}
	r.mu.Unlock()
	for _, e := range toRelease {
		e.release()
	}
}

// ExecuteRequest is the single entry point called for every inbound request
// from the hub. It parses the JSON, dispatches on `method`, and returns the
// JSON-encoded reply.
func (r *PluginRunner) ExecuteRequest(requestJSON string) (string, error) {
	var req map[string]interface{}
	if err := json.Unmarshal([]byte(requestJSON), &req); err != nil {
		return "", fmt.Errorf("parse request: %w", err)
	}

	method, ok := req["method"].(string)
	if !ok {
		return "", fmt.Errorf("missing method")
	}
	instanceID, _ := req["instance_id"].(string)
	if instanceID == "" {
		return "", fmt.Errorf("missing instance_id")
	}
	pluginName, _ := req["plugin_name"].(string)

	ctx := context.Background()

	switch method {
	case "Initialize":
		return r.handleInitialize(ctx, instanceID, pluginName, req)
	case "NewUser":
		return r.withPlugin(ctx, instanceID, pluginName, req, r.handleNewUser)
	case "UpdateUser":
		return r.withPlugin(ctx, instanceID, pluginName, req, r.handleUpdateUser)
	case "DeleteUser":
		return r.withPlugin(ctx, instanceID, pluginName, req, r.handleDeleteUser)
	case "Type":
		// The hub currently answers Type locally from p.pluginName and never
		// dispatches it; this branch exists so a future code path that does
		// route Type through the wire does not get "unknown method" back.
		return r.withPlugin(ctx, instanceID, pluginName, req, r.handleType)
	case "Close":
		return r.handleClose(instanceID)
	default:
		return "", fmt.Errorf("unknown method: %s", method)
	}
}

// --- Cache primitives -------------------------------------------------------

// acquire returns the cached entry for instanceID with refs bumped. The
// caller MUST call entry.release() when done.
func (r *PluginRunner) acquire(instanceID string) (*pluginEntry, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.plugins[instanceID]
	if !ok {
		return nil, false
	}
	e.refs.Add(1)
	e.lastUsed = time.Now()
	return e, true
}

// installOrReplace stores entry at instanceID, dropping the slot reference on
// any previously cached entry. If a handler is still mid-flight on the
// displaced entry, its db stays open until that handler releases; otherwise
// db.Close runs synchronously here.
func (r *PluginRunner) installOrReplace(instanceID string, entry *pluginEntry) {
	r.mu.Lock()
	old := r.plugins[instanceID]
	r.plugins[instanceID] = entry
	r.mu.Unlock()
	if old != nil {
		old.release()
	}
}

// remove drops the slot reference for instanceID. The underlying db is closed
// when the last in-flight handler releases (or immediately, if none).
// Returns true if an entry existed.
func (r *PluginRunner) remove(instanceID string) bool {
	r.mu.Lock()
	old, ok := r.plugins[instanceID]
	if ok {
		delete(r.plugins, instanceID)
	}
	r.mu.Unlock()
	if ok {
		old.release()
	}
	return ok
}

// loadLock returns the per-instance-id mutex used to single-flight Initialize
// and lazy re-init for the same id. Both single-flight call sites delete
// their entry from r.loading on the way out (success or failure), so the
// map's size at rest is the number of concurrent in-flight loads, not the
// number of distinct instance_ids ever served.
func (r *PluginRunner) loadLock(instanceID string) *sync.Mutex {
	r.mu.Lock()
	defer r.mu.Unlock()
	m, ok := r.loading[instanceID]
	if !ok {
		m = &sync.Mutex{}
		r.loading[instanceID] = m
	}
	return m
}

// withPlugin acquires the cached plugin for instanceID and runs handler with
// it. On cache miss it lazy-inits from the config carried in the request;
// concurrent cold-cache callers for the same id are single-flighted via
// loadLock. The handler runs with refs bumped, so evictIdle, Close, and
// re-Initialize cannot close the db underneath it.
func (r *PluginRunner) withPlugin(
	ctx context.Context,
	instanceID string,
	pluginName string,
	req map[string]interface{},
	handler func(ctx context.Context, plugin dbplugin.Database, req map[string]interface{}) (string, error),
) (string, error) {
	if entry, ok := r.acquire(instanceID); ok {
		defer r.releaseHandler(entry)
		return handler(ctx, entry.db, req)
	}

	cfg, _ := req["config"].(map[string]interface{})
	if len(cfg) == 0 {
		// Empty / missing config would let the built-in plugin's Initialize
		// silently apply its zero-value defaults and connect to whatever DSN
		// that resolves to. Refuse and surface to the hub; an operator
		// editing the mount config can fix it where it's actually stored.
		return "", fmt.Errorf("instance %s not cached and request carries no config to re-init", instanceID)
	}
	entry, err := r.loadOrInit(ctx, instanceID, pluginName, cfg)
	if err != nil {
		return "", err
	}
	defer r.releaseHandler(entry)
	return handler(ctx, entry.db, req)
}

// releaseHandler drops a handler's reference on entry, bumping lastUsed
// FIRST so an evictor that races between the bump and the refcount
// decrement sees refs > 1 (handler still held) and skips. Without the
// bump-first ordering, a long-running handler that returns just before
// the evictor wakes up would have its entry torn down on the very next
// tick using a lastUsed timestamp from acquire() time — possibly hours
// ago for a slow plugin call.
func (r *PluginRunner) releaseHandler(entry *pluginEntry) {
	r.mu.Lock()
	entry.lastUsed = time.Now()
	r.mu.Unlock()
	entry.release()
}

// loadOrInit single-flights cold-cache loads for instanceID. Callers race for
// the per-id load mutex; the first to acquire it does the Initialize and
// installs the result, subsequent acquirers re-check the cache and find the
// freshly-loaded entry. Returns an entry with refs already bumped for the
// caller (caller MUST release).
func (r *PluginRunner) loadOrInit(ctx context.Context, instanceID, pluginName string, cfg map[string]interface{}) (*pluginEntry, error) {
	loadMu := r.loadLock(instanceID)
	loadMu.Lock()
	defer loadMu.Unlock()

	// Double-check: another caller may have populated the cache while we were
	// queued on loadMu.
	if entry, ok := r.acquire(instanceID); ok {
		return entry, nil
	}

	plugin, err := loadPluginFunc(pluginName)
	if err != nil {
		return nil, err
	}
	// VerifyConnection is deliberately false here. Cache-miss self-heal runs
	// long after the operator's original Initialize, so the original
	// verify_connection setting isn't available (NewUser/UpdateUser/DeleteUser
	// don't carry it on the wire). Forcing true would surface as a spurious
	// NewUser failure if the DB is briefly unreachable at re-init time, even
	// though the original mount was configured with verify_connection=false;
	// forcing false matches the safer default the operator would pick if
	// they had to re-configure the mount during an outage.
	if _, err := plugin.Initialize(ctx, dbplugin.InitializeRequest{
		Config:           cfg,
		VerifyConnection: false,
	}); err != nil {
		if cerr := plugin.Close(); cerr != nil {
			log.Printf("[runner] close after failed initialize for instance %s: %v", instanceID, cerr)
		}
		// Drop the load mutex so a permanently-failing instance_id does not
		// leak one mutex per attempt across the spoke's lifetime. The cost
		// of a future concurrent retry attempting duplicate Initialize is
		// minor: each caller gets its own plugin, installOrReplace cleans
		// up the loser via the slot refcount, and either both succeed
		// (caller wins, the second one is reaped) or both fail (caller
		// gets the same error). Keeping the mutex only mattered while put()
		// could close an in-flight plugin, which the slot/handler refcount
		// rewrite already prevents.
		r.mu.Lock()
		delete(r.loading, instanceID)
		r.mu.Unlock()
		return nil, fmt.Errorf("lazy initialize: %w", err)
	}
	entry := newPluginEntry(pluginName, plugin)
	// Bump for the caller before installing, so the slot ref is not the only
	// thing keeping the entry alive between install and the caller's defer.
	entry.refs.Add(1)
	r.installOrReplace(instanceID, entry)
	// Drop the load mutex on success too; future cache misses for this id
	// (after a Close + re-mount, say) create a fresh mutex. Without this the
	// loading map grows once per distinct id the spoke has ever seen.
	r.mu.Lock()
	delete(r.loading, instanceID)
	r.mu.Unlock()
	return entry, nil
}

// --- Plugin loader ---------------------------------------------------------

// loadPluginFunc is the indirection through which the runner builds plugin
// instances. Production code points it at loadPlugin (the statically-linked
// switch below). Tests swap it with a stub that returns a fake
// dbplugin.Database, so the cache discipline can be exercised without an
// actual postgres/mysql/valkey binary or DB.
var loadPluginFunc = loadPlugin

// loadPlugin creates a fresh plugin instance of the named type. We hold the
// imports here so the spoke daemon binary statically links them all.
func loadPlugin(pluginName string) (dbplugin.Database, error) {
	var factory func() (interface{}, error)
	switch pluginName {
	case "postgresql-database-plugin":
		factory = dbPostgres.New
	case "mysql-database-plugin":
		factory = dbMySQL.New(dbMySQL.DefaultUserNameTemplate)
	case "valkey-database-plugin", "redis-database-plugin":
		factory = dbValkey.New
	case "cassandra-database-plugin":
		factory = dbCassandra.New
	case "influxdb-database-plugin":
		factory = dbInflux.New
	default:
		return nil, fmt.Errorf("unknown plugin: %s", pluginName)
	}
	raw, err := factory()
	if err != nil {
		return nil, fmt.Errorf("create plugin %s: %w", pluginName, err)
	}
	db, ok := raw.(dbplugin.Database)
	if !ok {
		return nil, fmt.Errorf("plugin %s does not implement dbplugin.Database", pluginName)
	}
	return db, nil
}

// --- Method handlers -------------------------------------------------------

func (r *PluginRunner) handleInitialize(ctx context.Context, instanceID, pluginName string, req map[string]interface{}) (string, error) {
	cfg, ok := req["config"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("missing config")
	}
	verifyConnection, _ := req["verify_connection"].(bool)

	// Single-flight against concurrent Initialize and lazy re-init for the
	// same id. Without this, two Initialize calls could both build a plugin
	// and both call installOrReplace, racing on the cleanup of the displaced
	// entry. Drop the per-id load mutex when done (on both success and
	// failure) so r.loading does not accumulate one entry per distinct
	// instance_id ever Initialized — matches loadOrInit's discipline so the
	// two single-flight paths are symmetric.
	loadMu := r.loadLock(instanceID)
	loadMu.Lock()
	defer func() {
		loadMu.Unlock()
		r.mu.Lock()
		delete(r.loading, instanceID)
		r.mu.Unlock()
	}()

	plugin, err := loadPluginFunc(pluginName)
	if err != nil {
		return "", err
	}
	resp, err := plugin.Initialize(ctx, dbplugin.InitializeRequest{
		Config:           cfg,
		VerifyConnection: verifyConnection,
	})
	if err != nil {
		if cerr := plugin.Close(); cerr != nil {
			log.Printf("[runner] close after failed initialize for instance %s: %v", instanceID, cerr)
		}
		return "", fmt.Errorf("initialize: %w", err)
	}
	r.installOrReplace(instanceID, newPluginEntry(pluginName, plugin))

	out, err := json.Marshal(map[string]interface{}{"config": resp.Config})
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func (r *PluginRunner) handleNewUser(ctx context.Context, plugin dbplugin.Database, req map[string]interface{}) (string, error) {
	usernameConfig, ok := req["username_config"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("missing username_config")
	}
	expiration, err := asInt64(req["expiration"])
	if err != nil {
		return "", fmt.Errorf("expiration: %w", err)
	}
	credType, err := parseCredentialType(req["credential_type"])
	if err != nil {
		return "", err
	}

	resp, err := plugin.NewUser(ctx, dbplugin.NewUserRequest{
		UsernameConfig: dbplugin.UsernameMetadata{
			DisplayName: stringField(usernameConfig, "display_name"),
			RoleName:    stringField(usernameConfig, "role_name"),
		},
		CredentialType: credType,
		Password:       stringField(req, "password"),
		PublicKey:      []byte(stringField(req, "public_key")),
		Subject:        stringField(req, "subject"),
		// expiration is Unix seconds: proxy.go sends req.Expiration.Unix(),
		// so the wire value is seconds since the epoch (not milliseconds).
		Expiration:         time.Unix(expiration, 0),
		Statements:         dbplugin.Statements{Commands: stringSlice(req["statements"])},
		RollbackStatements: dbplugin.Statements{Commands: stringSlice(req["rollback_statements"])},
	})
	if err != nil {
		return "", fmt.Errorf("NewUser: %w", err)
	}
	out, err := json.Marshal(map[string]interface{}{"username": resp.Username})
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func (r *PluginRunner) handleUpdateUser(ctx context.Context, plugin dbplugin.Database, req map[string]interface{}) (string, error) {
	username, ok := req["username"].(string)
	if !ok {
		return "", fmt.Errorf("missing username")
	}
	credType, err := parseCredentialType(req["credential_type"])
	if err != nil {
		return "", err
	}
	update := dbplugin.UpdateUserRequest{Username: username, CredentialType: credType}

	if pw, ok := req["password"].(map[string]interface{}); ok {
		update.Password = &dbplugin.ChangePassword{
			NewPassword: stringField(pw, "new_password"),
			Statements:  dbplugin.Statements{Commands: stringSlice(pw["statements"])},
		}
	}
	if pk, ok := req["public_key"].(map[string]interface{}); ok {
		update.PublicKey = &dbplugin.ChangePublicKey{
			NewPublicKey: []byte(stringField(pk, "new_public_key")),
			Statements:   dbplugin.Statements{Commands: stringSlice(pk["statements"])},
		}
	}
	if ex, ok := req["expiration"].(map[string]interface{}); ok {
		newExp, err := asInt64(ex["new_expiration"])
		if err != nil {
			return "", fmt.Errorf("expiration.new_expiration: %w", err)
		}
		update.Expiration = &dbplugin.ChangeExpiration{
			// Unix seconds; see handleNewUser.
			NewExpiration: time.Unix(newExp, 0),
			Statements:    dbplugin.Statements{Commands: stringSlice(ex["statements"])},
		}
	}
	if _, err := plugin.UpdateUser(ctx, update); err != nil {
		return "", fmt.Errorf("UpdateUser: %w", err)
	}
	return "{}", nil
}

func (r *PluginRunner) handleType(_ context.Context, plugin dbplugin.Database, _ map[string]interface{}) (string, error) {
	name, err := plugin.Type()
	if err != nil {
		return "", fmt.Errorf("plugin Type: %w", err)
	}
	out, err := json.Marshal(map[string]interface{}{"type": name})
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func (r *PluginRunner) handleDeleteUser(ctx context.Context, plugin dbplugin.Database, req map[string]interface{}) (string, error) {
	username, ok := req["username"].(string)
	if !ok {
		return "", fmt.Errorf("missing username")
	}
	if _, err := plugin.DeleteUser(ctx, dbplugin.DeleteUserRequest{
		Username:   username,
		Statements: dbplugin.Statements{Commands: stringSlice(req["statements"])},
	}); err != nil {
		return "", fmt.Errorf("DeleteUser: %w", err)
	}
	return "{}", nil
}

// handleClose drops the slot reference for the instance. The actual db.Close
// runs once the last in-flight handler releases — Close is therefore safe to
// invoke even while a NewUser/UpdateUser/DeleteUser is mid-flight on the same
// instance_id. Idempotent: closing an unknown id is a no-op.
func (r *PluginRunner) handleClose(instanceID string) (string, error) {
	r.remove(instanceID)
	return "{}", nil
}

// Shutdown drops the slot reference on every cached plugin. Each db.Close()
// runs once any in-flight handler holding the same entry releases (the
// refcount discipline guarantees exactly one close). Safe to call once on
// daemon teardown; further requests on this runner are racy after Shutdown
// returns. Idempotent.
func (r *PluginRunner) Shutdown() {
	r.mu.Lock()
	entries := make([]*pluginEntry, 0, len(r.plugins))
	for _, e := range r.plugins {
		entries = append(entries, e)
	}
	r.plugins = make(map[string]*pluginEntry)
	r.mu.Unlock()
	for _, e := range entries {
		e.release()
	}
}

// --- Decode helpers --------------------------------------------------------

func stringField(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func stringSlice(v interface{}) []string {
	arr, ok := v.([]interface{})
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, x := range arr {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// asInt64 coerces a JSON-decoded number to int64. encoding/json gives us
// float64 by default; json.Number is used when the decoder is configured for
// precise numbers. Cover both so this code works regardless of the upstream
// decode mode.
func asInt64(v interface{}) (int64, error) {
	switch n := v.(type) {
	case float64:
		return int64(n), nil
	case int64:
		return n, nil
	case int:
		return int64(n), nil
	case json.Number:
		return n.Int64()
	case nil:
		return 0, fmt.Errorf("nil")
	default:
		return 0, fmt.Errorf("unsupported type %T", v)
	}
}

// parseCredentialType decodes the wire form (one of "password",
// "rsa_private_key", "client_certificate", or absent/empty) into the SDK
// enum. Absence defaults to CredentialTypePassword to match the SDK's
// zero-value semantics, so an older hub that does not send the field still
// works.
func parseCredentialType(v interface{}) (dbplugin.CredentialType, error) {
	s, _ := v.(string)
	switch s {
	case "", "password":
		return dbplugin.CredentialTypePassword, nil
	case "rsa_private_key":
		return dbplugin.CredentialTypeRSAPrivateKey, nil
	case "client_certificate":
		return dbplugin.CredentialTypeClientCertificate, nil
	default:
		return 0, fmt.Errorf("unsupported credential_type: %q", s)
	}
}
