// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package postgresql

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/armon/go-metrics"
	"github.com/cenkalti/backoff/v4"
	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"github.com/hashicorp/go-uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/sdk/v2/database/helper/dbutil"
	"github.com/openbao/openbao/sdk/v2/physical"
)

const (

	// The lock TTL matches the default that Consul API uses, 15 seconds.
	// Used as part of SQL commands to set/extend lock expiry time relative to
	// database clock.
	PostgreSQLLockTTLSeconds = 15

	// The amount of time to wait between the lock renewals
	PostgreSQLLockRenewInterval = 5 * time.Second

	// PostgreSQLLockRetryInterval is the amount of time to wait
	// if a lock fails before trying again.
	PostgreSQLLockRetryInterval = time.Second
)

// Verify PostgreSQLBackend satisfies the correct interfaces
var (
	_ physical.Backend              = (*PostgreSQLBackend)(nil)
	_ physical.TransactionalBackend = (*PostgreSQLBackend)(nil)
)

// HA backend was implemented based on the DynamoDB backend pattern
// With distinction using central postgres clock, hereby avoiding
// possible issues with multiple clocks
var (
	_ physical.HABackend = (*PostgreSQLBackend)(nil)
	_ physical.Lock      = (*PostgreSQLLock)(nil)
)

// PostgreSQL Backend is a physical backend that stores data
// within a PostgreSQL database.
type PostgreSQLBackend struct {
	table                   string
	client                  *sql.DB
	put_query               string
	get_query               string
	delete_query            string
	list_query              string
	list_page_query         string
	list_page_limited_query string

	ha_table                 string
	haGetLockValueQuery      string
	haUpsertLockIdentityExec string
	haDeleteLockExec         string

	haEnabled     bool
	logger        log.Logger
	txnPermitPool *physical.PermitPool
}

// PostgreSQLLock implements a lock using an PostgreSQL client.
type PostgreSQLLock struct {
	backend    *PostgreSQLBackend
	value, key string
	identity   string
	lock       sync.Mutex

	renewTicker *time.Ticker

	// ttlSeconds is how long a lock is valid for
	ttlSeconds int

	// renewInterval is how much time to wait between lock renewals.  must be << ttl
	renewInterval time.Duration

	// retryInterval is how much time to wait between attempts to grab the lock
	retryInterval time.Duration
}

// NewPostgreSQLBackend constructs a PostgreSQL backend using the given
// API client, server address, credentials, and database.
func NewPostgreSQLBackend(conf map[string]string, logger log.Logger) (physical.Backend, error) {
	// Get the PostgreSQL credentials to perform read/write operations.
	connURL := connectionURL(conf)

	unquoted_table, ok := conf["table"]
	if !ok {
		unquoted_table = "openbao_kv_store"
	}
	quoted_table := dbutil.QuoteIdentifier(unquoted_table)

	maxParStr, ok := conf["max_parallel"]
	var maxParInt int
	var err error
	if ok {
		maxParInt, err = strconv.Atoi(maxParStr)
		if err != nil {
			return nil, fmt.Errorf("failed parsing max_parallel parameter: %w", err)
		}
		if logger.IsDebug() {
			logger.Debug("max_parallel set", "max_parallel", maxParInt)
		}
	} else {
		maxParInt = physical.DefaultParallelOperations
	}

	txnMaxParStr, ok := conf["transaction_max_parallel"]
	var txnMaxParInt int
	if ok {
		txnMaxParInt, err = strconv.Atoi(txnMaxParStr)
		if err != nil {
			return nil, fmt.Errorf("failed parsing transaction_max_parallel parameter: %w", err)
		}
		if logger.IsDebug() {
			logger.Debug("transaction_max_parallel set", "transaction_max_parallel", txnMaxParInt)
		}
	} else {
		txnMaxParInt = physical.DefaultParallelTransactions
	}

	maxIdleConnsStr, maxIdleConnsIsSet := conf["max_idle_connections"]
	var maxIdleConns int
	if maxIdleConnsIsSet {
		maxIdleConns, err = strconv.Atoi(maxIdleConnsStr)
		if err != nil {
			return nil, fmt.Errorf("failed parsing max_idle_connections parameter: %w", err)
		}
		if logger.IsDebug() {
			logger.Debug("max_idle_connections set", "max_idle_connections", maxIdleConnsStr)
		}
	}

	// Set maximum retries for DB connection liveness check on startup.
	maxRetriesStr, ok := conf["max_connect_retries"]
	var maxRetriesInt int
	if ok {
		maxRetriesInt, err = strconv.Atoi(maxRetriesStr)
		if err != nil {
			return nil, fmt.Errorf("failed parsing max_connect_retries parameter: %w", err)
		}
		if logger.IsDebug() {
			logger.Debug("max_connect_retries set", "max_connect_retries", maxRetriesInt)
		}
	} else {
		maxRetriesInt = 1
	}

	// Create PostgreSQL handle for the database.
	db, err := doRetryConnect(logger, connURL, uint64(maxRetriesInt))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to postgres: %w", err)
	}
	db.SetMaxOpenConns(maxParInt)

	if maxIdleConnsIsSet {
		db.SetMaxIdleConns(maxIdleConns)
	}

	// Ensure we're running on a supported version of PostgreSQL
	var supportedVersion bool
	supportedVersionQuery := "SELECT current_setting('server_version_num')::int >= 90500"
	if err := db.QueryRow(supportedVersionQuery).Scan(&supportedVersion); err != nil {
		return nil, fmt.Errorf("failed to check for supported PostgreSQL version: %w", err)
	}

	if !supportedVersion {
		return nil, errors.New("PostgreSQL version must be at least 9.5")
	}

	unquoted_ha_table, ok := conf["ha_table"]
	if !ok {
		unquoted_ha_table = "openbao_ha_locks"
	}
	quoted_ha_table := dbutil.QuoteIdentifier(unquoted_ha_table)

	// Setup the backend.
	m := &PostgreSQLBackend{
		table:  quoted_table,
		client: db,
		put_query: "INSERT INTO " + quoted_table + " VALUES($1, $2, $3, $4)" +
			" ON CONFLICT (path, key) DO " +
			" UPDATE SET (parent_path, path, key, value) = ($1, $2, $3, $4)",
		get_query:    "SELECT value FROM " + quoted_table + " WHERE path = $1 AND key = $2",
		delete_query: "DELETE FROM " + quoted_table + " WHERE path = $1 AND key = $2",
		list_query: "SELECT key FROM " + quoted_table + " WHERE path = $1" +
			" UNION ALL SELECT DISTINCT substring(substr(path, length($1)+1) from '^.*?/') FROM " + quoted_table +
			" WHERE parent_path LIKE $1 || '%'" +
			" ORDER BY key",
		list_page_query: "SELECT key FROM " + quoted_table + " WHERE path = $1 AND key > $2" +
			" UNION ALL SELECT DISTINCT substring(substr(path, length($1)+1) from '^.*?/') FROM " + quoted_table +
			" WHERE parent_path LIKE $1 || '%' AND substring(substr(path, length($1)+1) from '^.*?/') > $2" +
			" ORDER BY key",
		list_page_limited_query: "SELECT key FROM " + quoted_table + " WHERE path = $1 AND key > $2" +
			" UNION ALL SELECT DISTINCT substring(substr(path, length($1)+1) from '^.*?/') FROM " + quoted_table +
			" WHERE parent_path LIKE $1 || '%' AND substring(substr(path, length($1)+1) from '^.*?/') > $2" +
			" ORDER BY key LIMIT $3",
		ha_table: quoted_ha_table,
		haGetLockValueQuery:
		// only read non expired data
		" SELECT ha_value FROM " + quoted_ha_table + " WHERE NOW() <= valid_until AND ha_key = $1 ",
		haUpsertLockIdentityExec:
		// $1=identity $2=ha_key $3=ha_value $4=TTL in seconds
		// update either steal expired lock OR update expiry for lock owned by me
		" INSERT INTO " + quoted_ha_table + " as t (ha_identity, ha_key, ha_value, valid_until) VALUES ($1, $2, $3, NOW() + $4 * INTERVAL '1 seconds'  ) " +
			" ON CONFLICT (ha_key) DO " +
			" UPDATE SET (ha_identity, ha_key, ha_value, valid_until) = ($1, $2, $3, NOW() + $4 * INTERVAL '1 seconds') " +
			" WHERE (t.valid_until < NOW() AND t.ha_key = $2) OR " +
			" (t.ha_identity = $1 AND t.ha_key = $2)  ",
		haDeleteLockExec:
		// $1=ha_identity $2=ha_key
		" DELETE FROM " + quoted_ha_table + " WHERE ha_identity=$1 AND ha_key=$2 ",
		logger:        logger,
		txnPermitPool: physical.NewPermitPool(txnMaxParInt),
		haEnabled:     conf["ha_enabled"] == "true",
	}

	// Determine if we should create tables.
	raw_skip_create_table, ok := conf["skip_create_table"]
	if !ok {
		raw_skip_create_table = "false"
	}
	skip_create_table, err := parseutil.ParseBool(raw_skip_create_table)
	if err != nil {
		return nil, fmt.Errorf("failed to parse value for `skip_create_table`: %w", err)
	}
	if !skip_create_table {
		if err := m.createTables(); err != nil {
			return nil, fmt.Errorf("failed to create tables: %w", err)
		}
	}

	return m, nil
}

// connectionURL first check the environment variables for a connection URL. If
// no connection URL exists in the environment variable, the Vault config file is
// checked. If neither the environment variables or the config file set the connection
// URL for the Postgres backend, because it is a required field, an error is returned.
func connectionURL(conf map[string]string) string {
	connURL := conf["connection_url"]
	if envURL := api.ReadBaoVariable("BAO_PG_CONNECTION_URL"); envURL != "" {
		connURL = envURL
	}

	return connURL
}

func doRetryConnect(logger log.Logger, connURL string, retries uint64) (*sql.DB, error) {
	db, err := sql.Open("pgx", connURL)
	if err != nil {
		return nil, err
	}

	var b backoff.BackOff = backoff.NewExponentialBackOff(
		backoff.WithMaxInterval(5*time.Second),
		backoff.WithInitialInterval(15*time.Millisecond),
	)
	if retries > 0 {
		b = backoff.WithMaxRetries(b, retries)
	}

	b.Reset()

	if err := backoff.Retry(func() error {
		err := db.Ping()
		if err != nil {
			logger.Debug("database not ready", "err", err)
			return err
		}

		return nil
	}, b); err != nil {
		db.Close()
		return nil, fmt.Errorf("unable to verify connection: %w", err)
	}

	return db, nil
}

func (m *PostgreSQLBackend) createTables() error {
	txn, err := m.client.BeginTx(context.TODO(), &sql.TxOptions{
		Isolation: sql.LevelRepeatableRead,
	})
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	defer txn.Rollback()

	createTableQuery := "CREATE TABLE IF NOT EXISTS " + m.table + " (" +
		`parent_path TEXT COLLATE "C" NOT NULL,` +
		`  path        TEXT COLLATE "C",` +
		`  key         TEXT COLLATE "C",` +
		`  value       BYTEA,` +
		`  CONSTRAINT pkey PRIMARY KEY (path, key)` +
		`);`
	if _, err := txn.Exec(createTableQuery); err != nil {
		if strings.Contains(err.Error(), "SQLSTATE 25006") {
			m.logger.Warn("Skipping table creation as database is marked read-only", "err", err)
			return nil
		}
		if strings.Contains(err.Error(), "SQLSTATE 23505") {
			m.logger.Warn("Skipping table creation as other processes have already created the table", "err", err)
			return nil
		}

		return fmt.Errorf("failed to execute create query: %w", err)
	}

	createIndexQuery := `CREATE INDEX IF NOT EXISTS parent_path_idx ON ` + m.table + ` (parent_path);`
	if _, err := txn.Exec(createIndexQuery); err != nil {
		if strings.Contains(err.Error(), "SQLSTATE 23505") {
			m.logger.Warn("Skipping table creation as other processes have already created the index", "err", err)
			return nil
		}
		return fmt.Errorf("failed to create index on table: %w", err)
	}

	if m.haEnabled {
		// Successfully detected that there is no table; create it.
		createTableQuery := `CREATE TABLE IF NOT EXISTS ` + m.ha_table + ` (` +
			`  ha_key      TEXT COLLATE "C" NOT NULL,` +
			`  ha_identity TEXT COLLATE "C" NOT NULL,` +
			`  ha_value    TEXT COLLATE "C",` +
			`  valid_until TIMESTAMP WITH TIME ZONE NOT NULL,` +
			`  CONSTRAINT ha_key PRIMARY KEY (ha_key)` +
			`);`
		if _, err := txn.Exec(createTableQuery); err != nil {
			if strings.Contains(err.Error(), "SQLSTATE 23505") {
				m.logger.Warn("Skipping table creation as other processes have already created the table", "err", err)
				return nil
			}
			return fmt.Errorf("failed to create ha table: %w", err)
		}
	}

	if err := txn.Commit(); err != nil {
		if strings.Contains(err.Error(), "SQLSTATE 23505") {
			m.logger.Warn("Skipping table creation as other processes have already created the table", "err", err)
			return nil
		}
		return fmt.Errorf("failed to apply transaction: %w", err)
	}

	return nil
}

// splitKey is a helper to split a full path key into individual
// parts: parentPath, path, key
func (m *PostgreSQLBackend) splitKey(fullPath string) (string, string, string) {
	var parentPath string
	var path string

	pieces := strings.Split(fullPath, "/")
	depth := len(pieces)
	key := pieces[depth-1]

	if depth == 1 {
		parentPath = ""
		path = "/"
	} else if depth == 2 {
		parentPath = "/"
		path = "/" + pieces[0] + "/"
	} else {
		parentPath = "/" + strings.Join(pieces[:depth-2], "/") + "/"
		path = "/" + strings.Join(pieces[:depth-1], "/") + "/"
	}

	return parentPath, path, key
}

// Put is used to insert or update an entry.
func (m *PostgreSQLBackend) Put(ctx context.Context, entry *physical.Entry) error {
	defer metrics.MeasureSince([]string{"postgres", "put"}, time.Now())

	parentPath, path, key := m.splitKey(entry.Key)

	_, err := m.client.ExecContext(ctx, m.put_query, parentPath, path, key, entry.Value)
	if err != nil {
		return err
	}
	return nil
}

// Get is used to fetch and entry.
func (m *PostgreSQLBackend) Get(ctx context.Context, fullPath string) (*physical.Entry, error) {
	defer metrics.MeasureSince([]string{"postgres", "get"}, time.Now())

	_, path, key := m.splitKey(fullPath)

	var result []byte
	err := m.client.QueryRowContext(ctx, m.get_query, path, key).Scan(&result)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	ent := &physical.Entry{
		Key:   fullPath,
		Value: result,
	}
	return ent, nil
}

// Delete is used to permanently delete an entry
func (m *PostgreSQLBackend) Delete(ctx context.Context, fullPath string) error {
	defer metrics.MeasureSince([]string{"postgres", "delete"}, time.Now())

	_, path, key := m.splitKey(fullPath)

	_, err := m.client.ExecContext(ctx, m.delete_query, path, key)
	if err != nil {
		return err
	}
	return nil
}

// List is used to list all the keys under a given
// prefix, up to the next prefix.
func (m *PostgreSQLBackend) List(ctx context.Context, prefix string) ([]string, error) {
	defer metrics.MeasureSince([]string{"postgres", "list"}, time.Now())

	rows, err := m.client.QueryContext(ctx, m.list_query, "/"+prefix)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []string
	for rows.Next() {
		var key string
		err = rows.Scan(&key)
		if err != nil {
			return nil, fmt.Errorf("failed to scan rows: %w", err)
		}

		keys = append(keys, key)
	}

	return keys, nil
}

// ListPage is used to list all the keys under a given
// prefix, after the given key, up to the given key.
func (m *PostgreSQLBackend) ListPage(ctx context.Context, prefix string, after string, limit int) ([]string, error) {
	defer metrics.MeasureSince([]string{"postgres", "list-page"}, time.Now())

	var rows *sql.Rows
	var err error
	if limit <= 0 {
		rows, err = m.client.QueryContext(ctx, m.list_page_query, "/"+prefix, after)
	} else {
		rows, err = m.client.QueryContext(ctx, m.list_page_limited_query, "/"+prefix, after, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []string
	for rows.Next() {
		var key string
		err = rows.Scan(&key)
		if err != nil {
			return nil, fmt.Errorf("failed to scan rows: %w", err)
		}

		keys = append(keys, key)
	}

	return keys, nil
}

// LockWith is used for mutual exclusion based on the given key.
func (p *PostgreSQLBackend) LockWith(key, value string) (physical.Lock, error) {
	identity, err := uuid.GenerateUUID()
	if err != nil {
		return nil, err
	}
	return &PostgreSQLLock{
		backend:       p,
		key:           key,
		value:         value,
		identity:      identity,
		ttlSeconds:    PostgreSQLLockTTLSeconds,
		renewInterval: PostgreSQLLockRenewInterval,
		retryInterval: PostgreSQLLockRetryInterval,
	}, nil
}

func (p *PostgreSQLBackend) HAEnabled() bool {
	return p.haEnabled
}

// Lock tries to acquire the lock by repeatedly trying to create a record in the
// PostgreSQL table. It will block until either the stop channel is closed or
// the lock could be acquired successfully. The returned channel will be closed
// once the lock in the PostgreSQL table cannot be renewed, either due to an
// error speaking to PostgreSQL or because someone else has taken it.
func (l *PostgreSQLLock) Lock(stopCh <-chan struct{}) (<-chan struct{}, error) {
	l.lock.Lock()
	defer l.lock.Unlock()

	var (
		success = make(chan struct{})
		errors  = make(chan error)
		leader  = make(chan struct{})
	)
	// try to acquire the lock asynchronously
	go l.tryToLock(stopCh, success, errors)

	select {
	case <-success:
		// after acquiring it successfully, we must renew the lock periodically
		l.renewTicker = time.NewTicker(l.renewInterval)
		go l.periodicallyRenewLock(leader)
	case err := <-errors:
		return nil, err
	case <-stopCh:
		return nil, nil
	}

	return leader, nil
}

// Unlock releases the lock by deleting the lock record from the
// PostgreSQL table.
func (l *PostgreSQLLock) Unlock() error {
	pg := l.backend

	if l.renewTicker != nil {
		l.renewTicker.Stop()
	}

	// Delete lock owned by me
	_, err := pg.client.Exec(pg.haDeleteLockExec, l.identity, l.key)
	return err
}

// Value checks whether or not the lock is held by any instance of PostgreSQLLock,
// including this one, and returns the current value.
func (l *PostgreSQLLock) Value() (bool, string, error) {
	pg := l.backend
	var result string
	err := pg.client.QueryRow(pg.haGetLockValueQuery, l.key).Scan(&result)

	switch err {
	case nil:
		return true, result, nil
	case sql.ErrNoRows:
		return false, "", nil
	default:
		return false, "", err

	}
}

// tryToLock tries to create a new item in PostgreSQL every `retryInterval`.
// As long as the item cannot be created (because it already exists), it will
// be retried. If the operation fails due to an error, it is sent to the errors
// channel. When the lock could be acquired successfully, the success channel
// is closed.
func (l *PostgreSQLLock) tryToLock(stop <-chan struct{}, success chan struct{}, errors chan error) {
	ticker := time.NewTicker(l.retryInterval)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			gotlock, err := l.writeItem()
			switch {
			case err != nil:
				errors <- err
				return
			case gotlock:
				close(success)
				return
			}
		}
	}
}

func (l *PostgreSQLLock) periodicallyRenewLock(done chan struct{}) {
	for range l.renewTicker.C {
		gotlock, err := l.writeItem()
		if err != nil || !gotlock {
			close(done)
			l.renewTicker.Stop()
			return
		}
	}
}

// Attempts to put/update the PostgreSQL item using condition expressions to
// evaluate the TTL.  Returns true if the lock was obtained, false if not.
// If false error may be nil or non-nil: nil indicates simply that someone
// else has the lock, whereas non-nil means that something unexpected happened.
func (l *PostgreSQLLock) writeItem() (bool, error) {
	pg := l.backend

	// Try steal lock or update expiry on my lock

	sqlResult, err := pg.client.Exec(pg.haUpsertLockIdentityExec, l.identity, l.key, l.value, l.ttlSeconds)
	if err != nil {
		return false, err
	}
	if sqlResult == nil {
		return false, errors.New("empty SQL response received")
	}

	ar, err := sqlResult.RowsAffected()
	if err != nil {
		return false, err
	}
	return ar == 1, nil
}
