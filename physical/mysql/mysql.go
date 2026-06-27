// Copyright (c) 2024 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

// Package mysql implements a physical backend that stores OpenBao data in a
// MySQL-compatible database. It is a faithful adaptation of
// physical/postgresql, ported to the github.com/go-sql-driver/mysql driver and
// MySQL/InnoDB SQL dialect.
//
// Compatibility: this backend targets MySQL 5.7+/8.0 and is also designed to
// run against OceanBase in its MySQL (InnoDB) compatibility mode. Care has been
// taken to avoid MySQL-version-specific constructs that OceanBase does not
// implement: the directory-listing queries use SUBSTRING_INDEX/SUBSTRING rather
// than REGEXP_SUBSTR (8.0-only); the HA row-lease upsert uses
// INSERT ... ON DUPLICATE KEY UPDATE with VALUES(...) rather than an advisory
// GET_LOCK(); and index columns are length-bounded VARBINARY so the InnoDB
// 3072-byte index limit is respected.
package mysql

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v5"
	mysqldriver "github.com/go-sql-driver/mysql"
	log "github.com/hashicorp/go-hclog"
	metrics "github.com/hashicorp/go-metrics/compat"
	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"github.com/hashicorp/go-uuid"
	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/sdk/v2/physical"
)

const (
	// The lock TTL matches the default that Consul API uses, 15 seconds.
	// Used as part of SQL commands to set/extend lock expiry time relative to
	// database clock.
	MySQLLockTTLSeconds = 15

	// The amount of time to wait between the lock renewals
	MySQLLockRenewInterval = 5 * time.Second

	// MySQLLockRetryInterval is the amount of time to wait
	// if a lock fails before trying again.
	MySQLLockRetryInterval = time.Second
)

// Verify MySQLBackend satisfies the correct interfaces
var (
	_ physical.Backend              = (*MySQLBackend)(nil)
	_ physical.TransactionalBackend = (*MySQLBackend)(nil)
)

// HA backend was implemented based on the PostgreSQL backend pattern
// With distinction using the central MySQL clock, hereby avoiding
// possible issues with multiple clocks
var (
	_ physical.HABackend        = (*MySQLBackend)(nil)
	_ physical.FencingHABackend = (*MySQLBackend)(nil)
	_ physical.Lock             = (*MySQLLock)(nil)
)

// MySQLBackend is a physical backend that stores data
// within a MySQL/OceanBase database.
type MySQLBackend struct {
	table string
	index string

	client *sql.DB

	putQuery             string
	getQuery             string
	deleteQuery          string
	listQuery            string
	listPageQuery        string
	listPageLimitedQuery string

	haTable                  string
	haGetLockValueQuery      string
	haUpsertLockIdentityExec string
	haRenewLockIdentityExec  string
	haDeleteLockExec         string
	haCheckLockHeldQuery     string

	haEnabled     bool
	logger        log.Logger
	txnPermitPool *physical.PermitPool

	fenceLock sync.RWMutex
	fence     *MySQLLock
}

// MySQLLock implements a lock using a MySQL client.
type MySQLLock struct {
	backend    *MySQLBackend
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

// mysqlQuoteIdentifier quotes an identifier (table or column name) for use in
// a MySQL statement using backticks, escaping embedded backticks. If the input
// contains a zero byte the result is truncated immediately before it.
func mysqlQuoteIdentifier(name string) string {
	if end := strings.IndexRune(name, 0); end > -1 {
		name = name[:end]
	}
	return "`" + strings.ReplaceAll(name, "`", "``") + "`"
}

// NewMySQLBackend constructs a MySQL/OceanBase backend using the given
// connection details, credentials, and database.
func NewMySQLBackend(conf map[string]string, logger log.Logger) (physical.Backend, error) {
	// Determine the connection DSN. A raw connection_url/dsn (or its
	// environment variable) is preferred; otherwise assemble one from
	// individual host/port/username/password/database keys.
	dsn := connectionURL(conf)
	if dsn == "" {
		var err error
		dsn, err = buildDSNFromParts(conf)
		if err != nil {
			return nil, err
		}
	}
	if dsn == "" {
		return nil, errors.New("missing connection_url (or host/database) for mysql backend")
	}

	unquotedTable, ok := conf["table"]
	if !ok {
		unquotedTable = "openbao_kv_store"
	}
	quotedTable := mysqlQuoteIdentifier(unquotedTable)

	maxParStr, ok := conf["max_parallel"]
	var maxParInt int
	var err error
	if ok {
		maxParInt, err = strconv.Atoi(maxParStr)
		if err != nil {
			return nil, fmt.Errorf("failed parsing max_parallel parameter: %w", err)
		}
		logger.Debug("max_parallel set", "max_parallel", maxParInt)
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
		logger.Debug("transaction_max_parallel set", "transaction_max_parallel", txnMaxParInt)
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
		logger.Debug("max_idle_connections set", "max_idle_connections", maxIdleConnsStr)
	}

	// Set maximum retries for DB connection liveness check on startup.
	maxRetriesStr, ok := conf["max_connect_retries"]
	var maxRetriesInt int
	if ok {
		maxRetriesInt, err = strconv.Atoi(maxRetriesStr)
		if err != nil {
			return nil, fmt.Errorf("failed parsing max_connect_retries parameter: %w", err)
		}
		logger.Debug("max_connect_retries set", "max_connect_retries", maxRetriesInt)
	} else {
		maxRetriesInt = 1
	}

	// Create MySQL handle for the database.
	db, err := doRetryConnect(logger, dsn, uint(maxRetriesInt))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to mysql: %w", err)
	}
	db.SetMaxOpenConns(maxParInt)

	if maxIdleConnsIsSet {
		db.SetMaxIdleConns(maxIdleConns)
	}

	// Read the server version for logging/diagnostics. We intentionally do not
	// enforce a strict minimum here: OceanBase reports a MySQL-compatible
	// version string (e.g. "5.7.25-OceanBase-...") and we want to remain
	// compatible with it as well as stock MySQL 5.7+.
	var serverVersion string
	if err := db.QueryRow("SELECT VERSION()").Scan(&serverVersion); err != nil {
		return nil, fmt.Errorf("failed to query MySQL server version: %w", err)
	}
	logger.Debug("connected to mysql-compatible server", "version", serverVersion)

	unquotedHaTable, ok := conf["ha_table"]
	if !ok {
		unquotedHaTable, ok = conf["haTable"]
		if !ok {
			unquotedHaTable = "openbao_ha_locks"
		}
	}
	quotedHaTable := mysqlQuoteIdentifier(unquotedHaTable)

	// Setup the backend.
	m := &MySQLBackend{
		table:  quotedTable,
		index:  mysqlQuoteIdentifier(unquotedTable + "_idx"),
		client: db,
		putQuery: "INSERT INTO " + quotedTable + " (parent_path, path, `key`, `value`) VALUES (?, ?, ?, ?)" +
			" ON DUPLICATE KEY UPDATE parent_path=VALUES(parent_path), path=VALUES(path), `key`=VALUES(`key`), `value`=VALUES(`value`)",
		getQuery:    "SELECT `value` FROM " + quotedTable + " WHERE path = ? AND `key` = ?",
		deleteQuery: "DELETE FROM " + quotedTable + " WHERE path = ? AND `key` = ?",
		// listQuery placeholders (in order): prefix, prefix, prefix
		listQuery: "SELECT `key` FROM " + quotedTable + " WHERE path = ?" +
			" UNION ALL SELECT DISTINCT CONCAT(SUBSTRING_INDEX(SUBSTRING(path, LENGTH(?)+1), '/', 1), '/') FROM " + quotedTable +
			" WHERE parent_path LIKE CONCAT(?, '%')" +
			" ORDER BY `key`",
		// listPageQuery placeholders (in order): prefix, after, prefix, prefix, prefix, after
		listPageQuery: "SELECT `key` FROM " + quotedTable + " WHERE path = ? AND `key` > ?" +
			" UNION ALL SELECT DISTINCT CONCAT(SUBSTRING_INDEX(SUBSTRING(path, LENGTH(?)+1), '/', 1), '/') FROM " + quotedTable +
			" WHERE parent_path LIKE CONCAT(?, '%') AND CONCAT(SUBSTRING_INDEX(SUBSTRING(path, LENGTH(?)+1), '/', 1), '/') > ?" +
			" ORDER BY `key`",
		// listPageLimitedQuery placeholders (in order): prefix, after, prefix, prefix, prefix, after, limit
		listPageLimitedQuery: "SELECT `key` FROM " + quotedTable + " WHERE path = ? AND `key` > ?" +
			" UNION ALL SELECT DISTINCT CONCAT(SUBSTRING_INDEX(SUBSTRING(path, LENGTH(?)+1), '/', 1), '/') FROM " + quotedTable +
			" WHERE parent_path LIKE CONCAT(?, '%') AND CONCAT(SUBSTRING_INDEX(SUBSTRING(path, LENGTH(?)+1), '/', 1), '/') > ?" +
			" ORDER BY `key` LIMIT ?",
		haTable: quotedHaTable,
		haGetLockValueQuery:
		// only read non-expired data; placeholders: ha_key
		" SELECT ha_value FROM " + quotedHaTable + " WHERE NOW() <= valid_until AND ha_key = ? ",
		haUpsertLockIdentityExec:
		// placeholders (in order): ha_identity, ha_key, ha_value, TTL in seconds.
		//
		// The ON DUPLICATE KEY UPDATE clause only steals an EXPIRED lock: when
		// the existing lock has not yet expired the IF() guards keep every
		// column at its current value so no row is modified (RowsAffected==0).
		// When it has expired the columns change and RowsAffected is 2 (a
		// changed update); a fresh insert yields RowsAffected==1. Either of
		// those non-zero outcomes means we acquired the lock.
		" INSERT INTO " + quotedHaTable + " (ha_identity, ha_key, ha_value, valid_until)" +
			" VALUES (?, ?, ?, DATE_ADD(NOW(), INTERVAL ? SECOND))" +
			" ON DUPLICATE KEY UPDATE" +
			"  ha_identity = IF(valid_until < NOW(), VALUES(ha_identity), ha_identity)," +
			"  ha_value    = IF(valid_until < NOW(), VALUES(ha_value), ha_value)," +
			"  valid_until = IF(valid_until < NOW(), VALUES(valid_until), valid_until)",
		haRenewLockIdentityExec:
		// placeholders (in order): ha_value, TTL in seconds, ha_identity, ha_key.
		//
		// update only renews our lock; it will not steal it and will not
		// create it if it doesn't exist.
		" UPDATE " + quotedHaTable +
			" SET ha_value = ?, valid_until = DATE_ADD(NOW(), INTERVAL ? SECOND)" +
			" WHERE ha_identity = ? AND ha_key = ? AND valid_until > NOW()",
		haDeleteLockExec:
		// placeholders (in order): ha_identity, ha_key
		" DELETE FROM " + quotedHaTable + " WHERE ha_identity = ? AND ha_key = ? ",
		haCheckLockHeldQuery:
		// placeholders (in order): ha_identity, ha_key, ha_value
		" SELECT COUNT(*) FROM " + quotedHaTable + " WHERE " +
			" ha_identity = ? AND ha_key = ? AND ha_value = ? AND valid_until > NOW() ",
		logger:        logger,
		txnPermitPool: physical.NewPermitPool(txnMaxParInt),
		haEnabled:     conf["ha_enabled"] == "true",

		// No initial fence, but if a fence is here, we'll validate it inside
		// write transactions.
		fence: nil,
	}

	// Determine if we should create tables.
	rawSkipCreateTable, ok := conf["skip_create_table"]
	if !ok {
		rawSkipCreateTable = "false"
	}
	skipCreateTable, err := parseutil.ParseBool(rawSkipCreateTable)
	if err != nil {
		return nil, fmt.Errorf("failed to parse value for `skip_create_table`: %w", err)
	}
	if !skipCreateTable {
		if err := m.createTables(); err != nil {
			return nil, fmt.Errorf("failed to create tables: %w", err)
		}
	}

	return m, nil
}

// connectionURL checks the environment variable for a raw connection DSN and
// otherwise the OpenBao config file for a `connection_url` (or `dsn`) key. If
// none of these are present an empty string is returned, in which case the
// caller assembles a DSN from individual configuration keys.
func connectionURL(conf map[string]string) string {
	connURL := conf["connection_url"]
	if connURL == "" {
		connURL = conf["dsn"]
	}
	if envURL := api.ReadBaoVariable("BAO_MYSQL_CONNECTION_URL"); envURL != "" {
		connURL = envURL
	}

	return connURL
}

// buildDSNFromParts assembles a go-sql-driver/mysql DSN of the form
// user:password@tcp(host:port)/dbname?params from discrete configuration keys.
func buildDSNFromParts(conf map[string]string) (string, error) {
	host := conf["host"]
	if host == "" {
		// No host and no connection_url means we cannot build a DSN.
		return "", nil
	}

	port := conf["port"]
	if port == "" {
		port = "3306"
	}

	database := conf["database"]
	username := conf["username"]
	password := conf["password"]

	cfg := mysqldriver.NewConfig()
	cfg.Net = "tcp"
	cfg.Addr = host + ":" + port
	cfg.DBName = database
	cfg.User = username
	cfg.Passwd = password

	// TLS handling. `tls` is passed straight through to the driver
	// ("true"/"false"/"skip-verify"/"preferred" or a registered config name).
	// When `tls_ca_file` is provided we register a custom TLS config that
	// trusts that CA and select it.
	if caFile := conf["tls_ca_file"]; caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return "", fmt.Errorf("failed to read tls_ca_file: %w", err)
		}
		rootCertPool := x509.NewCertPool()
		if ok := rootCertPool.AppendCertsFromPEM(pem); !ok {
			return "", errors.New("failed to append PEM from tls_ca_file")
		}
		tlsName := "openbao-mysql-custom"
		if err := mysqldriver.RegisterTLSConfig(tlsName, &tls.Config{RootCAs: rootCertPool}); err != nil {
			return "", fmt.Errorf("failed to register custom TLS config: %w", err)
		}
		cfg.TLSConfig = tlsName
	} else if tlsParam := conf["tls"]; tlsParam != "" {
		cfg.TLSConfig = tlsParam
	}

	return cfg.FormatDSN(), nil
}

func doRetryConnect(logger log.Logger, dsn string, retries uint) (*sql.DB, error) {
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}

	b := backoff.NewExponentialBackOff()
	b.MaxInterval = 5 * time.Second
	b.InitialInterval = 15 * time.Millisecond

	op := func() (none struct{}, err error) {
		if err := db.Ping(); err != nil {
			logger.Debug("database not ready", "err", err)
			return none, err
		}
		return none, nil
	}

	if _, err := backoff.Retry(context.Background(), op, backoff.WithBackOff(b), backoff.WithMaxTries(retries)); err != nil {
		return nil, errors.Join(fmt.Errorf("unable to verify connection: %w", err), db.Close())
	}

	return db, nil
}

func (m *MySQLBackend) createTables() error {
	// MySQL/InnoDB DDL auto-commits each statement and cannot be rolled back,
	// so unlike the PostgreSQL backend we do not wrap creation in an explicit
	// transaction. We rely on CREATE TABLE IF NOT EXISTS for idempotency and
	// embed the secondary index in the table definition (CREATE INDEX
	// IF NOT EXISTS is not portable to MySQL 5.7/OceanBase).
	//
	// Columns use length-bounded VARBINARY so the InnoDB index limit
	// (<=3072 bytes; (path,key) is 1024 bytes here) is respected, matching the
	// historical Vault mysql backend. Binary types also give us C-locale-style
	// byte-ordered comparisons for keyset pagination.
	createTableQuery := "CREATE TABLE IF NOT EXISTS " + m.table + " (" +
		"  parent_path VARBINARY(512) NOT NULL," +
		"  path        VARBINARY(512) NOT NULL," +
		"  `key`       VARBINARY(512) NOT NULL," +
		"  `value`     LONGBLOB," +
		"  PRIMARY KEY (path, `key`)," +
		"  KEY " + m.index + " (parent_path)" +
		") ENGINE=InnoDB"
	if _, err := m.client.Exec(createTableQuery); err != nil {
		if isReadOnlyErr(err) {
			m.logger.Warn("Skipping table creation as database is marked read-only", "err", err)
			return nil
		}
		return fmt.Errorf("failed to execute create query: %w", err)
	}

	if m.haEnabled {
		createHaTableQuery := "CREATE TABLE IF NOT EXISTS " + m.haTable + " (" +
			"  ha_key      VARBINARY(512) NOT NULL," +
			"  ha_identity VARBINARY(512) NOT NULL," +
			"  ha_value    VARBINARY(512)," +
			"  valid_until DATETIME NOT NULL," +
			"  PRIMARY KEY (ha_key)" +
			") ENGINE=InnoDB"
		if _, err := m.client.Exec(createHaTableQuery); err != nil {
			if isReadOnlyErr(err) {
				m.logger.Warn("Skipping HA table creation as database is marked read-only", "err", err)
				return nil
			}
			return fmt.Errorf("failed to create ha table: %w", err)
		}
	}

	return nil
}

// isReadOnlyErr reports whether the given error is a MySQL "server is running
// with the --read-only option" (or super-read-only) failure, in which case we
// skip table creation as another (writable) node is expected to have created
// the schema.
func isReadOnlyErr(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "read-only") || strings.Contains(msg, "read only")
}

// splitKey is a helper to split a full path key into individual
// parts: parentPath, path, key
func (m *MySQLBackend) splitKey(fullPath string) (string, string, string) {
	var parentPath string
	var path string

	pieces := strings.Split(fullPath, "/")
	depth := len(pieces)
	key := pieces[depth-1]

	switch depth {
	case 1:
		parentPath = ""
		path = "/"
	case 2:
		parentPath = "/"
		path = "/" + pieces[0] + "/"
	default:
		parentPath = "/" + strings.Join(pieces[:depth-2], "/") + "/"
		path = "/" + strings.Join(pieces[:depth-1], "/") + "/"
	}

	return parentPath, path, key
}

// Put is used to insert or update an entry.
func (m *MySQLBackend) Put(ctx context.Context, entry *physical.Entry) error {
	defer metrics.MeasureSince([]string{"mysql", "put"}, time.Now())

	parentPath, path, key := m.splitKey(entry.Key)

	if err := m.validateFence(ctx); err != nil {
		return err
	}

	_, err := m.client.ExecContext(ctx, m.putQuery, parentPath, path, key, entry.Value)
	if err != nil {
		return err
	}
	return nil
}

// Get is used to fetch an entry.
func (m *MySQLBackend) Get(ctx context.Context, fullPath string) (*physical.Entry, error) {
	defer metrics.MeasureSince([]string{"mysql", "get"}, time.Now())

	_, path, key := m.splitKey(fullPath)

	var result []byte
	err := m.client.QueryRowContext(ctx, m.getQuery, path, key).Scan(&result)
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
func (m *MySQLBackend) Delete(ctx context.Context, fullPath string) error {
	defer metrics.MeasureSince([]string{"mysql", "delete"}, time.Now())

	_, path, key := m.splitKey(fullPath)

	if err := m.validateFence(ctx); err != nil {
		return err
	}

	_, err := m.client.ExecContext(ctx, m.deleteQuery, path, key)
	if err != nil {
		return err
	}
	return nil
}

// List is used to list all the keys under a given
// prefix, up to the next prefix.
func (m *MySQLBackend) List(ctx context.Context, prefix string) ([]string, error) {
	defer metrics.MeasureSince([]string{"mysql", "list"}, time.Now())

	prefixArg := "/" + prefix
	rows, err := m.client.QueryContext(ctx, m.listQuery, prefixArg, prefixArg, prefixArg)
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
// prefix, after the given key, up to the given limit.
func (m *MySQLBackend) ListPage(ctx context.Context, prefix string, after string, limit int) ([]string, error) {
	defer metrics.MeasureSince([]string{"mysql", "list-page"}, time.Now())

	prefixArg := "/" + prefix

	var rows *sql.Rows
	var err error
	if limit <= 0 {
		rows, err = m.client.QueryContext(ctx, m.listPageQuery, prefixArg, after, prefixArg, prefixArg, prefixArg, after)
	} else {
		rows, err = m.client.QueryContext(ctx, m.listPageLimitedQuery, prefixArg, after, prefixArg, prefixArg, prefixArg, after, limit)
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
func (m *MySQLBackend) LockWith(key, value string) (physical.Lock, error) {
	identity, err := uuid.GenerateUUID()
	if err != nil {
		return nil, err
	}
	return &MySQLLock{
		backend:       m,
		key:           key,
		value:         value,
		identity:      identity,
		ttlSeconds:    MySQLLockTTLSeconds,
		renewInterval: MySQLLockRenewInterval,
		retryInterval: MySQLLockRetryInterval,
	}, nil
}

func (m *MySQLBackend) HAEnabled() bool {
	return m.haEnabled
}

func (m *MySQLBackend) RegisterActiveNodeLock(l physical.Lock) error {
	lock, ok := l.(*MySQLLock)
	if !ok {
		return fmt.Errorf("expected MySQLLock; got %T", l)
	}

	m.fenceLock.Lock()
	defer m.fenceLock.Unlock()
	m.fence = lock

	return nil
}

func (m *MySQLBackend) validateFence(ctx context.Context) error {
	m.fenceLock.RLock()
	defer m.fenceLock.RUnlock()

	if m.fence == nil {
		return nil
	}

	if physical.IsUnfencedWrite(ctx) {
		return nil
	}

	held, err := m.fence.IsActivelyHeld(ctx)
	if err != nil {
		return fmt.Errorf("%v: err from database: %w", physical.ErrFencedWriteFailed, err)
	}
	if !held {
		return fmt.Errorf("%v: lock changed ownership", physical.ErrFencedWriteFailed)
	}

	return nil
}

// Lock tries to acquire the lock by repeatedly trying to create a record in the
// MySQL table. It will block until either the stop channel is closed or
// the lock could be acquired successfully. The returned channel will be closed
// once the lock in the MySQL table cannot be renewed, either due to an
// error speaking to MySQL or because someone else has taken it.
func (l *MySQLLock) Lock(stopCh <-chan struct{}) (<-chan struct{}, error) {
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
// MySQL table.
func (l *MySQLLock) Unlock() error {
	m := l.backend

	if l.renewTicker != nil {
		l.renewTicker.Stop()
	}

	// Delete lock owned by me
	_, err := m.client.Exec(m.haDeleteLockExec, l.identity, l.key)
	return err
}

// Value checks whether or not the lock is held by any instance of MySQLLock,
// including this one, and returns the current value.
func (l *MySQLLock) Value() (bool, string, error) {
	m := l.backend
	var result string
	err := m.client.QueryRow(m.haGetLockValueQuery, l.key).Scan(&result)

	switch err {
	case nil:
		return true, result, nil
	case sql.ErrNoRows:
		return false, "", nil
	default:
		return false, "", err
	}
}

// IsActivelyHeld reports whether or not this lock is currently held by this
// instance of the lock.
//
// Returns true if and only if this lock is active. Returns false if the lock
// is held by another caller or an error occurred. While errors may occur
// which prevent checking lock status, this likely also affects whether or not
// the lock can be renewed and so should likely be treated as an error.
//
// While leaderLossCh returned from Lock() is the ultimate notification of
// lock loss, this check is an online check and goes to the database to verify
// the lock is held.
func (l *MySQLLock) IsActivelyHeld(ctx context.Context) (bool, error) {
	m := l.backend

	// For simplicity and compatibility with all versions of MySQL, we
	// return the number of rows matching our lookup. This is zero if the
	// lock isn't held by us (identity, key, and value all match and the lock
	// is valid) and one if it is held by us. Uniqueness constraints prevent
	// us from having more than one lock.
	var result int
	err := m.client.QueryRowContext(ctx, m.haCheckLockHeldQuery, l.identity, l.key, l.value).Scan(&result)

	switch err {
	case nil:
		return result == 1, nil
	case sql.ErrNoRows:
		return false, nil
	default:
		return false, err
	}
}

// tryToLock tries to create a new item in MySQL every `retryInterval`.
// As long as the item cannot be created (because it already exists), it will
// be retried. If the operation fails due to an error, it is sent to the errors
// channel. When the lock could be acquired successfully, the success channel
// is closed.
func (l *MySQLLock) tryToLock(stop <-chan struct{}, success chan struct{}, errors chan error) {
	ticker := time.NewTicker(l.retryInterval)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			gotlock, err := l.writeItem(l.backend.haUpsertLockIdentityExec, l.identity, l.key, l.value, l.ttlSeconds)
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

func (l *MySQLLock) periodicallyRenewLock(done chan struct{}) {
	for range l.renewTicker.C {
		gotlock, err := l.writeItem(l.backend.haRenewLockIdentityExec, l.value, l.ttlSeconds, l.identity, l.key)
		if err != nil || !gotlock {
			close(done)
			l.renewTicker.Stop()

			// If we got an error, log it so that operators can see the
			// renewal failure.
			if err != nil {
				l.backend.logger.Error("lock renewal failed", "key", l.key, "err", err)
			}

			return
		}
	}
}

// writeItem attempts to put/update the MySQL lock row, evaluating the TTL in
// the database. Returns true if the lock was obtained, false if not. If false,
// the error may be nil or non-nil: nil indicates simply that someone else has
// the lock, whereas non-nil means that something unexpected happened.
//
// The args are passed positionally to match the placeholders in the supplied
// query (MySQL `?` placeholders cannot be reused like PostgreSQL's $N), so the
// acquire and renew flows pass their arguments in different orders.
//
// Notably, query is variable (but chosen between one of two static values)
// as we need to handle strict upsert (creating a new lock and/or claiming an
// expired lock from someone else) versus renewing our lock: if someone else
// grabs the lock (and it expires) before we get a chance to renew, or if the
// lock is deleted from under us, renewal should not happen. Similarly, if we
// attempt to grab the lock and we already hold it, we should fail. This is
// handled by the IF()-guarded ON DUPLICATE KEY UPDATE for acquisition and by
// the valid_until/identity predicate in the renewal UPDATE.
func (l *MySQLLock) writeItem(query string, args ...interface{}) (bool, error) {
	m := l.backend

	// Set a timeout on lock renewal: ensure we block at most 2/3rds of the
	// total lock period.
	//
	// This ensures we do not stall renewal indefinitely and miss a subsequent
	// lock acquisition by another party. We give ourselves a little grace
	// period to ensure we do not hit false positives due to network latency.
	//
	// This is important to ensure that we notify on leadership loss before the
	// other node could acquire the lock and take over as leader.
	ctx, cancel := context.WithTimeout(context.Background(), MySQLLockTTLSeconds*2/3*time.Second)
	defer cancel()

	// Try steal lock or update expiry on my lock.
	sqlResult, err := m.client.ExecContext(ctx, query, args...)
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

	// MySQL's INSERT ... ON DUPLICATE KEY UPDATE reports 1 affected row for a
	// fresh insert and 2 for an update that actually changed a row, while a
	// no-op (the lock is still validly held by someone else) reports 0. A
	// renewal UPDATE reports 1 when it renews our row and 0 otherwise. Any
	// non-zero count therefore means we hold the lock.
	return ar >= 1, nil
}
