// Copyright (c) 2024 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

// Adapted from physical/postgresql/postgresql_test.go for MySQL/OceanBase.
//
// The DB-backed tests require a reachable MySQL-compatible server. They are
// skipped unless a go-sql-driver/mysql DSN is provided via the MYSQL_URL or
// OCEANBASE_URL environment variable, e.g.:
//
//	MYSQL_URL='root:root@tcp(127.0.0.1:3306)/openbao' go test ./physical/mysql/...
//
// The pure-unit tests (DSN building, connectionURL resolution, splitKey,
// identifier quoting, parameter validation) always run without a database.

package mysql

import (
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
	log "github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/sdk/v2/helper/logging"
	"github.com/openbao/openbao/sdk/v2/physical"
	"github.com/stretchr/testify/require"
)

// requireTestDSN returns the configured DSN or skips the test when none is set.
func requireTestDSN(t *testing.T) string {
	t.Helper()
	dsn := mysqlTestDSN()
	if dsn == "" {
		t.Skip("skipping MySQL DB-backed test: set MYSQL_URL or OCEANBASE_URL to a go-sql-driver DSN to run")
	}
	return dsn
}

func TestMySQLBackend(t *testing.T) {
	t.Parallel()

	logger := logging.NewVaultLogger(log.Debug)

	connURL := requireTestDSN(t)

	table := os.Getenv("MYSQLTABLE")
	if table == "" {
		table = "openbao_kv_store"
	}

	hae := os.Getenv("MYSQLHAENABLED")
	if hae == "" {
		hae = "true"
	}

	logger.Info(fmt.Sprintf("Connection URL: %v", connURL))

	b1, err := NewMySQLBackend(map[string]string{
		"connection_url": connURL,
		"table":          table,
		"ha_enabled":     hae,
	}, logger)
	if err != nil {
		t.Fatalf("Failed to create new backend: %v", err)
	}

	b2, err := NewMySQLBackend(map[string]string{
		"connection_url": connURL,
		"table":          table,
		"ha_enabled":     hae,
	}, logger)
	if err != nil {
		t.Fatalf("Failed to create new backend: %v", err)
	}

	m := b1.(*MySQLBackend)

	var mysqlVersion string
	if err = m.client.QueryRow("SELECT VERSION()").Scan(&mysqlVersion); err != nil {
		t.Fatalf("Failed to check for MySQL version: %v", err)
	}
	logger.Info(fmt.Sprintf("MySQL Version: %v", mysqlVersion))

	SetupDatabaseObjects(t, m)

	defer func() {
		m := b1.(*MySQLBackend)
		_, err := m.client.Exec(fmt.Sprintf("TRUNCATE TABLE %v", m.table))
		if err != nil {
			t.Fatalf("Failed to truncate table: %v", err)
		}
	}()

	logger.Info("Running basic backend tests")
	physical.ExerciseBackend(t, b1)
	logger.Info("Running transactional backend tests")
	physical.ExerciseTransactionalBackend(t, b1.(physical.TransactionalBackend))
	logger.Info("Running list prefix backend tests")
	physical.ExerciseBackend_ListPrefix(t, b1)

	ha1, ok := b1.(physical.HABackend)
	if !ok {
		t.Fatal("MySQLDB does not implement HABackend")
	}

	ha2, ok := b2.(physical.HABackend)
	if !ok {
		t.Fatal("MySQLDB does not implement HABackend")
	}

	if ha1.HAEnabled() && ha2.HAEnabled() {
		logger.Info("Running ha backend tests")
		physical.ExerciseHABackend(t, ha1, ha2)
		testMySQLLockTTL(t, ha1)
		testMySQLLockRenewal(t, ha1)
	}
}

func TestMySQLBackendMaxIdleConnectionsParameter(t *testing.T) {
	t.Parallel()

	_, err := NewMySQLBackend(map[string]string{
		"connection_url":       "some connection url",
		"max_idle_connections": "bad param",
	}, logging.NewVaultLogger(log.Debug))
	if err == nil {
		t.Error("Expected invalid max_idle_connections param to return error")
	}
	expectedErrStr := "failed parsing max_idle_connections parameter: strconv.Atoi: parsing \"bad param\": invalid syntax"
	if err.Error() != expectedErrStr {
		t.Errorf("Expected: %q but found %q", expectedErrStr, err.Error())
	}
}

func TestConnectionURL(t *testing.T) {
	t.Parallel()

	type input struct {
		envar string
		conf  map[string]string
	}

	cases := map[string]struct {
		want  string
		input input
	}{
		"environment_variable_not_set_use_config_value": {
			want: "abc",
			input: input{
				envar: "",
				conf:  map[string]string{"connection_url": "abc"},
			},
		},

		"no_value_connection_url_set_key_exists": {
			want: "",
			input: input{
				envar: "",
				conf:  map[string]string{"connection_url": ""},
			},
		},

		"no_value_connection_url_set_key_doesnt_exist": {
			want: "",
			input: input{
				envar: "",
				conf:  map[string]string{},
			},
		},

		"dsn_key_used_when_connection_url_absent": {
			want: "from-dsn",
			input: input{
				envar: "",
				conf:  map[string]string{"dsn": "from-dsn"},
			},
		},

		"environment_variable_set": {
			want: "abc",
			input: input{
				envar: "abc",
				conf:  map[string]string{"connection_url": "def"},
			},
		},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			if tt.input.envar != "" {
				os.Setenv("BAO_MYSQL_CONNECTION_URL", tt.input.envar)
				defer os.Unsetenv("BAO_MYSQL_CONNECTION_URL")
			}

			got := connectionURL(tt.input.conf)

			if got != tt.want {
				t.Errorf("connectionURL(%v): want %q, got %q", tt.input, tt.want, got)
			}
		})
	}
}

func TestBuildDSNFromParts(t *testing.T) {
	t.Parallel()

	// No host => empty DSN (caller falls back to connection_url error).
	dsn, err := buildDSNFromParts(map[string]string{})
	require.NoError(t, err)
	require.Equal(t, "", dsn)

	// Host with defaults.
	dsn, err = buildDSNFromParts(map[string]string{
		"host":     "db.example.com",
		"username": "bao",
		"password": "secret",
		"database": "openbao",
	})
	require.NoError(t, err)
	require.Contains(t, dsn, "bao:secret@tcp(db.example.com:3306)/openbao")

	// Explicit port and a passthrough tls param.
	dsn, err = buildDSNFromParts(map[string]string{
		"host":     "db.example.com",
		"port":     "13306",
		"database": "openbao",
		"tls":      "skip-verify",
	})
	require.NoError(t, err)
	require.Contains(t, dsn, "tcp(db.example.com:13306)/openbao")
	require.Contains(t, dsn, "tls=skip-verify")
}

func TestSplitKey(t *testing.T) {
	t.Parallel()

	m := &MySQLBackend{}

	cases := []struct {
		full       string
		parentPath string
		path       string
		key        string
	}{
		{"foo", "", "/", "foo"},
		{"foo/bar", "/", "/foo/", "bar"},
		{"foo/bar/baz", "/foo/", "/foo/bar/", "baz"},
	}

	for _, tc := range cases {
		parentPath, path, key := m.splitKey(tc.full)
		require.Equal(t, tc.parentPath, parentPath, "parentPath for %q", tc.full)
		require.Equal(t, tc.path, path, "path for %q", tc.full)
		require.Equal(t, tc.key, key, "key for %q", tc.full)
	}
}

func TestMySQLQuoteIdentifier(t *testing.T) {
	t.Parallel()

	require.Equal(t, "`openbao_kv_store`", mysqlQuoteIdentifier("openbao_kv_store"))
	// Embedded backticks are doubled.
	require.Equal(t, "`a``b`", mysqlQuoteIdentifier("a`b"))
	// Truncated at a zero byte.
	require.Equal(t, "`ab`", mysqlQuoteIdentifier("ab\x00cd"))
}

// Similar to testHABackend, but using internal implementation details to
// trigger the lock failure scenario by setting the lock renew period for one
// of the locks to a higher value than the lock TTL.
const maxTries = 3

func testMySQLLockTTL(t *testing.T, ha physical.HABackend) {
	for tries := 1; tries <= maxTries; tries++ {
		// Try this several times.  If the test environment is too slow the lock can naturally lapse
		if attemptLockTTLTest(t, ha, tries) {
			break
		}
	}
}

func attemptLockTTLTest(t *testing.T, ha physical.HABackend, tries int) bool {
	// Set much smaller lock times to speed up the test.
	lockTTL := 3
	renewInterval := time.Second * 1
	retryInterval := time.Second * 1
	longRenewInterval := time.Duration(lockTTL*2) * time.Second
	lockkey := "mysqlttl"

	var leaderCh <-chan struct{}

	// Get the lock
	origLock, err := ha.LockWith(lockkey, "bar")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	{
		// set the first lock renew period to double the expected TTL.
		lock := origLock.(*MySQLLock)
		lock.renewInterval = longRenewInterval
		lock.ttlSeconds = lockTTL

		// Attempt to lock
		lockTime := time.Now()
		leaderCh, err = lock.Lock(nil)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if leaderCh == nil {
			t.Fatal("failed to get leader ch")
		}

		if tries == 1 {
			time.Sleep(3 * time.Second)
		}
		// Check the value
		held, val, err := lock.Value()
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if !held {
			if tries < maxTries && time.Since(lockTime) > (time.Second*time.Duration(lockTTL)) {
				// Our test environment is slow enough that we failed this, retry
				return false
			}
			t.Fatal("should be held")
		}
		if val != "bar" {
			t.Fatalf("bad value: %v", val)
		}
	}

	// Second acquisition should succeed because the first lock should
	// not renew within the 3 sec TTL.
	origLock2, err := ha.LockWith(lockkey, "baz")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	{
		lock2 := origLock2.(*MySQLLock)
		lock2.renewInterval = renewInterval
		lock2.ttlSeconds = lockTTL
		lock2.retryInterval = retryInterval

		// Cancel attempt in 6 sec so as not to block unit tests forever
		stopCh := make(chan struct{})
		time.AfterFunc(time.Duration(lockTTL*2)*time.Second, func() {
			close(stopCh)
		})

		// Attempt to lock should work
		lockTime := time.Now()
		leaderCh2, err := lock2.Lock(stopCh)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if leaderCh2 == nil {
			t.Fatal("should get leader ch")
		}
		defer lock2.Unlock()

		// Check the value
		held, val, err := lock2.Value()
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if !held {
			if tries < maxTries && time.Since(lockTime) > (time.Second*time.Duration(lockTTL)) {
				// Our test environment is slow enough that we failed this, retry
				return false
			}
			t.Fatal("should be held")
		}
		if val != "baz" {
			t.Fatalf("bad value: %v", val)
		}
	}
	// The first lock should have lost the leader channel
	select {
	case <-time.After(longRenewInterval * 2):
		t.Fatal("original lock did not have its leader channel closed.")
	case <-leaderCh:
	}
	return true
}

// Verify that once Unlock is called, we don't keep trying to renew the original
// lock.
func testMySQLLockRenewal(t *testing.T, ha physical.HABackend) {
	// Get the lock
	origLock, err := ha.LockWith("mysqlrenewal", "bar")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	lock := origLock.(*MySQLLock)

	// Attempt to lock
	leaderCh, err := lock.Lock(nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if leaderCh == nil {
		t.Fatal("failed to get leader ch")
	}

	// Check the value
	held, val, err := lock.Value()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !held {
		t.Fatal("should be held")
	}
	if val != "bar" {
		t.Fatalf("bad value: %v", val)
	}

	// Release the lock, which will delete the stored item
	if err := lock.Unlock(); err != nil {
		t.Fatalf("err: %v", err)
	}

	// Wait longer than the renewal time
	time.Sleep(1500 * time.Millisecond)

	// Attempt to lock with new lock
	newLock, err := ha.LockWith("mysqlrenewal", "baz")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	stopCh := make(chan struct{})
	timeout := time.Duration(lock.ttlSeconds)*time.Second + lock.retryInterval + time.Second

	var leaderCh2 <-chan struct{}
	newlockch := make(chan struct{})
	go func() {
		leaderCh2, err = newLock.Lock(stopCh)
		close(newlockch)
	}()

	// Cancel attempt after lock ttl + 1s so as not to block unit tests forever
	select {
	case <-time.After(timeout):
		t.Logf("giving up on lock attempt after %v", timeout)
		close(stopCh)
	case <-newlockch:
		// pass through
	}

	// Attempt to lock should work
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if leaderCh2 == nil {
		t.Fatal("should get leader ch")
	}

	// Check the value
	held, val, err = newLock.Value()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !held {
		t.Fatal("should be held")
	}
	if val != "baz" {
		t.Fatalf("bad value: %v", val)
	}

	// Cleanup
	newLock.Unlock()
}

func TestMySQLBackend_CreateTables(t *testing.T) {
	t.Parallel()

	logger := logging.NewVaultLogger(log.Debug)
	connURL := requireTestDSN(t)

	b, err := NewMySQLBackend(map[string]string{
		"connection_url": connURL,
		"table":          "openbao_kv_store",
		"ha_enabled":     "true",
	}, logger)
	if err != nil {
		t.Fatalf("Failed to create new backend: %v", err)
	}

	// Do not call SetupDatabaseObjects here; this should be handled automatically.
	logger.Info("Running basic backend tests")
	physical.ExerciseBackend(t, b)
}

func TestMySQLBackend_NoCreateTables(t *testing.T) {
	t.Parallel()

	logger := logging.NewVaultLogger(log.Debug)
	connURL := requireTestDSN(t)

	b, err := NewMySQLBackend(map[string]string{
		"connection_url":    connURL,
		"table":             "openbao_kv_store_nocreate",
		"ha_enabled":        "true",
		"skip_create_table": "true",
	}, logger)
	if err != nil {
		t.Fatalf("Failed to create new backend: %v", err)
	}

	// Put should fail with an error because the table does not exist.
	entry := &physical.Entry{Key: "foo", Value: []byte("data")}
	err = b.Put(t.Context(), entry)
	if err == nil {
		t.Fatal("expected put to fail due to missing tables")
	}

	m := b.(*MySQLBackend)
	SetupDatabaseObjects(t, m)

	logger.Info("Running basic backend tests")
	physical.ExerciseBackend(t, b)
}

// TestMySQLBackend_Parallel ensures that max_parallel is respected.
func TestMySQLBackend_Parallel(t *testing.T) {
	t.Parallel()

	logger := logging.NewVaultLogger(log.Debug)
	connURL := requireTestDSN(t)

	bRaw, err := NewMySQLBackend(map[string]string{
		"connection_url": connURL,
		"table":          "openbao_kv_store",
		"ha_enabled":     "true",
		"max_parallel":   "2",
	}, logger)
	if err != nil {
		t.Fatalf("Failed to create new backend: %v", err)
	}

	b := bRaw.(physical.TransactionalBackend)

	errs := make([]error, 100)
	var wg sync.WaitGroup
	for j := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			entry := &physical.Entry{Key: fmt.Sprintf("foo-%v", i), Value: []byte("data")}
			err := b.Put(t.Context(), entry)
			if err != nil {
				errs[i] = err
			}
		}(j)
	}
	wg.Wait()
	for j := range errs {
		if errs[j] != nil {
			t.Fatalf("process %v: %v", j, errs[j])
		}
	}

	// Use transactions so we can sleep while holding a connection.
	var count atomic.Int32
	for j := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			entry := &physical.Entry{Key: fmt.Sprintf("foo-%v", i), Value: []byte("data")}

			tx, err := b.BeginTx(t.Context())
			if err != nil {
				errs[i] = err
				return
			}

			value := count.Add(1)
			if value > 2 {
				errs[i] = fmt.Errorf("value for job %v exceeded max_parallel: %v", i, value)
			}

			time.Sleep(1 * time.Second)

			value = count.Load()
			if value > 2 {
				errs[i] = fmt.Errorf("value for job %v exceeded max_parallel: %v", i, value)
			}

			err = tx.Put(t.Context(), entry)
			if err != nil {
				errs[i] = err
				return
			}

			count.Add(-1)

			err = tx.Commit(t.Context())
			if err != nil {
				errs[i] = err
				return
			}
		}(j)
	}
	wg.Wait()
	for j := range errs {
		if errs[j] != nil {
			t.Fatalf("process %v: %v", j, errs[j])
		}
	}
}

// TestMySQLBackend_LockSemantics ensures our HA locking behaves
// according to expectations.
func TestMySQLBackend_LockSemantics(t *testing.T) {
	t.Parallel()

	logger := logging.NewVaultLogger(log.Debug)
	connURL := requireTestDSN(t)

	b, err := NewMySQLBackend(map[string]string{
		"connection_url": connURL,
		"ha_enabled":     "true",
	}, logger)
	require.NoError(t, err, "failed to create a new backend")

	bLocking := b.(physical.HABackend)
	bFencing := b.(physical.FencingHABackend)

	require.True(t, bLocking.HAEnabled())

	lockName := "my/lock"
	lock, err := bLocking.LockWith(lockName, "identifying-value")
	require.NoError(t, err)
	require.NotNil(t, lock)

	leaderLossCh, err := lock.Lock(nil)
	require.NoError(t, err)
	require.NotNil(t, leaderLossCh)

	err = bFencing.RegisterActiveNodeLock(lock)
	require.NoError(t, err)

	// Ensure fence allows us to write.
	err = b.Put(t.Context(), &physical.Entry{
		Key:   "a",
		Value: []byte("asdf"),
	})
	require.NoError(t, err)

	// Create a second backend and attempt to grab the lock.
	b2, err := NewMySQLBackend(map[string]string{
		"connection_url": connURL,
		"ha_enabled":     "true",
	}, logger)
	require.NoError(t, err, "failed to create a new backend")

	b2Locking := b2.(physical.HABackend)

	stopCh := make(chan struct{}, 1)

	lock2, err := b2Locking.LockWith(lockName, "secondary-identifying-value")
	require.NoError(t, err)
	require.NotNil(t, lock2)

	go func() {
		time.Sleep(5 * time.Second)
		close(stopCh)
	}()

	leaderLossCh2, err := lock2.Lock(stopCh)
	require.NoError(t, err)
	require.Nil(t, leaderLossCh2)

	held, value, err := lock2.Value()
	require.True(t, held)
	require.Equal(t, lock.(*MySQLLock).value, value)
	require.Nil(t, err)

	// Forcibly steal the lock: delete the currently held value.
	result, err := b2.(*MySQLBackend).client.Exec("TRUNCATE openbao_ha_locks")
	require.NoError(t, err)
	require.NotNil(t, result)

	// Write should subsequently fail.
	err = b.Put(t.Context(), &physical.Entry{
		Key:   "b",
		Value: []byte("asdf"),
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), physical.ErrFencedWriteFailed)

	// Acquiring the lock from the secondary should have the same behavior.
	leaderLossCh2, err = lock2.Lock(nil)
	require.NoError(t, err)
	require.NotNil(t, leaderLossCh2)

	err = b.Put(t.Context(), &physical.Entry{
		Key:   "c",
		Value: []byte("asdf"),
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), physical.ErrFencedWriteFailed)

	// But bypassing it manually should be fine.
	ctx := physical.UnfencedWriteCtx(t.Context())
	err = b.Put(ctx, &physical.Entry{
		Key:   "d",
		Value: []byte("asdf"),
	})
	require.NoError(t, err)

	// Same with writing from the secondary even though it doesn't
	// have a fence.
	err = b2.Put(t.Context(), &physical.Entry{
		Key:   "e",
		Value: []byte("asdf"),
	})
	require.NoError(t, err)

	err = lock2.Unlock()
	require.NoError(t, err)

	// Reacquire the first lock.
	leaderLossCh, err = lock.Lock(nil)
	require.NoError(t, err)
	require.NotNil(t, leaderLossCh)

	// Writes should succeed again on first database.
	err = b.Put(t.Context(), &physical.Entry{
		Key:   "f",
		Value: []byte("asdf"),
	})
	require.NoError(t, err)

	// Wait for several renewals.
	time.Sleep(MySQLLockTTLSeconds*time.Second + MySQLLockRenewInterval)

	// Ensure the lock is still held.
	select {
	case <-leaderLossCh:
		t.Fatal("leader loss channel was closed, implying leadership renewal failed")
	default:
	}
}

func TestMySQLBackend_ParallelTables(t *testing.T) {
	t.Parallel()

	logger := logging.NewVaultLogger(log.Debug)
	connURL := requireTestDSN(t)

	b1, err := NewMySQLBackend(map[string]string{
		"connection_url": connURL,
		"table":          "store_1",
		"ha_table":       "store_1_ha",
		"ha_enabled":     "true",
	}, logger)
	require.NoError(t, err)

	b2, err := NewMySQLBackend(map[string]string{
		"connection_url": connURL,
		"table":          "store_2",
		"ha_table":       "store_2_ha",
		"ha_enabled":     "true",
	}, logger)
	require.NoError(t, err)

	logger.Info("Running basic backend tests")
	physical.ExerciseBackend(t, b1)
	physical.ExerciseBackend(t, b2)
}
