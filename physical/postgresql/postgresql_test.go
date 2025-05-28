// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package postgresql

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	log "github.com/hashicorp/go-hclog"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/openbao/openbao/sdk/v2/helper/logging"
	"github.com/openbao/openbao/sdk/v2/helper/testhelpers/postgresql"
	"github.com/openbao/openbao/sdk/v2/physical"
	"github.com/stretchr/testify/require"
)

func TestPostgreSQLBackend(t *testing.T) {
	logger := logging.NewVaultLogger(log.Debug)

	// Use docker as pg backend if no url is provided via environment variables
	connURL := os.Getenv("PGURL")
	if connURL == "" {
		cleanup, u := postgresql.PrepareTestContainer(t, "11.1")
		connURL = u
		defer cleanup()
	}

	table := os.Getenv("PGTABLE")
	if table == "" {
		table = "openbao_kv_store"
	}

	hae := os.Getenv("PGHAENABLED")
	if hae == "" {
		hae = "true"
	}

	// Run vault tests
	logger.Info(fmt.Sprintf("Connection URL: %v", connURL))

	b1, err := NewPostgreSQLBackend(map[string]string{
		"connection_url": connURL,
		"table":          table,
		"ha_enabled":     hae,
	}, logger)
	if err != nil {
		t.Fatalf("Failed to create new backend: %v", err)
	}

	b2, err := NewPostgreSQLBackend(map[string]string{
		"connection_url": connURL,
		"table":          table,
		"ha_enabled":     hae,
	}, logger)
	if err != nil {
		t.Fatalf("Failed to create new backend: %v", err)
	}
	pg := b1.(*PostgreSQLBackend)

	// Read postgres version to test basic connects works
	var pgversion string
	if err = pg.client.QueryRow("SELECT current_setting('server_version_num')").Scan(&pgversion); err != nil {
		t.Fatalf("Failed to check for Postgres version: %v", err)
	}
	logger.Info(fmt.Sprintf("Postgres Version: %v", pgversion))

	SetupDatabaseObjects(t, pg)

	defer func() {
		pg := b1.(*PostgreSQLBackend)
		_, err := pg.client.Exec(fmt.Sprintf(" TRUNCATE TABLE %v ", pg.table))
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
		t.Fatal("PostgreSQLDB does not implement HABackend")
	}

	ha2, ok := b2.(physical.HABackend)
	if !ok {
		t.Fatal("PostgreSQLDB does not implement HABackend")
	}

	if ha1.HAEnabled() && ha2.HAEnabled() {
		logger.Info("Running ha backend tests")
		physical.ExerciseHABackend(t, ha1, ha2)
		testPostgresSQLLockTTL(t, ha1)
		testPostgresSQLLockRenewal(t, ha1)
	}
}

func TestPostgreSQLBackendMaxIdleConnectionsParameter(t *testing.T) {
	_, err := NewPostgreSQLBackend(map[string]string{
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
			// This is necessary to avoid always testing the branch where the env is set.
			// As long the the env is set --- even if the value is "" --- `ok` returns true.
			if tt.input.envar != "" {
				os.Setenv("VAULT_PG_CONNECTION_URL", tt.input.envar)
				defer os.Unsetenv("VAULT_PG_CONNECTION_URL")
			}

			got := connectionURL(tt.input.conf)

			if got != tt.want {
				t.Errorf("connectionURL(%s): want %q, got %q", tt.input, tt.want, got)
			}
		})
	}
}

// Similar to testHABackend, but using internal implementation details to
// trigger the lock failure scenario by setting the lock renew period for one
// of the locks to a higher value than the lock TTL.
const maxTries = 3

func testPostgresSQLLockTTL(t *testing.T, ha physical.HABackend) {
	t.Log("Skipping testPostgresSQLLockTTL portion of test.")
	return

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
	lockkey := "postgresttl"

	var leaderCh <-chan struct{}

	// Get the lock
	origLock, err := ha.LockWith(lockkey, "bar")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	{
		// set the first lock renew period to double the expected TTL.
		lock := origLock.(*PostgreSQLLock)
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
		lock2 := origLock2.(*PostgreSQLLock)
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
func testPostgresSQLLockRenewal(t *testing.T, ha physical.HABackend) {
	// Get the lock
	origLock, err := ha.LockWith("pgrenewal", "bar")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// customize the renewal and watch intervals
	lock := origLock.(*PostgreSQLLock)
	// lock.renewInterval = time.Second * 1

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
	newLock, err := ha.LockWith("pgrenewal", "baz")
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

func TestPostgreSQLBackend_CreateTables(t *testing.T) {
	t.Parallel()

	logger := logging.NewVaultLogger(log.Debug)

	cleanup, connURL := postgresql.PrepareTestContainer(t, "11.1")
	defer cleanup()

	b, err := NewPostgreSQLBackend(map[string]string{
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

func TestPostgreSQLBackend_NoCreateTables(t *testing.T) {
	t.Parallel()

	logger := logging.NewVaultLogger(log.Debug)

	cleanup, connURL := postgresql.PrepareTestContainer(t, "11.1")
	defer cleanup()

	b, err := NewPostgreSQLBackend(map[string]string{
		"connection_url":    connURL,
		"table":             "openbao_kv_store",
		"ha_enabled":        "true",
		"skip_create_table": "true",
	}, logger)
	if err != nil {
		t.Fatalf("Failed to create new backend: %v", err)
	}

	// Put should fail with an error.
	entry := &physical.Entry{Key: "foo", Value: []byte("data")}
	err = b.Put(context.Background(), entry)
	if err == nil {
		t.Fatal("expected put to fail due to missing tables")
	}

	pg := b.(*PostgreSQLBackend)
	SetupDatabaseObjects(t, pg)

	logger.Info("Running basic backend tests")
	physical.ExerciseBackend(t, b)
}

// TestPostgreSQLBackend_PGEnv ensures that standard PostgreSQL environment
// variables works.
func TestPostgreSQLBackend_PGEnv(t *testing.T) {
	logger := logging.NewVaultLogger(log.Debug)

	cleanup, connURL := postgresql.PrepareTestContainer(t, "11.1")
	defer cleanup()

	defer func(host, user, password, port, sslmode string) {
		os.Setenv("PGHOST", host)
		os.Setenv("PGUSER", user)
		os.Setenv("PGPASSWORD", password)
		os.Setenv("PGPORT", port)
		os.Setenv("PGSSLMODE", sslmode)
	}(
		os.Getenv("PGHOST"),
		os.Getenv("PGUSER"),
		os.Getenv("PGPASSWORD"),
		os.Getenv("PGPORT"),
		os.Getenv("PGSSLMODE"),
	)

	addr, err := url.Parse(connURL)
	require.NoError(t, err)

	password, _ := addr.User.Password()
	os.Setenv("PGHOST", addr.Hostname())
	os.Setenv("PGUSER", addr.User.Username())
	os.Setenv("PGPASSWORD", password)
	os.Setenv("PGPORT", addr.Port())
	os.Setenv("PGSSLMODE", "disable")

	_, err = NewPostgreSQLBackend(map[string]string{
		"table":             "openbao_kv_store",
		"ha_enabled":        "true",
		"skip_create_table": "true",
	}, logger)
	if err != nil {
		t.Fatalf("Failed to create new backend: %v", err)
	}
}

// TestPostgreSQLBackend_Retry verifies that we will connect to a PostgreSQL
// instance even if it is not yet ready. This is _usually_ the case as
// TestContainerNoWait does not connect to the container and PostgreSQL
// _usually_ takes some time to start up.
func TestPostgreSQLBackend_Retry(t *testing.T) {
	t.Parallel()

	logger := logging.NewVaultLogger(log.Debug)

	cleanup, connURL := postgresql.TestContainerNoWait(t)
	defer cleanup()

	var b physical.Backend
	var err error

	b, err = NewPostgreSQLBackend(map[string]string{
		"connection_url":      connURL,
		"table":               "openbao_kv_store",
		"ha_enabled":          "true",
		"max_connect_retries": "1000",
		"skip_create_table":   "true",
	}, logger)
	if err != nil {
		t.Fatalf("Failed to create new backend: %v", err)
	}
	if b == nil {
		t.Fatalf("failed to create backend")
	}
}

// TestPostgreSQLBackend_Parallel ensures that max_parallel is respected.
func TestPostgreSQLBackend_Parallel(t *testing.T) {
	t.Parallel()

	logger := logging.NewVaultLogger(log.Debug)

	cleanup, connURL := postgresql.PrepareTestContainer(t, "11.1")
	defer cleanup()

	bRaw, err := NewPostgreSQLBackend(map[string]string{
		"connection_url": connURL,
		"table":          "openbao_kv_store",
		"ha_enabled":     "true",
		"max_parallel":   "2",
	}, logger)
	if err != nil {
		t.Fatalf("Failed to create new backend: %v", err)
	}

	b := bRaw.(physical.TransactionalBackend)

	// Put should succeed without an error even with massively parallel
	// requests.
	errors := make([]error, 100)
	var wg sync.WaitGroup
	for j := range errors {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			entry := &physical.Entry{Key: fmt.Sprintf("foo-%v", i), Value: []byte("data")}
			err := b.Put(context.Background(), entry)
			if err != nil {
				errors[i] = err
			}
		}(j)
	}

	wg.Wait()

	for j := range errors {
		if errors[j] != nil {
			t.Fatalf("process %v: %v", j, errors[j])
		}
	}

	// Use transactions so we can sleep while holding a connection.
	var count atomic.Int32
	for j := range errors {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			entry := &physical.Entry{Key: fmt.Sprintf("foo-%v", i), Value: []byte("data")}

			tx, err := b.BeginTx(context.Background())
			if err != nil {
				errors[i] = err
				return
			}

			value := count.Add(1)
			if value > 2 {
				errors[i] = fmt.Errorf("value for job %v exceeded max_parallel: %v", i, value)
			}

			time.Sleep(1)

			value = count.Load()
			if value > 2 {
				errors[i] = fmt.Errorf("value for job %v exceeded max_parallel: %v", i, value)
			}

			err = tx.Put(context.Background(), entry)
			if err != nil {
				errors[i] = err
				return
			}

			value = count.Load()
			if value > 2 {
				errors[i] = fmt.Errorf("value for job %v exceeded max_parallel: %v", i, value)
			}

			time.Sleep(1)

			value = count.Load()
			if value > 2 {
				errors[i] = fmt.Errorf("value for job %v exceeded max_parallel: %v", i, value)
			}

			count.Add(-1)

			err = tx.Commit(context.Background())
			if err != nil {
				errors[i] = err
				return
			}
		}(j)

	}

	wg.Wait()

	for j := range errors {
		if errors[j] != nil {
			t.Fatalf("process %v: %v", j, errors[j])
		}
	}
}
