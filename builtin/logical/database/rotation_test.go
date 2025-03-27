// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v4/stdlib"
	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/helper/namespace"
	postgreshelper "github.com/openbao/openbao/helper/testhelpers/postgresql"
	v5 "github.com/openbao/openbao/sdk/v2/database/dbplugin/v5"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/openbao/openbao/sdk/v2/helper/dbtxn"
	"github.com/openbao/openbao/sdk/v2/helper/pluginutil"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/sdk/v2/queue"
	"github.com/stretchr/testify/mock"
)

const (
	dbUser                = "vaultstatictest"
	dbUserDefaultPassword = "password"
)

func TestBackend_StaticRole_Rotate_basic(t *testing.T) {
	cluster, sys := getCluster(t)
	defer cluster.Cleanup()

	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	config.System = sys

	lb, err := Factory(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	b, ok := lb.(*databaseBackend)
	if !ok {
		t.Fatal("could not convert to db backend")
	}
	defer b.Cleanup(context.Background())

	cleanup, connURL := postgreshelper.PrepareTestContainer(t, "")
	defer cleanup()

	// create the database user
	createTestPGUser(t, connURL, dbUser, dbUserDefaultPassword, testRoleStaticCreate)

	verifyPgConn(t, dbUser, dbUserDefaultPassword, connURL)

	// Configure a connection
	data := map[string]interface{}{
		"connection_url":    connURL,
		"plugin_name":       "postgresql-database-plugin",
		"verify_connection": false,
		"allowed_roles":     []string{"*"},
		"name":              "plugin-test",
	}

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/plugin-test",
		Storage:   config.StorageView,
		Data:      data,
	}
	resp, err := b.HandleRequest(namespace.RootContext(nil), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	data = map[string]interface{}{
		"name":                "plugin-role-test",
		"db_name":             "plugin-test",
		"rotation_statements": testRoleStaticUpdate,
		"username":            dbUser,
		"rotation_period":     "5400s",
	}

	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "static-roles/plugin-role-test",
		Storage:   config.StorageView,
		Data:      data,
	}

	resp, err = b.HandleRequest(namespace.RootContext(nil), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	// Read the creds
	data = map[string]interface{}{}
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "static-creds/plugin-role-test",
		Storage:   config.StorageView,
		Data:      data,
	}

	resp, err = b.HandleRequest(namespace.RootContext(nil), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	username := resp.Data["username"].(string)
	password := resp.Data["password"].(string)
	if username == "" || password == "" {
		t.Fatalf("empty username (%s) or password (%s)", username, password)
	}

	// Verify username/password
	verifyPgConn(t, dbUser, password, connURL)

	// Re-read the creds, verifying they aren't changing on read
	data = map[string]interface{}{}
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "static-creds/plugin-role-test",
		Storage:   config.StorageView,
		Data:      data,
	}
	resp, err = b.HandleRequest(namespace.RootContext(nil), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	if username != resp.Data["username"].(string) || password != resp.Data["password"].(string) {
		t.Fatal("expected re-read username/password to match, but didn't")
	}

	// Trigger rotation
	data = map[string]interface{}{"name": "plugin-role-test"}
	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "rotate-role/plugin-role-test",
		Storage:   config.StorageView,
		Data:      data,
	}
	resp, err = b.HandleRequest(namespace.RootContext(nil), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	if resp != nil {
		t.Fatalf("Expected empty response from rotate-role: (%#v)", resp)
	}

	// Re-Read the creds
	data = map[string]interface{}{}
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "static-creds/plugin-role-test",
		Storage:   config.StorageView,
		Data:      data,
	}
	resp, err = b.HandleRequest(namespace.RootContext(nil), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	newPassword := resp.Data["password"].(string)
	if password == newPassword {
		t.Fatalf("expected passwords to differ, got (%s)", newPassword)
	}

	// Verify new username/password
	verifyPgConn(t, username, newPassword, connURL)
}

// Sanity check to make sure we don't allow an attempt of rotating credentials
// for non-static accounts, which doesn't make sense anyway, but doesn't hurt to
// verify we return an error
func TestBackend_StaticRole_Rotate_NonStaticError(t *testing.T) {
	cluster, sys := getCluster(t)
	defer cluster.Cleanup()

	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	config.System = sys

	lb, err := Factory(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	b, ok := lb.(*databaseBackend)
	if !ok {
		t.Fatal("could not convert to db backend")
	}
	defer b.Cleanup(context.Background())

	cleanup, connURL := postgreshelper.PrepareTestContainer(t, "")
	defer cleanup()

	// create the database user
	createTestPGUser(t, connURL, dbUser, dbUserDefaultPassword, testRoleStaticCreate)

	// Configure a connection
	data := map[string]interface{}{
		"connection_url":    connURL,
		"plugin_name":       "postgresql-database-plugin",
		"verify_connection": false,
		"allowed_roles":     []string{"*"},
		"name":              "plugin-test",
	}

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/plugin-test",
		Storage:   config.StorageView,
		Data:      data,
	}
	resp, err := b.HandleRequest(namespace.RootContext(nil), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	data = map[string]interface{}{
		"name":                  "plugin-role-test",
		"db_name":               "plugin-test",
		"creation_statements":   testRoleStaticCreate,
		"rotation_statements":   testRoleStaticUpdate,
		"revocation_statements": defaultRevocationSQL,
	}

	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/plugin-role-test",
		Storage:   config.StorageView,
		Data:      data,
	}

	resp, err = b.HandleRequest(namespace.RootContext(nil), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	// Read the creds
	data = map[string]interface{}{}
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/plugin-role-test",
		Storage:   config.StorageView,
		Data:      data,
	}
	resp, err = b.HandleRequest(namespace.RootContext(nil), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	username := resp.Data["username"].(string)
	password := resp.Data["password"].(string)
	if username == "" || password == "" {
		t.Fatalf("empty username (%s) or password (%s)", username, password)
	}

	// Verify username/password
	verifyPgConn(t, dbUser, dbUserDefaultPassword, connURL)
	// Trigger rotation
	data = map[string]interface{}{"name": "plugin-role-test"}
	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "rotate-role/plugin-role-test",
		Storage:   config.StorageView,
		Data:      data,
	}
	// expect resp to be an error
	resp, _ = b.HandleRequest(namespace.RootContext(nil), req)
	if !resp.IsError() {
		t.Fatal("expected error rotating non-static role")
	}

	if resp.Error().Error() != "no static role found for role name" {
		t.Fatalf("wrong error message: %s", err)
	}
}

func TestBackend_StaticRole_Revoke_user(t *testing.T) {
	cluster, sys := getCluster(t)
	defer cluster.Cleanup()

	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	config.System = sys

	lb, err := Factory(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	b, ok := lb.(*databaseBackend)
	if !ok {
		t.Fatal("could not convert to db backend")
	}
	defer b.Cleanup(context.Background())

	cleanup, connURL := postgreshelper.PrepareTestContainer(t, "")
	defer cleanup()

	// create the database user
	createTestPGUser(t, connURL, dbUser, dbUserDefaultPassword, testRoleStaticCreate)

	// Configure a connection
	data := map[string]interface{}{
		"connection_url":    connURL,
		"plugin_name":       "postgresql-database-plugin",
		"verify_connection": false,
		"allowed_roles":     []string{"*"},
		"name":              "plugin-test",
	}

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/plugin-test",
		Storage:   config.StorageView,
		Data:      data,
	}
	resp, err := b.HandleRequest(namespace.RootContext(nil), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	testCases := map[string]struct {
		revoke          *bool
		expectVerifyErr bool
	}{
		// Default case: user does not specify, Vault leaves the database user
		// untouched, and the final connection check passes because the user still
		// exists
		"unset": {},
		// Revoke on delete. The final connection check should fail because the user
		// no longer exists
		"revoke": {
			revoke:          newBoolPtr(true),
			expectVerifyErr: true,
		},
		// Revoke false, final connection check should still pass
		"persist": {
			revoke: newBoolPtr(false),
		},
	}
	for k, tc := range testCases {
		t.Run(k, func(t *testing.T) {
			data = map[string]interface{}{
				"name":                "plugin-role-test",
				"db_name":             "plugin-test",
				"rotation_statements": testRoleStaticUpdate,
				"username":            dbUser,
				"rotation_period":     "5400s",
			}
			if tc.revoke != nil {
				data["revoke_user_on_delete"] = *tc.revoke
			}

			req = &logical.Request{
				Operation: logical.CreateOperation,
				Path:      "static-roles/plugin-role-test",
				Storage:   config.StorageView,
				Data:      data,
			}

			resp, err = b.HandleRequest(namespace.RootContext(nil), req)
			if err != nil || (resp != nil && resp.IsError()) {
				t.Fatalf("err:%s resp:%#v\n", err, resp)
			}

			// Read the creds
			data = map[string]interface{}{}
			req = &logical.Request{
				Operation: logical.ReadOperation,
				Path:      "static-creds/plugin-role-test",
				Storage:   config.StorageView,
				Data:      data,
			}

			resp, err = b.HandleRequest(namespace.RootContext(nil), req)
			if err != nil || (resp != nil && resp.IsError()) {
				t.Fatalf("err:%s resp:%#v\n", err, resp)
			}

			username := resp.Data["username"].(string)
			password := resp.Data["password"].(string)
			if username == "" || password == "" {
				t.Fatalf("empty username (%s) or password (%s)", username, password)
			}

			// Verify username/password
			verifyPgConn(t, username, password, connURL)

			// delete the role, expect the default where the user is not destroyed
			// Read the creds
			req = &logical.Request{
				Operation: logical.DeleteOperation,
				Path:      "static-roles/plugin-role-test",
				Storage:   config.StorageView,
			}

			resp, err = b.HandleRequest(namespace.RootContext(nil), req)
			if err != nil || (resp != nil && resp.IsError()) {
				t.Fatalf("err:%s resp:%#v\n", err, resp)
			}

			// Verify new username/password still work
			verifyPgConn(t, username, password, connURL)
		})
	}
}

func createTestPGUser(t *testing.T, connURL string, username, password, query string) {
	t.Helper()
	log.Printf("[TRACE] Creating test user")

	db, err := sql.Open("pgx", connURL)
	defer db.Close()
	if err != nil {
		t.Fatal(err)
	}

	// Start a transaction
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	m := map[string]string{
		"name":     username,
		"password": password,
	}
	if err := dbtxn.ExecuteTxQueryDirect(ctx, tx, m, query); err != nil {
		t.Fatal(err)
	}
	// Commit the transaction
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func verifyPgConn(t *testing.T, username, password, connURL string) {
	t.Helper()
	cURL := strings.Replace(connURL, "postgres:secret", username+":"+password, 1)
	db, err := sql.Open("pgx", cURL)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Ping(); err != nil {
		t.Fatal(err)
	}
}

// WAL testing
//
// First scenario, WAL contains a role name that does not exist.
func TestBackend_Static_QueueWAL_discard_role_not_found(t *testing.T) {
	cluster, sys := getCluster(t)
	defer cluster.Cleanup()

	ctx := context.Background()

	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	config.System = sys

	_, err := framework.PutWAL(ctx, config.StorageView, staticWALKey, &setCredentialsWAL{
		RoleName: "doesnotexist",
	})
	if err != nil {
		t.Fatalf("error with PutWAL: %s", err)
	}

	assertWALCount(t, config.StorageView, 1, staticWALKey)

	b, err := Factory(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Cleanup(ctx)

	time.Sleep(5 * time.Second)
	bd := b.(*databaseBackend)
	if bd.credRotationQueue == nil {
		t.Fatal("database backend had no credential rotation queue")
	}

	// Verify empty queue
	if bd.credRotationQueue.Len() != 0 {
		t.Fatalf("expected zero queue items, got: %d", bd.credRotationQueue.Len())
	}

	assertWALCount(t, config.StorageView, 0, staticWALKey)
}

// Second scenario, WAL contains a role name that does exist, but the role's
// LastVaultRotation is greater than the WAL has
func TestBackend_Static_QueueWAL_discard_role_newer_rotation_date(t *testing.T) {
	cluster, sys := getCluster(t)
	defer cluster.Cleanup()

	ctx := context.Background()

	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	config.System = sys

	roleName := "test-discard-by-date"
	lb, err := Factory(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	b, ok := lb.(*databaseBackend)
	if !ok {
		t.Fatal("could not convert to db backend")
	}

	cleanup, connURL := postgreshelper.PrepareTestContainer(t, "")
	defer cleanup()

	// create the database user
	createTestPGUser(t, connURL, dbUser, dbUserDefaultPassword, testRoleStaticCreate)

	// Configure a connection
	data := map[string]interface{}{
		"connection_url":    connURL,
		"plugin_name":       "postgresql-database-plugin",
		"verify_connection": false,
		"allowed_roles":     []string{"*"},
		"name":              "plugin-test",
	}

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/plugin-test",
		Storage:   config.StorageView,
		Data:      data,
	}
	resp, err := b.HandleRequest(namespace.RootContext(nil), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	// Save Now() to make sure rotation time is after this, as well as the WAL
	// time
	roleTime := time.Now()

	// Create role
	data = map[string]interface{}{
		"name":                roleName,
		"db_name":             "plugin-test",
		"rotation_statements": testRoleStaticUpdate,
		"username":            dbUser,
		// Low value here, to make sure the backend rotates this password at least
		// once before we compare it to the WAL
		"rotation_period": "10s",
	}

	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "static-roles/" + roleName,
		Storage:   config.StorageView,
		Data:      data,
	}

	resp, err = b.HandleRequest(namespace.RootContext(nil), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	// Allow the first rotation to occur, setting LastVaultRotation
	time.Sleep(time.Second * 12)

	// Cleanup the backend, then create a WAL for the role with a
	// LastVaultRotation of 1 hour ago, so that when we recreate the backend the
	// WAL will be read but discarded
	b.Cleanup(ctx)
	b = nil
	time.Sleep(time.Second * 3)

	// Make a fake WAL entry with an older time
	oldRotationTime := roleTime.Add(time.Hour * -1)
	walPassword := "somejunkpassword"
	_, err = framework.PutWAL(ctx, config.StorageView, staticWALKey, &setCredentialsWAL{
		RoleName:          roleName,
		NewPassword:       walPassword,
		LastVaultRotation: oldRotationTime,
		Username:          dbUser,
	})
	if err != nil {
		t.Fatalf("error with PutWAL: %s", err)
	}

	assertWALCount(t, config.StorageView, 1, staticWALKey)

	// Reload backend
	lb, err = Factory(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	b, ok = lb.(*databaseBackend)
	if !ok {
		t.Fatal("could not convert to db backend")
	}
	defer b.Cleanup(ctx)

	// Allow enough time for populateQueue to work after boot
	time.Sleep(time.Second * 12)

	// PopulateQueue should have processed the entry
	assertWALCount(t, config.StorageView, 0, staticWALKey)

	// Read the role
	data = map[string]interface{}{}
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "static-roles/" + roleName,
		Storage:   config.StorageView,
		Data:      data,
	}
	resp, err = b.HandleRequest(namespace.RootContext(nil), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	lastVaultRotation := resp.Data["last_vault_rotation"].(time.Time)
	if !lastVaultRotation.After(oldRotationTime) {
		t.Fatal("last vault rotation time not greater than WAL time")
	}

	if !lastVaultRotation.After(roleTime) {
		t.Fatal("last vault rotation time not greater than role creation time")
	}

	// Grab password to verify it didn't change
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "static-creds/" + roleName,
		Storage:   config.StorageView,
	}
	resp, err = b.HandleRequest(namespace.RootContext(nil), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	password := resp.Data["password"].(string)
	if password == walPassword {
		t.Fatal("expected password to not be changed by WAL, but was")
	}
}

// Helper to assert the number of WAL entries is what we expect
func assertWALCount(t *testing.T, s logical.Storage, expected int, key string) {
	t.Helper()

	var count int
	ctx := context.Background()
	keys, err := framework.ListWAL(ctx, s)
	if err != nil {
		t.Fatal("error listing WALs")
	}

	// Loop through WAL keys and process any rotation ones
	for _, k := range keys {
		walEntry, _ := framework.GetWAL(ctx, s, k)
		if walEntry == nil {
			continue
		}

		if walEntry.Kind != key {
			continue
		}
		count++
	}
	if expected != count {
		t.Fatalf("WAL count mismatch, expected (%d), got (%d)", expected, count)
	}
}

//
// End WAL testing
//

type userCreator func(t *testing.T, username, password string)

func TestBackend_StaticRole_Rotations_PostgreSQL(t *testing.T) {
	cleanup, connURL := postgreshelper.PrepareTestContainer(t, "13.4-buster")
	defer cleanup()
	uc := userCreator(func(t *testing.T, username, password string) {
		createTestPGUser(t, connURL, username, password, testRoleStaticCreate)
	})
	testBackend_StaticRole_Rotations(t, uc, map[string]interface{}{
		"connection_url": connURL,
		"plugin_name":    "postgresql-database-plugin",
	})
}

func testBackend_StaticRole_Rotations(t *testing.T, createUser userCreator, opts map[string]interface{}) {
	// We need to set this value for the plugin to run, but it doesn't matter what we set it to.
	oldToken := api.ReadBaoVariable(pluginutil.PluginUnwrapTokenEnv)
	os.Setenv(pluginutil.PluginUnwrapTokenEnv, "...")
	defer func() {
		if oldToken != "" {
			os.Setenv(pluginutil.PluginUnwrapTokenEnv, oldToken)
		} else {
			os.Unsetenv(pluginutil.PluginUnwrapTokenEnv)
		}
	}()

	cluster, sys := getCluster(t)
	defer cluster.Cleanup()

	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	config.System = sys
	// Change background task interval to 1s to give more margin
	// for it to successfully run during the sleeps below.
	config.Config[queueTickIntervalKey] = "1"

	// Rotation ticker starts running in Factory call
	b, err := Factory(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Cleanup(context.Background())

	// allow initQueue to finish
	bd := b.(*databaseBackend)
	if bd.credRotationQueue == nil {
		t.Fatal("database backend had no credential rotation queue")
	}

	// Configure a connection
	data := map[string]interface{}{
		"verify_connection": false,
		"allowed_roles":     []string{"*"},
	}
	for k, v := range opts {
		data[k] = v
	}

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/plugin-test",
		Storage:   config.StorageView,
		Data:      data,
	}
	resp, err := b.HandleRequest(namespace.RootContext(nil), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	testCases := []string{"10", "20", "100"}
	// Create database users ahead
	for _, tc := range testCases {
		createUser(t, "statictest"+tc, "test")
	}

	// create three static roles with different rotation periods
	for _, tc := range testCases {
		roleName := "plugin-static-role-" + tc
		data = map[string]interface{}{
			"name":            roleName,
			"db_name":         "plugin-test",
			"username":        "statictest" + tc,
			"rotation_period": tc,
		}

		req = &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "static-roles/" + roleName,
			Storage:   config.StorageView,
			Data:      data,
		}

		resp, err = b.HandleRequest(namespace.RootContext(nil), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%s resp:%#v\n", err, resp)
		}
	}

	// verify the queue has 3 items in it
	if bd.credRotationQueue.Len() != 3 {
		t.Fatalf("expected 3 items in the rotation queue, got: (%d)", bd.credRotationQueue.Len())
	}

	// List the roles
	data = map[string]interface{}{}
	req = &logical.Request{
		Operation: logical.ListOperation,
		Path:      "static-roles/",
		Storage:   config.StorageView,
		Data:      data,
	}
	resp, err = b.HandleRequest(namespace.RootContext(nil), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	keys := resp.Data["keys"].([]string)
	if len(keys) != 3 {
		t.Fatalf("expected 3 roles, got: (%d)", len(keys))
	}

	// capture initial passwords, before the periodic function is triggered
	pws := make(map[string][]string, 0)
	pws = capturePasswords(t, b, config, testCases, pws)

	// sleep to make sure the periodic func has time to actually run
	time.Sleep(15 * time.Second)
	pws = capturePasswords(t, b, config, testCases, pws)

	// sleep more, this should allow both sr10 and sr20 to rotate
	time.Sleep(10 * time.Second)
	pws = capturePasswords(t, b, config, testCases, pws)

	// verify all pws are as they should
	pass := true
	for k, v := range pws {
		if len(v) < 3 {
			t.Fatalf("expected to find 3 passwords for (%s), only found (%d)", k, len(v))
		}
		switch {
		case k == "plugin-static-role-10":
			// expect all passwords to be different
			if v[0] == v[1] || v[1] == v[2] || v[0] == v[2] {
				pass = false
			}
		case k == "plugin-static-role-20":
			// expect the first two to be equal, but different from the third
			if v[0] != v[1] || v[0] == v[2] {
				pass = false
			}
		case k == "plugin-static-role-100":
			// expect all passwords to be equal
			if v[0] != v[1] || v[1] != v[2] {
				pass = false
			}
		default:
			t.Fatalf("unexpected password key: %v", k)
		}
	}
	if !pass {
		t.Fatalf("password rotations did not match expected: %#v", pws)
	}
}

type createUserCommand struct {
	Username string        `bson:"createUser"`
	Password string        `bson:"pwd"`
	Roles    []interface{} `bson:"roles"`
}

// Demonstrates a bug fix for the credential rotation not releasing locks
func TestBackend_StaticRole_LockRegression(t *testing.T) {
	cluster, sys := getCluster(t)
	defer cluster.Cleanup()

	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	config.System = sys

	lb, err := Factory(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	b, ok := lb.(*databaseBackend)
	if !ok {
		t.Fatal("could not convert to db backend")
	}
	defer b.Cleanup(context.Background())

	cleanup, connURL := postgreshelper.PrepareTestContainer(t, "")
	defer cleanup()

	// Configure a connection
	data := map[string]interface{}{
		"connection_url":    connURL,
		"plugin_name":       "postgresql-database-plugin",
		"verify_connection": false,
		"allowed_roles":     []string{"*"},
		"name":              "plugin-test",
	}

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/plugin-test",
		Storage:   config.StorageView,
		Data:      data,
	}
	resp, err := b.HandleRequest(namespace.RootContext(nil), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	createTestPGUser(t, connURL, dbUser, dbUserDefaultPassword, testRoleStaticCreate)
	data = map[string]interface{}{
		"name":                "plugin-role-test",
		"db_name":             "plugin-test",
		"rotation_statements": testRoleStaticUpdate,
		"username":            dbUser,
		"rotation_period":     "7s",
	}
	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "static-roles/plugin-role-test",
		Storage:   config.StorageView,
		Data:      data,
	}

	resp, err = b.HandleRequest(namespace.RootContext(nil), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}
	for i := 0; i < 25; i++ {
		req = &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "static-roles/plugin-role-test",
			Storage:   config.StorageView,
			Data:      data,
		}

		resp, err = b.HandleRequest(namespace.RootContext(nil), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%s resp:%#v\n", err, resp)
		}

		// sleeping is needed to trigger the deadlock, otherwise things are
		// processed too quickly to trigger the rotation lock on so few roles
		time.Sleep(500 * time.Millisecond)
	}
}

func TestBackend_StaticRole_Rotate_Invalid_Role(t *testing.T) {
	cluster, sys := getCluster(t)
	defer cluster.Cleanup()

	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	config.System = sys

	lb, err := Factory(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	b, ok := lb.(*databaseBackend)
	if !ok {
		t.Fatal("could not convert to db backend")
	}
	defer b.Cleanup(context.Background())

	cleanup, connURL := postgreshelper.PrepareTestContainer(t, "")
	defer cleanup()

	// create the database user
	createTestPGUser(t, connURL, dbUser, dbUserDefaultPassword, testRoleStaticCreate)

	verifyPgConn(t, dbUser, dbUserDefaultPassword, connURL)

	// Configure a connection
	data := map[string]interface{}{
		"connection_url":    connURL,
		"plugin_name":       "postgresql-database-plugin",
		"verify_connection": false,
		"allowed_roles":     []string{"*"},
		"name":              "plugin-test",
	}

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/plugin-test",
		Storage:   config.StorageView,
		Data:      data,
	}
	resp, err := b.HandleRequest(namespace.RootContext(nil), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	data = map[string]interface{}{
		"name":                "plugin-role-test",
		"db_name":             "plugin-test",
		"rotation_statements": testRoleStaticUpdate,
		"username":            dbUser,
		"rotation_period":     "5400s",
	}

	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "static-roles/plugin-role-test",
		Storage:   config.StorageView,
		Data:      data,
	}

	resp, err = b.HandleRequest(namespace.RootContext(nil), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	// Pop manually key to emulate a queue without existing key
	b.credRotationQueue.PopByKey("plugin-role-test")

	// Make sure queue is empty
	if b.credRotationQueue.Len() != 0 {
		t.Fatalf("expected queue length to be 0 but is %d", b.credRotationQueue.Len())
	}

	// Trigger rotation
	data = map[string]interface{}{"name": "plugin-role-test"}
	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "rotate-role/plugin-role-test",
		Storage:   config.StorageView,
		Data:      data,
	}
	resp, err = b.HandleRequest(namespace.RootContext(nil), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	// Check if key is in queue
	if b.credRotationQueue.Len() != 1 {
		t.Fatalf("expected queue length to be 1 but is %d", b.credRotationQueue.Len())
	}
}

func TestRollsPasswordForwardsUsingWAL(t *testing.T) {
	ctx := context.Background()
	b, storage, mockDB := getBackend(t)
	defer b.Cleanup(ctx)
	configureDBMount(t, storage)
	createRole(t, b, storage, mockDB, "hashicorp")

	role, err := b.StaticRole(ctx, storage, "hashicorp")
	if err != nil {
		t.Fatal(err)
	}
	oldPassword := role.StaticAccount.Password

	generateWALFromFailedRotation(t, b, storage, mockDB, "hashicorp")

	walIDs := requireWALs(t, storage, 1)
	wal, err := b.findStaticWAL(ctx, storage, walIDs[0])
	if err != nil {
		t.Fatal(err)
	}
	role, err = b.StaticRole(ctx, storage, "hashicorp")
	if err != nil {
		t.Fatal(err)
	}
	// Role's password should still be the WAL's old password
	if role.StaticAccount.Password != oldPassword {
		t.Fatal(role.StaticAccount.Password, oldPassword)
	}

	rotateRole(t, b, storage, mockDB, "hashicorp")

	role, err = b.StaticRole(ctx, storage, "hashicorp")
	if err != nil {
		t.Fatal(err)
	}
	if role.StaticAccount.Password != wal.NewPassword {
		t.Fatal("role password", role.StaticAccount.Password, "WAL new password", wal.NewPassword)
	}
	// WAL should be cleared by the successful rotate
	requireWALs(t, storage, 0)
}

func TestStoredWALsCorrectlyProcessed(t *testing.T) {
	const walNewPassword = "new-password-from-wal"
	for _, tc := range []struct {
		name         string
		shouldRotate bool
		wal          *setCredentialsWAL
	}{
		{
			"WAL is kept and used for roll forward",
			true,
			&setCredentialsWAL{
				RoleName:          "hashicorp",
				Username:          "hashicorp",
				NewPassword:       walNewPassword,
				LastVaultRotation: time.Now().Add(time.Hour),
			},
		},
		{
			"zero-time WAL is discarded on load",
			false,
			&setCredentialsWAL{
				RoleName:          "hashicorp",
				Username:          "hashicorp",
				NewPassword:       walNewPassword,
				LastVaultRotation: time.Time{},
			},
		},
		{
			"empty-password WAL is kept but a new password is generated",
			true,
			&setCredentialsWAL{
				RoleName:          "hashicorp",
				Username:          "hashicorp",
				NewPassword:       "",
				LastVaultRotation: time.Now().Add(time.Hour),
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			config := logical.TestBackendConfig()
			storage := &logical.InmemStorage{}
			config.StorageView = storage
			b := Backend(config)
			defer b.Cleanup(ctx)
			mockDB := setupMockDB(b)
			if err := b.Setup(ctx, config); err != nil {
				t.Fatal(err)
			}
			b.credRotationQueue = queue.New()
			configureDBMount(t, config.StorageView)
			createRole(t, b, config.StorageView, mockDB, "hashicorp")
			role, err := b.StaticRole(ctx, config.StorageView, "hashicorp")
			if err != nil {
				t.Fatal(err)
			}
			initialPassword := role.StaticAccount.Password

			// Set up a WAL for our test case
			framework.PutWAL(ctx, config.StorageView, staticWALKey, tc.wal)
			requireWALs(t, config.StorageView, 1)
			// Reset the rotation queue to simulate startup memory state
			b.credRotationQueue = queue.New()

			// Now finish the startup process by populating the queue, which should discard the WAL
			b.initQueue(ctx, config, consts.ReplicationUnknown)

			if tc.shouldRotate {
				requireWALs(t, storage, 1)
			} else {
				requireWALs(t, storage, 0)
			}

			// Run one tick
			mockDB.On("UpdateUser", mock.Anything, mock.Anything).
				Return(v5.UpdateUserResponse{}, nil).
				Once()
			b.rotateCredentials(ctx, storage)
			requireWALs(t, storage, 0)

			role, err = b.StaticRole(ctx, storage, "hashicorp")
			if err != nil {
				t.Fatal(err)
			}
			item, err := b.popFromRotationQueueByKey("hashicorp")
			if err != nil {
				t.Fatal(err)
			}

			if tc.shouldRotate {
				if tc.wal.NewPassword != "" {
					// Should use WAL's new_password field
					if role.StaticAccount.Password != walNewPassword {
						t.Fatal()
					}
				} else {
					// Should rotate but ignore WAL's new_password field
					if role.StaticAccount.Password == initialPassword {
						t.Fatal()
					}
					if role.StaticAccount.Password == walNewPassword {
						t.Fatal()
					}
				}
			} else {
				// Ensure the role was not promoted for early rotation
				if item.Priority < time.Now().Add(time.Hour).Unix() {
					t.Fatal("priority should be for about a week away, but was", item.Priority)
				}
				if role.StaticAccount.Password != initialPassword {
					t.Fatal("password should not have been rotated yet")
				}
			}
		})
	}
}

func TestDeletesOlderWALsOnLoad(t *testing.T) {
	ctx := context.Background()
	b, storage, mockDB := getBackend(t)
	defer b.Cleanup(ctx)
	configureDBMount(t, storage)
	createRole(t, b, storage, mockDB, "hashicorp")

	// Create 4 WALs, with a clear winner for most recent.
	wal := &setCredentialsWAL{
		RoleName:          "hashicorp",
		Username:          "hashicorp",
		NewPassword:       "some-new-password",
		LastVaultRotation: time.Now(),
	}
	for i := 0; i < 3; i++ {
		_, err := framework.PutWAL(ctx, storage, staticWALKey, wal)
		if err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(2 * time.Second)
	// We expect this WAL to have the latest createdAt timestamp
	walID, err := framework.PutWAL(ctx, storage, staticWALKey, wal)
	if err != nil {
		t.Fatal(err)
	}
	requireWALs(t, storage, 4)

	walMap, err := b.loadStaticWALs(ctx, storage)
	if err != nil {
		t.Fatal(err)
	}
	if len(walMap) != 1 || walMap["hashicorp"] == nil || walMap["hashicorp"].walID != walID {
		t.Fatal()
	}
	requireWALs(t, storage, 1)
}

func generateWALFromFailedRotation(t *testing.T, b *databaseBackend, storage logical.Storage, mockDB *mockNewDatabase, roleName string) {
	t.Helper()
	mockDB.On("UpdateUser", mock.Anything, mock.Anything).
		Return(v5.UpdateUserResponse{}, errors.New("forced error")).
		Once()
	_, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "rotate-role/" + roleName,
		Storage:   storage,
	})
	if err == nil {
		t.Fatal("expected error")
	}
}

func rotateRole(t *testing.T, b *databaseBackend, storage logical.Storage, mockDB *mockNewDatabase, roleName string) {
	t.Helper()
	mockDB.On("UpdateUser", mock.Anything, mock.Anything).
		Return(v5.UpdateUserResponse{}, nil).
		Once()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "rotate-role/" + roleName,
		Storage:   storage,
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatal(resp, err)
	}
}

// returns a slice of the WAL IDs in storage
func requireWALs(t *testing.T, storage logical.Storage, expectedCount int) []string {
	t.Helper()
	wals, err := storage.List(context.Background(), "wal/")
	if err != nil {
		t.Fatal(err)
	}
	if len(wals) != expectedCount {
		t.Fatal("expected WALs", expectedCount, "got", len(wals))
	}

	return wals
}

func getBackend(t *testing.T) (*databaseBackend, logical.Storage, *mockNewDatabase) {
	t.Helper()
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	// Create and init the backend ourselves instead of using a Factory because
	// the factory function kicks off threads that cause racy tests.
	b := Backend(config)
	if err := b.Setup(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	b.credRotationQueue = queue.New()
	b.populateQueue(context.Background(), config.StorageView)

	mockDB := setupMockDB(b)

	return b, config.StorageView, mockDB
}

func setupMockDB(b *databaseBackend) *mockNewDatabase {
	mockDB := &mockNewDatabase{}
	mockDB.On("Initialize", mock.Anything, mock.Anything).Return(v5.InitializeResponse{}, nil)
	mockDB.On("Close").Return(nil)
	mockDB.On("Type").Return("mock", nil)
	dbw := databaseVersionWrapper{
		v5: mockDB,
	}

	dbi := &dbPluginInstance{
		database: dbw,
		id:       "foo-id",
		name:     "mockV5",
	}
	b.connections["mockv5"] = dbi

	return mockDB
}

// configureDBMount puts config directly into storage to avoid the DB engine's
// plugin init code paths, allowing us to use a manually populated mock DB object.
func configureDBMount(t *testing.T, storage logical.Storage) {
	t.Helper()
	entry, err := logical.StorageEntryJSON(fmt.Sprintf("config/mockv5"), &DatabaseConfig{
		AllowedRoles: []string{"*"},
	})
	if err != nil {
		t.Fatal(err)
	}

	err = storage.Put(context.Background(), entry)
	if err != nil {
		t.Fatal(err)
	}
}

// capturePasswords captures the current passwords at the time of calling, and
// returns a map of username / passwords building off of the input map
func capturePasswords(t *testing.T, b logical.Backend, config *logical.BackendConfig, testCases []string, pws map[string][]string) map[string][]string {
	new := make(map[string][]string, 0)
	for _, tc := range testCases {
		// Read the role
		roleName := "plugin-static-role-" + tc
		req := &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "static-creds/" + roleName,
			Storage:   config.StorageView,
		}
		resp, err := b.HandleRequest(namespace.RootContext(nil), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%s resp:%#v\n", err, resp)
		}

		username := resp.Data["username"].(string)
		password := resp.Data["password"].(string)
		if username == "" || password == "" {
			t.Fatalf("expected both username/password for (%s), got (%s), (%s)", roleName, username, password)
		}
		new[roleName] = append(new[roleName], password)
	}

	for k, v := range new {
		pws[k] = append(pws[k], v...)
	}

	return pws
}

func newBoolPtr(b bool) *bool {
	v := b
	return &v
}
