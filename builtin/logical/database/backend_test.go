// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package database

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/go-test/deep"
	"github.com/hashicorp/go-hclog"
	_ "github.com/jackc/pgx/v4"
	"github.com/mitchellh/mapstructure"
	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/helper/builtinplugins"
	"github.com/openbao/openbao/helper/namespace"
	postgreshelper "github.com/openbao/openbao/helper/testhelpers/postgresql"
	vaulthttp "github.com/openbao/openbao/http"
	"github.com/openbao/openbao/plugins/database/postgresql"
	v4 "github.com/openbao/openbao/sdk/v2/database/dbplugin"
	v5 "github.com/openbao/openbao/sdk/v2/database/dbplugin/v5"
	"github.com/openbao/openbao/sdk/v2/database/helper/dbutil"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/openbao/openbao/sdk/v2/helper/pluginutil"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/vault"
)

func getCluster(t *testing.T) (*vault.TestCluster, logical.SystemView) {
	coreConfig := &vault.CoreConfig{
		LogicalBackends: map[string]logical.Factory{
			"database": Factory,
		},
		BuiltinRegistry: builtinplugins.Registry,
	}

	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
	})
	cluster.Start()
	cores := cluster.Cores
	vault.TestWaitActive(t, cores[0].Core)

	os.Setenv(pluginutil.PluginCACertPEMEnv, cluster.CACertPEMFile)

	sys := vault.TestDynamicSystemView(cores[0].Core, nil)
	vault.TestAddTestPlugin(t, cores[0].Core, "postgresql-database-plugin", consts.PluginTypeDatabase, "", "TestBackend_PluginMain_Postgres", []string{}, "")
	vault.TestAddTestPlugin(t, cores[0].Core, "postgresql-database-plugin-muxed", consts.PluginTypeDatabase, "", "TestBackend_PluginMain_PostgresMultiplexed", []string{}, "")

	return cluster, sys
}

func TestBackend_PluginMain_Postgres(t *testing.T) {
	if api.ReadBaoVariable(pluginutil.PluginVaultVersionEnv) == "" {
		return
	}

	dbType, err := postgresql.New()
	if err != nil {
		t.Fatalf("Failed to initialize postgres: %s", err)
	}

	v5.Serve(dbType.(v5.Database))
}

func TestBackend_PluginMain_PostgresMultiplexed(t *testing.T) {
	if api.ReadBaoVariable(pluginutil.PluginVaultVersionEnv) == "" {
		return
	}

	v5.ServeMultiplex(postgresql.New)
}

func TestBackend_RoleUpgrade(t *testing.T) {
	storage := &logical.InmemStorage{}
	backend := &databaseBackend{}

	roleExpected := &roleEntry{
		Statements: v4.Statements{
			CreationStatements: "test",
			Creation:           []string{"test"},
		},
	}

	entry, err := logical.StorageEntryJSON("role/test", &roleEntry{
		Statements: v4.Statements{
			CreationStatements: "test",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.Put(context.Background(), entry); err != nil {
		t.Fatal(err)
	}

	role, err := backend.Role(context.Background(), storage, "test")
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(role, roleExpected) {
		t.Fatalf("bad role %#v, %#v", role, roleExpected)
	}

	// Upgrade case
	badJSON := `{"statments":{"creation_statments":"test","revocation_statements":"","rollback_statements":"","renew_statements":""}}`
	entry = &logical.StorageEntry{
		Key:   "role/test",
		Value: []byte(badJSON),
	}
	if err := storage.Put(context.Background(), entry); err != nil {
		t.Fatal(err)
	}

	role, err = backend.Role(context.Background(), storage, "test")
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(role, roleExpected) {
		t.Fatalf("bad role %#v, %#v", role, roleExpected)
	}
}

func TestBackend_config_connection(t *testing.T) {
	var resp *logical.Response
	var err error

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
		t.Fatal("could not convert to database backend")
	}
	defer b.Cleanup(context.Background())

	// Test creation
	{
		configData := map[string]interface{}{
			"connection_url":    "sample_connection_url",
			"someotherdata":     "testing",
			"plugin_name":       "postgresql-database-plugin",
			"verify_connection": false,
			"allowed_roles":     []string{"*"},
			"name":              "plugin-test",
		}

		configReq := &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "config/plugin-test",
			Storage:   config.StorageView,
			Data:      configData,
		}

		exists, err := b.connectionExistenceCheck()(context.Background(), configReq, &framework.FieldData{
			Raw:    configData,
			Schema: pathConfigurePluginConnection(b).Fields,
		})
		if err != nil {
			t.Fatal(err)
		}
		if exists {
			t.Fatal("expected not exists")
		}

		resp, err = b.HandleRequest(namespace.RootContext(nil), configReq)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%v resp:%#v\n", err, resp)
		}

		expected := map[string]interface{}{
			"plugin_name": "postgresql-database-plugin",
			"connection_details": map[string]interface{}{
				"connection_url": "sample_connection_url",
				"someotherdata":  "testing",
			},
			"allowed_roles":                      []string{"*"},
			"root_credentials_rotate_statements": []string{},
			"password_policy":                    "",
			"plugin_version":                     "",
		}
		configReq.Operation = logical.ReadOperation
		resp, err = b.HandleRequest(namespace.RootContext(nil), configReq)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%s resp:%#v\n", err, resp)
		}

		delete(resp.Data["connection_details"].(map[string]interface{}), "name")
		if !reflect.DeepEqual(expected, resp.Data) {
			t.Fatalf("bad: expected:%#v\nactual:%#v\n", expected, resp.Data)
		}
	}

	// Test existence check and an update to a single connection detail parameter
	{
		configData := map[string]interface{}{
			"connection_url":    "sample_convection_url",
			"verify_connection": false,
			"name":              "plugin-test",
		}

		configReq := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "config/plugin-test",
			Storage:   config.StorageView,
			Data:      configData,
		}

		exists, err := b.connectionExistenceCheck()(context.Background(), configReq, &framework.FieldData{
			Raw:    configData,
			Schema: pathConfigurePluginConnection(b).Fields,
		})
		if err != nil {
			t.Fatal(err)
		}
		if !exists {
			t.Fatal("expected exists")
		}

		resp, err = b.HandleRequest(namespace.RootContext(nil), configReq)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%v resp:%#v\n", err, resp)
		}

		expected := map[string]interface{}{
			"plugin_name": "postgresql-database-plugin",
			"connection_details": map[string]interface{}{
				"connection_url": "sample_convection_url",
				"someotherdata":  "testing",
			},
			"allowed_roles":                      []string{"*"},
			"root_credentials_rotate_statements": []string{},
			"password_policy":                    "",
			"plugin_version":                     "",
		}
		configReq.Operation = logical.ReadOperation
		resp, err = b.HandleRequest(namespace.RootContext(nil), configReq)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%s resp:%#v\n", err, resp)
		}

		delete(resp.Data["connection_details"].(map[string]interface{}), "name")
		if !reflect.DeepEqual(expected, resp.Data) {
			t.Fatalf("bad: expected:%#v\nactual:%#v\n", expected, resp.Data)
		}
	}

	// Test an update to a non-details value
	{
		configData := map[string]interface{}{
			"verify_connection": false,
			"allowed_roles":     []string{"flu", "barre"},
			"name":              "plugin-test",
		}

		configReq := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "config/plugin-test",
			Storage:   config.StorageView,
			Data:      configData,
		}

		resp, err = b.HandleRequest(namespace.RootContext(nil), configReq)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%v resp:%#v\n", err, resp)
		}

		expected := map[string]interface{}{
			"plugin_name": "postgresql-database-plugin",
			"connection_details": map[string]interface{}{
				"connection_url": "sample_convection_url",
				"someotherdata":  "testing",
			},
			"allowed_roles":                      []string{"flu", "barre"},
			"root_credentials_rotate_statements": []string{},
			"password_policy":                    "",
			"plugin_version":                     "",
		}
		configReq.Operation = logical.ReadOperation
		resp, err = b.HandleRequest(namespace.RootContext(nil), configReq)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%s resp:%#v\n", err, resp)
		}

		delete(resp.Data["connection_details"].(map[string]interface{}), "name")
		if !reflect.DeepEqual(expected, resp.Data) {
			t.Fatalf("bad: expected:%#v\nactual:%#v\n", expected, resp.Data)
		}
	}

	req := &logical.Request{
		Operation: logical.ListOperation,
		Storage:   config.StorageView,
		Path:      "config/",
	}
	resp, err = b.HandleRequest(namespace.RootContext(nil), req)
	if err != nil {
		t.Fatal(err)
	}
	keys := resp.Data["keys"].([]string)
	key := keys[0]
	if key != "plugin-test" {
		t.Fatalf("bad key: %q", key)
	}
}

func TestBackend_BadConnectionString(t *testing.T) {
	cluster, sys := getCluster(t)
	defer cluster.Cleanup()

	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	config.System = sys

	b, err := Factory(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Cleanup(context.Background())

	cleanup, _ := postgreshelper.PrepareTestContainer(t, "13.4-buster")
	defer cleanup()

	respCheck := func(req *logical.Request) {
		t.Helper()
		resp, err := b.HandleRequest(namespace.RootContext(nil), req)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if resp == nil || !resp.IsError() {
			t.Fatalf("expected error, resp:%#v", resp)
		}
		err = resp.Error()
		if strings.Contains(err.Error(), "localhost") {
			t.Fatal("error should not contain connection info")
		}
	}

	// Configure a connection
	data := map[string]interface{}{
		"connection_url": "postgresql://:pw@[localhost",
		"plugin_name":    "postgresql-database-plugin",
		"allowed_roles":  []string{"plugin-role-test"},
	}
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/plugin-test",
		Storage:   config.StorageView,
		Data:      data,
	}
	respCheck(req)

	time.Sleep(1 * time.Second)
}

func TestBackend_basic(t *testing.T) {
	cluster, sys := getCluster(t)
	defer cluster.Cleanup()

	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	config.System = sys

	b, err := Factory(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Cleanup(context.Background())

	cleanup, connURL := postgreshelper.PrepareTestContainer(t, "13.4-buster")
	defer cleanup()

	// Configure a connection
	data := map[string]interface{}{
		"connection_url": connURL,
		"plugin_name":    "postgresql-database-plugin",
		"allowed_roles":  []string{"plugin-role-test"},
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

	// Create a role
	data = map[string]interface{}{
		"db_name":             "plugin-test",
		"creation_statements": testRole,
		"max_ttl":             "10m",
	}
	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/plugin-role-test",
		Storage:   config.StorageView,
		Data:      data,
	}
	resp, err = b.HandleRequest(namespace.RootContext(nil), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}
	// Get creds
	data = map[string]interface{}{}
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/plugin-role-test",
		Storage:   config.StorageView,
		Data:      data,
	}
	credsResp, err := b.HandleRequest(namespace.RootContext(nil), req)
	if err != nil || (credsResp != nil && credsResp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, credsResp)
	}
	// Update the role with no max ttl
	data = map[string]interface{}{
		"db_name":             "plugin-test",
		"creation_statements": testRole,
		"default_ttl":         "5m",
		"max_ttl":             0,
	}
	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/plugin-role-test",
		Storage:   config.StorageView,
		Data:      data,
	}
	resp, err = b.HandleRequest(namespace.RootContext(nil), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}
	// Get creds
	data = map[string]interface{}{}
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/plugin-role-test",
		Storage:   config.StorageView,
		Data:      data,
	}
	credsResp, err = b.HandleRequest(namespace.RootContext(nil), req)
	if err != nil || (credsResp != nil && credsResp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, credsResp)
	}
	// Test for #3812
	if credsResp.Secret.TTL != 5*time.Minute {
		t.Fatalf("unexpected TTL of %d", credsResp.Secret.TTL)
	}
	// Update the role with a max ttl
	data = map[string]interface{}{
		"db_name":             "plugin-test",
		"creation_statements": testRole,
		"default_ttl":         "5m",
		"max_ttl":             "10m",
	}
	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/plugin-role-test",
		Storage:   config.StorageView,
		Data:      data,
	}
	resp, err = b.HandleRequest(namespace.RootContext(nil), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	// Get creds and revoke when the role stays in existence
	{
		data = map[string]interface{}{}
		req = &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "creds/plugin-role-test",
			Storage:   config.StorageView,
			Data:      data,
		}
		credsResp, err = b.HandleRequest(namespace.RootContext(nil), req)
		if err != nil || (credsResp != nil && credsResp.IsError()) {
			t.Fatalf("err:%s resp:%#v\n", err, credsResp)
		}
		// Test for #3812
		if credsResp.Secret.TTL != 5*time.Minute {
			t.Fatalf("unexpected TTL of %d", credsResp.Secret.TTL)
		}
		if !testCredsExist(t, credsResp, connURL) {
			t.Fatal("Creds should exist")
		}

		// Revoke creds
		resp, err = b.HandleRequest(namespace.RootContext(nil), &logical.Request{
			Operation: logical.RevokeOperation,
			Storage:   config.StorageView,
			Secret: &logical.Secret{
				InternalData: map[string]interface{}{
					"secret_type": "creds",
					"username":    credsResp.Data["username"],
					"role":        "plugin-role-test",
				},
			},
		})
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%s resp:%#v\n", err, resp)
		}

		if testCredsExist(t, credsResp, connURL) {
			t.Fatal("Creds should not exist")
		}
	}

	// Get creds and revoke using embedded revocation data
	{
		data = map[string]interface{}{}
		req = &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "creds/plugin-role-test",
			Storage:   config.StorageView,
			Data:      data,
		}
		credsResp, err = b.HandleRequest(namespace.RootContext(nil), req)
		if err != nil || (credsResp != nil && credsResp.IsError()) {
			t.Fatalf("err:%s resp:%#v\n", err, credsResp)
		}
		if !testCredsExist(t, credsResp, connURL) {
			t.Fatal("Creds should exist")
		}

		// Delete role, forcing us to rely on embedded data
		req = &logical.Request{
			Operation: logical.DeleteOperation,
			Path:      "roles/plugin-role-test",
			Storage:   config.StorageView,
		}
		resp, err = b.HandleRequest(namespace.RootContext(nil), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%s resp:%#v\n", err, resp)
		}

		// Revoke creds
		resp, err = b.HandleRequest(namespace.RootContext(nil), &logical.Request{
			Operation: logical.RevokeOperation,
			Storage:   config.StorageView,
			Secret: &logical.Secret{
				InternalData: map[string]interface{}{
					"secret_type":           "creds",
					"username":              credsResp.Data["username"],
					"role":                  "plugin-role-test",
					"db_name":               "plugin-test",
					"revocation_statements": nil,
				},
			},
		})
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%s resp:%#v\n", err, resp)
		}

		if testCredsExist(t, credsResp, connURL) {
			t.Fatal("Creds should not exist")
		}
	}
}

func TestBackend_connectionCrud(t *testing.T) {
	cluster, sys := getCluster(t)
	defer cluster.Cleanup()

	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	config.System = sys

	b, err := Factory(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Cleanup(context.Background())

	cleanup, connURL := postgreshelper.PrepareTestContainer(t, "13.4-buster")
	defer cleanup()

	// Configure a connection
	data := map[string]interface{}{
		"connection_url":    "test",
		"plugin_name":       "postgresql-database-plugin",
		"verify_connection": false,
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

	// Create a role
	data = map[string]interface{}{
		"db_name":               "plugin-test",
		"creation_statements":   testRole,
		"revocation_statements": defaultRevocationSQL,
		"default_ttl":           "5m",
		"max_ttl":               "10m",
	}
	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/plugin-role-test",
		Storage:   config.StorageView,
		Data:      data,
	}
	resp, err = b.HandleRequest(namespace.RootContext(nil), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	// Update the connection
	data = map[string]interface{}{
		"connection_url": connURL,
		"plugin_name":    "postgresql-database-plugin",
		"allowed_roles":  []string{"plugin-role-test"},
		"username":       "postgres",
		"password":       "secret",
		"private_key":    "PRIVATE_KEY",
	}
	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/plugin-test",
		Storage:   config.StorageView,
		Data:      data,
	}
	resp, err = b.HandleRequest(namespace.RootContext(nil), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}
	if len(resp.Warnings) == 0 {
		t.Fatalf("expected warning about password in url %s, resp:%#v\n", connURL, resp)
	}

	req.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(namespace.RootContext(nil), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}
	returnedConnectionDetails := resp.Data["connection_details"].(map[string]interface{})
	if strings.Contains(returnedConnectionDetails["connection_url"].(string), "secret") {
		t.Fatal("password should not be found in the connection url")
	}
	// Covered by the filled out `expected` value below, but be explicit about this requirement.
	if _, exists := returnedConnectionDetails["password"]; exists {
		t.Fatal("password should NOT be found in the returned config")
	}
	if _, exists := returnedConnectionDetails["private_key"]; exists {
		t.Fatal("private_key should NOT be found in the returned config")
	}

	// Replace connection url with templated version
	req.Operation = logical.UpdateOperation
	connURL = strings.ReplaceAll(connURL, "postgres:secret", "{{username}}:{{password}}")
	data["connection_url"] = connURL
	resp, err = b.HandleRequest(namespace.RootContext(nil), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	// Read connection
	expected := map[string]interface{}{
		"plugin_name": "postgresql-database-plugin",
		"connection_details": map[string]interface{}{
			"username":       "postgres",
			"connection_url": connURL,
		},
		"allowed_roles":                      []string{"plugin-role-test"},
		"root_credentials_rotate_statements": []string(nil),
		"password_policy":                    "",
		"plugin_version":                     "",
	}
	req.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(namespace.RootContext(nil), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	delete(resp.Data["connection_details"].(map[string]interface{}), "name")
	if diff := deep.Equal(resp.Data, expected); diff != nil {
		t.Fatal(diff)
	}

	// Reset Connection
	data = map[string]interface{}{}
	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "reset/plugin-test",
		Storage:   config.StorageView,
		Data:      data,
	}
	resp, err = b.HandleRequest(namespace.RootContext(nil), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	// Get creds
	data = map[string]interface{}{}
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/plugin-role-test",
		Storage:   config.StorageView,
		Data:      data,
	}
	credsResp, err := b.HandleRequest(namespace.RootContext(nil), req)
	if err != nil || (credsResp != nil && credsResp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, credsResp)
	}

	credCheckURL := dbutil.QueryHelper(connURL, map[string]string{
		"username": "postgres",
		"password": "secret",
	})
	if !testCredsExist(t, credsResp, credCheckURL) {
		t.Fatal("Creds should exist")
	}

	// Delete Connection
	data = map[string]interface{}{}
	req = &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "config/plugin-test",
		Storage:   config.StorageView,
		Data:      data,
	}
	resp, err = b.HandleRequest(namespace.RootContext(nil), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	// Read connection
	req.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(namespace.RootContext(nil), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	// Should be empty
	if resp != nil {
		t.Fatal("Expected response to be nil")
	}
}

func TestBackend_roleCrud(t *testing.T) {
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

	cleanup, connURL := postgreshelper.PrepareTestContainer(t, "13.4-buster")
	defer cleanup()

	// Configure a connection
	data := map[string]interface{}{
		"connection_url": connURL,
		"plugin_name":    "postgresql-database-plugin",
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

	// Test role creation
	{
		data = map[string]interface{}{
			"db_name":               "plugin-test",
			"creation_statements":   testRole,
			"revocation_statements": defaultRevocationSQL,
			"default_ttl":           "5m",
			"max_ttl":               "10m",
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

		// Read the role
		data = map[string]interface{}{}
		req = &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "roles/plugin-role-test",
			Storage:   config.StorageView,
			Data:      data,
		}
		resp, err = b.HandleRequest(namespace.RootContext(nil), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%s resp:%#v\n", err, resp)
		}

		expected := v4.Statements{
			Creation:   []string{strings.TrimSpace(testRole)},
			Revocation: []string{strings.TrimSpace(defaultRevocationSQL)},
			Rollback:   []string{},
			Renewal:    []string{},
		}

		actual := v4.Statements{
			Creation:   resp.Data["creation_statements"].([]string),
			Revocation: resp.Data["revocation_statements"].([]string),
			Rollback:   resp.Data["rollback_statements"].([]string),
			Renewal:    resp.Data["renew_statements"].([]string),
		}

		if diff := deep.Equal(expected, actual); diff != nil {
			t.Fatal(diff)
		}

		if diff := deep.Equal(resp.Data["db_name"], "plugin-test"); diff != nil {
			t.Fatal(diff)
		}
		if diff := deep.Equal(resp.Data["default_ttl"], float64(300)); diff != nil {
			t.Fatal(diff)
		}
		if diff := deep.Equal(resp.Data["max_ttl"], float64(600)); diff != nil {
			t.Fatal(diff)
		}
	}

	// Test role modification of TTL
	{
		data = map[string]interface{}{
			"name":    "plugin-role-test",
			"max_ttl": "7m",
		}
		req = &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "roles/plugin-role-test",
			Storage:   config.StorageView,
			Data:      data,
		}
		resp, err = b.HandleRequest(namespace.RootContext(nil), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%v resp:%#v\n", err, resp)
		}

		// Read the role
		data = map[string]interface{}{}
		req = &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "roles/plugin-role-test",
			Storage:   config.StorageView,
			Data:      data,
		}
		resp, err = b.HandleRequest(namespace.RootContext(nil), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%s resp:%#v\n", err, resp)
		}

		expected := v4.Statements{
			Creation:   []string{strings.TrimSpace(testRole)},
			Revocation: []string{strings.TrimSpace(defaultRevocationSQL)},
			Rollback:   []string{},
			Renewal:    []string{},
		}

		actual := v4.Statements{
			Creation:   resp.Data["creation_statements"].([]string),
			Revocation: resp.Data["revocation_statements"].([]string),
			Rollback:   resp.Data["rollback_statements"].([]string),
			Renewal:    resp.Data["renew_statements"].([]string),
		}

		if !reflect.DeepEqual(expected, actual) {
			t.Fatalf("Statements did not match, expected %#v, got %#v", expected, actual)
		}

		if diff := deep.Equal(resp.Data["db_name"], "plugin-test"); diff != nil {
			t.Fatal(diff)
		}
		if diff := deep.Equal(resp.Data["default_ttl"], float64(300)); diff != nil {
			t.Fatal(diff)
		}
		if diff := deep.Equal(resp.Data["max_ttl"], float64(420)); diff != nil {
			t.Fatal(diff)
		}

	}

	// Test role modification of statements
	{
		data = map[string]interface{}{
			"name":                  "plugin-role-test",
			"creation_statements":   []string{testRole, testRole},
			"revocation_statements": []string{defaultRevocationSQL, defaultRevocationSQL},
			"rollback_statements":   testRole,
			"renew_statements":      defaultRevocationSQL,
		}
		req = &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "roles/plugin-role-test",
			Storage:   config.StorageView,
			Data:      data,
		}
		resp, err = b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%v resp:%#v\n", err, resp)
		}

		// Read the role
		data = map[string]interface{}{}
		req = &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "roles/plugin-role-test",
			Storage:   config.StorageView,
			Data:      data,
		}
		resp, err = b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%s resp:%#v\n", err, resp)
		}

		expected := v4.Statements{
			Creation:   []string{strings.TrimSpace(testRole), strings.TrimSpace(testRole)},
			Rollback:   []string{strings.TrimSpace(testRole)},
			Revocation: []string{strings.TrimSpace(defaultRevocationSQL), strings.TrimSpace(defaultRevocationSQL)},
			Renewal:    []string{strings.TrimSpace(defaultRevocationSQL)},
		}

		actual := v4.Statements{
			Creation:   resp.Data["creation_statements"].([]string),
			Revocation: resp.Data["revocation_statements"].([]string),
			Rollback:   resp.Data["rollback_statements"].([]string),
			Renewal:    resp.Data["renew_statements"].([]string),
		}

		if diff := deep.Equal(expected, actual); diff != nil {
			t.Fatal(diff)
		}

		if diff := deep.Equal(resp.Data["db_name"], "plugin-test"); diff != nil {
			t.Fatal(diff)
		}
		if diff := deep.Equal(resp.Data["default_ttl"], float64(300)); diff != nil {
			t.Fatal(diff)
		}
		if diff := deep.Equal(resp.Data["max_ttl"], float64(420)); diff != nil {
			t.Fatal(diff)
		}
	}

	// Delete the role
	data = map[string]interface{}{}
	req = &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "roles/plugin-role-test",
		Storage:   config.StorageView,
		Data:      data,
	}
	resp, err = b.HandleRequest(namespace.RootContext(nil), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	// Read the role
	data = map[string]interface{}{}
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "roles/plugin-role-test",
		Storage:   config.StorageView,
		Data:      data,
	}
	resp, err = b.HandleRequest(namespace.RootContext(nil), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	// Should be empty
	if resp != nil {
		t.Fatal("Expected response to be nil")
	}
}

func TestBackend_allowedRoles(t *testing.T) {
	cluster, sys := getCluster(t)
	defer cluster.Cleanup()

	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	config.System = sys

	b, err := Factory(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Cleanup(context.Background())

	cleanup, connURL := postgreshelper.PrepareTestContainer(t, "13.4-buster")
	defer cleanup()

	// Configure a connection
	data := map[string]interface{}{
		"connection_url": connURL,
		"plugin_name":    "postgresql-database-plugin",
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

	// Create a denied and an allowed role
	data = map[string]interface{}{
		"db_name":             "plugin-test",
		"creation_statements": testRole,
		"default_ttl":         "5m",
		"max_ttl":             "10m",
	}
	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/denied",
		Storage:   config.StorageView,
		Data:      data,
	}
	resp, err = b.HandleRequest(namespace.RootContext(nil), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	data = map[string]interface{}{
		"db_name":             "plugin-test",
		"creation_statements": testRole,
		"default_ttl":         "5m",
		"max_ttl":             "10m",
	}
	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/allowed",
		Storage:   config.StorageView,
		Data:      data,
	}
	resp, err = b.HandleRequest(namespace.RootContext(nil), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	// Get creds from denied role, should fail
	data = map[string]interface{}{}
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/denied",
		Storage:   config.StorageView,
		Data:      data,
	}
	credsResp, err := b.HandleRequest(namespace.RootContext(nil), req)
	if err == nil {
		t.Fatal("expected error because role is denied")
	}

	// update connection with glob allowed roles connection
	data = map[string]interface{}{
		"connection_url": connURL,
		"plugin_name":    "postgresql-database-plugin",
		"allowed_roles":  "allow*",
	}
	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/plugin-test",
		Storage:   config.StorageView,
		Data:      data,
	}
	resp, err = b.HandleRequest(namespace.RootContext(nil), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	// Get creds, should work.
	data = map[string]interface{}{}
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/allowed",
		Storage:   config.StorageView,
		Data:      data,
	}
	credsResp, err = b.HandleRequest(namespace.RootContext(nil), req)
	if err != nil || (credsResp != nil && credsResp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, credsResp)
	}

	if !testCredsExist(t, credsResp, connURL) {
		t.Fatal("Creds should exist")
	}

	// update connection with * allowed roles connection
	data = map[string]interface{}{
		"connection_url": connURL,
		"plugin_name":    "postgresql-database-plugin",
		"allowed_roles":  "*",
	}
	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/plugin-test",
		Storage:   config.StorageView,
		Data:      data,
	}
	resp, err = b.HandleRequest(namespace.RootContext(nil), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	// Get creds, should work.
	data = map[string]interface{}{}
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/allowed",
		Storage:   config.StorageView,
		Data:      data,
	}
	credsResp, err = b.HandleRequest(namespace.RootContext(nil), req)
	if err != nil || (credsResp != nil && credsResp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, credsResp)
	}

	if !testCredsExist(t, credsResp, connURL) {
		t.Fatal("Creds should exist")
	}

	// update connection with allowed roles
	data = map[string]interface{}{
		"connection_url": connURL,
		"plugin_name":    "postgresql-database-plugin",
		"allowed_roles":  "allow, allowed",
	}
	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/plugin-test",
		Storage:   config.StorageView,
		Data:      data,
	}
	resp, err = b.HandleRequest(namespace.RootContext(nil), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	// Get creds from denied role, should fail
	data = map[string]interface{}{}
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/denied",
		Storage:   config.StorageView,
		Data:      data,
	}
	credsResp, err = b.HandleRequest(namespace.RootContext(nil), req)
	if err == nil {
		t.Fatal("expected error because role is denied")
	}

	// Get creds from allowed role, should work.
	data = map[string]interface{}{}
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/allowed",
		Storage:   config.StorageView,
		Data:      data,
	}
	credsResp, err = b.HandleRequest(namespace.RootContext(nil), req)
	if err != nil || (credsResp != nil && credsResp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, credsResp)
	}

	if !testCredsExist(t, credsResp, connURL) {
		t.Fatal("Creds should exist")
	}
}

func TestBackend_RotateRootCredentials(t *testing.T) {
	cluster, sys := getCluster(t)
	defer cluster.Cleanup()

	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	config.System = sys

	b, err := Factory(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Cleanup(context.Background())

	cleanup, connURL := postgreshelper.PrepareTestContainer(t, "13.4-buster")
	defer cleanup()

	connURL = strings.ReplaceAll(connURL, "postgres:secret", "{{username}}:{{password}}")

	// Configure a connection
	data := map[string]interface{}{
		"connection_url": connURL,
		"plugin_name":    "postgresql-database-plugin",
		"allowed_roles":  []string{"plugin-role-test"},
		"username":       "postgres",
		"password":       "secret",
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

	// Create a role
	data = map[string]interface{}{
		"db_name":             "plugin-test",
		"creation_statements": testRole,
		"max_ttl":             "10m",
	}
	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/plugin-role-test",
		Storage:   config.StorageView,
		Data:      data,
	}
	resp, err = b.HandleRequest(namespace.RootContext(nil), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}
	// Get creds
	data = map[string]interface{}{}
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/plugin-role-test",
		Storage:   config.StorageView,
		Data:      data,
	}
	credsResp, err := b.HandleRequest(namespace.RootContext(nil), req)
	if err != nil || (credsResp != nil && credsResp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, credsResp)
	}

	data = map[string]interface{}{}
	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "rotate-root/plugin-test",
		Storage:   config.StorageView,
		Data:      data,
	}
	resp, err = b.HandleRequest(namespace.RootContext(nil), req)
	if err != nil || (credsResp != nil && credsResp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, credsResp)
	}

	dbConfig, err := b.(*databaseBackend).DatabaseConfig(context.Background(), config.StorageView, "plugin-test")
	if err != nil {
		t.Fatalf("err: %#v", err)
	}
	if dbConfig.ConnectionDetails["password"].(string) == "secret" {
		t.Fatal("root credentials not rotated")
	}

	// Get creds to make sure it still works
	data = map[string]interface{}{}
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/plugin-role-test",
		Storage:   config.StorageView,
		Data:      data,
	}
	credsResp, err = b.HandleRequest(namespace.RootContext(nil), req)
	if err != nil || (credsResp != nil && credsResp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, credsResp)
	}
}

func TestBackend_ConnectionURL_redacted(t *testing.T) {
	cluster, sys := getCluster(t)
	t.Cleanup(cluster.Cleanup)

	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	config.System = sys

	b, err := Factory(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Cleanup(context.Background())

	tests := []struct {
		name     string
		password string
	}{
		{
			name:     "basic",
			password: "secret",
		},
		{
			name:     "encoded",
			password: "yourStrong(!)Password",
		},
	}

	respCheck := func(req *logical.Request) *logical.Response {
		t.Helper()
		resp, err := b.HandleRequest(namespace.RootContext(nil), req)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if resp == nil {
			t.Fatalf("expected a response, resp: %#v", resp)
		}

		if resp.Error() != nil {
			t.Fatalf("unexpected error in response, err: %#v", resp.Error())
		}

		return resp
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cleanup, u := postgreshelper.PrepareTestContainerWithPassword(t, "13.4-buster", tt.password)
			t.Cleanup(cleanup)

			p, err := url.Parse(u)
			if err != nil {
				t.Fatal(err)
			}

			actualPassword, _ := p.User.Password()
			if tt.password != actualPassword {
				t.Fatalf("expected computed URL password %#v, actual %#v", tt.password, actualPassword)
			}

			// Configure a connection
			data := map[string]interface{}{
				"connection_url": u,
				"plugin_name":    "postgresql-database-plugin",
				"allowed_roles":  []string{"plugin-role-test"},
			}
			req := &logical.Request{
				Operation: logical.UpdateOperation,
				Path:      fmt.Sprintf("config/%s", tt.name),
				Storage:   config.StorageView,
				Data:      data,
			}
			respCheck(req)

			// read config
			readReq := &logical.Request{
				Operation: logical.ReadOperation,
				Path:      req.Path,
				Storage:   config.StorageView,
			}
			resp := respCheck(readReq)

			var connDetails map[string]interface{}
			if v, ok := resp.Data["connection_details"]; ok {
				connDetails = v.(map[string]interface{})
			}

			if connDetails == nil {
				t.Fatalf("response data missing connection_details, resp: %#v", resp)
			}

			actual := connDetails["connection_url"].(string)
			expected := p.Redacted()
			if expected != actual {
				t.Fatalf("expected redacted URL %q, actual %q", expected, actual)
			}

			if tt.password != "" {
				// extra test to ensure that URL.Redacted() is working as expected.
				p, err = url.Parse(actual)
				if err != nil {
					t.Fatal(err)
				}
				if pp, _ := p.User.Password(); pp == tt.password {
					t.Fatal("password was not redacted by URL.Redacted()")
				}
			}
		})
	}
}

type hangingPlugin struct{}

func (h hangingPlugin) Initialize(_ context.Context, req v5.InitializeRequest) (v5.InitializeResponse, error) {
	return v5.InitializeResponse{
		Config: req.Config,
	}, nil
}

func (h hangingPlugin) NewUser(_ context.Context, _ v5.NewUserRequest) (v5.NewUserResponse, error) {
	return v5.NewUserResponse{}, nil
}

func (h hangingPlugin) UpdateUser(_ context.Context, _ v5.UpdateUserRequest) (v5.UpdateUserResponse, error) {
	return v5.UpdateUserResponse{}, nil
}

func (h hangingPlugin) DeleteUser(_ context.Context, _ v5.DeleteUserRequest) (v5.DeleteUserResponse, error) {
	return v5.DeleteUserResponse{}, nil
}

func (h hangingPlugin) Type() (string, error) {
	return "hanging", nil
}

func (h hangingPlugin) Close() error {
	time.Sleep(1000 * time.Second)
	return nil
}

var _ v5.Database = (*hangingPlugin)(nil)

func TestBackend_PluginMain_Hanging(t *testing.T) {
	if api.ReadBaoVariable(pluginutil.PluginVaultVersionEnv) == "" {
		return
	}
	v5.Serve(&hangingPlugin{})
}

func TestBackend_AsyncClose(t *testing.T) {
	// Test that having a plugin that takes a LONG time to close will not cause the cleanup function to take
	// longer than 750ms.
	cluster, sys := getCluster(t)
	vault.TestAddTestPlugin(t, cluster.Cores[0].Core, "hanging-plugin", consts.PluginTypeDatabase, "", "TestBackend_PluginMain_Hanging", []string{}, "")
	t.Cleanup(cluster.Cleanup)

	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	config.System = sys

	b, err := Factory(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}

	// Configure a connection
	data := map[string]interface{}{
		"connection_url": "doesn't matter",
		"plugin_name":    "hanging-plugin",
		"allowed_roles":  []string{"plugin-role-test"},
	}
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/hang",
		Storage:   config.StorageView,
		Data:      data,
	}
	_, err = b.HandleRequest(namespace.RootContext(nil), req)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	timeout := time.NewTimer(750 * time.Millisecond)
	done := make(chan bool)
	go func() {
		b.Cleanup(context.Background())
		// check that clean can be called twice safely
		b.Cleanup(context.Background())
		done <- true
	}()
	select {
	case <-timeout.C:
		t.Error("Hanging plugin caused Close() to take longer than 750ms")
	case <-done:
	}
}

func TestNewDatabaseWrapper_IgnoresBuiltinVersion(t *testing.T) {
	cluster, sys := getCluster(t)
	t.Cleanup(cluster.Cleanup)
	_, err := newDatabaseWrapper(context.Background(), "mysql-database-plugin", "v1.0.0+builtin", sys, hclog.Default())
	if err != nil {
		t.Fatal(err)
	}
}

func testCredsExist(t *testing.T, resp *logical.Response, connURL string) bool {
	t.Helper()
	var d struct {
		Username string `mapstructure:"username"`
		Password string `mapstructure:"password"`
	}
	if err := mapstructure.Decode(resp.Data, &d); err != nil {
		t.Fatal(err)
	}
	log.Printf("[TRACE] Generated credentials: %v", d)

	db, err := sql.Open("pgx", connURL+"&timezone=utc")
	if err != nil {
		t.Fatal(err)
	}

	returnedRows := func() int {
		stmt, err := db.Prepare("SELECT DISTINCT schemaname FROM pg_tables WHERE has_table_privilege($1, 'information_schema.role_column_grants', 'select');")
		if err != nil {
			return -1
		}
		defer stmt.Close()

		rows, err := stmt.Query(d.Username)
		if err != nil {
			return -1
		}
		defer rows.Close()

		i := 0
		for rows.Next() {
			i++
		}
		return i
	}

	return returnedRows() == 2
}

const testRole = `
CREATE ROLE "{{name}}" WITH
  LOGIN
  PASSWORD '{{password}}'
  VALID UNTIL '{{expiration}}';
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO "{{name}}";
`

const defaultRevocationSQL = `
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM {{name}};
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM {{name}};
REVOKE USAGE ON SCHEMA public FROM {{name}};

DROP ROLE IF EXISTS {{name}};
`
