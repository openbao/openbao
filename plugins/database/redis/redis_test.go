// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package redis

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mediocregopher/radix/v4"
	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/sdk/v2/database/dbplugin/v5"
	"github.com/ory/dockertest/v3"
	dc "github.com/ory/dockertest/v3/docker"
)

var pre6dot5 = false // check for Pre 6.5.0 Redis

const (
	defaultUsername       = "default"
	defaultPassword       = "default-pa55w0rd"
	adminUsername         = "Administrator"
	adminPassword         = "password"
	aclCat                = "+@admin"
	testRedisRole         = `["%s"]`
	testRedisGroup        = `["+@all"]`
	testRedisRoleAndGroup = `["%s"]`
)

var redisTls = false

func prepareRedisTestContainer(t *testing.T) (func(), string, int) {
	if os.Getenv("TEST_REDIS_TLS") != "" {
		redisTls = true
	}
	if os.Getenv("TEST_REDIS_HOST") != "" {
		return func() {}, os.Getenv("TEST_REDIS_HOST"), 6379
	}
	// redver should match a redis repository tag. Default to latest.
	redver := os.Getenv("REDIS_VERSION")
	if redver == "" {
		redver = "latest"
	}

	pool, err := dockertest.NewPool("")
	if err != nil {
		t.Fatalf("Failed to connect to docker: %s", err)
	}

	ro := &dockertest.RunOptions{
		Repository:   "docker.io/redis",
		Tag:          redver,
		ExposedPorts: []string{"6379"},
		PortBindings: map[dc.Port][]dc.PortBinding{
			"6379": {
				{HostIP: "0.0.0.0", HostPort: "6379"},
			},
		},
	}
	resource, err := pool.RunWithOptions(ro)
	if err != nil {
		t.Fatalf("Could not start local redis docker container: %s", err)
	}

	cleanup := func() {
		err := pool.Retry(func() error {
			return pool.Purge(resource)
		})
		if err != nil {
			if strings.Contains(err.Error(), "No such container") {
				return
			}
			t.Fatalf("Failed to cleanup local container: %s", err)
		}
	}

	address := "127.0.0.1:6379"

	if err = pool.Retry(func() error {
		t.Log("Waiting for the database to start...")
		poolConfig := radix.PoolConfig{}
		_, err := poolConfig.New(context.Background(), "tcp", address)
		if err != nil {
			return err
		}

		return nil
	}); err != nil {
		t.Fatalf("Could not connect to redis: %s", err)
		cleanup()
	}
	time.Sleep(3 * time.Second)
	return cleanup, "0.0.0.0", 6379
}

func TestDriver(t *testing.T) {
	var err error
	var caCert []byte
	if os.Getenv("TEST_REDIS_TLS") != "" {
		caCertFile := os.Getenv("CA_CERT_FILE")
		caCert, err = os.ReadFile(caCertFile)
		if err != nil {
			t.Fatal(fmt.Errorf("unable to read CA_CERT_FILE at %v: %w", caCertFile, err))
		}
	}

	// Spin up redis
	cleanup, host, port := prepareRedisTestContainer(t)
	defer cleanup()

	err = createUser(host, port, redisTls, caCert, defaultUsername, defaultPassword, "Administrator", "password",
		aclCat)
	if err != nil {
		t.Fatalf("Failed to create Administrator user using 'default' user: %s", err)
	}
	err = createUser(host, port, redisTls, caCert, adminUsername, adminPassword, "rotate-root", "rotate-rootpassword",
		aclCat)
	if err != nil {
		t.Fatalf("Failed to create rotate-root test user: %s", err)
	}
	err = createUser(host, port, redisTls, caCert, adminUsername, adminPassword, "vault-edu", "password",
		aclCat)
	if err != nil {
		t.Fatalf("Failed to create vault-edu test user: %s", err)
	}

	t.Run("Init", func(t *testing.T) { testRedisDBInitialize_NoTLS(t, host, port) })
	t.Run("Init", func(t *testing.T) { testRedisDBInitialize_TLS(t, host, port) })
	t.Run("Create/Revoke", func(t *testing.T) { testRedisDBCreateUser(t, host, port) })
	t.Run("Create/Revoke", func(t *testing.T) { testRedisDBCreateUser_DefaultRule(t, host, port) })
	t.Run("Create/Revoke", func(t *testing.T) { testRedisDBCreateUser_plusRole(t, host, port) })
	t.Run("Create/Revoke", func(t *testing.T) { testRedisDBCreateUser_groupOnly(t, host, port) })
	t.Run("Create/Revoke", func(t *testing.T) { testRedisDBCreateUser_roleAndGroup(t, host, port) })
	t.Run("Rotate", func(t *testing.T) { testRedisDBRotateRootCredentials(t, host, port) })
	t.Run("Creds", func(t *testing.T) { testRedisDBSetCredentials(t, host, port) })
	t.Run("Secret", func(t *testing.T) { testConnectionProducerSecretValues(t) })
	t.Run("TimeoutCalc", func(t *testing.T) { testComputeTimeout(t) })
}

func setupRedisDBInitialize(t *testing.T, connectionDetails map[string]interface{}) (err error) {
	initReq := dbplugin.InitializeRequest{
		Config:           connectionDetails,
		VerifyConnection: true,
	}

	db := new()
	_, err = db.Initialize(context.Background(), initReq)
	if err != nil {
		return err
	}

	if !db.Initialized {
		t.Fatal("Database should be initialized")
	}

	err = db.Close()
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	return nil
}

func testRedisDBInitialize_NoTLS(t *testing.T, host string, port int) {
	if redisTls {
		t.Skip("skipping plain text Init() test in TLS mode")
	}

	t.Log("Testing plain text Init()")

	connectionDetails := map[string]interface{}{
		"host":     host,
		"port":     port,
		"username": adminUsername,
		"password": adminPassword,
	}
	err := setupRedisDBInitialize(t, connectionDetails)
	if err != nil {
		t.Fatalf("Testing Init() failed: error: %s", err)
	}
}

func testRedisDBInitialize_TLS(t *testing.T, host string, port int) {
	if !redisTls {
		t.Skip("skipping TLS Init() test in plain text mode")
	}

	CACertFile := os.Getenv("CA_CERT_FILE")
	CACert, err := os.ReadFile(CACertFile)
	if err != nil {
		t.Fatal(fmt.Errorf("unable to read CA_CERT_FILE at %v: %w", CACertFile, err))
	}

	t.Log("Testing TLS Init()")

	connectionDetails := map[string]interface{}{
		"host":         host,
		"port":         port,
		"username":     adminUsername,
		"password":     adminPassword,
		"tls":          true,
		"ca_cert":      CACert,
		"insecure_tls": true,
	}
	err = setupRedisDBInitialize(t, connectionDetails)
	if err != nil {
		t.Fatalf("Testing TLS Init() failed: error: %s", err)
	}
}

func testRedisDBCreateUser(t *testing.T, address string, port int) {
	if api.ReadBaoVariable("BAO_ACC") == "" {
		t.SkipNow()
	}

	t.Log("Testing CreateUser()")

	connectionDetails := map[string]interface{}{
		"host":     address,
		"port":     port,
		"username": adminUsername,
		"password": adminPassword,
	}

	if redisTls {
		CACertFile := os.Getenv("CA_CERT_FILE")
		CACert, err := os.ReadFile(CACertFile)
		if err != nil {
			t.Fatal(fmt.Errorf("unable to read CA_CERT_FILE at %v: %w", CACertFile, err))
		}

		connectionDetails["tls"] = true
		connectionDetails["ca_cert"] = CACert
		connectionDetails["insecure_tls"] = true
	}

	initReq := dbplugin.InitializeRequest{
		Config:           connectionDetails,
		VerifyConnection: true,
	}

	db := new()
	_, err := db.Initialize(context.Background(), initReq)
	if err != nil {
		t.Fatalf("Failed to initialize database: %s", err)
	}

	if !db.Initialized {
		t.Fatal("Database should be initialized")
	}

	password := "y8fva_sdVA3rasf"

	createReq := dbplugin.NewUserRequest{
		UsernameConfig: dbplugin.UsernameMetadata{
			DisplayName: "test",
			RoleName:    "test",
		},
		Statements: dbplugin.Statements{
			Commands: []string{},
		},
		Password:   password,
		Expiration: time.Now().Add(time.Minute),
	}

	userResp, err := db.NewUser(context.Background(), createReq)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	db.Close()

	if err := checkCredsExist(t, userResp.Username, password, address, port); err != nil {
		t.Fatalf("Could not connect with new credentials: %s", err)
	}

	err = revokeUser(t, userResp.Username, address, port)
	if err != nil {
		t.Fatalf("Could not revoke user: %s", userResp.Username)
	}
}

func checkCredsExist(t *testing.T, username, password, address string, port int) error {
	if api.ReadBaoVariable("BAO_ACC") == "" {
		t.SkipNow()
	}

	t.Log("Testing checkCredsExist()")

	connectionDetails := map[string]interface{}{
		"host":     address,
		"port":     port,
		"username": username,
		"password": password,
	}

	if redisTls {
		CACertFile := os.Getenv("CA_CERT_FILE")
		CACert, err := os.ReadFile(CACertFile)
		if err != nil {
			t.Fatal(fmt.Errorf("unable to read CA_CERT_FILE at %v: %w", CACertFile, err))
		}

		connectionDetails["tls"] = true
		connectionDetails["ca_cert"] = CACert
		connectionDetails["insecure_tls"] = true
	}

	initReq := dbplugin.InitializeRequest{
		Config:           connectionDetails,
		VerifyConnection: true,
	}

	db := new()
	_, err := db.Initialize(context.Background(), initReq)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	if !db.Initialized {
		t.Fatal("Database should be initialized")
	}

	return nil
}

func checkRuleAllowed(t *testing.T, username, password, address string, port int, cmd string, rules []string) error {
	if api.ReadBaoVariable("BAO_ACC") == "" {
		t.SkipNow()
	}

	t.Log("Testing checkRuleAllowed()")

	connectionDetails := map[string]interface{}{
		"host":     address,
		"port":     port,
		"username": username,
		"password": password,
	}

	if redisTls {
		CACertFile := os.Getenv("CA_CERT_FILE")
		CACert, err := os.ReadFile(CACertFile)
		if err != nil {
			t.Fatal(fmt.Errorf("unable to read CA_CERT_FILE at %v: %w", CACertFile, err))
		}

		connectionDetails["tls"] = true
		connectionDetails["ca_cert"] = CACert
		connectionDetails["insecure_tls"] = true
	}

	initReq := dbplugin.InitializeRequest{
		Config:           connectionDetails,
		VerifyConnection: true,
	}

	db := new()
	_, err := db.Initialize(context.Background(), initReq)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	if !db.Initialized {
		t.Fatal("Database should be initialized")
	}
	var response string
	err = db.client.Do(context.Background(), radix.Cmd(&response, cmd, rules...))

	return err
}

func revokeUser(t *testing.T, username, address string, port int) error {
	if api.ReadBaoVariable("BAO_ACC") == "" {
		t.SkipNow()
	}

	t.Log("Testing RevokeUser()")

	connectionDetails := map[string]interface{}{
		"host":     address,
		"port":     port,
		"username": adminUsername,
		"password": adminPassword,
	}

	if redisTls {
		CACertFile := os.Getenv("CA_CERT_FILE")
		CACert, err := os.ReadFile(CACertFile)
		if err != nil {
			t.Fatal(fmt.Errorf("unable to read CA_CERT_FILE at %v: %w", CACertFile, err))
		}

		connectionDetails["tls"] = true
		connectionDetails["ca_cert"] = CACert
		connectionDetails["insecure_tls"] = true
	}

	initReq := dbplugin.InitializeRequest{
		Config:           connectionDetails,
		VerifyConnection: true,
	}

	db := new()
	_, err := db.Initialize(context.Background(), initReq)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	if !db.Initialized {
		t.Fatal("Database should be initialized")
	}

	delUserReq := dbplugin.DeleteUserRequest{Username: username}

	_, err = db.DeleteUser(context.Background(), delUserReq)
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	return nil
}

func testRedisDBCreateUser_DefaultRule(t *testing.T, address string, port int) {
	if api.ReadBaoVariable("BAO_ACC") == "" {
		t.SkipNow()
	}

	t.Log("Testing CreateUser_DefaultRule()")

	connectionDetails := map[string]interface{}{
		"host":     address,
		"port":     port,
		"username": adminUsername,
		"password": adminPassword,
	}

	if redisTls {
		CACertFile := os.Getenv("CA_CERT_FILE")
		CACert, err := os.ReadFile(CACertFile)
		if err != nil {
			t.Fatal(fmt.Errorf("unable to read CA_CERT_FILE at %v: %w", CACertFile, err))
		}

		connectionDetails["tls"] = true
		connectionDetails["ca_cert"] = CACert
		connectionDetails["insecure_tls"] = true
	}

	initReq := dbplugin.InitializeRequest{
		Config:           connectionDetails,
		VerifyConnection: true,
	}

	db := new()
	_, err := db.Initialize(context.Background(), initReq)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	if !db.Initialized {
		t.Fatal("Database should be initialized")
	}

	username := "test"
	password := "y8fva_sdVA3rasf"

	createReq := dbplugin.NewUserRequest{
		UsernameConfig: dbplugin.UsernameMetadata{
			DisplayName: username,
			RoleName:    username,
		},
		Statements: dbplugin.Statements{
			Commands: []string{},
		},
		Password:   password,
		Expiration: time.Now().Add(time.Minute),
	}

	userResp, err := db.NewUser(context.Background(), createReq)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	if err := checkCredsExist(t, userResp.Username, password, address, port); err != nil {
		t.Fatalf("Could not connect with new credentials: %s", err)
	}
	rules := []string{"foo"}
	if err := checkRuleAllowed(t, userResp.Username, password, address, port, "get", rules); err != nil {
		t.Fatalf("get failed with +@read rule: %s", err)
	}

	rules = []string{"foo", "bar"}
	if err = checkRuleAllowed(t, userResp.Username, password, address, port, "set", rules); err == nil {
		t.Fatalf("set did not fail with +@read rule: %s", err)
	}

	err = revokeUser(t, userResp.Username, address, port)
	if err != nil {
		t.Fatalf("Could not revoke user: %s", username)
	}

	db.Close()
}

func testRedisDBCreateUser_plusRole(t *testing.T, address string, port int) {
	if api.ReadBaoVariable("BAO_ACC") == "" {
		t.SkipNow()
	}

	t.Log("Testing CreateUser_plusRole()")

	connectionDetails := map[string]interface{}{
		"host":             address,
		"port":             port,
		"username":         adminUsername,
		"password":         adminPassword,
		"protocol_version": 4,
	}

	if redisTls {
		CACertFile := os.Getenv("CA_CERT_FILE")
		CACert, err := os.ReadFile(CACertFile)
		if err != nil {
			t.Fatal(fmt.Errorf("unable to read CA_CERT_FILE at %v: %w", CACertFile, err))
		}

		connectionDetails["tls"] = true
		connectionDetails["ca_cert"] = CACert
		connectionDetails["insecure_tls"] = true
	}

	initReq := dbplugin.InitializeRequest{
		Config:           connectionDetails,
		VerifyConnection: true,
	}

	db := new()
	_, err := db.Initialize(context.Background(), initReq)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	if !db.Initialized {
		t.Fatal("Database should be initialized")
	}

	password := "y8fva_sdVA3rasf"

	createReq := dbplugin.NewUserRequest{
		UsernameConfig: dbplugin.UsernameMetadata{
			DisplayName: "test",
			RoleName:    "test",
		},
		Statements: dbplugin.Statements{
			Commands: []string{fmt.Sprintf(testRedisRole, aclCat)},
		},
		Password:   password,
		Expiration: time.Now().Add(time.Minute),
	}

	userResp, err := db.NewUser(context.Background(), createReq)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	db.Close()

	if err := checkCredsExist(t, userResp.Username, password, address, port); err != nil {
		t.Fatalf("Could not connect with new credentials: %s", err)
	}

	err = revokeUser(t, userResp.Username, address, port)
	if err != nil {
		t.Fatalf("Could not revoke user: %s", userResp.Username)
	}
}

// g1 & g2 must exist in the database.
func testRedisDBCreateUser_groupOnly(t *testing.T, address string, port int) {
	if api.ReadBaoVariable("BAO_ACC") == "" {
		t.SkipNow()
	}

	if pre6dot5 {
		t.Log("Skipping as groups are not supported pre6.5.0")
		t.SkipNow()
	}
	t.Log("Testing CreateUser_groupOnly()")

	connectionDetails := map[string]interface{}{
		"host":             address,
		"port":             port,
		"username":         adminUsername,
		"password":         adminPassword,
		"protocol_version": 4,
	}

	if redisTls {
		CACertFile := os.Getenv("CA_CERT_FILE")
		CACert, err := os.ReadFile(CACertFile)
		if err != nil {
			t.Fatal(fmt.Errorf("unable to read CA_CERT_FILE at %v: %w", CACertFile, err))
		}

		connectionDetails["tls"] = true
		connectionDetails["ca_cert"] = CACert
		connectionDetails["insecure_tls"] = true
	}

	initReq := dbplugin.InitializeRequest{
		Config:           connectionDetails,
		VerifyConnection: true,
	}

	db := new()
	_, err := db.Initialize(context.Background(), initReq)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	if !db.Initialized {
		t.Fatal("Database should be initialized")
	}

	password := "y8fva_sdVA3rasf"

	createReq := dbplugin.NewUserRequest{
		UsernameConfig: dbplugin.UsernameMetadata{
			DisplayName: "test",
			RoleName:    "test",
		},
		Statements: dbplugin.Statements{
			Commands: []string{fmt.Sprintf(testRedisGroup)},
		},
		Password:   password,
		Expiration: time.Now().Add(time.Minute),
	}

	userResp, err := db.NewUser(context.Background(), createReq)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	db.Close()

	if err := checkCredsExist(t, userResp.Username, password, address, port); err != nil {
		t.Fatalf("Could not connect with new credentials: %s", err)
	}

	err = revokeUser(t, userResp.Username, address, port)
	if err != nil {
		t.Fatalf("Could not revoke user: %s", userResp.Username)
	}
}

func testRedisDBCreateUser_roleAndGroup(t *testing.T, address string, port int) {
	if api.ReadBaoVariable("BAO_ACC") == "" {
		t.SkipNow()
	}

	if pre6dot5 {
		t.Log("Skipping as groups are not supported pre6.5.0")
		t.SkipNow()
	}
	t.Log("Testing CreateUser_roleAndGroup()")

	connectionDetails := map[string]interface{}{
		"host":             address,
		"port":             port,
		"username":         adminUsername,
		"password":         adminPassword,
		"protocol_version": 4,
	}

	if redisTls {
		CACertFile := os.Getenv("CA_CERT_FILE")
		CACert, err := os.ReadFile(CACertFile)
		if err != nil {
			t.Fatal(fmt.Errorf("unable to read CA_CERT_FILE at %v: %w", CACertFile, err))
		}

		connectionDetails["tls"] = true
		connectionDetails["ca_cert"] = CACert
		connectionDetails["insecure_tls"] = true
	}

	initReq := dbplugin.InitializeRequest{
		Config:           connectionDetails,
		VerifyConnection: true,
	}

	db := new()
	_, err := db.Initialize(context.Background(), initReq)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	if !db.Initialized {
		t.Fatal("Database should be initialized")
	}

	password := "y8fva_sdVA3rasf"

	createReq := dbplugin.NewUserRequest{
		UsernameConfig: dbplugin.UsernameMetadata{
			DisplayName: "test",
			RoleName:    "test",
		},
		Statements: dbplugin.Statements{
			Commands: []string{fmt.Sprintf(testRedisRoleAndGroup, aclCat)},
		},
		Password:   password,
		Expiration: time.Now().Add(time.Minute),
	}

	userResp, err := db.NewUser(context.Background(), createReq)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	db.Close()

	if err := checkCredsExist(t, userResp.Username, password, address, port); err != nil {
		t.Fatalf("Could not connect with new credentials: %s", err)
	}

	err = revokeUser(t, userResp.Username, address, port)
	if err != nil {
		t.Fatalf("Could not revoke user: %s", userResp.Username)
	}
}

func testRedisDBRotateRootCredentials(t *testing.T, address string, port int) {
	if api.ReadBaoVariable("BAO_ACC") == "" {
		t.SkipNow()
	}

	t.Log("Testing RotateRootCredentials()")

	connectionDetails := map[string]interface{}{
		"host":     address,
		"port":     port,
		"username": "rotate-root",
		"password": "rotate-rootpassword",
	}

	if redisTls {
		CACertFile := os.Getenv("CA_CERT_FILE")
		CACert, err := os.ReadFile(CACertFile)
		if err != nil {
			t.Fatal(fmt.Errorf("unable to read CA_CERT_FILE at %v: %w", CACertFile, err))
		}

		connectionDetails["tls"] = true
		connectionDetails["ca_cert"] = CACert
		connectionDetails["insecure_tls"] = true
	}

	initReq := dbplugin.InitializeRequest{
		Config:           connectionDetails,
		VerifyConnection: true,
	}

	db := new()
	_, err := db.Initialize(context.Background(), initReq)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	if !db.Initialized {
		t.Fatal("Database should be initialized")
	}

	defer db.Close()

	updateReq := dbplugin.UpdateUserRequest{
		Username: "rotate-root",
		Password: &dbplugin.ChangePassword{
			NewPassword: "newpassword",
		},
	}

	_, err = db.UpdateUser(context.Background(), updateReq)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	// defer setting the password back in case the test fails.
	defer doRedisDBSetCredentials(t, "rotate-root", "rotate-rootpassword", address, port)

	if err := checkCredsExist(t, db.Username, "newpassword", address, port); err != nil {
		t.Fatalf("Could not connect with new RotatedRootcredentials: %s", err)
	}
}

func doRedisDBSetCredentials(t *testing.T, username, password, address string, port int) {
	t.Log("Testing SetCredentials()")

	connectionDetails := map[string]interface{}{
		"host":     address,
		"port":     port,
		"username": adminUsername,
		"password": adminPassword,
	}

	if redisTls {
		CACertFile := os.Getenv("CA_CERT_FILE")
		CACert, err := os.ReadFile(CACertFile)
		if err != nil {
			t.Fatal(fmt.Errorf("unable to read CA_CERT_FILE at %v: %w", CACertFile, err))
		}

		connectionDetails["tls"] = true
		connectionDetails["ca_cert"] = CACert
		connectionDetails["insecure_tls"] = true
	}

	initReq := dbplugin.InitializeRequest{
		Config:           connectionDetails,
		VerifyConnection: true,
	}

	db := new()
	_, err := db.Initialize(context.Background(), initReq)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	if !db.Initialized {
		t.Fatal("Database should be initialized")
	}

	// test that SetCredentials fails if the user does not exist...
	updateReq := dbplugin.UpdateUserRequest{
		Username: "userThatDoesNotExist",
		Password: &dbplugin.ChangePassword{
			NewPassword: "goodPassword",
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5000*time.Millisecond)
	defer cancel()
	_, err = db.UpdateUser(ctx, updateReq)
	if err == nil {
		t.Fatalf("err: did not error on setting password for userThatDoesNotExist")
	}

	updateReq = dbplugin.UpdateUserRequest{
		Username: username,
		Password: &dbplugin.ChangePassword{
			NewPassword: password,
		},
	}

	_, err = db.UpdateUser(context.Background(), updateReq)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	db.Close()

	if err := checkCredsExist(t, username, password, address, port); err != nil {
		t.Fatalf("Could not connect with rotated credentials: %s", err)
	}
}

func testRedisDBSetCredentials(t *testing.T, address string, port int) {
	if api.ReadBaoVariable("BAO_ACC") == "" {
		t.SkipNow()
	}

	doRedisDBSetCredentials(t, "vault-edu", "password", address, port)
}

func testConnectionProducerSecretValues(t *testing.T) {
	t.Log("Testing redisDBConnectionProducer.secretValues()")

	cp := &redisDBConnectionProducer{
		Username: "USR",
		Password: "PWD",
	}

	if cp.secretValues()["USR"] != "[username]" &&
		cp.secretValues()["PWD"] != "[password]" {
		t.Fatal("redisDBConnectionProducer.secretValues() test failed.")
	}
}

func testComputeTimeout(t *testing.T) {
	t.Log("Testing computeTimeout")
	if computeTimeout(context.Background()) != defaultTimeout {
		t.Fatalf("Background timeout not set to %s milliseconds.", defaultTimeout)
	}
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()
	if computeTimeout(ctx) == defaultTimeout {
		t.Fatal("WithTimeout failed")
	}
}

func createUser(hostname string, port int, redisTls bool, CACert []byte, adminuser, adminpassword, username, password, aclRule string) (err error) {
	var poolConfig radix.PoolConfig

	if redisTls {
		rootCAs := x509.NewCertPool()
		ok := rootCAs.AppendCertsFromPEM(CACert)
		if !ok {
			return fmt.Errorf("failed to parse root certificate")
		}

		poolConfig = radix.PoolConfig{
			Dialer: radix.Dialer{
				AuthUser: adminuser,
				AuthPass: adminpassword,
				NetDialer: &tls.Dialer{
					Config: &tls.Config{
						RootCAs:            rootCAs,
						InsecureSkipVerify: true,
					},
				},
			},
		}
	} else {
		poolConfig = radix.PoolConfig{
			Dialer: radix.Dialer{
				AuthUser: adminuser,
				AuthPass: adminpassword,
			},
		}
	}

	addr := fmt.Sprintf("%s:%d", hostname, port)
	client, err := poolConfig.New(context.Background(), "tcp", addr)
	if err != nil {
		return err
	}

	var response string
	err = client.Do(context.Background(), radix.Cmd(&response, "ACL", "SETUSER", username, "on", ">"+password, aclRule))

	fmt.Printf("Response in createUser: %s\n", response)

	if err != nil {
		return err
	}

	if client != nil {
		if err = client.Close(); err != nil {
			return err
		}
	}

	return nil
}
