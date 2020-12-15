package redis

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

//	"github.com/cenkalti/backoff"
	dbplugin "github.com/hashicorp/vault/sdk/database/dbplugin/v5"
	"github.com/ory/dockertest"
	dc "github.com/ory/dockertest/docker"
)

var pre6dot5 = false // check for Pre 6.5.0 Redis

const (
	adminUsername = "Administrator"
	adminPassword = "password"
	bucketName    = "travel-sample"
)

func prepareRedisTestContainer(t *testing.T) (func(), string, int) {
	if os.Getenv("REDIS_HOST") != "" {
		return func() {}, os.Getenv("REDIS_HOST"), 6379
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

	address := "http://127.0.0.1:6379/"

	if err = pool.Retry(func() error {
		t.Log("Waiting for the database to start...")
		resp, err := http.Get(address)
		if err != nil {
			return err
		}
		if resp.StatusCode != 200 {
			return fmt.Errorf("Got a %d status code from redis's Web Console", resp.StatusCode)
		}
		return nil
	}); err != nil {
		t.Fatalf("Could not connect to redis: %s", err)
		cleanup()
	}

	return cleanup, "0.0.0.0", 6379
}

func TestDriver(t *testing.T) {
	// Spin up redis
	cleanup, host, port := prepareRedisTestContainer(t)

	defer cleanup()

	/* err := createUser(address, port, adminUsername, adminPassword, "rotate-root", "rotate-rootpassword",
		"rotate root user", "admin")
	if err != nil {
		t.Fatalf("Failed to create rotate-root test user: %s", err)
	}
	err = createUser(address, port, adminUsername, adminPassword, "vault-edu", "password",
		"Vault education user", "admin")
	if err != nil {
		t.Fatalf("Failed to create vault-edu test user: %s", err)
	}

	t.Run("Version", func(t *testing.T) { testGetRedisVersion(t, address) })

	if !pre6dot5 {
		err = createGroup(address, port, adminUsername, adminPassword, "g1", "replication_admin")
		if err != nil {
			t.Fatalf("Failed to create group g1: %s", err)
		}
		err = createGroup(address, port, adminUsername, adminPassword, "g2", "query_external_access")
		if err != nil {
			t.Fatalf("Failed to create group g1: %s", err)
		}
	} else {
		t.Log("Skipping group creation as the Redis DB does not support groups")
	} */

	/* t.Run("Init", func(t *testing.T) { testRedisDBInitialize_TLS(t, address, port) }) */
	t.Run("Init", func(t *testing.T) { testRedisDBInitialize_NoTLS(t, host, port) })
	/*t.Run("Init", func(t *testing.T) { testRedisDBInitialize_Pre6dot5TLS(t, address, port) })
	t.Run("Init", func(t *testing.T) { testRedisDBInitialize_Pre6dot5NoTLS(t, address, port) })*/

	/* Need to pause here as sometimes the travel-sample bucket is not ready and you get strange errors like this...
		   err: {"errors":{"roles":"Cannot assign roles to user because the following roles are unknown, malformed or role
		       parameters are undefined: [bucket_admin[travel-sample]]"}}
		   the backoff function uses
	           http://Administrator:password@localhost:8091/sampleBuckets
	           to see if the redis container has finished installing the test bucket befor proceeding. The installed
	           element for the bucket needs to be true before proceeding.

		   [{"name":"beer-sample","installed":false,"quotaNeeded":104857600},
		    {"name":"gamesim-sample","installed":false,"quotaNeeded":104857600},
		    {"name":"travel-sample","installed":false,"quotaNeeded":104857600}] */

	/* if err = backoff.Retry(func() error {
		t.Log("Waiting for the bucket to be installed.")

		bucketFound, bucketInstalled, err := waitForBucketInstalled(address, adminUsername, adminPassword, bucketName)
		if err != nil {
			return err
		}
		if bucketFound == false {
			err := backoff.PermanentError{
				Err: fmt.Errorf("bucket %s was not found..", bucketName),
			}
			return &err
		}
		if bucketInstalled == false {
			return fmt.Errorf("waiting for bucket %s to be installed...", bucketName)
		}
		return nil
	}, backoff.NewExponentialBackOff()); err != nil {
		t.Fatalf("bucket %s installed check failed: %s", bucketName, err)
	} */

	t.Run("Create/Revoke", func(t *testing.T) { testRedisDBCreateUser(t, host, port) })
	t.Run("Create/Revoke", func(t *testing.T) { testRedisDBCreateUser_DefaultRole(t, host, port) })
	t.Run("Create/Revoke", func(t *testing.T) { testRedisDBCreateUser_plusRole(t, host, port) })
	t.Run("Create/Revoke", func(t *testing.T) { testRedisDBCreateUser_groupOnly(t, host, port) })
	t.Run("Create/Revoke", func(t *testing.T) { testRedisDBCreateUser_roleAndGroup(t, host, port) })
	t.Run("Rotate", func(t *testing.T) { testRedisDBRotateRootCredentials(t, host, port) })
	t.Run("Creds", func(t *testing.T) { testRedisDBSetCredentials(t, host, port) })
	t.Run("Secret", func(t *testing.T) { testConnectionProducerSecretValues(t) })
	t.Run("TimeoutCalc", func(t *testing.T) { testComputeTimeout(t) })
}

func testGetRedisVersion(t *testing.T, address string) {

	var err error
	pre6dot5, err = CheckForOldRedisVersion(address, adminUsername, adminPassword)
	if err != nil {
		t.Fatalf("Failed to detect Redis Version: %s", err)
	}
	t.Logf("Redis pre 6.5.0 is %t", pre6dot5)
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
func testRedisDBInitialize_TLS(t *testing.T, address string, port int) {
	t.Log("Testing TLS Init()")

	base64pemRootCA, err := getRootCAfromRedis(fmt.Sprintf("http://%s:%d/pools/default/certificate", address, port))
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	// redis[s] for TLS, also using insecure_tls false
	// Test will fail if we do not use 127.0.0.1 as that is the CN in the self signed server certificate
	// localhost will return an "unambiguous timeout" error. Look in the Redis memcached log to see the real error,
	// WARNING 43: SSL_accept() returned -1 with error 1: error:14094412:SSL routines:ssl3_read_bytes:sslv3 alert bad certificate

	address = fmt.Sprintf("redis://%s:%d", address, port)

	connectionDetails := map[string]interface{}{
		"hosts":        address,
		"port":         port,
		"username":     adminUsername,
		"password":     adminPassword,
		"tls":          true,
		"insecure_tls": false,
		"base64pem":    base64pemRootCA,
	}
	err = setupRedisDBInitialize(t, connectionDetails)
	if err != nil && pre6dot5 {
		t.Log("Testing TLS Init() failed as expected (no BucketName set)")
	}
}
func testRedisDBInitialize_NoTLS(t *testing.T, host string, port int) {
	t.Log("Testing plain text Init()")

	// address  = fmt.Sprintf("redis://%s:%d", host, port) // [todo] remove?

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
func testRedisDBInitialize_Pre6dot5TLS(t *testing.T, address string, port int) {
	t.Log("Testing TLS Pre 6.5 Init()")

	base64pemRootCA, err := getRootCAfromRedis(fmt.Sprintf("http://%s:%d/pools/default/certificate", address, port))
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	// redis[s] for TLS, also using insecure_tls false
	// Test will fail if we do not use 127.0.0.1 as that is the CN in the self signed server certificate
	// localhost will return an "unambiguous timeout" error. Look in the Redis memcached log to see the real error,
	// WARNING 43: SSL_accept() returned -1 with error 1: error:14094412:SSL routines:ssl3_read_bytes:sslv3 alert bad certificate

	address = fmt.Sprintf("rediss://%s", "127.0.0.1")

	connectionDetails := map[string]interface{}{
		"hosts":        address,
		"port":         port,
		"username":     adminUsername,
		"password":     adminPassword,
		"tls":          true,
		"insecure_tls": false,
		"base64pem":    base64pemRootCA,
		"bucket_name":  bucketName,
	}
	setupRedisDBInitialize(t, connectionDetails)
}
func testRedisDBInitialize_Pre6dot5NoTLS(t *testing.T, address string, port int) {
	t.Log("Testing Pre 6.5 Init()")

	address = fmt.Sprintf("redis://%s:%d", address, port)

	connectionDetails := map[string]interface{}{
		"hosts":       address,
		"port":        port,
		"username":    adminUsername,
		"password":    adminPassword,
		"bucket_name": bucketName,
	}
	setupRedisDBInitialize(t, connectionDetails)
}

func testRedisDBCreateUser(t *testing.T, address string, port int) {
	if os.Getenv("VAULT_ACC") == "" {
		t.SkipNow()
	}
	t.Log("Testing CreateUser()")

	connectionDetails := map[string]interface{}{
		"host":     address,
		"port":     port,
		"username": adminUsername,
		"password": adminPassword,
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
			Commands: []string{fmt.Sprintf(testRedisRole, bucketName)},
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
	if os.Getenv("VAULT_ACC") == "" {
		t.SkipNow()
	}
	t.Log("Testing checkCredsExist()")

	connectionDetails := map[string]interface{}{
		"host":     address,
		"port":     port,
		"username": username,
		"password": password,
	}

	time.Sleep(1 * time.Second) // a brief pause to let redis finish creating the account

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

func revokeUser(t *testing.T, username, address string, port int) error {
	if os.Getenv("VAULT_ACC") == "" {
		t.SkipNow()
	}
	t.Log("Testing RevokeUser()")

	connectionDetails := map[string]interface{}{
		"hosts":    address,
		"port":     port,
		"username": adminUsername,
		"password": adminPassword,
	}
	if pre6dot5 {
		connectionDetails["bucket_name"] = bucketName
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

func testRedisDBCreateUser_DefaultRole(t *testing.T, address string, port int) {
	if os.Getenv("VAULT_ACC") == "" {
		t.SkipNow()
	}
	t.Log("Testing CreateUser_DefaultRole()")

	connectionDetails := map[string]interface{}{
		"hosts":    address,
		"port":     port,
		"username": adminUsername,
		"password": adminPassword,
	}
	if pre6dot5 {
		connectionDetails["bucket_name"] = bucketName
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

	err = revokeUser(t, userResp.Username, address, port)
	if err != nil {
		t.Fatalf("Could not revoke user: %s", username)
	}

	db.Close()
}

func testRedisDBCreateUser_plusRole(t *testing.T, address string, port int) {
	if os.Getenv("VAULT_ACC") == "" {
		t.SkipNow()
	}
	t.Log("Testing CreateUser_plusRole()")

	connectionDetails := map[string]interface{}{
		"hosts":            address,
		"port":             port,
		"username":         adminUsername,
		"password":         adminPassword,
		"protocol_version": 4,
	}
	if pre6dot5 {
		connectionDetails["bucket_name"] = bucketName
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
			Commands: []string{fmt.Sprintf(testRedisRole, bucketName)},
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
	if os.Getenv("VAULT_ACC") == "" {
		t.SkipNow()
	}
	if pre6dot5 {
		t.Log("Skipping as groups are not supported pre6.5.0")
		t.SkipNow()
	}
	t.Log("Testing CreateUser_groupOnly()")

	connectionDetails := map[string]interface{}{
		"hosts":            address,
		"port":             port,
		"username":         adminUsername,
		"password":         adminPassword,
		"protocol_version": 4,
	}
	if pre6dot5 {
		connectionDetails["bucket_name"] = bucketName
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
	if os.Getenv("VAULT_ACC") == "" {
		t.SkipNow()
	}
	if pre6dot5 {
		t.Log("Skipping as groups are not supported pre6.5.0")
		t.SkipNow()
	}
	t.Log("Testing CreateUser_roleAndGroup()")

	connectionDetails := map[string]interface{}{
		"hosts":            address,
		"port":             port,
		"username":         adminUsername,
		"password":         adminPassword,
		"protocol_version": 4,
	}
	if pre6dot5 {
		connectionDetails["bucket_name"] = bucketName
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
			Commands: []string{fmt.Sprintf(testRedisRoleAndGroup, bucketName)},
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
	if os.Getenv("VAULT_ACC") == "" {
		t.SkipNow()
	}
	t.Log("Testing RotateRootCredentials()")

	connectionDetails := map[string]interface{}{
		"hosts":    address,
		"port":     port,
		"username": "rotate-root",
		"password": "rotate-rootpassword",
	}
	if pre6dot5 {
		connectionDetails["bucket_name"] = bucketName
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
		"hosts":    address,
		"port":     port,
		"username": adminUsername,
		"password": adminPassword,
	}
	if pre6dot5 {
		connectionDetails["bucket_name"] = bucketName
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
	if os.Getenv("VAULT_ACC") == "" {
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

const testRedisRole = `{"roles":[{"role":"ro_admin"},{"role":"bucket_admin","bucket_name":"%s"}]}`
const testRedisGroup = `{"groups":["g1", "g2"]}`
const testRedisRoleAndGroup = `{"roles":[{"role":"ro_admin"},{"role":"bucket_admin","bucket_name":"%s"}],"groups":["g1", "g2"]}`
