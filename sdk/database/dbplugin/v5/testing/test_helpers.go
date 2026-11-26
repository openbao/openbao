// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package dbtesting

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/sdk/v2/database/dbplugin/v5"
	"github.com/stretchr/testify/require"
)

func getRequestTimeout(t *testing.T) time.Duration {
	rawDur := api.ReadBaoVariable("BAO_TEST_DATABASE_REQUEST_TIMEOUT")
	if rawDur == "" {
		// Note: we incremented the default timeout from 5 to 10 seconds in a bid
		// to fix sporadic failures of mssql_test.go tests TestInitialize() and
		// TestUpdateUser_password().

		return 10 * time.Second
	}

	dur, err := parseutil.ParseDurationSecond(rawDur)
	require.NoErrorf(t, err, "Failed to parse custom request timeout %q", rawDur)
	return dur
}

// AssertInitializeCircleCiTest help to diagnose CircleCI failures within AssertInitialize for mssql tests failing
// with "Failed to initialize: error verifying connection ...". This will now mark a test as failed instead of being fatal
func AssertInitializeCircleCiTest(t *testing.T, db dbplugin.Database, req dbplugin.InitializeRequest) dbplugin.InitializeResponse {
	t.Helper()
	maxAttempts := 5
	var resp dbplugin.InitializeResponse
	var err error

	for i := 1; i <= maxAttempts; i++ {
		resp, err = verifyInitialize(t, db, req)
		if err != nil {
			t.Errorf("Failed AssertInitialize attempt: %d with error:\n%+v\n", i, err)
			time.Sleep(1 * time.Second)
			continue
		}

		if i > 1 {
			t.Logf("AssertInitialize worked the %d time around with a 1 second sleep", i)
		}
		break
	}

	return resp
}

func AssertInitialize(t *testing.T, db dbplugin.Database, req dbplugin.InitializeRequest) dbplugin.InitializeResponse {
	t.Helper()
	resp, err := verifyInitialize(t, db, req)
	require.NoError(t, err, "Failed to initialize")
	return resp
}

func verifyInitialize(t *testing.T, db dbplugin.Database, req dbplugin.InitializeRequest) (dbplugin.InitializeResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), getRequestTimeout(t))
	defer cancel()

	return db.Initialize(ctx, req)
}

func AssertNewUser(t *testing.T, db dbplugin.Database, req dbplugin.NewUserRequest) dbplugin.NewUserResponse {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), getRequestTimeout(t))
	defer cancel()

	resp, err := db.NewUser(ctx, req)
	require.NoError(t, err, "Failed to create new user")

	if resp.Username == "" {
		t.Fatal("Missing username from NewUser response")
	}
	return resp
}

func AssertUpdateUser(t *testing.T, db dbplugin.Database, req dbplugin.UpdateUserRequest) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), getRequestTimeout(t))
	defer cancel()

	_, err := db.UpdateUser(ctx, req)
	require.NoError(t, err, "Failed to update user")
}

func AssertDeleteUser(t *testing.T, db dbplugin.Database, req dbplugin.DeleteUserRequest) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), getRequestTimeout(t))
	defer cancel()

	_, err := db.DeleteUser(ctx, req)
	require.NoErrorf(t, err, "Failed to delete user %q", req.Username)
}

func AssertClose(t *testing.T, db dbplugin.Database) {
	t.Helper()
	err := db.Close()
	require.NoError(t, err, "Failed to close database")
}
