// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package userpass

import (
	"context"
	"testing"
	"time"

	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
)

func TestPathLogin_TimingLeak(t *testing.T) {
	storage := &logical.InmemStorage{}
	config := logical.TestBackendConfig()
	config.StorageView = storage

	ctx := namespace.RootContext(context.Background())
	b, err := Factory(ctx, config)
	require.NoError(t, err)
	require.NotNil(t, b)

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "users/test",
		Storage:   storage,
		Data: map[string]interface{}{
			"password": "password",
			"policies": "foo",
		},
	}

	// Create user
	_, err = b.HandleRequest(ctx, req)
	require.NoError(t, err)

	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login/test",
		Storage:   storage,
		Data: map[string]interface{}{
			"password": "invalid-password",
		},
	}

	start := time.Now()
	resp, err := b.HandleRequest(ctx, req)
	existingUserTime := time.Since(start)
	require.Equal(t, resp.Data["error"], "invalid username or password")
	require.ErrorIs(t, err, logical.ErrInvalidCredentials)

	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login/non-existing",
		Storage:   storage,
		Data: map[string]interface{}{
			"password": "invalid-password",
		},
	}

	start = time.Now()
	resp, err = b.HandleRequest(ctx, req)
	notExistingUserTime := time.Since(start)
	require.Equal(t, resp.Data["error"], "invalid username or password")
	require.Nil(t, err)

	// verify that read of existing user takes the
	// same amount of time as read of non-existing user
	require.InDelta(t, existingUserTime.Abs().Milliseconds(), notExistingUserTime.Abs().Milliseconds(), float64(time.Millisecond))
}
