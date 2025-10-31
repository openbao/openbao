// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package identity

import (
	"context"
	"testing"

	"github.com/kr/pretty"
	"github.com/openbao/openbao/api/v2"
	vaulthttp "github.com/openbao/openbao/http"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/vault"
)

func TestIdentityStore_EntityDisabled(t *testing.T) {
	be := &framework.Backend{
		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{
				"login*",
			},
		},
		Paths: []*framework.Path{
			{
				Pattern: "login",
				Callbacks: map[logical.Operation]framework.OperationFunc{
					logical.ReadOperation: func(context.Context, *logical.Request, *framework.FieldData) (*logical.Response, error) {
						return &logical.Response{
							Headers: map[string][]string{
								"www-authenticate": {"Negotiate"},
							},
						}, logical.CodedError(401, "authentication required")
					},
				},
			},
			{
				Pattern: "loginnoerror",
				Callbacks: map[logical.Operation]framework.OperationFunc{
					logical.ReadOperation: func(context.Context, *logical.Request, *framework.FieldData) (*logical.Response, error) {
						return &logical.Response{
							Auth: &logical.Auth{},
							Headers: map[string][]string{
								"www-authenticate": {"Negotiate"},
							},
						}, nil
					},
				},
			},
		},
		BackendType: logical.TypeCredential,
	}

	// Use a TestCluster and the approle backend to get a token and entity for testing
	coreConfig := &vault.CoreConfig{
		CredentialBackends: map[string]logical.Factory{
			"headtest": func(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
				err := be.Setup(ctx, conf)
				if err != nil {
					return nil, err
				}
				return be, nil
			},
		},
	}
	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
	})
	cluster.Start()
	defer cluster.Cleanup()

	core := cluster.Cores[0].Core
	vault.TestWaitActive(t, core)
	client := cluster.Cores[0].Client

	// Mount the auth backend
	err := client.Sys().EnableAuthWithOptions("headtest", &api.EnableAuthOptions{
		Type: "headtest",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Here, should succeed but we should not see the header since it's
	// not in the allowed list
	resp, err := client.Logical().ReadRaw("auth/headtest/loginnoerror")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("expected code 200, got %d", resp.StatusCode)
	}
	if resp.Header.Get("www-authenticate") != "" {
		t.Fatal("expected header to not be allowed")
	}

	// Should fail but we should not see the header since it's
	// not in the allowed list
	resp, err = client.Logical().ReadRaw("auth/headtest/login")
	if err == nil {
		t.Fatal("expected error")
	}
	if resp.StatusCode != 401 {
		t.Fatalf("expected code 401, got %d", resp.StatusCode)
	}
	if resp.Header.Get("www-authenticate") != "" {
		t.Fatal("expected header to not be allowed")
	}

	// Tune the mount
	err = client.Sys().TuneMount("auth/headtest", api.MountConfigInput{
		AllowedResponseHeaders: []string{"WwW-AuthenTicate"},
	})
	if err != nil {
		t.Fatal(err)
	}

	resp, err = client.Logical().ReadRaw("auth/headtest/loginnoerror")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("expected code 200, got %d", resp.StatusCode)
	}
	if resp.Header.Get("www-authenticate") != "Negotiate" {
		t.Fatalf("expected negotiate header; headers:\n%s", pretty.Sprint(resp.Header))
	}

	resp, err = client.Logical().ReadRaw("auth/headtest/login")
	if err == nil {
		t.Fatal("expected error")
	}
	if resp.StatusCode != 401 {
		t.Fatalf("expected code 401, got %d", resp.StatusCode)
	}
	if resp.Header.Get("www-authenticate") != "Negotiate" {
		t.Fatalf("expected negotiate header; headers:\n%s", pretty.Sprint(resp.Header))
	}
}
