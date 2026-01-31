// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package openldap

import (
	"context"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
)

func TestCreds(t *testing.T) {
	t.Run("happy path with creds", func(t *testing.T) {
		b, storage := getBackend(t, false)
		defer b.Cleanup(context.Background())

		data := map[string]interface{}{
			"binddn":      "tester",
			"bindpass":    "pa$$w0rd",
			"url":         "ldap://138.91.247.105",
			"certificate": validCertificate,
		}

		req := &logical.Request{
			Operation: logical.CreateOperation,
			Path:      configPath,
			Storage:   storage,
			Data:      data,
		}

		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%s resp:%#v\n", err, resp)
		}

		data = map[string]interface{}{
			"username":        "hashicorp",
			"dn":              "uid=hashicorp,ou=users,dc=hashicorp,dc=com",
			"rotation_period": "60s",
		}

		req = &logical.Request{
			Operation: logical.CreateOperation,
			Path:      staticRolePath + "hashicorp",
			Storage:   storage,
			Data:      data,
		}

		resp, err = b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%s resp:%#v\n", err, resp)
		}

		req = &logical.Request{
			Operation: logical.ReadOperation,
			Path:      staticRolePath + "hashicorp",
			Storage:   storage,
			Data:      nil,
		}

		resp, err = b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%s resp:%#v\n", err, resp)
		}

		req = &logical.Request{
			Operation: logical.ReadOperation,
			Path:      staticCredPath + "hashicorp",
			Storage:   storage,
			Data:      nil,
		}

		resp, err = b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%s resp:%#v\n", err, resp)
		}

		if resp.Data["dn"] == "" {
			t.Fatal("expected dn to be set, it wasn't")
		}

		if resp.Data["password"] == "" {
			t.Fatal("expected password to be set, it wasn't")
		}

		if resp.Data["username"] == "" {
			t.Fatal("expected username to be set, it wasn't")
		}

		if resp.Data["last_vault_rotation"] == nil {
			t.Fatal("expected last_vault_rotation to be set, it wasn't")
		}

		if resp.Data["rotation_period"] != float64(60) {
			t.Fatalf("expected rotation_period to be %f, got %f", float64(60), resp.Data["rotation_period"])
		}

		if resp.Data["ttl"] == nil {
			t.Fatal("expected ttl to be set, it wasn't")
		}
	})

	t.Run("cred doesn't exist", func(t *testing.T) {
		b, storage := getBackend(t, false)
		defer b.Cleanup(context.Background())

		req := &logical.Request{
			Operation: logical.ReadOperation,
			Path:      staticCredPath + "hashicorp",
			Storage:   storage,
			Data:      nil,
		}

		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil {
			t.Fatalf("error reading cred: %s", err)
		}
		if resp == nil || !resp.IsError() {
			t.Fatal("expected error")
		}
	})
}
