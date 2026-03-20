// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package openldap

import (
	"context"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
)

func TestManualRotate(t *testing.T) {
	t.Run("rotate root", func(t *testing.T) {
		b, storage := getBackend(t, false)
		defer b.Cleanup(context.Background())

		originalBindPass := "pa$$w0rd"

		data := map[string]interface{}{
			"binddn":      "tester",
			"bindpass":    originalBindPass,
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

		req = &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      rotateRootPath,
			Storage:   storage,
			Data:      nil,
		}

		resp, err = b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%s resp:%#v\n", err, resp)
		}

		config, err := readConfig(context.Background(), storage)
		if err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
		if config.LDAP.LastBindPassword != originalBindPass {
			t.Fatalf("expected last_bind_password %q, got %q", originalBindPass,
				config.LDAP.LastBindPassword)
		}
		if config.LDAP.LastBindPasswordRotation.IsZero() {
			t.Fatal("expected last_bind_password_rotation to not be the zero time instant")
		}
	})

	t.Run("rotate root that doesn't exist", func(t *testing.T) {
		b, storage := getBackend(t, false)
		defer b.Cleanup(context.Background())

		req := &logical.Request{
			Operation: logical.CreateOperation,
			Path:      rotateRootPath,
			Storage:   storage,
			Data:      nil,
		}

		_, err := b.HandleRequest(context.Background(), req)
		if err == nil {
			t.Fatal("should have got error, didn't")
		}
	})

	t.Run("rotate role", func(t *testing.T) {
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

		req = &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      rotateRootPath,
			Storage:   storage,
			Data:      nil,
		}

		resp, err = b.HandleRequest(context.Background(), req)
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
			Path:      staticCredPath + "hashicorp",
			Storage:   storage,
			Data:      nil,
		}

		resp, err = b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%s resp:%#v\n", err, resp)
		}

		if resp.Data["password"] == "" {
			t.Fatal("expected password to be set, it wasn't")
		}
		oldPassword := resp.Data["password"]

		req = &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      rotateRolePath + "hashicorp",
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

		if resp.Data["password"] == "" {
			t.Fatal("expected password to be set after rotate, it wasn't")
		}

		if oldPassword == resp.Data["password"] {
			t.Fatal("expected passwords to be different after rotation, they weren't")
		}
	})

	t.Run("rotate role that doesn't exist", func(t *testing.T) {
		b, storage := getBackend(t, false)
		defer b.Cleanup(context.Background())

		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      rotateRolePath + "hashicorp",
			Storage:   storage,
			Data:      nil,
		}

		resp, _ := b.HandleRequest(context.Background(), req)
		if resp == nil || !resp.IsError() {
			t.Fatal("expected error")
		}
	})
}
