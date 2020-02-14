package openldap

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

func TestAutoRotate(t *testing.T) {
	t.Run("auto rotate role", func(t *testing.T) {
		b, storage := getBackend(false)
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
			Operation: logical.CreateOperation,
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
			"rotation_period": "5s",
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

		// Wait for auto rotation (5s) + 1 second for breathing room
		time.Sleep(time.Second * 6)

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
			t.Fatal("expected password to be set after auto rotation, it wasn't")
		}

		if oldPassword == resp.Data["password"] {
			t.Fatal("expected passwords to be different after auto rotation, they weren't")
		}
	})
}
