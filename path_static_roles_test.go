package openldap

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

func TestRoles(t *testing.T) {
	t.Run("happy path with roles", func(t *testing.T) {
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
			Path:      staticRolePath + "hashicorp",
			Storage:   storage,
			Data:      nil,
		}

		resp, err = b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%s resp:%#v\n", err, resp)
		}

		if resp.Data["dn"] != data["dn"] {
			t.Fatalf("expected dn to be %s but got %s", data["dn"], resp.Data["dn"])
		}

		if resp.Data["username"] != data["username"] {
			t.Fatalf("expected username to be %s but got %s", data["username"], resp.Data["username"])
		}

		if resp.Data["rotation_period"] != float64(5) {
			t.Fatalf("expected rotation_period to be %d but got %s", 5, resp.Data["rotation_period"])
		}

		if resp.Data["last_vault_rotation"] == nil {
			t.Fatal("expected last_vault_rotation to not be empty")
		}
	})
	t.Run("happy path with roles", func(t *testing.T) {
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
			Path:      staticRolePath + "hashicorp",
			Storage:   storage,
			Data:      nil,
		}

		resp, err = b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%s resp:%#v\n", err, resp)
		}

		if resp.Data["dn"] != data["dn"] {
			t.Fatalf("expected dn to be %s but got %s", data["dn"], resp.Data["dn"])
		}

		if resp.Data["username"] != data["username"] {
			t.Fatalf("expected username to be %s but got %s", data["username"], resp.Data["username"])
		}

		if resp.Data["rotation_period"] != float64(5) {
			t.Fatalf("expected rotation_period to be %d but got %s", 5, resp.Data["rotation_period"])
		}

		if resp.Data["last_vault_rotation"] == nil {
			t.Fatal("expected last_vault_rotation to not be empty")
		}
	})

	t.Run("missing dn", func(t *testing.T) {
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

		data = map[string]interface{}{
			"username":        "hashicorp",
			"rotation_period": "5s",
		}

		req = &logical.Request{
			Operation: logical.CreateOperation,
			Path:      staticRolePath + "hashicorp",
			Storage:   storage,
			Data:      data,
		}

		resp, err = b.HandleRequest(context.Background(), req)
		if resp == nil || !resp.IsError() {
			t.Fatal("expected error")
		}
	})

	t.Run("missing username", func(t *testing.T) {
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

		data = map[string]interface{}{
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
		if resp == nil || !resp.IsError() {
			t.Fatal("expected error")
		}
	})

	t.Run("missing rotation_period", func(t *testing.T) {
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

		data = map[string]interface{}{
			"username": "hashicorp",
			"dn":       "uid=hashicorp,ou=users,dc=hashicorp,dc=com",
		}

		req = &logical.Request{
			Operation: logical.CreateOperation,
			Path:      staticRolePath + "hashicorp",
			Storage:   storage,
			Data:      data,
		}

		resp, err = b.HandleRequest(context.Background(), req)
		if resp == nil || !resp.IsError() {
			t.Fatal("expected error")
		}
	})

	t.Run("rotation_period lower than 5s", func(t *testing.T) {
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

		data = map[string]interface{}{
			"username":        "hashicorp",
			"dn":              "uid=hashicorp,ou=users,dc=hashicorp,dc=com",
			"rotation_period": "4s",
		}

		req = &logical.Request{
			Operation: logical.CreateOperation,
			Path:      staticRolePath + "hashicorp",
			Storage:   storage,
			Data:      data,
		}

		resp, err = b.HandleRequest(context.Background(), req)
		if resp == nil || !resp.IsError() {
			t.Fatal("expected error")
		}
	})

	t.Run("user doesn't exist (ldap error)", func(t *testing.T) {
		b, storage := getBackend(true)
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
			"rotation_period": "5s",
		}

		req = &logical.Request{
			Operation: logical.CreateOperation,
			Path:      staticRolePath + "hashicorp",
			Storage:   storage,
			Data:      data,
		}

		resp, err = b.HandleRequest(context.Background(), req)
		if err == nil {
			t.Fatal("expected error, got none")
		}
	})

	t.Run("role doesn't exist", func(t *testing.T) {
		b, storage := getBackend(false)
		defer b.Cleanup(context.Background())

		req := &logical.Request{
			Operation: logical.ReadOperation,
			Path:      staticRolePath + "hashicorp",
			Storage:   storage,
			Data:      nil,
		}

		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil {
			t.Fatalf("error reading role: %s", err)
		}
		if resp != nil {
			t.Fatal("expected error")
		}
	})
}

func TestListRoles(t *testing.T) {
	t.Run("list roles", func(t *testing.T) {
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

		data = map[string]interface{}{
			"username":        "vault",
			"dn":              "uid=vault,ou=users,dc=hashicorp,dc=com",
			"rotation_period": "5s",
		}

		req = &logical.Request{
			Operation: logical.CreateOperation,
			Path:      staticRolePath + "vault",
			Storage:   storage,
			Data:      data,
		}

		resp, err = b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%s resp:%#v\n", err, resp)
		}

		req = &logical.Request{
			Operation: logical.ListOperation,
			Path:      staticRolePath,
			Storage:   storage,
			Data:      nil,
		}

		resp, err = b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%s resp:%#v\n", err, resp)
		}

		if len(resp.Data["keys"].([]string)) != 2 {
			t.Fatalf("expected list with %d keys, got %d", 2, len(resp.Data["keys"].([]string)))
		}
	})
}

func TestWALsStillTrackedAfterUpdate(t *testing.T) {
	ctx := context.Background()
	b, storage := getBackend(false)
	defer b.Cleanup(ctx)
	configureOpenLDAPMount(t, b, storage)

	createRole(t, b, storage, "hashicorp")

	generateWALFromFailedRotation(t, b, storage, "hashicorp")
	requireWALs(t, storage, 1)

	_, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      staticRolePath + "hashicorp",
		Storage:   storage,
		Data: map[string]interface{}{
			"username":        "hashicorp",
			"dn":              "uid=hashicorp,ou=users,dc=hashicorp,dc=com",
			"rotation_period": "600s",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	walIDs := requireWALs(t, storage, 1)

	// Now when we trigger a manual rotate, it should use the WAL's new password
	// which will tell us that the in-memory structure still kept track of the
	// WAL in addition to it still being in storage.
	wal, err := b.findStaticWAL(ctx, storage, walIDs[0])
	if err != nil {
		t.Fatal(err)
	}
	_, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "rotate-role/hashicorp",
		Storage:   storage,
	})
	if err != nil {
		t.Fatal(err)
	}
	role, err := b.staticRole(ctx, storage, "hashicorp")
	if err != nil {
		t.Fatal(err)
	}
	if role.StaticAccount.Password != wal.NewPassword {
		t.Fatal()
	}
	requireWALs(t, storage, 0)
}

func TestWALsDeletedOnRoleCreationFailed(t *testing.T) {
	ctx := context.Background()
	b, storage := getBackend(true)
	defer b.Cleanup(ctx)
	configureOpenLDAPMount(t, b, storage)

	for i := 0; i < 3; i++ {
		resp, err := b.HandleRequest(ctx, &logical.Request{
			Operation: logical.CreateOperation,
			Path:      staticRolePath + "hashicorp",
			Storage:   storage,
			Data: map[string]interface{}{
				"username":        "hashicorp",
				"dn":              "uid=hashicorp,ou=users,dc=hashicorp,dc=com",
				"rotation_period": "5s",
			},
		})
		if err == nil {
			t.Fatal("expected error from OpenLDAP")
		}
		if !strings.Contains(err.Error(), "forced error") {
			t.Fatal("expected forced error message", resp, err)
		}
	}

	requireWALs(t, storage, 0)
}

func TestWALsDeletedOnRoleDeletion(t *testing.T) {
	ctx := context.Background()
	b, storage := getBackend(false)
	defer b.Cleanup(ctx)
	configureOpenLDAPMount(t, b, storage)

	// Create the roles
	roleNames := []string{"hashicorp", "2"}
	for _, roleName := range roleNames {
		createRole(t, b, storage, roleName)
	}

	// Fail to rotate the roles
	for _, roleName := range roleNames {
		generateWALFromFailedRotation(t, b, storage, roleName)
	}

	// Should have 2 WALs hanging around
	requireWALs(t, storage, 2)

	// Delete one of the static roles
	_, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "static-role/hashicorp",
		Storage:   storage,
	})
	if err != nil {
		t.Fatal(err)
	}

	// 1 WAL should be cleared by the delete
	requireWALs(t, storage, 1)
}

func configureOpenLDAPMount(t *testing.T, b *backend, storage logical.Storage) {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      configPath,
		Storage:   storage,
		Data: map[string]interface{}{
			"binddn":      "tester",
			"bindpass":    "pa$$w0rd",
			"url":         "ldap://138.91.247.105",
			"certificate": validCertificate,
		},
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}
}

func createRole(t *testing.T, b *backend, storage logical.Storage, roleName string) {
	_, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "static-role/" + roleName,
		Storage:   storage,
		Data: map[string]interface{}{
			"username":        roleName,
			"dn":              "uid=hashicorp,ou=users,dc=hashicorp,dc=com",
			"rotation_period": "86400s",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
}
