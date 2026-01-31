// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package openldap

import (
	"context"
	"testing"
	"time"

	log "github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/helper/logging"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/sdk/v2/queue"
	"github.com/stretchr/testify/require"
)

func TestAutoRotate(t *testing.T) {
	t.Run("auto rotate role", func(t *testing.T) {
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
		if resp.Data["last_password"] == "" {
			t.Fatal("expected last_password to be set after auto rotation, it wasn't")
		}

		if oldPassword == resp.Data["password"] {
			t.Fatal("expected passwords to be different after auto rotation, they weren't")
		}
		if oldPassword != resp.Data["last_password"] {
			t.Fatal("expected last_password to be equal to old password after auto rotation")
		}
	})
}

// TestPasswordPolicyModificationInvalidatesWAL tests that modification of the
// password policy set on the config invalidates pre-generated passwords in WAL
// entries. WAL entries are used to roll forward during partial failure, but
// a password policy change should cause the WAL to be discarded and a new
// password to be generated using the updated policy.
func TestPasswordPolicyModificationInvalidatesWAL(t *testing.T) {
	ctx := context.Background()
	b, storage := getBackend(t, false)
	defer b.Cleanup(ctx)

	configureOpenLDAPMountWithPasswordPolicy(t, b, storage, testPasswordPolicy1)
	createRole(t, b, storage, "hashicorp")

	// Create a WAL entry from a partial failure to rotate
	generateWALFromFailedRotation(t, b, storage, "hashicorp")
	requireWALs(t, storage, 1)

	// The role password should still be the password generated from policy 1
	role, err := b.staticRole(ctx, storage, "hashicorp")
	if err != nil {
		t.Fatal(err)
	}
	if role.StaticAccount.Password != testPasswordFromPolicy1 {
		t.Fatalf("expected %v, got %v", testPasswordFromPolicy1, role.StaticAccount.Password)
	}

	// Update the password policy on the configuration
	configureOpenLDAPMountWithPasswordPolicy(t, b, storage, testPasswordPolicy2)

	// Manually rotate the role. It should not use the password from the WAL entry
	// created earlier. Instead, it should result in generation of a new password
	// using the updated policy 2.
	_, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "rotate-role/hashicorp",
		Storage:   storage,
	})
	if err != nil {
		t.Fatal(err)
	}

	// The role password should be the password generated from policy 2
	role, err = b.staticRole(ctx, storage, "hashicorp")
	if err != nil {
		t.Fatal(err)
	}
	if role.StaticAccount.Password != testPasswordFromPolicy2 {
		t.Fatalf("expected %v, got %v", testPasswordFromPolicy2, role.StaticAccount.Password)
	}
	if role.StaticAccount.LastPassword != testPasswordFromPolicy1 {
		t.Fatalf("expected %v, got %v", testPasswordFromPolicy1, role.StaticAccount.LastPassword)
	}

	// The WAL entry should be deleted after the successful rotation
	requireWALs(t, storage, 0)
}

func TestRollsPasswordForwardsUsingWAL(t *testing.T) {
	ctx := context.Background()
	b, storage := getBackend(t, false)
	defer b.Cleanup(ctx)
	configureOpenLDAPMount(t, b, storage)
	createRole(t, b, storage, "hashicorp")

	role, err := b.staticRole(ctx, storage, "hashicorp")
	if err != nil {
		t.Fatal(err)
	}
	oldPassword := role.StaticAccount.Password

	generateWALFromFailedRotation(t, b, storage, "hashicorp")
	walIDs := requireWALs(t, storage, 1)
	wal, err := b.findStaticWAL(ctx, storage, walIDs[0])
	if err != nil {
		t.Fatal(err)
	}
	role, err = b.staticRole(ctx, storage, "hashicorp")
	if err != nil {
		t.Fatal(err)
	}
	// Role's password should still be the WAL's old password
	if role.StaticAccount.Password != oldPassword {
		t.Fatal(role.StaticAccount.Password, oldPassword)
	}

	// Trigger a retry on the rotation, it should use WAL's new password
	_, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "rotate-role/hashicorp",
		Storage:   storage,
	})
	if err != nil {
		t.Fatal(err)
	}

	role, err = b.staticRole(ctx, storage, "hashicorp")
	if err != nil {
		t.Fatal(err)
	}
	if role.StaticAccount.Password != wal.NewPassword {
		t.Fatal(role.StaticAccount.Password, wal.NewPassword)
	}
	// WAL should be cleared by the successful rotate
	requireWALs(t, storage, 0)
}

func TestStoredWALsCorrectlyProcessed(t *testing.T) {
	const walNewPassword = "new-password-from-wal"
	for _, tc := range []struct {
		name         string
		shouldRotate bool
		wal          *setCredentialsWAL
	}{
		{
			"WAL is kept and used for roll forward",
			true,
			&setCredentialsWAL{
				RoleName:          "hashicorp",
				Username:          "hashicorp",
				DN:                "uid=hashicorp,ou=users,dc=hashicorp,dc=com",
				NewPassword:       walNewPassword,
				LastVaultRotation: time.Now().Add(time.Hour),
			},
		},
		{
			"zero-time WAL is discarded on load",
			false,
			&setCredentialsWAL{
				RoleName:          "hashicorp",
				Username:          "hashicorp",
				DN:                "uid=hashicorp,ou=users,dc=hashicorp,dc=com",
				NewPassword:       walNewPassword,
				LastVaultRotation: time.Time{},
			},
		},
		{
			"empty-password WAL is kept but a new password is generated",
			true,
			&setCredentialsWAL{
				RoleName:          "hashicorp",
				Username:          "hashicorp",
				DN:                "uid=hashicorp,ou=users,dc=hashicorp,dc=com",
				NewPassword:       "",
				LastVaultRotation: time.Now().Add(time.Hour),
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			config := &logical.BackendConfig{
				Logger: logging.NewVaultLogger(log.Debug),

				System: &logical.StaticSystemView{
					DefaultLeaseTTLVal: defaultLeaseTTLVal,
					MaxLeaseTTLVal:     maxLeaseTTLVal,
				},
				StorageView: &logical.InmemStorage{},
			}

			b := Backend(&fakeLdapClient{throwErrs: false})
			if err := b.Setup(context.Background(), config); err != nil {
				t.Fatal(err)
			}

			b.credRotationQueue = queue.New()
			initCtx := context.Background()
			ictx, cancel := context.WithCancel(initCtx)
			b.cancelQueue = cancel

			defer b.Cleanup(ctx)
			configureOpenLDAPMount(t, b, config.StorageView)
			createRole(t, b, config.StorageView, "hashicorp")
			role, err := b.staticRole(ctx, config.StorageView, "hashicorp")
			if err != nil {
				t.Fatal(err)
			}
			initialPassword := role.StaticAccount.Password

			// Set up a WAL for our test case
			framework.PutWAL(ctx, config.StorageView, staticWALKey, tc.wal)
			requireWALs(t, config.StorageView, 1)
			// Reset the rotation queue to simulate startup memory state
			b.credRotationQueue = queue.New()

			// Now finish the startup process by populating the queue, which should discard the WAL
			b.initQueue(ictx, &logical.InitializationRequest{
				Storage: config.StorageView,
			})

			if tc.shouldRotate {
				requireWALs(t, config.StorageView, 1)
			} else {
				requireWALs(t, config.StorageView, 0)
			}

			// Run one tick
			b.rotateCredentials(ctx, config.StorageView)
			requireWALs(t, config.StorageView, 0)

			role, err = b.staticRole(ctx, config.StorageView, "hashicorp")
			if err != nil {
				t.Fatal(err)
			}
			item, err := b.popFromRotationQueueByKey("hashicorp")
			if err != nil {
				t.Fatal(err)
			}

			if tc.shouldRotate {
				if tc.wal.NewPassword != "" {
					// Should use WAL's new_password field
					if role.StaticAccount.Password != walNewPassword {
						t.Fatal()
					}
				} else {
					// Should rotate but ignore WAL's new_password field
					if role.StaticAccount.Password == initialPassword {
						t.Fatal()
					}
					if role.StaticAccount.Password == walNewPassword {
						t.Fatal()
					}
				}
			} else {
				// Ensure the role was not promoted for early rotation
				if item.Priority < time.Now().Add(time.Hour).Unix() {
					t.Fatal("priority should be for about a week away, but was", item.Priority)
				}
				if role.StaticAccount.Password != initialPassword {
					t.Fatal("password should not have been rotated yet")
				}
			}
		})
	}
}

func TestDeletesOlderWALsOnLoad(t *testing.T) {
	ctx := context.Background()
	b, storage := getBackend(t, false)
	defer b.Cleanup(ctx)
	configureOpenLDAPMount(t, b, storage)
	createRole(t, b, storage, "hashicorp")

	// Create 4 WALs, with a clear winner for most recent.
	wal := &setCredentialsWAL{
		RoleName:          "hashicorp",
		Username:          "hashicorp",
		DN:                "uid=hashicorp,ou=users,dc=hashicorp,dc=com",
		NewPassword:       "some-new-password",
		LastVaultRotation: time.Now(),
	}
	for i := 0; i < 3; i++ {
		_, err := framework.PutWAL(ctx, storage, staticWALKey, wal)
		if err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(2 * time.Second)
	// We expect this WAL to have the latest createdAt timestamp
	walID, err := framework.PutWAL(ctx, storage, staticWALKey, wal)
	if err != nil {
		t.Fatal(err)
	}
	requireWALs(t, storage, 4)

	walMap, err := b.loadStaticWALs(ctx, storage)
	if err != nil {
		t.Fatal(err)
	}
	if len(walMap) != 1 || walMap["hashicorp"] == nil || walMap["hashicorp"].walID != walID {
		t.Fatal()
	}
	requireWALs(t, storage, 1)
}

func generateWALFromFailedRotation(t *testing.T, b *backend, storage logical.Storage, roleName string) {
	t.Helper()
	// Fail to rotate the roles
	ldapClient := b.client.(*fakeLdapClient)
	originalValue := ldapClient.throwErrs
	ldapClient.throwErrs = true
	defer func() {
		ldapClient.throwErrs = originalValue
	}()

	_, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "rotate-role/" + roleName,
		Storage:   storage,
	})
	if err == nil {
		t.Fatal("expected error")
	}
}

// returns a slice of the WAL IDs in storage
func requireWALs(t *testing.T, storage logical.Storage, expectedCount int) []string {
	t.Helper()
	wals, err := storage.List(context.Background(), "wal/")
	if err != nil {
		t.Fatal(err)
	}
	if len(wals) != expectedCount {
		t.Fatal("expected WALs", expectedCount, "got", len(wals))
	}

	return wals
}

// Test_backend_findStaticWAL_DecodeWALMissingField tests that WAL decoding in
// findStaticWAL can handle the case where WAL entries have missing fields. This
// can happen when a WAL entry exists prior to a plugin upgrade that changes the
// data in the WAL. The decoding should not panic and set zero values for any
// missing fields.
func Test_backend_findStaticWAL_DecodeWALMissingField(t *testing.T) {
	ctx := context.Background()
	b, storage := getBackend(t, false)
	defer b.Cleanup(ctx)

	// Intentionally missing the PasswordPolicy field
	type priorSetCredentialsWAL struct {
		NewPassword       string    `json:"new_password" mapstructure:"new_password"`
		RoleName          string    `json:"role_name" mapstructure:"role_name"`
		Username          string    `json:"username" mapstructure:"username"`
		DN                string    `json:"dn" mapstructure:"dn"`
		LastVaultRotation time.Time `json:"last_vault_rotation" mapstructure:"last_vault_rotation"`
	}

	// Write a WAL entry to storage
	walEntry := priorSetCredentialsWAL{
		NewPassword:       "Str0ngPassw0rd",
		RoleName:          "test",
		Username:          "static_user",
		DN:                "cn=static_user,ou=users,dc=hashicorp,dc=com",
		LastVaultRotation: time.Now(),
	}
	id, err := framework.PutWAL(ctx, storage, staticWALKey, walEntry)
	require.NoError(t, err)
	require.NotEmpty(t, id)

	// Assert that the decoded WAL entry data matches the original input
	got, err := b.findStaticWAL(ctx, storage, id)
	require.NoError(t, err)
	require.Equal(t, walEntry.NewPassword, got.NewPassword)
	require.Equal(t, walEntry.RoleName, got.RoleName)
	require.Equal(t, walEntry.Username, got.Username)
	require.Equal(t, walEntry.DN, got.DN)
	require.True(t, walEntry.LastVaultRotation.Equal(got.LastVaultRotation))
	require.Equal(t, id, got.walID)

	// Assert that any missing fields take the zero value after decoding
	require.Equal(t, "", got.PasswordPolicy)
}
