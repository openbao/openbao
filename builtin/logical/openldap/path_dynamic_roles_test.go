// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package openldap

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"path"
	"reflect"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestDynamicRoleCreateUpdate(t *testing.T) {
	roleName := "testrole"

	type testCase struct {
		operation  logical.Operation
		createData *framework.FieldData

		putErr   error
		putTimes int

		expectErr bool
	}

	tests := map[string]testCase{
		"bad default_ttl": {
			operation: logical.CreateOperation,
			createData: dynamicRoleFieldData(map[string]interface{}{
				"name":          roleName,
				"default_ttl":   "foo",
				"creation_ldif": ldifCreationTemplate,
				"deletion_ldif": ldifDeleteTemplate,
			}),

			putErr:   nil,
			putTimes: 0,

			expectErr: true,
		},
		"bad max_ttl": {
			operation: logical.CreateOperation,
			createData: dynamicRoleFieldData(map[string]interface{}{
				"name":          roleName,
				"max_ttl":       "foo",
				"creation_ldif": ldifCreationTemplate,
				"deletion_ldif": ldifDeleteTemplate,
			}),

			putErr:   nil,
			putTimes: 0,

			expectErr: true,
		},
		"missing creation_ldif": {
			operation: logical.CreateOperation,
			createData: dynamicRoleFieldData(map[string]interface{}{
				"name":          roleName,
				"deletion_ldif": ldifDeleteTemplate,
			}),

			putErr:   nil,
			putTimes: 0,

			expectErr: true,
		},
		"missing deletion_ldif": {
			operation: logical.CreateOperation,
			createData: dynamicRoleFieldData(map[string]interface{}{
				"name":          roleName,
				"creation_ldif": ldifCreationTemplate,
			}),

			putErr:   nil,
			putTimes: 0,

			expectErr: true,
		},
		"creation_ldif bad template syntax": {
			operation: logical.CreateOperation,
			createData: dynamicRoleFieldData(map[string]interface{}{
				"name":          roleName,
				"creation_ldif": `dn: cn={{.Username,ou=users,dc=learn,dc=example`,
				"deletion_ldif": ldifDeleteTemplate,
			}),

			putErr:   nil,
			putTimes: 0,

			expectErr: true,
		},
		"creation_ldif bad LDIF syntax": {
			operation: logical.CreateOperation,
			createData: dynamicRoleFieldData(map[string]interface{}{
				"name":          roleName,
				"creation_ldif": `foo bar`,
				"deletion_ldif": ldifDeleteTemplate,
			}),

			putErr:   nil,
			putTimes: 0,

			expectErr: true,
		},
		"deletion_ldif bad template syntax": {
			operation: logical.CreateOperation,
			createData: dynamicRoleFieldData(map[string]interface{}{
				"name":          roleName,
				"creation_ldif": ldifCreationTemplate,
				"deletion_ldif": "dn: cn={{.Username,ou=users,dc=learn,dc=example\nchangetype: delete",
			}),

			putErr:   nil,
			putTimes: 0,

			expectErr: true,
		},
		"deletion_ldif bad LDIF syntax": {
			operation: logical.CreateOperation,
			createData: dynamicRoleFieldData(map[string]interface{}{
				"name":          roleName,
				"creation_ldif": ldifCreationTemplate,
				"deletion_ldif": `foo bar`,
			}),

			putErr:   nil,
			putTimes: 0,

			expectErr: true,
		},
		"rollback_ldif bad template syntax": {
			operation: logical.CreateOperation,
			createData: dynamicRoleFieldData(map[string]interface{}{
				"name":          roleName,
				"creation_ldif": ldifCreationTemplate,
				"deletion_ldif": ldifDeleteTemplate,
				"rollback_ldif": "dn: cn={{.Username,ou=users,dc=learn,dc=example\nchangetype: delete",
			}),

			putErr:   nil,
			putTimes: 0,

			expectErr: true,
		},
		"rollback_ldif bad LDIF syntax": {
			operation: logical.CreateOperation,
			createData: dynamicRoleFieldData(map[string]interface{}{
				"name":          roleName,
				"creation_ldif": ldifCreationTemplate,
				"deletion_ldif": ldifDeleteTemplate,
				"rollback_ldif": `foo bar`,
			}),

			putErr:   nil,
			putTimes: 0,

			expectErr: true,
		},
		"multiple LDIF entries": {
			operation: logical.CreateOperation,
			createData: dynamicRoleFieldData(map[string]interface{}{
				"name":          roleName,
				"creation_ldif": ldifCreateAndModifyTemplate,
				"deletion_ldif": ldifDeleteTemplate,
			}),

			putErr:   nil,
			putTimes: 1,

			expectErr: false,
		},
		"storage error": {
			operation: logical.CreateOperation,
			createData: dynamicRoleFieldData(map[string]interface{}{
				"name":          roleName,
				"creation_ldif": ldifCreationTemplate,
				"deletion_ldif": ldifDeleteTemplate,
			}),

			putErr:   errors.New("test error"),
			putTimes: 1,

			expectErr: true,
		},
		"happy path": {
			operation: logical.CreateOperation,
			createData: dynamicRoleFieldData(map[string]interface{}{
				"name":          roleName,
				"creation_ldif": ldifCreationTemplate,
				"deletion_ldif": ldifDeleteTemplate,
			}),

			putErr:   nil,
			putTimes: 1,

			expectErr: false,
		},
		"base64 encoded templates": {
			operation: logical.CreateOperation,
			createData: dynamicRoleFieldData(map[string]interface{}{
				"name":          roleName,
				"creation_ldif": base64Encode(ldifCreationTemplate),
				"rollback_ldif": base64Encode(ldifRollbackTemplate),
				"deletion_ldif": base64Encode(ldifDeleteTemplate),
			}),

			putErr:   nil,
			putTimes: 1,

			expectErr: false,
		},
		"update operation with missing role": {
			operation: logical.UpdateOperation,
			createData: dynamicRoleFieldData(map[string]interface{}{
				"name":          roleName,
				"creation_ldif": base64Encode(ldifCreationTemplate),
				"rollback_ldif": base64Encode(ldifRollbackTemplate),
				"deletion_ldif": base64Encode(ldifDeleteTemplate),
			}),

			putErr:   nil,
			putTimes: 0,

			expectErr: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			client := new(mockLDAPClient)
			defer client.AssertExpectations(t) // No expectations

			b := Backend(client)

			storage := new(mockStorage)
			storage.On("Get", mock.Anything, mock.Anything).
				Return((*logical.StorageEntry)(nil), (error)(nil)).Maybe()
			storage.On("Put", mock.Anything, mock.Anything).
				Return(test.putErr)
			defer storage.AssertNumberOfCalls(t, "Put", test.putTimes)

			req := &logical.Request{
				Operation: test.operation,
				Storage:   storage,
			}

			// ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			ctx := context.Background()
			// defer cancel()

			_, err := b.pathDynamicRoleCreateUpdate(ctx, req, test.createData)
			if test.expectErr && err == nil {
				t.Fatalf("err expected, got nil")
			}
			if !test.expectErr && err != nil {
				t.Fatalf("no error expected, got: %s", err)
			}
		})
	}
}

func TestDynamicRole_partialUpdate(t *testing.T) {
	type testCase struct {
		initialData map[string]interface{}
		initialRole *dynamicRole

		updateData map[string]interface{}
		updateRole *dynamicRole
		expectErr  bool
	}

	roleName := "test-role"

	tests := map[string]testCase{
		"new default_ttl": {
			initialData: map[string]interface{}{
				"name":              roleName,
				"creation_ldif":     ldifCreationTemplate,
				"deletion_ldif":     ldifDeleteTemplate,
				"rollback_ldif":     ldifRollbackTemplate,
				"username_template": "v-foo-{{.RoleName}}-{{rand 20}}-{{unix_seconds}}",
				"default_ttl":       "10s",
				"max_ttl":           "1m",
			},
			initialRole: &dynamicRole{
				Name:             roleName,
				CreationLDIF:     ldifCreationTemplate,
				DeletionLDIF:     ldifDeleteTemplate,
				RollbackLDIF:     ldifRollbackTemplate,
				UsernameTemplate: "v-foo-{{.RoleName}}-{{rand 20}}-{{unix_seconds}}",
				DefaultTTL:       10 * time.Second,
				MaxTTL:           1 * time.Minute,
			},

			updateData: map[string]interface{}{
				"name":        roleName,
				"default_ttl": "30s",
			},
			updateRole: &dynamicRole{
				Name:             roleName,
				CreationLDIF:     ldifCreationTemplate,
				DeletionLDIF:     ldifDeleteTemplate,
				RollbackLDIF:     ldifRollbackTemplate,
				UsernameTemplate: "v-foo-{{.RoleName}}-{{rand 20}}-{{unix_seconds}}",
				DefaultTTL:       30 * time.Second,
				MaxTTL:           1 * time.Minute,
			},
			expectErr: false,
		},
		"new max_ttl": {
			initialData: map[string]interface{}{
				"name":              roleName,
				"creation_ldif":     ldifCreationTemplate,
				"deletion_ldif":     ldifDeleteTemplate,
				"rollback_ldif":     ldifRollbackTemplate,
				"username_template": "v-foo-{{.RoleName}}-{{rand 20}}-{{unix_seconds}}",
				"default_ttl":       "10s",
				"max_ttl":           "1m",
			},
			initialRole: &dynamicRole{
				Name:             roleName,
				CreationLDIF:     ldifCreationTemplate,
				DeletionLDIF:     ldifDeleteTemplate,
				RollbackLDIF:     ldifRollbackTemplate,
				UsernameTemplate: "v-foo-{{.RoleName}}-{{rand 20}}-{{unix_seconds}}",
				DefaultTTL:       10 * time.Second,
				MaxTTL:           1 * time.Minute,
			},

			updateData: map[string]interface{}{
				"name":    roleName,
				"max_ttl": "2m",
			},
			updateRole: &dynamicRole{
				Name:             roleName,
				CreationLDIF:     ldifCreationTemplate,
				DeletionLDIF:     ldifDeleteTemplate,
				RollbackLDIF:     ldifRollbackTemplate,
				UsernameTemplate: "v-foo-{{.RoleName}}-{{rand 20}}-{{unix_seconds}}",
				DefaultTTL:       10 * time.Second,
				MaxTTL:           2 * time.Minute,
			},
			expectErr: false,
		},
		"new creation_ldif": {
			initialData: map[string]interface{}{
				"name":              roleName,
				"creation_ldif":     ldifCreationTemplate,
				"deletion_ldif":     ldifDeleteTemplate,
				"rollback_ldif":     ldifRollbackTemplate,
				"username_template": "v-foo-{{.RoleName}}-{{rand 20}}-{{unix_seconds}}",
				"default_ttl":       "10s",
				"max_ttl":           "1m",
			},
			initialRole: &dynamicRole{
				Name:             roleName,
				CreationLDIF:     ldifCreationTemplate,
				DeletionLDIF:     ldifDeleteTemplate,
				RollbackLDIF:     ldifRollbackTemplate,
				UsernameTemplate: "v-foo-{{.RoleName}}-{{rand 20}}-{{unix_seconds}}",
				DefaultTTL:       10 * time.Second,
				MaxTTL:           1 * time.Minute,
			},

			updateData: map[string]interface{}{
				"name": roleName,
				"creation_ldif": `dn: cn={{.Username}},ou=users,dc=hashicorp,dc=com
objectClass: person2
objectClass: top2
cn: learn2
sn: learn2
memberOf: cn=dev,ou=groups,dc=hashicorp,dc=com
userPassword: {{.Password}}`,
			},
			updateRole: &dynamicRole{
				Name: roleName,
				CreationLDIF: `dn: cn={{.Username}},ou=users,dc=hashicorp,dc=com
objectClass: person2
objectClass: top2
cn: learn2
sn: learn2
memberOf: cn=dev,ou=groups,dc=hashicorp,dc=com
userPassword: {{.Password}}`,
				DeletionLDIF:     ldifDeleteTemplate,
				RollbackLDIF:     ldifRollbackTemplate,
				UsernameTemplate: "v-foo-{{.RoleName}}-{{rand 20}}-{{unix_seconds}}",
				DefaultTTL:       10 * time.Second,
				MaxTTL:           1 * time.Minute,
			},
			expectErr: false,
		},
		"new deletion_ldif": {
			initialData: map[string]interface{}{
				"name":              roleName,
				"creation_ldif":     ldifCreationTemplate,
				"deletion_ldif":     ldifDeleteTemplate,
				"rollback_ldif":     ldifRollbackTemplate,
				"username_template": "v-foo-{{.RoleName}}-{{rand 20}}-{{unix_seconds}}",
				"default_ttl":       "10s",
				"max_ttl":           "1m",
			},
			initialRole: &dynamicRole{
				Name:             roleName,
				CreationLDIF:     ldifCreationTemplate,
				DeletionLDIF:     ldifDeleteTemplate,
				RollbackLDIF:     ldifRollbackTemplate,
				UsernameTemplate: "v-foo-{{.RoleName}}-{{rand 20}}-{{unix_seconds}}",
				DefaultTTL:       10 * time.Second,
				MaxTTL:           1 * time.Minute,
			},

			updateData: map[string]interface{}{
				"name": roleName,
				"deletion_ldif": `dn: cn={{.Username | lowercase}},ou=users,dc=learn,dc=example
changetype: delete`,
			},
			updateRole: &dynamicRole{
				Name:         roleName,
				CreationLDIF: ldifCreationTemplate,
				DeletionLDIF: `dn: cn={{.Username | lowercase}},ou=users,dc=learn,dc=example
changetype: delete`,
				RollbackLDIF:     ldifRollbackTemplate,
				UsernameTemplate: "v-foo-{{.RoleName}}-{{rand 20}}-{{unix_seconds}}",
				DefaultTTL:       10 * time.Second,
				MaxTTL:           1 * time.Minute,
			},
			expectErr: false,
		},
		"new rollback_ldif": {
			initialData: map[string]interface{}{
				"name":              roleName,
				"creation_ldif":     ldifCreationTemplate,
				"deletion_ldif":     ldifDeleteTemplate,
				"rollback_ldif":     ldifRollbackTemplate,
				"username_template": "v-foo-{{.RoleName}}-{{rand 20}}-{{unix_seconds}}",
				"default_ttl":       "10s",
				"max_ttl":           "1m",
			},
			initialRole: &dynamicRole{
				Name:             roleName,
				CreationLDIF:     ldifCreationTemplate,
				DeletionLDIF:     ldifDeleteTemplate,
				RollbackLDIF:     ldifRollbackTemplate,
				UsernameTemplate: "v-foo-{{.RoleName}}-{{rand 20}}-{{unix_seconds}}",
				DefaultTTL:       10 * time.Second,
				MaxTTL:           1 * time.Minute,
			},

			updateData: map[string]interface{}{
				"name": roleName,
				"rollback_ldif": `dn: cn={{.Username | lowercase}},ou=users,dc=learn,dc=example
changetype: delete`,
			},
			updateRole: &dynamicRole{
				Name:         roleName,
				CreationLDIF: ldifCreationTemplate,
				DeletionLDIF: ldifDeleteTemplate,
				RollbackLDIF: `dn: cn={{.Username | lowercase}},ou=users,dc=learn,dc=example
changetype: delete`,
				UsernameTemplate: "v-foo-{{.RoleName}}-{{rand 20}}-{{unix_seconds}}",
				DefaultTTL:       10 * time.Second,
				MaxTTL:           1 * time.Minute,
			},
			expectErr: false,
		},
		"new username_template": {
			initialData: map[string]interface{}{
				"name":              roleName,
				"creation_ldif":     ldifCreationTemplate,
				"deletion_ldif":     ldifDeleteTemplate,
				"rollback_ldif":     ldifRollbackTemplate,
				"username_template": "v-foo-{{.RoleName}}-{{rand 20}}-{{unix_seconds}}",
				"default_ttl":       "10s",
				"max_ttl":           "1m",
			},
			initialRole: &dynamicRole{
				Name:             roleName,
				CreationLDIF:     ldifCreationTemplate,
				DeletionLDIF:     ldifDeleteTemplate,
				RollbackLDIF:     ldifRollbackTemplate,
				UsernameTemplate: "v-foo-{{.RoleName}}-{{rand 20}}-{{unix_seconds}}",
				DefaultTTL:       10 * time.Second,
				MaxTTL:           1 * time.Minute,
			},

			updateData: map[string]interface{}{
				"name":              roleName,
				"username_template": "v.{{.RoleName | lowercase}}.{{rand 10}}",
			},
			updateRole: &dynamicRole{
				Name:             roleName,
				CreationLDIF:     ldifCreationTemplate,
				DeletionLDIF:     ldifDeleteTemplate,
				RollbackLDIF:     ldifRollbackTemplate,
				UsernameTemplate: "v.{{.RoleName | lowercase}}.{{rand 10}}",
				DefaultTTL:       10 * time.Second,
				MaxTTL:           1 * time.Minute,
			},
			expectErr: false,
		},
		"removed creation_ldif": {
			initialData: map[string]interface{}{
				"name":              roleName,
				"creation_ldif":     ldifCreationTemplate,
				"deletion_ldif":     ldifDeleteTemplate,
				"rollback_ldif":     ldifRollbackTemplate,
				"username_template": "v-foo-{{.RoleName}}-{{rand 20}}-{{unix_seconds}}",
				"default_ttl":       "10s",
				"max_ttl":           "1m",
			},
			initialRole: &dynamicRole{
				Name:             roleName,
				CreationLDIF:     ldifCreationTemplate,
				DeletionLDIF:     ldifDeleteTemplate,
				RollbackLDIF:     ldifRollbackTemplate,
				UsernameTemplate: "v-foo-{{.RoleName}}-{{rand 20}}-{{unix_seconds}}",
				DefaultTTL:       10 * time.Second,
				MaxTTL:           1 * time.Minute,
			},

			updateData: map[string]interface{}{
				"name":          roleName,
				"creation_ldif": "",
			},
			updateRole: &dynamicRole{
				Name:             roleName,
				CreationLDIF:     ldifCreationTemplate,
				DeletionLDIF:     ldifDeleteTemplate,
				RollbackLDIF:     ldifRollbackTemplate,
				UsernameTemplate: "v-foo-{{.RoleName}}-{{rand 20}}-{{unix_seconds}}",
				DefaultTTL:       10 * time.Second,
				MaxTTL:           1 * time.Minute,
			},
			expectErr: true,
		},
		"removed deletion_ldif": {
			initialData: map[string]interface{}{
				"name":              roleName,
				"creation_ldif":     ldifCreationTemplate,
				"deletion_ldif":     ldifDeleteTemplate,
				"rollback_ldif":     ldifRollbackTemplate,
				"username_template": "v-foo-{{.RoleName}}-{{rand 20}}-{{unix_seconds}}",
				"default_ttl":       "10s",
				"max_ttl":           "1m",
			},
			initialRole: &dynamicRole{
				Name:             roleName,
				CreationLDIF:     ldifCreationTemplate,
				DeletionLDIF:     ldifDeleteTemplate,
				RollbackLDIF:     ldifRollbackTemplate,
				UsernameTemplate: "v-foo-{{.RoleName}}-{{rand 20}}-{{unix_seconds}}",
				DefaultTTL:       10 * time.Second,
				MaxTTL:           1 * time.Minute,
			},

			updateData: map[string]interface{}{
				"name":          roleName,
				"deletion_ldif": "",
			},
			updateRole: &dynamicRole{
				Name:             roleName,
				CreationLDIF:     ldifCreationTemplate,
				DeletionLDIF:     ldifDeleteTemplate,
				RollbackLDIF:     ldifRollbackTemplate,
				UsernameTemplate: "v-foo-{{.RoleName}}-{{rand 20}}-{{unix_seconds}}",
				DefaultTTL:       10 * time.Second,
				MaxTTL:           1 * time.Minute,
			},
			expectErr: true,
		},
		"removed rollback_ldif": {
			initialData: map[string]interface{}{
				"name":              roleName,
				"creation_ldif":     ldifCreationTemplate,
				"deletion_ldif":     ldifDeleteTemplate,
				"rollback_ldif":     ldifRollbackTemplate,
				"username_template": "v-foo-{{.RoleName}}-{{rand 20}}-{{unix_seconds}}",
				"default_ttl":       "10s",
				"max_ttl":           "1m",
			},
			initialRole: &dynamicRole{
				Name:             roleName,
				CreationLDIF:     ldifCreationTemplate,
				DeletionLDIF:     ldifDeleteTemplate,
				RollbackLDIF:     ldifRollbackTemplate,
				UsernameTemplate: "v-foo-{{.RoleName}}-{{rand 20}}-{{unix_seconds}}",
				DefaultTTL:       10 * time.Second,
				MaxTTL:           1 * time.Minute,
			},

			updateData: map[string]interface{}{
				"name":          roleName,
				"rollback_ldif": "", // This field is optional, so deleting it is okay
			},
			updateRole: &dynamicRole{
				Name:             roleName,
				CreationLDIF:     ldifCreationTemplate,
				DeletionLDIF:     ldifDeleteTemplate,
				RollbackLDIF:     "",
				UsernameTemplate: "v-foo-{{.RoleName}}-{{rand 20}}-{{unix_seconds}}",
				DefaultTTL:       10 * time.Second,
				MaxTTL:           1 * time.Minute,
			},
			expectErr: false,
		},
		"removed username_template": {
			initialData: map[string]interface{}{
				"name":              roleName,
				"creation_ldif":     ldifCreationTemplate,
				"deletion_ldif":     ldifDeleteTemplate,
				"rollback_ldif":     ldifRollbackTemplate,
				"username_template": "v-foo-{{.RoleName}}-{{rand 20}}-{{unix_seconds}}",
				"default_ttl":       "10s",
				"max_ttl":           "1m",
			},
			initialRole: &dynamicRole{
				Name:             roleName,
				CreationLDIF:     ldifCreationTemplate,
				DeletionLDIF:     ldifDeleteTemplate,
				RollbackLDIF:     ldifRollbackTemplate,
				UsernameTemplate: "v-foo-{{.RoleName}}-{{rand 20}}-{{unix_seconds}}",
				DefaultTTL:       10 * time.Second,
				MaxTTL:           1 * time.Minute,
			},

			updateData: map[string]interface{}{
				"name":              roleName,
				"username_template": "",
			},
			updateRole: &dynamicRole{
				Name:             roleName,
				CreationLDIF:     ldifCreationTemplate,
				DeletionLDIF:     ldifDeleteTemplate,
				RollbackLDIF:     ldifRollbackTemplate,
				UsernameTemplate: "",
				DefaultTTL:       10 * time.Second,
				MaxTTL:           1 * time.Minute,
			},
			expectErr: false,
		},
		"removed default_ttl (empty string)": {
			initialData: map[string]interface{}{
				"name":              roleName,
				"creation_ldif":     ldifCreationTemplate,
				"deletion_ldif":     ldifDeleteTemplate,
				"rollback_ldif":     ldifRollbackTemplate,
				"username_template": "v-foo-{{.RoleName}}-{{rand 20}}-{{unix_seconds}}",
				"default_ttl":       "10s",
				"max_ttl":           "1m",
			},
			initialRole: &dynamicRole{
				Name:             roleName,
				CreationLDIF:     ldifCreationTemplate,
				DeletionLDIF:     ldifDeleteTemplate,
				RollbackLDIF:     ldifRollbackTemplate,
				UsernameTemplate: "v-foo-{{.RoleName}}-{{rand 20}}-{{unix_seconds}}",
				DefaultTTL:       10 * time.Second,
				MaxTTL:           1 * time.Minute,
			},

			updateData: map[string]interface{}{
				"name":        roleName,
				"default_ttl": "",
			},
			updateRole: &dynamicRole{
				Name:             roleName,
				CreationLDIF:     ldifCreationTemplate,
				DeletionLDIF:     ldifDeleteTemplate,
				RollbackLDIF:     ldifRollbackTemplate,
				UsernameTemplate: "v-foo-{{.RoleName}}-{{rand 20}}-{{unix_seconds}}",
				DefaultTTL:       0,
				MaxTTL:           1 * time.Minute,
			},
			expectErr: false,
		},
		"removed default_ttl (zero)": {
			initialData: map[string]interface{}{
				"name":              roleName,
				"creation_ldif":     ldifCreationTemplate,
				"deletion_ldif":     ldifDeleteTemplate,
				"rollback_ldif":     ldifRollbackTemplate,
				"username_template": "v-foo-{{.RoleName}}-{{rand 20}}-{{unix_seconds}}",
				"default_ttl":       "10s",
				"max_ttl":           "1m",
			},
			initialRole: &dynamicRole{
				Name:             roleName,
				CreationLDIF:     ldifCreationTemplate,
				DeletionLDIF:     ldifDeleteTemplate,
				RollbackLDIF:     ldifRollbackTemplate,
				UsernameTemplate: "v-foo-{{.RoleName}}-{{rand 20}}-{{unix_seconds}}",
				DefaultTTL:       10 * time.Second,
				MaxTTL:           1 * time.Minute,
			},

			updateData: map[string]interface{}{
				"name":        roleName,
				"default_ttl": "0",
			},
			updateRole: &dynamicRole{
				Name:             roleName,
				CreationLDIF:     ldifCreationTemplate,
				DeletionLDIF:     ldifDeleteTemplate,
				RollbackLDIF:     ldifRollbackTemplate,
				UsernameTemplate: "v-foo-{{.RoleName}}-{{rand 20}}-{{unix_seconds}}",
				DefaultTTL:       0,
				MaxTTL:           1 * time.Minute,
			},
			expectErr: false,
		},
		"removed max_ttl (empty string)": {
			initialData: map[string]interface{}{
				"name":              roleName,
				"creation_ldif":     ldifCreationTemplate,
				"deletion_ldif":     ldifDeleteTemplate,
				"rollback_ldif":     ldifRollbackTemplate,
				"username_template": "v-foo-{{.RoleName}}-{{rand 20}}-{{unix_seconds}}",
				"default_ttl":       "10s",
				"max_ttl":           "1m",
			},
			initialRole: &dynamicRole{
				Name:             roleName,
				CreationLDIF:     ldifCreationTemplate,
				DeletionLDIF:     ldifDeleteTemplate,
				RollbackLDIF:     ldifRollbackTemplate,
				UsernameTemplate: "v-foo-{{.RoleName}}-{{rand 20}}-{{unix_seconds}}",
				DefaultTTL:       10 * time.Second,
				MaxTTL:           1 * time.Minute,
			},

			updateData: map[string]interface{}{
				"name":    roleName,
				"max_ttl": "",
			},
			updateRole: &dynamicRole{
				Name:             roleName,
				CreationLDIF:     ldifCreationTemplate,
				DeletionLDIF:     ldifDeleteTemplate,
				RollbackLDIF:     ldifRollbackTemplate,
				UsernameTemplate: "v-foo-{{.RoleName}}-{{rand 20}}-{{unix_seconds}}",
				DefaultTTL:       10 * time.Second,
				MaxTTL:           0,
			},
			expectErr: false,
		},
		"removed max_ttl (zero)": {
			initialData: map[string]interface{}{
				"name":              roleName,
				"creation_ldif":     ldifCreationTemplate,
				"deletion_ldif":     ldifDeleteTemplate,
				"rollback_ldif":     ldifRollbackTemplate,
				"username_template": "v-foo-{{.RoleName}}-{{rand 20}}-{{unix_seconds}}",
				"default_ttl":       "10s",
				"max_ttl":           "1m",
			},
			initialRole: &dynamicRole{
				Name:             roleName,
				CreationLDIF:     ldifCreationTemplate,
				DeletionLDIF:     ldifDeleteTemplate,
				RollbackLDIF:     ldifRollbackTemplate,
				UsernameTemplate: "v-foo-{{.RoleName}}-{{rand 20}}-{{unix_seconds}}",
				DefaultTTL:       10 * time.Second,
				MaxTTL:           1 * time.Minute,
			},

			updateData: map[string]interface{}{
				"name":    roleName,
				"max_ttl": "0",
			},
			updateRole: &dynamicRole{
				Name:             roleName,
				CreationLDIF:     ldifCreationTemplate,
				DeletionLDIF:     ldifDeleteTemplate,
				RollbackLDIF:     ldifRollbackTemplate,
				UsernameTemplate: "v-foo-{{.RoleName}}-{{rand 20}}-{{unix_seconds}}",
				DefaultTTL:       10 * time.Second,
				MaxTTL:           0,
			},
			expectErr: false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			client := new(mockLDAPClient)
			defer client.AssertExpectations(t) // No expectations

			b := Backend(client)

			storage := &logical.InmemStorage{}

			// Find the creation endpoint & use its schema
			var schema map[string]*framework.FieldSchema
			for _, endpoint := range b.pathDynamicRoles() {
				if endpoint.Pattern != path.Join(dynamicRolePath, framework.GenericNameRegex("name")) {
					continue
				}
				if _, exists := endpoint.Operations[logical.CreateOperation]; !exists {
					continue
				}
				schema = endpoint.Fields
			}

			initialData := &framework.FieldData{
				Raw:    test.initialData,
				Schema: schema,
			}

			req := &logical.Request{
				Storage: storage,
			}

			// Shared context, but with timeout to ensure the test ends
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()

			// Save original version
			resp, err := b.pathDynamicRoleCreateUpdate(ctx, req, initialData)
			require.NoError(t, err)
			require.Nil(t, resp)

			actualRole, err := retrieveDynamicRole(ctx, storage, roleName)
			require.NoError(t, err)
			require.Equal(t, test.initialRole, actualRole)

			// Update to new version
			updateData := &framework.FieldData{
				Raw:    test.updateData,
				Schema: schema,
			}
			resp, err = b.pathDynamicRoleCreateUpdate(ctx, req, updateData)
			if test.expectErr && err == nil {
				t.Fatalf("err expected, got nil")
			}
			if !test.expectErr && err != nil {
				t.Fatalf("no error expected, got: %s", err)
			}
			require.Nil(t, resp)

			actualRole, err = retrieveDynamicRole(ctx, storage, roleName)
			require.NoError(t, err)
			require.Equal(t, test.updateRole, actualRole)
		})
	}
}

func TestDynamicRoleRead(t *testing.T) {
	roleName := "testrole"

	type testCase struct {
		storageResp *logical.StorageEntry
		storageErr  error

		expectedResp *logical.Response
		expectErr    bool
	}

	tests := map[string]testCase{
		"storage failure": {
			storageResp:  nil,
			storageErr:   errors.New("test error"),
			expectedResp: nil,
			expectErr:    true,
		},
		"no role found": {
			storageResp:  nil,
			storageErr:   nil,
			expectedResp: nil,
			expectErr:    false,
		},
		"happy path": {
			storageResp: &logical.StorageEntry{
				Key: path.Join(dynamicRolePath, roleName),
				Value: jsonEncode(t, dynamicRole{
					Name:             roleName,
					CreationLDIF:     ldifCreationTemplate,
					RollbackLDIF:     ldifRollbackTemplate,
					DeletionLDIF:     ldifDeleteTemplate,
					UsernameTemplate: "v-foo-{{.RoleName}}-{{rand 20}}-{{unix_seconds}}",
					DefaultTTL:       24 * time.Hour,
					MaxTTL:           5 * 24 * time.Hour,
				}),
			},
			storageErr: nil,
			expectedResp: &logical.Response{
				Data: map[string]interface{}{
					"creation_ldif":     ldifCreationTemplate,
					"rollback_ldif":     ldifRollbackTemplate,
					"deletion_ldif":     ldifDeleteTemplate,
					"username_template": "v-foo-{{.RoleName}}-{{rand 20}}-{{unix_seconds}}",
					"default_ttl":       (24 * time.Hour).Seconds(),
					"max_ttl":           (5 * 24 * time.Hour).Seconds(),
				},
			},
			expectErr: false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			client := new(mockLDAPClient)
			defer client.AssertExpectations(t) // No expectations

			b := Backend(client)

			storage := new(mockStorage)
			storage.On("Get", mock.Anything, path.Join(dynamicRolePath, roleName)).
				Return(test.storageResp, test.storageErr)
			defer storage.AssertNumberOfCalls(t, "Get", 1)

			req := &logical.Request{
				Storage: storage,
			}
			data := dynamicRoleFieldData(map[string]interface{}{
				"name": roleName,
			})
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			defer cancel()

			resp, err := b.pathDynamicRoleRead(ctx, req, data)
			if test.expectErr && err == nil {
				t.Fatalf("err expected, got nil")
			}
			if !test.expectErr && err != nil {
				t.Fatalf("no error expected, got: %s", err)
			}
			if !reflect.DeepEqual(resp, test.expectedResp) {
				t.Fatalf("Actual response: %#v\nExpected response: %#v", resp, test.expectedResp)
			}
		})
	}
}

func TestDynamicRoleList(t *testing.T) {
	type testCase struct {
		storageResp []string
		storageErr  error

		expectedResp *logical.Response
		expectErr    bool
	}

	tests := map[string]testCase{
		"storage failure": {
			storageResp:  nil,
			storageErr:   errors.New("test error"),
			expectedResp: nil,
			expectErr:    true,
		},
		"happy path": {
			storageResp: []string{
				"foo",
				"bar",
				"baz",
			},
			storageErr: nil,
			expectedResp: &logical.Response{
				Data: map[string]interface{}{
					"keys": []string{
						"foo",
						"bar",
						"baz",
					},
				},
			},
			expectErr: false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			client := new(mockLDAPClient)
			defer client.AssertExpectations(t) // No expectations

			b := Backend(client)

			storage := new(mockStorage)
			storage.On("List", mock.Anything, dynamicRolePath).
				Return(test.storageResp, test.storageErr)
			defer storage.AssertNumberOfCalls(t, "List", 1)

			req := &logical.Request{
				Storage: storage,
			}
			data := dynamicRoleFieldData(map[string]interface{}{})
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			defer cancel()

			resp, err := b.pathDynamicRoleList(ctx, req, data)
			if test.expectErr && err == nil {
				t.Fatalf("err expected, got nil")
			}
			if !test.expectErr && err != nil {
				t.Fatalf("no error expected, got: %s", err)
			}
			if !reflect.DeepEqual(resp, test.expectedResp) {
				t.Fatalf("Actual response: %#v\nExpected response: %#v", resp, test.expectedResp)
			}
		})
	}
}

func TestDynamicRoleExistenceCheck(t *testing.T) {
	roleName := "testrole"

	type testCase struct {
		storageResp *logical.StorageEntry
		storageErr  error

		expectedExists bool
		expectErr      bool
	}

	tests := map[string]testCase{
		"storage failure": {
			storageResp:    nil,
			storageErr:     errors.New("test error"),
			expectedExists: false,
			expectErr:      true,
		},
		"no role found": {
			storageResp:    nil,
			storageErr:     nil,
			expectedExists: false,
			expectErr:      false,
		},
		"happy path": {
			storageResp: &logical.StorageEntry{
				Key: path.Join(dynamicRolePath, roleName),
				Value: jsonEncode(t, dynamicRole{
					Name: roleName,
					CreationLDIF: `dn: cn={{.Username}},ou=users,dc=hashicorp,dc=com
objectClass: person
objectClass: top
cn: learn
sn: learn
memberOf: cn=dev,ou=groups,dc=hashicorp,dc=com
userPassword: {{.Password}}`,
					UsernameTemplate: "v-foo-{{.RoleName}}-{{rand 20}}-{{unix_seconds}}",
					DefaultTTL:       24 * time.Hour,
					MaxTTL:           5 * 24 * time.Hour,
				}),
			},
			storageErr:     nil,
			expectedExists: true,
			expectErr:      false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			client := new(mockLDAPClient)
			defer client.AssertExpectations(t) // No expectations

			b := Backend(client)

			storage := new(mockStorage)
			storage.On("Get", mock.Anything, path.Join(dynamicRolePath, roleName)).
				Return(test.storageResp, test.storageErr)
			defer storage.AssertNumberOfCalls(t, "Get", 1)

			req := &logical.Request{
				Storage: storage,
			}
			data := dynamicRoleFieldData(map[string]interface{}{
				"name": roleName,
			})
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			defer cancel()

			exists, err := b.pathDynamicRoleExistenceCheck(ctx, req, data)
			if test.expectErr && err == nil {
				t.Fatalf("err expected, got nil")
			}
			if !test.expectErr && err != nil {
				t.Fatalf("no error expected, got: %s", err)
			}

			if test.expectedExists && !exists {
				t.Fatalf("expected role to exist, did not")
			}
			if !test.expectedExists && exists {
				t.Fatalf("did not expect role to exist, but did")
			}
		})
	}
}

func TestConvertToDuration(t *testing.T) {
	type testCase struct {
		input         map[string]interface{}
		keysToConvert []string

		expectedOutput map[string]interface{}
		expectErr      bool
	}

	tests := map[string]testCase{
		"missing key": {
			input: map[string]interface{}{
				"foo": "1h",
			},
			keysToConvert: []string{
				"bar",
			},
			expectedOutput: map[string]interface{}{
				"foo": "1h",
			},
			expectErr: false,
		},
		"time.Duration": {
			input: map[string]interface{}{
				"foo": 1 * time.Hour,
			},
			keysToConvert: []string{
				"foo",
			},
			expectedOutput: map[string]interface{}{
				"foo": 1 * time.Hour,
			},
			expectErr: false,
		},
		"int": {
			input: map[string]interface{}{
				"foo": int(1),
			},
			keysToConvert: []string{
				"foo",
			},
			expectedOutput: map[string]interface{}{
				"foo": 1 * time.Second,
			},
			expectErr: false,
		},
		"int32": {
			input: map[string]interface{}{
				"foo": int32(123),
			},
			keysToConvert: []string{
				"foo",
			},
			expectedOutput: map[string]interface{}{
				"foo": 123 * time.Second,
			},
			expectErr: false,
		},
		"int64": {
			input: map[string]interface{}{
				"foo": int64(321),
			},
			keysToConvert: []string{
				"foo",
			},
			expectedOutput: map[string]interface{}{
				"foo": 321 * time.Second,
			},
			expectErr: false,
		},
		"string": {
			input: map[string]interface{}{
				"foo": "1h",
			},
			keysToConvert: []string{
				"foo",
			},
			expectedOutput: map[string]interface{}{
				"foo": 1 * time.Hour,
			},
			expectErr: false,
		},
		"bad string": {
			input: map[string]interface{}{
				"foo": "foo",
			},
			keysToConvert: []string{
				"foo",
			},
			expectedOutput: map[string]interface{}{
				"foo": "foo",
			},
			expectErr: true,
		},
		"unsupported type": {
			input: map[string]interface{}{
				"foo": struct {
					Dur string
				}{
					Dur: "1h",
				},
			},
			keysToConvert: []string{
				"foo",
			},
			expectedOutput: map[string]interface{}{
				"foo": struct {
					Dur string
				}{
					Dur: "1h",
				},
			},
			expectErr: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			data := test.input // The original map is being modified so let's make this an explicit variable
			err := convertToDuration(data, test.keysToConvert...)
			if test.expectErr && err == nil {
				t.Fatalf("err expected, got nil")
			}
			if !test.expectErr && err != nil {
				t.Fatalf("no error expected, got: %s", err)
			}

			if !reflect.DeepEqual(data, test.expectedOutput) {
				t.Fatalf("Actual: %#v\nExpected: %#v", data, test.expectedOutput)
			}
		})
	}
}

func dynamicRoleFieldData(data map[string]interface{}) *framework.FieldData {
	schema := map[string]*framework.FieldSchema{
		"name": {
			Type:        framework.TypeLowerCaseString,
			Description: "Name of the role",
			Required:    true,
		},
		"creation_ldif": {
			Type:        framework.TypeString,
			Description: "LDIF string used to create new entities within the LDAP system. This LDIF can be templated.",
			Required:    true,
		},
		"username_template": {
			Type:        framework.TypeString,
			Description: "The template used to create a username",
		},
		"default_ttl": {
			Type:        framework.TypeDurationSecond,
			Description: "Default TTL for dynamic credentials",
		},
		"max_ttl": {
			Type:        framework.TypeDurationSecond,
			Description: "Max TTL a dynamic credential can be extended to",
		},
	}

	return &framework.FieldData{
		Raw:    data,
		Schema: schema,
	}
}

func base64Encode(str string) string {
	return base64.StdEncoding.EncodeToString([]byte(str))
}

func jsonEncode(t *testing.T, value interface{}) []byte {
	t.Helper()

	b, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("failed to marshal object: %s", err)
	}
	return b
}

const (
	ldifCreationTemplate = `dn: cn={{.Username}},ou=users,dc=hashicorp,dc=com
objectClass: person
objectClass: top
cn: learn
sn: learn
memberOf: cn=dev,ou=groups,dc=hashicorp,dc=com
userPassword: {{.Password}}`

	ldifCreateAndModifyTemplate = `dn: cn={{.Username}},ou=users,dc=hashicorp,dc=com
objectClass: person
objectClass: top
cn: learn
sn: learn
memberOf: cn=dev,ou=groups,dc=hashicorp,dc=com
userPassword: {{.Password}}

dn: cn=testuser,ou=users,dc=hashicorp,dc=com
changetype: modify
add: mail
mail: test@hashicorp.com
-`

	ldifDeleteTemplate = `dn: cn={{.Username}},ou=users,dc=learn,dc=example
changetype: delete`

	ldifRollbackTemplate = `dn: cn={{.Username}},ou=users,dc=learn,dc=example
changetype: delete`
)
