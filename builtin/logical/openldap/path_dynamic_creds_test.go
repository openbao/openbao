// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package openldap

import (
	"context"
	"errors"
	"path"
	"reflect"
	"strconv"
	"testing"
	"time"

	log "github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/helper/logging"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestDynamicCredsRead_failures(t *testing.T) {
	t.Run("failed to retrieve role", func(t *testing.T) {
		roleName := "testrole"

		storage := new(mockStorage)
		storage.On("Get", mock.Anything, path.Join(dynamicRolePath, roleName)).
			Return((*logical.StorageEntry)(nil), errors.New("test error")).Once()
		defer storage.AssertExpectations(t)

		client := new(mockLDAPClient)
		defer client.AssertExpectations(t)

		b := Backend(client)

		req := &logical.Request{
			Storage:     storage,
			DisplayName: "token-dispname",
		}
		data := dynamicRoleFieldData(map[string]interface{}{
			"name": roleName,
		})
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()

		resp, err := b.pathDynamicCredsRead(ctx, req, data)
		require.Error(t, err)
		require.Nil(t, resp)
	})

	t.Run("failed to retrieve config", func(t *testing.T) {
		roleName := "testrole"

		storage := new(mockStorage)

		roleStorageResp := &logical.StorageEntry{
			Key: path.Join(dynamicRolePath, roleName),
			Value: jsonEncode(t, dynamicRole{
				Name:         roleName,
				CreationLDIF: ldifCreationTemplate,
			}),
		}
		storage.On("Get", mock.Anything, path.Join(dynamicRolePath, roleName)).
			Return(roleStorageResp, nil).
			Once()
		storage.On("Get", mock.Anything, configPath).
			Return((*logical.StorageEntry)(nil), errors.New("test error")).
			Once()
		defer storage.AssertExpectations(t)

		client := new(mockLDAPClient)
		defer client.AssertExpectations(t)

		b := Backend(client)

		req := &logical.Request{
			Storage:     storage,
			DisplayName: "token-dispname",
		}
		data := dynamicRoleFieldData(map[string]interface{}{
			"name": roleName,
		})
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()

		resp, err := b.pathDynamicCredsRead(ctx, req, data)
		require.Error(t, err)
		require.Nil(t, resp)
	})

	t.Run("missing config", func(t *testing.T) {
		roleName := "testrole"

		storage := new(mockStorage)

		roleStorageResp := &logical.StorageEntry{
			Key: path.Join(dynamicRolePath, roleName),
			Value: jsonEncode(t, dynamicRole{
				Name:         roleName,
				CreationLDIF: ldifCreationTemplate,
			}),
		}
		storage.On("Get", mock.Anything, path.Join(dynamicRolePath, roleName)).
			Return(roleStorageResp, nil).
			Once()
		storage.On("Get", mock.Anything, configPath).
			Return((*logical.StorageEntry)(nil), nil).
			Once()
		defer storage.AssertExpectations(t)

		client := new(mockLDAPClient)
		defer client.AssertExpectations(t)

		b := Backend(client)

		req := &logical.Request{
			Storage:     storage,
			DisplayName: "token-dispname",
		}
		data := dynamicRoleFieldData(map[string]interface{}{
			"name": roleName,
		})
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()

		resp, err := b.pathDynamicCredsRead(ctx, req, data)
		require.Error(t, err)
		require.Nil(t, resp)
	})

	t.Run("LDAP client failure", func(t *testing.T) {
		roleName := "testrole"

		storage := new(mockStorage)

		roleStorageResp := &logical.StorageEntry{
			Key: path.Join(dynamicRolePath, roleName),
			Value: jsonEncode(t, dynamicRole{
				Name:         roleName,
				CreationLDIF: ldifCreationTemplate,
			}),
		}
		configStorageResp := &logical.StorageEntry{
			Key:   configPath,
			Value: jsonEncode(t, config{}),
		}
		storage.On("Get", mock.Anything, path.Join(dynamicRolePath, roleName)).
			Return(roleStorageResp, nil).
			Once()
		storage.On("Get", mock.Anything, configPath).
			Return(configStorageResp, nil).
			Once()
		defer storage.AssertExpectations(t)

		client := new(mockLDAPClient)
		client.On("Execute", mock.Anything, mock.Anything, mock.Anything).
			Return(errors.New("test error")).
			Once()

		b := Backend(client)

		req := &logical.Request{
			Storage:     storage,
			DisplayName: "token-dispname",
		}
		data := dynamicRoleFieldData(map[string]interface{}{
			"name": roleName,
		})
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()

		resp, err := b.pathDynamicCredsRead(ctx, req, data)
		require.Error(t, err)
		require.Nil(t, resp)
	})
}

func TestDynamicCredsRead_missing_role(t *testing.T) {
	roleName := "testrole"

	storage := new(mockStorage)

	storage.On("Get", mock.Anything, path.Join(dynamicRolePath, roleName)).
		Return((*logical.StorageEntry)(nil), nil).
		Once()
	defer storage.AssertExpectations(t)

	client := new(mockLDAPClient)
	defer client.AssertExpectations(t)

	b := Backend(client)

	req := &logical.Request{
		Storage:     storage,
		DisplayName: "token-dispname",
	}
	data := dynamicRoleFieldData(map[string]interface{}{
		"name": roleName,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	resp, err := b.pathDynamicCredsRead(ctx, req, data)
	require.NoError(t, err)
	require.Nil(t, resp)
}

func TestDynamicCredsRead_success(t *testing.T) {
	roleName := "testrole"
	passwordPolicyName := "testpolicy"
	fakePassword := "fake password"

	type testCase struct {
		reqDisplayName string

		role   dynamicRole
		config config

		expectedDNRegex       string
		expectedUsernameRegex string
		expectedPasswordRegex string
		expectedTTL           time.Duration
		expectedMaxTTL        time.Duration
	}

	tests := map[string]testCase{
		"default config": {
			reqDisplayName: "token-dispname",

			role: dynamicRole{
				Name:         roleName,
				CreationLDIF: ldifCreationTemplate,
			},

			config: config{},

			expectedDNRegex:       "^cn=v_token-dispname_testrole_[a-zA-Z0-9]{10}_[0-9]{10},ou=users,dc=hashicorp,dc=com$",
			expectedUsernameRegex: "^v_token-dispname_testrole_[a-zA-Z0-9]{10}_[0-9]{10}$",
			expectedPasswordRegex: "^[a-zA-Z0-9]{64}$",
			expectedTTL:           0,
			expectedMaxTTL:        0,
		},
		"custom password": {
			reqDisplayName: "token-dispname",

			role: dynamicRole{
				Name:         roleName,
				CreationLDIF: ldifCreationTemplate,
			},

			config: config{
				PasswordPolicy: passwordPolicyName,
			},

			expectedDNRegex:       "^cn=v_token-dispname_testrole_[a-zA-Z0-9]{10}_[0-9]{10},ou=users,dc=hashicorp,dc=com$",
			expectedUsernameRegex: "^v_token-dispname_testrole_[a-zA-Z0-9]{10}_[0-9]{10}$",
			expectedPasswordRegex: "^" + fakePassword + "$",
			expectedTTL:           0,
			expectedMaxTTL:        0,
		},
		"custom username": {
			reqDisplayName: "token-dispname",

			role: dynamicRole{
				Name:             roleName,
				CreationLDIF:     ldifCreationTemplate,
				UsernameTemplate: "v.{{random 10}}.{{.RoleName}}.{{unix_time}}.{{.DisplayName}}",
			},

			config: config{},

			expectedDNRegex:       "^cn=v.[a-zA-Z0-9]{10}.testrole.[0-9]{10}.token-dispname,ou=users,dc=hashicorp,dc=com$",
			expectedUsernameRegex: "^v.[a-zA-Z0-9]{10}.testrole.[0-9]{10}.token-dispname$",
			expectedPasswordRegex: "^[a-zA-Z0-9]{64}$",
			expectedTTL:           0,
			expectedMaxTTL:        0,
		},
		"explicit TTLs": {
			reqDisplayName: "token-dispname",

			role: dynamicRole{
				Name:             roleName,
				CreationLDIF:     ldifCreationTemplate,
				UsernameTemplate: "v.{{random 10}}.{{.RoleName}}.{{unix_time}}.{{.DisplayName}}",
				DefaultTTL:       1 * time.Hour,
				MaxTTL:           24 * time.Hour,
			},

			config: config{},

			expectedDNRegex:       "^cn=v.[a-zA-Z0-9]{10}.testrole.[0-9]{10}.token-dispname,ou=users,dc=hashicorp,dc=com$",
			expectedUsernameRegex: "^v.[a-zA-Z0-9]{10}.testrole.[0-9]{10}.token-dispname$",
			expectedPasswordRegex: "^[a-zA-Z0-9]{64}$",
			expectedTTL:           1 * time.Hour,
			expectedMaxTTL:        24 * time.Hour,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			client := new(mockLDAPClient)
			client.On("Execute", mock.Anything, mock.Anything, mock.Anything).
				Return(error(nil)).
				Once()
			defer client.AssertExpectations(t)

			backendConfig := &logical.BackendConfig{
				Logger: logging.NewVaultLogger(log.Error),

				System: &logical.StaticSystemView{
					DefaultLeaseTTLVal: defaultLeaseTTLVal,
					MaxLeaseTTLVal:     maxLeaseTTLVal,
					PasswordPolicies: map[string]logical.PasswordGenerator{
						passwordPolicyName: func() (pass string, err error) {
							return fakePassword, nil
						},
					},
				},
				StorageView: &logical.InmemStorage{},
			}

			storage := new(mockStorage)

			roleStore := &logical.StorageEntry{
				Key:   path.Join(dynamicRolePath, roleName),
				Value: jsonEncode(t, test.role),
			}
			storage.On("Get", mock.Anything, path.Join(dynamicRolePath, roleName)).
				Return(roleStore, error(nil)).
				Once()

			configStore := &logical.StorageEntry{
				Key:   configPath,
				Value: jsonEncode(t, test.config),
			}
			storage.On("Get", mock.Anything, configPath).
				Return(configStore, error(nil)).
				Once()
			defer storage.AssertExpectations(t)

			b := Backend(client)
			b.Setup(context.Background(), backendConfig)

			req := &logical.Request{
				Storage:     storage,
				DisplayName: test.reqDisplayName,
			}
			data := dynamicRoleFieldData(map[string]interface{}{
				"name": roleName,
			})
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			defer cancel()

			resp, err := b.pathDynamicCredsRead(ctx, req, data)
			require.NoError(t, err)

			username := getStringT(t, resp.Data, "username")
			require.Regexp(t, test.expectedUsernameRegex, username)

			password := getStringT(t, resp.Data, "password")
			require.Regexp(t, test.expectedPasswordRegex, password)

			dns := getStringSlice(t, resp.Data, "distinguished_names")
			require.Len(t, dns, 1)
			require.Regexp(t, test.expectedDNRegex, dns[0])
		})
	}
}

func TestSecretCredsRenew(t *testing.T) {
	roleName := "testrole"
	now := time.Now()

	type testCase struct {
		req *logical.Request

		storageResp *logical.StorageEntry
		storageErr  error

		expectedResp *logical.Response
		expectErr    bool
	}

	tests := map[string]testCase{
		"error getting role": {
			req: &logical.Request{
				Secret: &logical.Secret{
					InternalData: map[string]interface{}{
						"name":          roleName,
						"deletion_ldif": ldifDeleteTemplate,
					},
					LeaseID: "foo bar",
				},
			},
			storageResp:  nil,
			storageErr:   errors.New("test error"),
			expectedResp: nil,
			expectErr:    true,
		},
		"no role found": {
			req: &logical.Request{
				Secret: &logical.Secret{
					InternalData: map[string]interface{}{
						"name":          roleName,
						"deletion_ldif": ldifDeleteTemplate,
					},
					LeaseID: "foo bar",
				},
			},
			storageResp:  nil,
			storageErr:   nil,
			expectedResp: nil,
			expectErr:    true,
		},
		"happy path": {
			req: &logical.Request{
				Secret: &logical.Secret{
					InternalData: map[string]interface{}{
						"name":          roleName,
						"deletion_ldif": ldifDeleteTemplate,
						"template_data": dynamicTemplateData{
							Username:              "alice",
							Password:              "r3allys3cu4ePassw0rd!",
							DisplayName:           "disp_name",
							RoleName:              roleName,
							IssueTime:             now.Format(time.RFC3339),
							IssueTimeSeconds:      now.Unix(),
							ExpirationTime:        now.Add(1 * time.Minute).Format(time.RFC3339),
							ExpirationTimeSeconds: now.Add(1 * time.Minute).Unix(),
						},
					},
					LeaseID: "foo bar",
				},
			},
			storageResp: &logical.StorageEntry{
				Key: path.Join(dynamicRolePath, roleName),
				Value: jsonEncode(t, dynamicRole{
					Name:         roleName,
					CreationLDIF: "foo bar", // Actual value doesn't matter here
				}),
			},
			storageErr: nil,
			expectedResp: &logical.Response{
				Secret: &logical.Secret{
					InternalData: map[string]interface{}{
						"name":          roleName,
						"deletion_ldif": ldifDeleteTemplate,
						"template_data": dynamicTemplateData{
							Username:              "alice",
							Password:              "r3allys3cu4ePassw0rd!",
							DisplayName:           "disp_name",
							RoleName:              roleName,
							IssueTime:             now.Format(time.RFC3339),
							IssueTimeSeconds:      now.Unix(),
							ExpirationTime:        now.Add(1 * time.Minute).Format(time.RFC3339),
							ExpirationTimeSeconds: now.Add(1 * time.Minute).Unix(),
						},
					},
					LeaseID: "foo bar",
				},
			},
			expectErr: false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			storage := new(mockStorage)

			storage.On("Get", mock.Anything, path.Join(dynamicRolePath, roleName)).
				Return(test.storageResp, test.storageErr).
				Once()
			defer storage.AssertExpectations(t)

			client := new(mockLDAPClient)
			defer client.AssertExpectations(t)

			b := Backend(client)

			test.req.Storage = storage
			data := dynamicRoleFieldData(map[string]interface{}{
				"name": roleName,
			})
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			defer cancel()

			resp, err := b.secretCredsRenew()(ctx, test.req, data)
			if test.expectErr && err == nil {
				t.Fatal("err expected, got nil")
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

func TestSecretCredsRevoke(t *testing.T) {
	t.Run("error getting config", func(t *testing.T) {
		storage := new(mockStorage)

		storage.On("Get", mock.Anything, configPath).
			Return((*logical.StorageEntry)(nil), errors.New("test error")).
			Once()
		defer storage.AssertExpectations(t)

		client := new(mockLDAPClient)
		defer client.AssertExpectations(t)

		b := Backend(client)

		req := &logical.Request{
			Storage: storage,
			Secret: &logical.Secret{
				InternalData: map[string]interface{}{
					"deletion_ldif": ldifDeleteTemplate,
				},
			},
		}
		var data *framework.FieldData
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()

		_, err := b.secretCredsRevoke()(ctx, req, data)
		require.Error(t, err)
	})

	t.Run("missing config", func(t *testing.T) {
		storage := new(mockStorage)

		storage.On("Get", mock.Anything, configPath).
			Return((*logical.StorageEntry)(nil), error(nil)).
			Once()
		defer storage.AssertExpectations(t)

		client := new(mockLDAPClient)
		defer client.AssertExpectations(t)

		b := Backend(client)

		req := &logical.Request{
			Storage: storage,
			Secret: &logical.Secret{
				InternalData: map[string]interface{}{
					"deletion_ldif": ldifDeleteTemplate,
				},
			},
		}
		var data *framework.FieldData
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()

		_, err := b.secretCredsRevoke()(ctx, req, data)
		require.Error(t, err)
	})

	t.Run("missing deletion_ldif template", func(t *testing.T) {
		storage := new(mockStorage)

		storageResp := &logical.StorageEntry{
			Key:   configPath,
			Value: jsonEncode(t, config{}),
		}
		storage.On("Get", mock.Anything, configPath).
			Return(storageResp, error(nil)).
			Once()
		defer storage.AssertExpectations(t)

		client := new(mockLDAPClient)
		defer client.AssertExpectations(t)

		b := Backend(client)

		req := &logical.Request{
			Storage: storage,
			Secret: &logical.Secret{
				InternalData: map[string]interface{}{},
			},
		}
		var data *framework.FieldData
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()

		_, err := b.secretCredsRevoke()(ctx, req, data)
		require.Error(t, err)
	})

	t.Run("bad deletion_ldif template", func(t *testing.T) {
		storage := new(mockStorage)

		storageResp := &logical.StorageEntry{
			Key:   configPath,
			Value: jsonEncode(t, config{}),
		}
		storage.On("Get", mock.Anything, configPath).
			Return(storageResp, error(nil)).
			Once()
		defer storage.AssertExpectations(t)

		client := new(mockLDAPClient)
		defer client.AssertExpectations(t)

		b := Backend(client)

		req := &logical.Request{
			Storage: storage,
			Secret: &logical.Secret{
				InternalData: map[string]interface{}{
					"deletion_ldif": "foo bar",
				},
			},
		}
		var data *framework.FieldData
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()

		_, err := b.secretCredsRevoke()(ctx, req, data)
		require.Error(t, err)
	})

	t.Run("ldap error", func(t *testing.T) {
		storage := new(mockStorage)

		storageResp := &logical.StorageEntry{
			Key:   configPath,
			Value: jsonEncode(t, config{}),
		}
		storage.On("Get", mock.Anything, configPath).
			Return(storageResp, error(nil)).
			Once()
		defer storage.AssertExpectations(t)

		client := new(mockLDAPClient)
		client.On("Execute", mock.Anything, mock.Anything, mock.Anything).
			Return(errors.New("test error")).
			Once()
		defer client.AssertExpectations(t)

		b := Backend(client)

		now := time.Now()
		exp := now.Add(1 * time.Hour)
		req := &logical.Request{
			Storage: storage,
			Secret: &logical.Secret{
				InternalData: map[string]interface{}{
					"name":          "testrole",
					"deletion_ldif": ldifDeleteTemplate,
					"template_data": dynamicTemplateData{
						Username:              "testuser",
						Password:              "asdfa08ay4t98hoizvohiuz",
						DisplayName:           "token",
						RoleName:              "testrole",
						IssueTime:             now.Format(time.RFC3339),
						IssueTimeSeconds:      now.Unix(),
						ExpirationTime:        exp.Format(time.RFC3339),
						ExpirationTimeSeconds: exp.Unix(),
					},
				},
			},
		}
		var data *framework.FieldData
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()

		_, err := b.secretCredsRevoke()(ctx, req, data)
		require.Error(t, err)
	})

	t.Run("happy path", func(t *testing.T) {
		storage := new(mockStorage)

		storageResp := &logical.StorageEntry{
			Key:   configPath,
			Value: jsonEncode(t, config{}),
		}
		storage.On("Get", mock.Anything, configPath).
			Return(storageResp, error(nil)).
			Once()
		defer storage.AssertExpectations(t)

		client := new(mockLDAPClient)
		client.On("Execute", mock.Anything, mock.Anything, mock.Anything).
			Return(error(nil)).
			Once()
		defer client.AssertExpectations(t)

		b := Backend(client)

		now := time.Now()
		exp := now.Add(1 * time.Hour)
		req := &logical.Request{
			Storage: storage,
			Secret: &logical.Secret{
				InternalData: map[string]interface{}{
					"name":          "testrole",
					"deletion_ldif": ldifDeleteTemplate,
					"template_data": dynamicTemplateData{
						Username:              "testuser",
						Password:              "asdfa08ay4t98hoizvohiuz",
						DisplayName:           "token",
						RoleName:              "testrole",
						IssueTime:             now.Format(time.RFC3339),
						IssueTimeSeconds:      now.Unix(),
						ExpirationTime:        exp.Format(time.RFC3339),
						ExpirationTimeSeconds: exp.Unix(),
					},
				},
			},
		}
		var data *framework.FieldData
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()

		_, err := b.secretCredsRevoke()(ctx, req, data)
		require.NoError(t, err)
	})
}

func TestApplyTemplate(t *testing.T) {
	type testCase struct {
		template string
		data     dynamicTemplateData

		expected  string
		expectErr bool
	}

	now := time.Now()
	nowRFC3339 := now.Format(time.RFC3339)
	nowSeconds := now.Unix()
	nowSecondsStr := strconv.FormatInt(nowSeconds, 10)

	exp := now.Add(24 * time.Hour)
	expRFC3339 := exp.Format(time.RFC3339)
	expSeconds := exp.Unix()
	expSecondsStr := strconv.FormatInt(expSeconds, 10)

	tests := map[string]testCase{
		"empty template": {
			template: "",
			data: dynamicTemplateData{
				Username: "testusername",
			},

			expected:  "",
			expectErr: true,
		},
		"Username": {
			template: "{{.Username}}",
			data: dynamicTemplateData{
				Username:              "testusername",
				Password:              "myreallysecurepassword",
				DisplayName:           "token",
				RoleName:              "testrole",
				IssueTime:             nowRFC3339,
				IssueTimeSeconds:      nowSeconds,
				ExpirationTime:        expRFC3339,
				ExpirationTimeSeconds: expSeconds,
			},

			expected:  "testusername",
			expectErr: false,
		},
		"Password": {
			template: "{{.Password}}",
			data: dynamicTemplateData{
				Password: "myreallysecurepassword",
			},

			expected:  "myreallysecurepassword",
			expectErr: false,
		},
		"DisplayName": {
			template: "{{.DisplayName}}",
			data: dynamicTemplateData{
				DisplayName: "token",
			},

			expected:  "token",
			expectErr: false,
		},
		"RoleName": {
			template: "{{.RoleName}}",
			data: dynamicTemplateData{
				RoleName: "testrole",
			},

			expected:  "testrole",
			expectErr: false,
		},
		"IssueTime": {
			template: "{{.IssueTime}}",
			data: dynamicTemplateData{
				IssueTime: nowRFC3339,
			},

			expected:  nowRFC3339,
			expectErr: false,
		},
		"IssueTimeSeconds": {
			template: "{{.IssueTimeSeconds}}",
			data: dynamicTemplateData{
				IssueTimeSeconds: nowSeconds,
			},

			expected:  nowSecondsStr,
			expectErr: false,
		},
		"ExpirationTime": {
			template: "{{.ExpirationTime}}",
			data: dynamicTemplateData{
				ExpirationTime: expRFC3339,
			},

			expected:  expRFC3339,
			expectErr: false,
		},
		"ExpirationTimeSeconds": {
			template: "{{.ExpirationTimeSeconds}}",
			data: dynamicTemplateData{
				ExpirationTimeSeconds: expSeconds,
			},

			expected:  expSecondsStr,
			expectErr: false,
		},
		"all fields": {
			template: `dn: cn={{.Username}},ou=users,dc=hashicorp,dc=com
objectClass: person
objectClass: top
cn: learn
sn: {{.DisplayName | utf16le | base64}}
memberOf: cn=dev,ou=groups,dc=hashicorp,dc=com
userPassword: {{.Password}}
displayName: {{.DisplayName}}
roleName: {{.RoleName}}
issueTime: {{.IssueTime}}
issueTimeSeconds: {{.IssueTimeSeconds}}
expirationTime: {{.ExpirationTime}}
expirationTimeSeconds: {{.ExpirationTimeSeconds}}`,
			data: dynamicTemplateData{
				Username:              "testusername",
				Password:              "myreallysecurepassword",
				DisplayName:           "token",
				RoleName:              "testrole",
				IssueTime:             nowRFC3339,
				IssueTimeSeconds:      nowSeconds,
				ExpirationTime:        expRFC3339,
				ExpirationTimeSeconds: expSeconds,
			},

			expected: `dn: cn=testusername,ou=users,dc=hashicorp,dc=com
objectClass: person
objectClass: top
cn: learn
sn: dABvAGsAZQBuAA==
memberOf: cn=dev,ou=groups,dc=hashicorp,dc=com
userPassword: myreallysecurepassword
displayName: token
roleName: testrole
issueTime: ` + nowRFC3339 + `
issueTimeSeconds: ` + nowSecondsStr + `
expirationTime: ` + expRFC3339 + `
expirationTimeSeconds: ` + expSecondsStr,
			expectErr: false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			actual, err := applyTemplate(test.template, test.data)
			if test.expectErr && err == nil {
				t.Fatal("err expected, got nil")
			}
			if !test.expectErr && err != nil {
				t.Fatalf("no error expected, got: %s", err)
			}
			require.Equal(t, test.expected, actual)
		})
	}
}

func getStringT(t *testing.T, m map[string]interface{}, key string) string {
	t.Helper()

	str, err := getString(m, key)
	if err != nil {
		t.Fatalf("%s", err)
	}
	return str
}

func getStringSlice(t *testing.T, m map[string]interface{}, key string) []string {
	t.Helper()

	rawSlice, ok := m[key]
	if !ok {
		t.Fatalf("Key %s is missing from map", key)
	}

	strSlice, ok := rawSlice.([]string)
	if ok {
		return strSlice
	}

	iSlice, ok := rawSlice.([]interface{})
	if !ok {
		t.Fatalf("Unable to coerce key %s to a string slice: is a %T", key, rawSlice)
	}

	strSlice = []string{}
	for _, rawVal := range iSlice {
		str, ok := rawVal.(string)
		if !ok {
			t.Fatal("Unable to coerce value within slice to string")
		}
		strSlice = append(strSlice, str)
	}

	return strSlice
}
