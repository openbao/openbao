// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package openldap

import (
	"context"

	"github.com/go-ldap/ldif"
	"github.com/hashicorp/vault-plugin-secrets-openldap/client"
	"github.com/openbao/openbao/sdk/logical"
	"github.com/stretchr/testify/mock"
)

var _ ldapClient = (*mockLDAPClient)(nil)

type mockLDAPClient struct {
	mock.Mock
}

func (m *mockLDAPClient) UpdateDNPassword(conf *client.Config, dn string, newPassword string) error {
	args := m.Called(conf, dn, newPassword)
	return args.Error(0)
}

func (m *mockLDAPClient) UpdateUserPassword(conf *client.Config, user string, newPassword string) error {
	args := m.Called(conf, user, newPassword)
	return args.Error(0)
}

func (m *mockLDAPClient) Execute(conf *client.Config, entries []*ldif.Entry, continueOnError bool) (err error) {
	args := m.Called(conf, entries, continueOnError)
	return args.Error(0)
}

var _ logical.Storage = (*mockStorage)(nil)

type mockStorage struct {
	mock.Mock
}

func (m *mockStorage) List(ctx context.Context, s string) ([]string, error) {
	args := m.Called(ctx, s)
	return args.Get(0).([]string), args.Error(1)
}

func (m *mockStorage) Get(ctx context.Context, s string) (*logical.StorageEntry, error) {
	args := m.Called(ctx, s)
	return args.Get(0).(*logical.StorageEntry), args.Error(1)
}

func (m *mockStorage) Put(ctx context.Context, entry *logical.StorageEntry) error {
	args := m.Called(ctx, entry)
	return args.Error(0)
}

func (m *mockStorage) Delete(ctx context.Context, s string) error {
	args := m.Called(ctx, s)
	return args.Error(0)
}
