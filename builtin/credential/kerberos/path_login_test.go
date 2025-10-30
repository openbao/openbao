// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package kerberos

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/openbao/openbao/sdk/v2/helper/docker"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/ory/dockertest/v3"
)

func setupTestBackend(t *testing.T) (logical.Backend, logical.Storage) {
	b, storage := getTestBackend(t)

	data := map[string]interface{}{
		"keytab":          testValidKeytab,
		"service_account": "testuser",
	}

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      configPath,
		Storage:   storage,
		Data:      data,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err: %s resp: %#v\n", err, resp)
	}

	return b, storage
}

func TestLogin(t *testing.T) {
	b, storage := setupTestBackend(t)

	cleanup, connURL := prepareLDAPTestContainer(t)
	defer cleanup()

	ldapReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      ldapConfPath,
		Storage:   storage,
		Data: map[string]interface{}{
			"url": connURL,
		},
	}

	resp, err := b.HandleRequest(context.Background(), ldapReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err: %s resp: %#v\n", err, resp)
	}

	data := map[string]interface{}{
		"authorization": "",
	}

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Storage:   storage,
		Data:      data,
		Connection: &logical.Connection{
			RemoteAddr: connURL,
		},
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err == nil || resp == nil || resp.IsError() {
		t.Fatalf("err: %s resp: %#v\n", err, resp)
	}

	if e, ok := err.(logical.HTTPCodedError); !ok || e.Code() != 401 {
		t.Fatalf("no 401 thrown. err: %s resp: %#v\n", err, resp)
	}

	if headerVal, ok := resp.Headers["www-authenticate"]; ok {
		if strings.Compare(headerVal[0], "Negotiate") != 0 {
			t.Fatalf("www-authenticate not set to Negotiate. err: %s resp: %#v\n", err, resp)
		}
	} else {
		t.Fatalf("no www-authenticate header. err: %s resp: %#v\n", err, resp)
	}
}

func prepareLDAPTestContainer(t *testing.T) (cleanup func(), retURL string) {
	docker.CheckSkipContainerTests(t)

	pool, err := dockertest.NewPool("")
	if err != nil {
		t.Fatalf("Failed to connect to docker: %s", err)
	}

	runOpts := &dockertest.RunOptions{
		Repository: "quay.io/minio/openldap",
		Tag:        "latest",
		Env: []string{
			"LDAP_TLS=false",
			"LDAP_DOMAIN=min.io", // Required for minio/openldap to boot up...
		},
	}
	resource, err := pool.RunWithOptions(runOpts)
	if err != nil {
		t.Fatalf("Could not start local MSSQL docker container: %s", err)
	}

	cleanup = func() {
		if err := pool.Purge(resource); err != nil {
			t.Fatalf("Failed to cleanup local container: %s", err)
		}
	}

	retURL = fmt.Sprintf("ldap://localhost:%s", resource.GetPort("389/tcp"))

	// exponential backoff-retry
	if err = pool.Retry(func() error {
		conn, err := ldap.DialURL(retURL)
		if err != nil {
			return err
		}
		defer conn.Close()

		if err := conn.Bind("cn=admin,dc=min,dc=io", "admin"); err != nil {
			return err
		}

		searchRequest := ldap.NewSearchRequest(
			"dc=min,dc=io",
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			"(&(objectClass=*))",
			[]string{"dn", "cn"},
			nil,
		)
		if _, err := conn.Search(searchRequest); err != nil {
			return err
		}
		return nil
	}); err != nil {
		t.Fatalf("Could not connect to ldap auth docker container: %s", err)
	}

	return cleanup, retURL
}
