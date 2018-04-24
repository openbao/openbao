package kerberos

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/vault/logical"
)

func setupTestBackend(t *testing.T) (logical.Backend, logical.Storage) {
	b, storage := getTestBackend(t)

	data := map[string]interface{}{
		"keytab":          testValidKeytab,
		"service_account": "testuser",
	}

	req := &logical.Request{
		Operation: logical.CreateOperation,
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

	data := map[string]interface{}{
		"authorization": "",
	}

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Storage:   storage,
		Data:      data,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || resp == nil {
		t.Fatalf("err: %s resp: %#v\n", err, resp)
	}
	if !resp.IsError() && !strings.HasPrefix(resp.Error().Error(), "Missing or invalid authorization") {
		t.Fatalf("err: %s resp: %#v\n", err, resp)
	}
}
