package kerberos

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/vault/logical"
	"github.com/mgutz/logxi/v1"
)

func getTestBackend(t *testing.T) (logical.Backend, logical.Storage) {
	defaultLeaseTTLVal := time.Hour * 12
	maxLeaseTTLVal := time.Hour * 24

	config := &logical.BackendConfig{
		Logger: nil,
		System: &logical.StaticSystemView{
			DefaultLeaseTTLVal: defaultLeaseTTLVal,
			MaxLeaseTTLVal:     maxLeaseTTLVal,
		},
		StorageView: &logical.InmemStorage{},
	}

	b := Backend(config)
	err := b.Setup(config)
	if err != nil {
		t.Fatalf("unable to create backend: %v", err)
	}

	return b, config.StorageView
}

func TestConfig_ReadWrite(t *testing.T) {
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

	resp, err := b.HandleRequest(req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err: %s resp: %#v\n", err, resp)
	}

	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      configPath,
		Storage:   storage,
		Data:      nil,
	}

	resp, err = b.HandleRequest(req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err: %s resp: %#v\n", err, resp)
	}

	// TODO: do we really want to return the keytab?
	if !reflect.DeepEqual(resp.Data, data) {
		t.Fatalf("Expected did not equal actual: expected %#v\n got %#v\n", data, resp.Data)
	}
}

func TestConfig_RejectsBadWrites(t *testing.T) {
	b, storage := getTestBackend(t)

	testConfigWriteError(t, b, storage, map[string]interface{}{
		"keytab": testValidKeytab,
	}, "data does not contain service_account")

	testConfigWriteError(t, b, storage, map[string]interface{}{
		"service_account": "testuser",
	}, "data does not contain keytab")

	testConfigWriteError(t, b, storage, map[string]interface{}{
		"service_account": "testuser",
		"keytab":          testNotBase64Keytab,
	}, "could not base64 decode keytab")

	testConfigWriteError(t, b, storage, map[string]interface{}{
		"service_account": "testuser",
		"keytab":          testInvalidKeytab,
	}, "invalid keytab")
}

func testConfigWriteError(t *testing.T, b logical.Backend, storage logical.Storage,
	data map[string]interface{}, e string) {
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      configPath,
		Storage:   storage,
		Data:      data,
	}

	_, err := b.HandleRequest(req)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.HasPrefix(err.Error(), e) {
		t.Fatalf("got unexpected error: %v, expected %v", err.Error(), e)
	}
}

var testValidKeytab string = "BQIAAABFAAEAC1RFU1QuR09LUkI1AAdzeXNIVFRQAAAAAVkNxa8CABIAIEN2NwKGiXjRttkaNnBLmH4n5RclAFW9/EC4prOEjZqu"
var testNotBase64Keytab string = "NOT_VALID_BASE64"
var testInvalidKeytab string = "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD"
