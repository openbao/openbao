package kubeauth

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/hashicorp/vault/helper/logging"
	"github.com/hashicorp/vault/logical"
	log "github.com/mgutz/logxi/v1"
)

func getBackend(t *testing.T) (logical.Backend, logical.Storage) {
	defaultLeaseTTLVal := time.Hour * 12
	maxLeaseTTLVal := time.Hour * 24
	b := Backend()

	config := &logical.BackendConfig{
		Logger: logging.NewVaultLogger(log.LevelTrace),
		System: &logical.StaticSystemView{
			DefaultLeaseTTLVal: defaultLeaseTTLVal,
			MaxLeaseTTLVal:     maxLeaseTTLVal,
		},
		StorageView: &logical.InmemStorage{},
	}
	err := b.Setup(context.Background(), config)
	if err != nil {
		t.Fatalf("unable to create backend: %v", err)
	}

	return b, config.StorageView
}

func TestPath_Create(t *testing.T) {
	b, storage := getBackend(t)

	data := map[string]interface{}{
		"bound_service_account_names":      "name",
		"bound_service_account_namespaces": "namespace",
		"policies":                         "test",
		"period":                           "3s",
		"ttl":                              "1s",
		"num_uses":                         12,
		"max_ttl":                          "5s",
	}

	expected := &roleStorageEntry{
		Policies:                 []string{"test"},
		Period:                   3 * time.Second,
		ServiceAccountNames:      []string{"name"},
		ServiceAccountNamespaces: []string{"namespace"},
		TTL:     1 * time.Second,
		MaxTTL:  5 * time.Second,
		NumUses: 12,
	}

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/plugin-test",
		Storage:   storage,
		Data:      data,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}
	actual, err := b.(*kubeAuthBackend).role(context.Background(), storage, "plugin-test")
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(expected, actual) {
		t.Fatalf("Unexpected role data: expected %#v\n got %#v\n", expected, actual)
	}

	// Test no service account info
	data = map[string]interface{}{
		"policies": "test",
	}

	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/test2",
		Storage:   storage,
		Data:      data,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if resp != nil && !resp.IsError() {
		t.Fatalf("expected error")
	}
	if resp.Error().Error() != "\"bound_service_account_names\" can not be empty" {
		t.Fatalf("unexpected err: %v", resp)
	}

	// Test no service account info
	data = map[string]interface{}{
		"bound_service_account_names": "name",
		"policies":                    "test",
	}

	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/test2",
		Storage:   storage,
		Data:      data,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if resp != nil && !resp.IsError() {
		t.Fatalf("expected error")
	}
	if resp.Error().Error() != "\"bound_service_account_namespaces\" can not be empty" {
		t.Fatalf("unexpected err: %v", resp)
	}

	// Test both "*"
	data = map[string]interface{}{
		"bound_service_account_names":      "*",
		"bound_service_account_namespaces": "*",
		"policies":                         "test",
	}

	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/test2",
		Storage:   storage,
		Data:      data,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected error")
	}
	if resp.Error().Error() != "service_account_names and service_account_namespaces can not both be \"*\"" {
		t.Fatalf("unexpected err: %v", resp)
	}

	// Test mixed "*" and values
	data = map[string]interface{}{
		"bound_service_account_names":      "*, test",
		"bound_service_account_namespaces": "*",
		"policies":                         "test",
	}

	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/test2",
		Storage:   storage,
		Data:      data,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected error")
	}
	if resp.Error().Error() != "can not mix \"*\" with values" {
		t.Fatalf("unexpected err: %v", resp)
	}

	data = map[string]interface{}{
		"bound_service_account_names":      "*",
		"bound_service_account_namespaces": "*, test",
		"policies":                         "test",
	}

	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/test2",
		Storage:   storage,
		Data:      data,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected error")
	}
	if resp.Error().Error() != "can not mix \"*\" with values" {
		t.Fatalf("unexpected err: %v", resp)
	}
}

func TestPath_Read(t *testing.T) {
	b, storage := getBackend(t)

	configData := map[string]interface{}{
		"bound_service_account_names":      "name",
		"bound_service_account_namespaces": "namespace",
		"policies":                         "test",
		"period":                           "3s",
		"ttl":                              "1s",
		"num_uses":                         12,
		"max_ttl":                          "5s",
	}

	expected := map[string]interface{}{
		"bound_service_account_names":      []string{"name"},
		"bound_service_account_namespaces": []string{"namespace"},
		"policies":                         []string{"test"},
		"period":                           time.Duration(3),
		"ttl":                              time.Duration(1),
		"num_uses":                         12,
		"max_ttl":                          time.Duration(5),
	}

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/plugin-test",
		Storage:   storage,
		Data:      configData,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "role/plugin-test",
		Storage:   storage,
		Data:      configData,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	if !reflect.DeepEqual(expected, resp.Data) {
		t.Fatalf("Unexpected role data: expected %#v\n got %#v\n", expected, resp.Data)
	}
}

func TestPath_Delete(t *testing.T) {
	b, storage := getBackend(t)

	configData := map[string]interface{}{
		"bound_service_account_names":      "name",
		"bound_service_account_namespaces": "namespace",
		"policies":                         "test",
		"period":                           "3s",
		"ttl":                              "1s",
		"num_uses":                         12,
		"max_ttl":                          "5s",
	}

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/plugin-test",
		Storage:   storage,
		Data:      configData,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	req = &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "role/plugin-test",
		Storage:   storage,
		Data:      nil,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	if resp != nil {
		t.Fatalf("Unexpected resp data: expected nil got %#v\n", resp.Data)
	}

	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "role/plugin-test",
		Storage:   storage,
		Data:      nil,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	if resp != nil {
		t.Fatalf("Unexpected resp data: expected nil got %#v\n", resp.Data)
	}
}
