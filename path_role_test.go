package kubeauth

import (
	"context"
	"testing"
	"time"

	"github.com/go-test/deep"
	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/helper/logging"
	"github.com/hashicorp/vault/sdk/helper/tokenutil"
	"github.com/hashicorp/vault/sdk/logical"
)

func getBackend(t *testing.T) (logical.Backend, logical.Storage) {
	defaultLeaseTTLVal := time.Hour * 12
	maxLeaseTTLVal := time.Hour * 24
	b := Backend()

	config := &logical.BackendConfig{
		Logger: logging.NewVaultLogger(log.Trace),

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
		TokenParams: tokenutil.TokenParams{
			TokenPolicies:   []string{"test"},
			TokenPeriod:     3 * time.Second,
			TokenTTL:        1 * time.Second,
			TokenMaxTTL:     5 * time.Second,
			TokenNumUses:    12,
			TokenBoundCIDRs: nil,
		},
		Policies:                 []string{"test"},
		Period:                   3 * time.Second,
		ServiceAccountNames:      []string{"name"},
		ServiceAccountNamespaces: []string{"namespace"},
		TTL:                      1 * time.Second,
		MaxTTL:                   5 * time.Second,
		NumUses:                  12,
		BoundCIDRs:               nil,
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

	if diff := deep.Equal(expected, actual); diff != nil {
		t.Fatal(diff)
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
		"token_policies":                   []string{"test"},
		"policies":                         []string{"test"},
		"token_period":                     int64(3),
		"period":                           int64(3),
		"token_ttl":                        int64(1),
		"ttl":                              int64(1),
		"token_num_uses":                   12,
		"num_uses":                         12,
		"token_max_ttl":                    int64(5),
		"max_ttl":                          int64(5),
		"token_bound_cidrs":                []string{},
		"token_type":                       logical.TokenTypeDefault.String(),
		"token_explicit_max_ttl":           int64(0),
		"token_no_default_policy":          false,
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

	if diff := deep.Equal(expected, resp.Data); diff != nil {
		t.Fatal(diff)
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
