package profiles

import (
	"reflect"
	"strings"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
)

func newHistory() *EvaluationHistory {
	return &EvaluationHistory{
		Requests:  make(map[string]map[string]map[string]interface{}),
		Responses: make(map[string]map[string]map[string]interface{}),
	}
}

func TestAddRequest_Success(t *testing.T) {
	h := newHistory()
	req := &logical.Request{
		ID:          "1234",
		Operation:   logical.UpdateOperation,
		Path:        "sys/auth/userpass",
		ClientToken: "s.1234567890abcdef",
		Data: map[string]interface{}{
			"type":        "userpass",
			"description": "Username/password",
		},
	}

	if err := h.AddRequest("initialize", "userpass", req); err != nil {
		t.Fatalf("AddRequest failed: %v", err)
	}

	got, err := h.GetRequest("initialize", "userpass")
	if err != nil {
		t.Fatalf("GetRequest failed: %v", err)
	}

	d, ok := got["map"].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected payload under key 'map', got %T", got["map"])
	}
	if d["type"] != "userpass" {
		t.Errorf("type mismatch: got %v", d["type"])
	}
	if got["id"] != "1234" {
		t.Errorf("id mismatch: got %v", got["id"])
	}
	if got["operation"] != "update" {
		t.Errorf("operation mismatch: got %v", got["operation"])
	}
	if got["path"] != "sys/auth/userpass" {
		t.Errorf("path mismatch: got %v", got["path"])
	}
	if got["client_token"] != "s.1234567890abcdef" {
		t.Errorf("client_token mismatch: got %v", got["client_token"])
	}
}

func TestAddAndGetResponse_Success(t *testing.T) {
	h := newHistory()
	resp := &logical.Response{
		Data: map[string]interface{}{
			"accessor":    "auth_userpass_abcd1234",
			"type":        "userpass",
			"description": "Username and password auth method",
		},
		Warnings: []string{"auth deprecated"},
	}

	if err := h.AddResponse("initialize", "userpass", resp); err != nil {
		t.Fatalf("AddResponse failed: %v", err)
	}

	got, err := h.GetResponse("initialize", "userpass")
	if err != nil {
		t.Fatalf("GetResponse failed: %v", err)
	}

	d, ok := got["data"].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected data under key 'data', got %T", got["data"])
	}
	if d["accessor"] != "auth_userpass_abcd1234" {
		t.Errorf("accessor mismatch: got %v", d["accessor"])
	}
	if d["type"] != "userpass" {
		t.Errorf("type mismatch: got %v", d["type"])
	}

	w, ok := got["warnings"].([]interface{})
	if !ok || len(w) != 1 {
		t.Fatalf("warnings format error: got %v", got["warnings"])
	}
}

func TestAddAndGetRequestData_Success(t *testing.T) {
	history := newHistory()

	payload := map[string]interface{}{
		"operation": "update",
		"path":      "sys/auth/userpass",
		"data": map[string]interface{}{
			"test": "test",
		},
	}
	if err := history.AddRequestData("initialize", "userpass", payload); err != nil {
		t.Fatalf("AddRequestData error: %v", err)
	}

	retrieved, err := history.GetRequest("initialize", "userpass")
	if err != nil {
		t.Fatalf("GetRequest error: %v", err)
	}
	if !reflect.DeepEqual(retrieved, payload) {
		t.Errorf("GetRequest returned %v; want %v", retrieved, payload)
	}
}

func TestAddRequestData_Duplicate(t *testing.T) {
	history := newHistory()

	sample := map[string]interface{}{
		"operation": "update",
		"path":      "sys/policies/acl/admin",
		"data": map[string]interface{}{
			"test": "test",
		},
	}
	if err := history.AddRequestData("initialize", "add-test-data", sample); err != nil {
		t.Fatalf("first AddRequestData: %v", err)
	}
	if err := history.AddRequestData("initialize", "add-test-data", sample); err == nil {
		t.Fatal("expected error on duplicate AddRequestData, got nil")
	}
}

func TestGetRequest_NotFound(t *testing.T) {
	history := newHistory()
	_, err := history.GetRequest("bootstrap", "configure-auth")
	if err == nil {
		t.Fatal("expected error for missing outer block, got nil")
	}
	expected := "missing outer block 'bootstrap'"
	if err.Error() != expected {
		t.Fatalf("expected error %q, got %q", expected, err.Error())
	}
}

func TestGetRequestField_SingleKey(t *testing.T) {
	history := newHistory()
	data := map[string]interface{}{
		"operation": "create",
		"path":      "auth/token/create",
		"token_ttl": float64(3600),
	}
	if err := history.AddRequestData("tokenInit", "create-token", data); err != nil {
		t.Fatalf("AddRequestData: %v", err)
	}

	value, err := history.GetRequestField("tokenInit", "create-token", "token_ttl")
	if err != nil {
		t.Fatalf("GetRequestField error: %v", err)
	}
	ttl, ok := value.(float64)
	if !ok || ttl != 3600 {
		t.Errorf("GetRequestField returned %v; want %v", value, 3600)
	}
}

func TestGetRequestField_NestedKeyPath(t *testing.T) {
	history := newHistory()
	nestedData := map[string]interface{}{
		"config_key": "example",
	}
	data := map[string]interface{}{
		"operation": "update",
		"path":      "secret/data/app/config",
		"data": map[string]interface{}{
			"data": nestedData,
		},
	}
	if err := history.AddRequestData("secretInit", "write-config", data); err != nil {
		t.Fatalf("AddRequestData: %v", err)
	}

	selector := []string{"data", "data", "config_key"}
	value, err := history.GetRequestField("secretInit", "write-config", selector)
	if err != nil {
		t.Fatalf("GetRequestField nested error: %v", err)
	}
	if key, ok := value.(string); !ok || key != "example" {
		t.Errorf("GetRequestField nested returned %v; want %q", value, "example")
	}
}

func TestGetRequestField_MissingKey(t *testing.T) {
	history := newHistory()
	data := map[string]interface{}{
		"operation": "read",
		"path":      "sys/health",
	}
	if err := history.AddRequestData("healthInit", "check-health", data); err != nil {
		t.Fatalf("AddRequestData: %v", err)
	}

	_, err := history.GetRequestField("healthInit", "check-health", "status")
	if err == nil {
		t.Fatal("expected error for missing field, got nil")
	}
}

func TestAddAndGetResponseData_Success(t *testing.T) {
	history := newHistory()
	responsePayload := map[string]interface{}{
		"request_id":     "1234-5678-90ab-cdef",
		"lease_duration": float64(0),
		"warnings":       nil,
	}
	if err := history.AddResponseData("initialize", "userpass", responsePayload); err != nil {
		t.Fatalf("AddResponseData: %v", err)
	}
	result, err := history.GetResponse("initialize", "userpass")
	if err != nil {
		t.Fatalf("GetResponse: %v", err)
	}
	if !reflect.DeepEqual(result, responsePayload) {
		t.Errorf("GetResponse returned %v; want %v", result, responsePayload)
	}
}

func TestGetResponse_NotFound(t *testing.T) {
	history := newHistory()
	_, err := history.GetResponse("auditInit", "enable-audit")
	if err == nil {
		t.Fatal("expected error for missing response, got nil")
	}
	if !strings.Contains(err.Error(), "missing outer block") ||
		!strings.Contains(err.Error(), "auditInit") {
		t.Fatalf("unexpected error: %q", err.Error())
	}
}

func TestGetResponseField_Success(t *testing.T) {
	history := newHistory()
	respData := map[string]interface{}{
		"auth": map[string]interface{}{
			"client_token":   "s.xxxx",
			"lease_duration": float64(3600),
		},
	}
	if err := history.AddResponseData("tokenInit", "create-token", respData); err != nil {
		t.Fatalf("AddResponseData: %v", err)
	}

	selector := []string{"auth", "client_token"}
	value, err := history.GetResponseField("tokenInit", "create-token", selector)
	if err != nil {
		t.Fatalf("GetResponseField error: %v", err)
	}
	if token, ok := value.(string); !ok || token != "s.xxxx" {
		t.Errorf("GetResponseField returned %v; want %q", value, "s.xxxx")
	}
}

func TestGetResponseField_InvalidSelectorType(t *testing.T) {
	history := newHistory()
	respData := map[string]interface{}{
		"data": map[string]interface{}{"foo": "bar"},
	}
	if err := history.AddResponseData("configInit", "read-config", respData); err != nil {
		t.Fatalf("AddResponseData: %v", err)
	}

	_, err := history.GetResponseField("configInit", "read-config", 42)
	if err == nil {
		t.Fatal("expected selector type error, got nil")
	}
	if !strings.Contains(err.Error(), "selector") {
		t.Fatalf("unexpected error: %q", err.Error())
	}
}

func TestHistory_EmptyEntries(t *testing.T) {
	history := &EvaluationHistory{
		Requests:  make(map[string]map[string]map[string]interface{}),
		Responses: make(map[string]map[string]map[string]interface{}),
	}

	if _, err := history.GetRequest("noInit", "noReq"); err == nil {
		t.Error("expected error for empty request history, got nil")
	}
	if _, err := history.GetResponse("noInit", "noResp"); err == nil {
		t.Error("expected error for empty response history, got nil")
	}
}
