package profiles

import (
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/hcl"
	"github.com/hashicorp/hcl/hcl/ast"
)

func parseBlockList(hclStr, blockName string) (*ast.ObjectList, error) {
	file, err := hcl.Parse(hclStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse HCL: %w", err)
	}
	rootList, ok := file.Node.(*ast.ObjectList)
	if !ok {
		return nil, fmt.Errorf("root node is not *ast.ObjectList, got %T", file.Node)
	}
	return rootList.Filter(blockName), nil
}

func TestParseOuterConfig_Success(t *testing.T) {
	hclStr := `
initialize "auth" {
  request "mount" {
    operation = "update"
    path      = "sys/auth/userpass"
  }
  request "add-admin" {
    operation     = "update"
    path          = "auth/userpass/users/admin"
    allow_failure = true
    data = {
      password = "secret"
    }
  }
}
`
	list, err := parseBlockList(hclStr, "initialize")
	if err != nil {
		t.Fatalf("parseBlockList error: %v", err)
	}
	outers, err := ParseOuterConfig("initialize", nil, list)
	if err != nil {
		t.Fatalf("ParseOuterConfig returned error: %v", err)
	}
	if len(outers) != 1 {
		t.Fatalf("expected 1 OuterConfig, got %d", len(outers))
	}
	outer := outers[0]
	if outer.Type != "auth" {
		t.Errorf("expected outer.Type 'auth', got %q", outer.Type)
	}
	if len(outer.Requests) != 2 {
		t.Fatalf("expected 2 requests, got %d", len(outer.Requests))
	}

	req2 := outer.Requests[1]
	rawData, exists := req2.RawConfig["data"]
	if !exists {
		t.Fatalf("expected RawConfig to contain key 'data'")
	}
	var dataMap map[string]interface{}
	switch v := rawData.(type) {
	case map[string]interface{}:
		dataMap = v
	case []map[string]interface{}:
		if len(v) == 0 {
			t.Fatalf("expected non-empty slice for RawConfig['data'], got empty")
		}
		dataMap = v[0]
	default:
		t.Fatalf("expected RawConfig['data'] to be map or []map[string]interface{}, got %T", rawData)
	}

	if pwd, ok := dataMap["password"].(string); !ok || pwd != "secret" {
		t.Errorf("expected data.password 'secret', got %v", dataMap["password"])
	}
}

func TestParseOuterConfig_EmptyList(t *testing.T) {
	hclStr := `other "x" { }`
	list, err := parseBlockList(hclStr, "initialize")
	if err != nil {
		t.Fatalf("parseBlockList error: %v", err)
	}
	outers, err := ParseOuterConfig("initialize", nil, list)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(outers) != 0 {
		t.Errorf("expected 0 OuterConfig, got %d", len(outers))
	}
}

func TestParseOuterConfig_ErrorMissingType(t *testing.T) {
	hclStr := `
initialize {
  request "foo" {}
}
`
	list, err := parseBlockList(hclStr, "initialize")
	if err != nil {
		t.Fatalf("parseBlockList error: %v", err)
	}
	_, err = ParseOuterConfig("initialize", nil, list)
	if err == nil || !strings.Contains(err.Error(), "type must be specified") {
		t.Fatalf("expected type-specification error, got %v", err)
	}
}

func TestCreateOuterConfig(t *testing.T) {
	req := &RequestConfig{Type: "r1"}
	outers := CreateOuterConfig([]*RequestConfig{req})
	if len(outers) != 1 {
		t.Fatalf("expected 1 OuterConfig, got %d", len(outers))
	}
	if len(outers[0].Requests) != 1 {
		t.Fatalf("expected inner Requests length 1, got %d", len(outers[0].Requests))
	}
	if outers[0].Requests[0] != req {
		t.Errorf("expected Requests[0] to be original req, got %v", outers[0].Requests[0])
	}
}

func TestParseRequestConfig_Success(t *testing.T) {
	hclStr := `
request "op1" {
  operation = "read"
  path      = "sys/health"
  token     = "tok"
  data      = { key = "value" }
}
`
	file, err := hcl.Parse(hclStr)
	if err != nil {
		t.Fatalf("failed to parse HCL: %v", err)
	}
	rootList := file.Node.(*ast.ObjectList)
	items := rootList.Filter("request")
	reqs, err := ParseRequestConfig(nil, items)
	if err != nil {
		t.Fatalf("ParseRequestConfig error: %v", err)
	}
	if len(reqs) != 1 {
		t.Fatalf("expected 1 RequestConfig, got %d", len(reqs))
	}
	r := reqs[0]
	if r.Type != "op1" {
		t.Errorf("expected Type 'op1', got %q", r.Type)
	}
	if op, _ := r.Operation.(string); op != "read" {
		t.Errorf("expected Operation 'read', got %v", r.Operation)
	}
	if path, _ := r.Path.(string); path != "sys/health" {
		t.Errorf("expected Path 'sys/health', got %v", r.Path)
	}
}

func TestParseRequestConfig_ErrorMissingType(t *testing.T) {
	hclStr := `
request {
  operation = "read"
}
`
	file, err := hcl.Parse(hclStr)
	if err != nil {
		t.Fatalf("failed to parse HCL: %v", err)
	}
	items := file.Node.(*ast.ObjectList).Filter("request")
	_, err = ParseRequestConfig(nil, items)
	if err == nil || !strings.Contains(err.Error(), "type must be specified") {
		t.Fatalf("expected missing-type error, got %v", err)
	}
}
