package profiles

import (
	"context"
	"os"
	"reflect"
	"testing"
)

func TestEnvSourceBuilder_Success(t *testing.T) {
	ctx := context.Background()
	engine := &ProfileEngine{sourceBuilders: make(map[string]SourceBuilder)}
	field := map[string]interface{}{"env_var": "TEST_VAR"}
	src := EnvSourceBuilder(ctx, engine, field)
	if src == nil {
		t.Errorf("Expected non-nil source")
	}
	if _, ok := src.(*EnvSource); !ok {
		t.Errorf("Expected *EnvSource, got %T", src)
	}
}

func TestEnvSource_Validate_SuccessRequired(t *testing.T) {
	const name = "REQ_VAR"
	const val = "value"
	os.Setenv(name, val)
	defer os.Unsetenv(name)

	src := &EnvSource{field: map[string]interface{}{
		"env_var":         name,
		"require_present": true,
	}}

	deps, provides, err := src.Validate(context.Background())
	if err != nil {
		t.Fatalf("Validate, error: %v", err)
	}
	if deps != nil {
		t.Errorf("Expected deps=nil, got %v", deps)
	}
	if provides != nil {
		t.Errorf("Expected provides=nil, got %v", provides)
	}
	if src.value != val {
		t.Errorf("Expected value %q, got %q", val, src.value)
	}
}

func TestEnvSource_Validate_OptionalMissing(t *testing.T) {
	src := &EnvSource{field: map[string]interface{}{
		"env_var": "MISSING_VAR",
	}}
	deps, provides, err := src.Validate(context.Background())
	if err != nil {
		t.Fatalf("Validate, error: %v", err)
	}
	if src.value != "" {
		t.Errorf("Expected empty value, got %q", src.value)
	}
	if deps != nil || provides != nil {
		t.Errorf("Expected deps,provides=nil")
	}
}

func TestEnvSource_Validate_ErrorMissingEnvVarField(t *testing.T) {
	src := &EnvSource{field: map[string]interface{}{
		"require_present": true,
	}}
	_, _, err := src.Validate(context.Background())
	if err == nil ||
		err.Error() != "env source is missing required field 'env_var'" {
		t.Fatalf("Expected missing-field error, got %v", err)
	}
}

func TestEnvSource_Validate_ErrorWrongTypes(t *testing.T) {
	cases := []struct {
		field map[string]interface{}
		want  string
	}{
		{map[string]interface{}{"env_var": 123}, "field 'env_var' is of wrong type: expected 'string'"},
		{
			map[string]interface{}{"env_var": "X", "require_present": "yes"},
			"field 'require_present' is of wrong type: expecting 'bool'",
		},
	}
	for _, c := range cases {
		src := &EnvSource{field: c.field}
		_, _, err := src.Validate(context.Background())
		if err == nil || !reflect.DeepEqual(err.Error()[:len(c.want)], c.want) {
			t.Errorf("field=%v: expected error prefix %q, got %v", c.field, c.want, err)
		}
	}
}

func TestEnvSource_EvaluateAndClose(t *testing.T) {
	src := &EnvSource{value: "v"}

	out, err := src.Evaluate(context.Background(), nil)
	if err != nil {
		t.Fatalf("Evaluate, error: %v", err)
	}
	if out != "v" {
		t.Errorf("Expected Evaluate->%q, got %q", "v", out)
	}

	if err := src.Close(context.Background()); err != nil {
		t.Errorf("Close, error: %v", err)
	}
}
