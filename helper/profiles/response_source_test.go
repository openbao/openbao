package profiles

import (
	"context"
	"reflect"
	"testing"
)

func TestSourceBuilder_Success(t *testing.T) {
	ctx := context.Background()
	engine := &ProfileEngine{outerBlockName: "outer", sourceBuilders: make(map[string]SourceBuilder)}
	field := map[string]interface{}{"response_name": "mount-userpass"}

	src := ResponseSourceBuilder(ctx, engine, field)
	respSrc, ok := src.(*ResponseSource)
	if !ok {
		t.Fatalf("expected *ResponseSource, got %T", src)
	}
	if !reflect.DeepEqual(respSrc.field, field) {
		t.Errorf("field = %v; want %v", respSrc.field, field)
	}
}

func TestWithResponseSource(t *testing.T) {
	engine := &ProfileEngine{
		sourceBuilders: make(map[string]SourceBuilder),
	}

	WithResponseSource()(engine)
	builder, found := engine.sourceBuilders["response"]
	if !found {
		t.Fatal("expected sourceBuilders['response'] to be set")
	}

	src := builder(context.Background(), engine, map[string]interface{}{"response_name": "x"})
	if src == nil {
		t.Fatalf("builder returned nil")
	}
	if _, ok := src.(*ResponseSource); !ok {
		t.Errorf("expected *ResponseSource, got %T", src)
	}
}

func TestValidate_MissingField(t *testing.T) {
	source := &ResponseSource{field: map[string]interface{}{}}
	_, _, err := source.Validate(context.Background())
	if err == nil {
		t.Fatal("expected error for missing 'response_name', got nil")
	}
}

func TestValidate_MissingOuterNameField(t *testing.T) {
	rs := &ResponseSource{
		outer: "profile",
		field: map[string]interface{}{
			"response_name": "r1",
		},
	}
	_, _, err := rs.Validate(context.Background())
	want := "response source is missing required field \"profile_name\""
	if err == nil || err.Error() != want {
		t.Fatalf("expected error %q, got %v", want, err)
	}
}

func TestValidate_WrongType(t *testing.T) {
	source := &ResponseSource{field: map[string]interface{}{"response_name": 1}}
	_, _, err := source.Validate(context.Background())
	if err == nil {
		t.Fatal("expected type error for 'response_name', got nil")
	}
}

func TestValidate_OuterNameWrongType(t *testing.T) {
	rs := &ResponseSource{
		outer: "profile",
		field: map[string]interface{}{
			"profile_name":  123,
			"response_name": "r1",
		},
	}
	_, _, err := rs.Validate(context.Background())
	want := "field \"profile_name\" is of wrong type: expected 'string' got 'int'"
	if err == nil || err.Error() != want {
		t.Fatalf("expected error %q, got %v", want, err)
	}
}

func TestEvaluate_WithFieldSelector_String(t *testing.T) {
	ctx := context.Background()
	source := &ResponseSource{
		field: map[string]interface{}{"response_name": "mount-userpass", "field_selector": "status"},
	}

	if _, _, err := source.Validate(ctx); err != nil {
		t.Fatalf("Validate error: %v", err)
	}

	history := &EvaluationHistory{}
	data := map[string]interface{}{
		"status": "active",
	}
	if err := history.AddResponseData("", "mount-userpass", data); err != nil {
		t.Fatalf("AddResponseData error: %v", err)
	}

	result, err := source.Evaluate(ctx, history)
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}
	expected := "active"
	if !reflect.DeepEqual(result, expected) {
		t.Fatalf("Evaluate result = %#v; want %#v", result, expected)
	}
}

func TestClose(t *testing.T) {
	ctx := context.Background()
	src := &ResponseSource{}
	err := src.Close(ctx)
	if err != nil {
		t.Errorf("Close returned error: %v", err)
	}
}
