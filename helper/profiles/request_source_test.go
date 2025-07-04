package profiles

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

func TestWithRequestSource_RegistersBuilder(t *testing.T) {
	engine := &ProfileEngine{
		outerBlockName: "initialize",
		sourceBuilders: make(map[string]SourceBuilder),
	}
	WithRequestSource()(engine)
	builder, ok := engine.sourceBuilders["request"]
	if !ok {
		t.Fatal(`expected key "request" in sourceBuilders`)
	}
	if reflect.ValueOf(builder).Pointer() != reflect.ValueOf(RequestSourceBuilder).Pointer() {
		t.Errorf("registered builder = %v; want RequestSourceBuilder", builder)
	}
}

func TestRequestSourceBuilder_Success(t *testing.T) {
	ctx := context.Background()
	engine := &ProfileEngine{
		outerBlockName: "initialize",
		sourceBuilders: make(map[string]SourceBuilder),
	}
	field := map[string]interface{}{"request": "userpass"}

	source, err := RequestSourceBuilder(ctx, engine, field)
	if err != nil {
		t.Fatalf("RequestSourceBuilder returned error: %v", err)
	}
	if source == nil {
		t.Fatal("expected non-nil Source")
	}

	reqSource, ok := source.(*RequestSource)
	if !ok {
		t.Errorf("expected *RequestSource, got %T", source)
	}
	if !reflect.DeepEqual(reqSource.field, field) {
		t.Errorf("expected field %v, got %v", field, reqSource.field)
	}
}

func TestRequestSource_ValidateMissingField(t *testing.T) {
	source := &RequestSource{field: map[string]interface{}{}}
	ctx := context.Background()

	_, _, err := source.Validate(ctx)
	if err == nil {
		t.Fatal("expected error for missing 'req_name' field, got nil")
	}

	if !strings.HasPrefix(err.Error(), "request source is missing required field 'req_name'") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRequestSource_ValidateWrongType(t *testing.T) {
	source := &RequestSource{field: map[string]interface{}{"req_name": 123}}
	ctx := context.Background()

	_, _, err := source.Validate(ctx)
	if err == nil {
		t.Fatal("expected type error")
	}
	if !strings.HasPrefix(err.Error(), "field 'req_name' is of wrong type") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRequestSource_Validate_Success(t *testing.T) {
	source := &RequestSource{field: map[string]interface{}{"req_name": "mount-userpass"}}
	ctx := context.Background()

	request, _, err := source.Validate(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(request) != 1 || request[0] != "mount-userpass" {
		t.Errorf("expected request=[mount-userpass], got %v", request)
	}
	if source.requestName != "mount-userpass" {
		t.Errorf("expected requestName 'mount-userpass', got %q", source.requestName)
	}
}

func TestRequestSource_Close(t *testing.T) {
	ctx := context.Background()
	source := &RequestSource{}
	err := source.Close(ctx)
	if err != nil {
		t.Errorf("Close returned error: %v", err)
	}
}

func TestRequestSource_Evaluate_Success(t *testing.T) {
	ctx := context.Background()
	history := &EvaluationHistory{}
	source := &RequestSource{
		field: map[string]interface{}{"req_name": "mount-userpass"},
	}

	gotPaths, _, err := source.Validate(ctx)
	if err != nil {
		t.Fatalf("Validate error: %v", err)
	}
	wantPaths := []string{"mount-userpass"}
	if !reflect.DeepEqual(gotPaths, wantPaths) {
		t.Fatalf("Validate paths = %v; want %v", gotPaths, wantPaths)
	}

	expectedData := map[string]interface{}{"foo": "bar"}
	if err := history.AddRequestData("", "mount-userpass", expectedData); err != nil {
		t.Fatalf("AddRequestData error: %v", err)
	}

	result, err := source.Evaluate(ctx, history)
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}
	gotData, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("Evaluate returned %T; want map[string]interface{}", result)
	}
	if !reflect.DeepEqual(gotData, expectedData) {
		t.Fatalf("Evaluate result = %#v; want %#v", gotData, expectedData)
	}
}

func TestRequestSource_Evaluate_WithFieldSelector_String(t *testing.T) {
	ctx := context.Background()
	history := &EvaluationHistory{}
	source := &RequestSource{
		field: map[string]interface{}{"req_name": "mount-userpass", "field_selector": "userPass"},
	}

	if _, _, err := source.Validate(ctx); err != nil {
		t.Fatalf("Validate error: %v", err)
	}

	requestData := map[string]interface{}{
		"userPass": "test",
	}
	if err := history.AddRequestData("", "mount-userpass", requestData); err != nil {
		t.Fatalf("AddRequestData error: %v", err)
	}

	result, err := source.Evaluate(ctx, history)
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}
	expected := "test"
	if !reflect.DeepEqual(result, expected) {
		t.Fatalf("Evaluate result = %#v; want %#v", result, expected)
	}
}
