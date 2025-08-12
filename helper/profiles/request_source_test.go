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

	source := RequestSourceBuilder(ctx, engine, field)
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
		t.Fatal("expected error for missing 'request_name' field, got nil")
	}

	if !strings.HasPrefix(err.Error(), "request source is missing required field \"request_name\"") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRequestSource_Validate_MissingOuterNameField(t *testing.T) {
	rs := &RequestSource{
		outer: "profile",
		field: map[string]interface{}{"request_name": "r1"},
	}

	_, _, err := rs.Validate(context.Background())
	want := "request source is missing required field 'profile_name'"
	if err == nil {
		t.Fatalf("expected error %q, got nil", want)
	}
	if err.Error() != want {
		t.Fatalf("expected error %q, got %q", want, err.Error())
	}
}

func TestRequestSource_Validate_Success(t *testing.T) {
	source := &RequestSource{
		field: map[string]interface{}{
			"request_name":   "mount-userpass",
			"field_selector": "",
		},
	}
	ctx := context.Background()

	reqs, _, err := source.Validate(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(reqs) != 1 || reqs[0] != "mount-userpass" {
		t.Errorf("expected request=[mount-userpass], got %v", reqs)
	}
	if source.requestName != "mount-userpass" {
		t.Errorf("expected requestName 'mount-userpass', got %q", source.requestName)
	}
}

func TestRequestValidate_OuterNameWrongType(t *testing.T) {
	rs := &RequestSource{
		outer: "profile",
		field: map[string]interface{}{"profile_name": 123, "request_name": "r1"},
	}

	_, _, err := rs.Validate(context.Background())
	want := "field 'profile_name' is of wrong type: expected 'string' got 'int'"
	if err == nil {
		t.Fatalf("expected error %q, got nil", want)
	}
	if err.Error() != want {
		t.Fatalf("expected error %q, got %q", want, err.Error())
	}
}

func TestRequestValidate_OuterNameOK(t *testing.T) {
	rs := &RequestSource{
		outer: "profile",
		field: map[string]interface{}{
			"profile_name":   "outer1",
			"request_name":   "r1",
			"field_selector": "",
		},
	}

	gotReqDeps, gotRespDeps, err := rs.Validate(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	wantDeps := []string{"outer1.r1"}
	if !reflect.DeepEqual(gotReqDeps, wantDeps) {
		t.Errorf("requestDeps = %v; want %v", gotReqDeps, wantDeps)
	}
	if len(gotRespDeps) != 0 {
		t.Errorf("responseDeps = %v; want empty", gotRespDeps)
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

func TestRequestSource_Evaluate_WithFieldSelector_String(t *testing.T) {
	ctx := context.Background()
	history := &EvaluationHistory{}
	source := &RequestSource{
		field: map[string]interface{}{"request_name": "mount-userpass", "field_selector": "userPass"},
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
