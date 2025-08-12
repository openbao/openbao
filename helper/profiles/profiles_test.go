package profiles

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/sdk/v2/logical"
)

type minimalSource struct {
	validateFunc func(ctx context.Context) ([]string, []string, error)
	evalFunc     func(ctx context.Context, hist *EvaluationHistory) (interface{}, error)
}

func (m *minimalSource) Validate(ctx context.Context) ([]string, []string, error) {
	return m.validateFunc(ctx)
}

func (m *minimalSource) Evaluate(ctx context.Context, hist *EvaluationHistory) (interface{}, error) {
	return m.evalFunc(ctx, hist)
}
func (m *minimalSource) Close(ctx context.Context) error { return nil }

func testBuilder(evalResult interface{}, evalErr error) SourceBuilder {
	return func(ctx context.Context, _ *ProfileEngine, field map[string]interface{}) Source {
		if evalResult == nil && evalErr == nil {
			return nil
		}
		return &minimalSource{
			validateFunc: func(context.Context) ([]string, []string, error) {
				return nil, nil, nil
			},
			evalFunc: func(context.Context, *EvaluationHistory) (interface{}, error) {
				return evalResult, evalErr
			},
		}
	}
}

func testBuilderNotEmpty(evalResult interface{}, evalErr error) SourceBuilder {
	return func(ctx context.Context, _ *ProfileEngine, field map[string]interface{}) Source {
		if evalResult == nil && evalErr == nil {
			return nil
		}
		return &minimalSource{
			validateFunc: func(context.Context) ([]string, []string, error) {
				return []string{"mock-request"}, []string{"mock-response"}, nil
			},
			evalFunc: func(context.Context, *EvaluationHistory) (interface{}, error) {
				return evalResult, evalErr
			},
		}
	}
}

var testHandler = RequestHandlerFunc(func(ctx context.Context, req *logical.Request) (*logical.Response, error) {
	return &logical.Response{}, nil
})

func WithProfileAndHandler(profile []*OuterConfig, handler RequestHandlerFunc, outerName string) func(*ProfileEngine) {
	return func(e *ProfileEngine) {
		e.profile = profile
		e.requestHandler = handler
		e.outerBlockName = outerName
	}
}

func TestNewEngine_Success(t *testing.T) {
	engine, err := NewEngine(func(e *ProfileEngine) {
		e.profile = []*OuterConfig{
			{Type: "outer", Requests: []*RequestConfig{{Type: "req"}}},
		}
		e.requestHandler = testHandler
		e.outerBlockName = "outer"
	})
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if engine == nil {
		t.Fatal("expected non-nil engine")
	}
	if engine.requestHandler == nil {
		t.Fatal("expected requestHandler to be set")
	}
	if len(engine.profile) != 1 || engine.profile[0].Type != "outer" {
		t.Fatalf("unexpected profile data: %+v", engine.profile)
	}
}

func TestWithSourceBuilder(t *testing.T) {
	engine := &ProfileEngine{sourceBuilders: make(map[string]SourceBuilder)}
	sb := testBuilder(nil, nil)
	WithSourceBuilder("foo", sb)(engine)

	builder, ok := engine.sourceBuilders["foo"]
	if !ok {
		t.Fatal(`expected sourceBuilders["foo"] to be set`)
	}

	got := reflect.ValueOf(builder).Pointer()
	want := reflect.ValueOf(sb).Pointer()
	if got != want {
		t.Errorf("builder pointer = %v; want %v", got, want)
	}
}

func TestWithDefaultToken(t *testing.T) {
	engine := &ProfileEngine{}
	WithDefaultToken("tok123")(engine)
	if engine.defaultToken != "tok123" {
		t.Errorf("defaultToken = %q; want %q", engine.defaultToken, "tok123")
	}
}

func TestWithProfile(t *testing.T) {
	outer := &OuterConfig{Type: "X"}
	engine := &ProfileEngine{}
	WithProfile([]*OuterConfig{outer})(engine)
	if len(engine.profile) != 1 || engine.profile[0] != outer {
		t.Errorf("profile = %v; want [%v]", engine.profile, outer)
	}
}

func TestWithOuterBlockName(t *testing.T) {
	engine := &ProfileEngine{}
	WithOuterBlockName("blockA")(engine)
	if engine.outerBlockName != "blockA" {
		t.Errorf("outerBlockName = %q; want %q", engine.outerBlockName, "blockA")
	}
}

func TestWithLogger(t *testing.T) {
	engine := &ProfileEngine{}
	logger := hclog.NewNullLogger()
	WithLogger(logger)(engine)
	if engine.logger != logger {
		t.Errorf("logger = %v; want %v", engine.logger, logger)
	}
}

func TestWithRequestHandler(t *testing.T) {
	engine := &ProfileEngine{}
	WithRequestHandler(testHandler)(engine)

	got := reflect.ValueOf(engine.requestHandler).Pointer()
	want := reflect.ValueOf(testHandler).Pointer()
	if got != want {
		t.Errorf("requestHandler pointer = %v; want %v", got, want)
	}
}

func TestValidate_EmptySourceName(t *testing.T) {
	validBuilder := func(ctx context.Context, engine *ProfileEngine, cfg map[string]interface{}) Source {
		return nil
	}

	engine := &ProfileEngine{
		sourceBuilders: map[string]SourceBuilder{
			"": validBuilder,
		},
		profile:        []*OuterConfig{{Type: "outer", Requests: []*RequestConfig{{Type: "r"}}}},
		requestHandler: testHandler,
		outerBlockName: "outer",
	}

	err := engine.validate()
	if err == nil {
		t.Fatal("expected error for empty source name, got nil")
	}
	if !strings.Contains(err.Error(), "a source is missing a name") {
		t.Fatalf("expected 'a source is missing a name' error, got: %v", err)
	}
}

func TestValidate_NilBuilder(t *testing.T) {
	engine := &ProfileEngine{
		sourceBuilders: map[string]SourceBuilder{
			"nil_builder": nil,
		},
		profile:        []*OuterConfig{{Type: "outer", Requests: []*RequestConfig{{Type: "r"}}}},
		requestHandler: testHandler,
		outerBlockName: "outer",
	}

	err := engine.validate()
	if err == nil {
		t.Fatal("expected error for nil builder, got nil")
	}
	if !strings.Contains(err.Error(), "source 'nil_builder' has nil builder") {
		t.Fatalf("expected 'source 'nil_builder' has nil builder' error, got: %v", err)
	}
}

func TestProfileEngine_Validate_SuccessSingleBlock(t *testing.T) {
	engine, err := NewEngine(
		func(e *ProfileEngine) {
			e.profile = []*OuterConfig{{Type: "outer", Requests: []*RequestConfig{{Type: "req"}}}}
			e.requestHandler = testHandler
			e.outerBlockName = "outer"
		},
	)
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}
	if err := engine.validate(); err != nil {
		t.Fatalf("validate error: %v", err)
	}
}

func TestProfileEngine_Validate_MissingHandler(t *testing.T) {
	engine, err := NewEngine(
		func(e *ProfileEngine) {
			e.profile = []*OuterConfig{{Type: "o", Requests: []*RequestConfig{{Type: "r"}}}}
			e.outerBlockName = "o"
		},
	)
	if err == nil || !strings.Contains(err.Error(), "missing a request handler") {
		t.Fatalf("expected missing-handler error, got: %v", err)
	}
	if engine != nil {
		t.Fatal("expected engine to be nil on error")
	}
}

func TestValidateOuterBlockUniqueness_OK(t *testing.T) {
	_, err := NewEngine(
		WithProfileAndHandler(
			[]*OuterConfig{{Type: "one"}, {Type: "two"}},
			testHandler,
			"one",
		),
	)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestValidateOuterBlockUniqueness_Duplicate(t *testing.T) {
	_, err := NewEngine(
		WithProfileAndHandler(
			[]*OuterConfig{{Type: "dup"}, {Type: "dup"}},
			testHandler,
			"dup",
		),
	)
	if err == nil || !strings.Contains(err.Error(), "duplicate outer block name 'dup'") {
		t.Fatalf("expected duplicate-name error, got: %v", err)
	}
}

func TestValidateRequestNameUniqueness_Duplicate(t *testing.T) {
	_, err := NewEngine(
		WithProfileAndHandler(
			[]*OuterConfig{{
				Type: "block",
				Requests: []*RequestConfig{
					{Type: "dup"}, {Type: "dup"},
				},
			}},
			testHandler,
			"block",
		),
	)
	if err == nil || !strings.Contains(err.Error(), "duplicate request name 'dup'") {
		t.Fatalf("expected duplicate-request error, got: %v", err)
	}
}

func TestValidateRequestNameUniqueness_EmptyType(t *testing.T) {
	_, err := NewEngine(
		WithProfileAndHandler(
			[]*OuterConfig{{
				Type: "",
				Requests: []*RequestConfig{
					{Type: ""},
				},
			}},
			testHandler,
			"",
		),
	)
	if err == nil || !strings.Contains(err.Error(), "empty request name") {
		t.Fatalf("expected empty request name error, got: %v", err)
	}
}

func TestValidateNameConvention_Fail(t *testing.T) {
	_, err := NewEngine(
		WithProfileAndHandler(
			[]*OuterConfig{{Type: "#bad", Requests: []*RequestConfig{{Type: "r"}}}},
			testHandler,
			"#bad",
		),
	)
	if err == nil {
		t.Fatal("expected error for invalid outer block name, got nil")
	} else if !strings.Contains(err.Error(), "outer block name '#bad' is invalid") {
		t.Fatalf("expected naming-convention error, got: %v", err)
	}
}

func TestValidate_MultiBlockNoOuterName(t *testing.T) {
	_, err := NewEngine(
		WithProfileAndHandler(
			[]*OuterConfig{
				{Type: "o1", Requests: []*RequestConfig{{Type: "r1"}}},
				{Type: "o2", Requests: []*RequestConfig{{Type: "r2"}}},
			},
			testHandler,
			"",
		),
	)
	if err == nil || !strings.Contains(err.Error(), "must have named outer block") {
		t.Fatalf("expected multi-block error, got: %v", err)
	}
}

func TestValidate_SingleBlockEmptyOuterName(t *testing.T) {
	_, err := NewEngine(
		WithProfileAndHandler(
			[]*OuterConfig{{Type: "single", Requests: []*RequestConfig{{Type: "r"}}}},
			testHandler,
			"",
		),
	)
	if err != nil {
		t.Fatalf("expected no error for single block, got: %v", err)
	}
}

func Test_Evaluate_Success(t *testing.T) {
	ctx := context.Background()

	engine, err := NewEngine(
		WithProfile([]*OuterConfig{
			{
				Type: "test",
				Requests: []*RequestConfig{
					{
						Type:      "testr",
						Operation: "read",
						Path:      "sys/health",
					},
				},
			},
		}),
		WithRequestHandler(testHandler),
		WithOuterBlockName("test"),
	)
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}

	err = engine.Evaluate(ctx)
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}
}

func TestBuildRequest_BasicRequestCreation(t *testing.T) {
	engine := &ProfileEngine{
		sourceBuilders: map[string]SourceBuilder{},
		requestHandler: testHandler,
	}

	hist := &EvaluationHistory{
		Requests:  map[string]map[string]map[string]interface{}{},
		Responses: map[string]map[string]map[string]interface{}{},
	}

	outerConfig := &OuterConfig{Type: "outer"}
	requestConfig := &RequestConfig{
		Type:      "test-request",
		Operation: "read",
		Path:      "secret/test",
		Data: map[string]interface{}{
			"key": "value",
		},
	}

	req, allowFailure, err := engine.buildRequest(context.Background(), hist, 0, outerConfig, 0, requestConfig)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if req == nil {
		t.Fatal("expected non-nil request")
	}

	if req.Operation != logical.ReadOperation {
		t.Errorf("expected operation %v, got %v", logical.ReadOperation, req.Operation)
	}

	if req.Path != "secret/test" {
		t.Errorf("expected path 'secret/test', got '%s'", req.Path)
	}

	if req.Data["key"] != "value" {
		t.Errorf("expected data key 'value', got %v", req.Data["key"])
	}

	if allowFailure {
		t.Error("expected allowFailure to be false by default")
	}
}

func TestEvaluateField_NilDestination(t *testing.T) {
	engine := &ProfileEngine{
		sourceBuilders: map[string]SourceBuilder{},
		requestHandler: testHandler,
	}
	hist := &EvaluationHistory{Requests: map[string]map[string]map[string]interface{}{}, Responses: map[string]map[string]map[string]interface{}{}}
	err := engine.evaluateField(context.Background(), hist, "foo", nil)
	if err == nil {
		t.Fatal("expected error for nil destination, got nil")
	}
}

func TestEvaluateField_EvalSourceSuccess(t *testing.T) {
	engine := &ProfileEngine{
		sourceBuilders: map[string]SourceBuilder{"b": testBuilderNotEmpty("hello", nil)},
		requestHandler: testHandler,
	}
	hist := &EvaluationHistory{Requests: map[string]map[string]map[string]interface{}{}, Responses: map[string]map[string]map[string]interface{}{"": {}}}

	field := map[string]interface{}{"eval_source": "b", "eval_type": "string"}
	var dest string
	err := engine.evaluateField(context.Background(), hist, field, &dest)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if dest != "hello" {
		t.Errorf("dest = %q; want \"hello\"", dest)
	}
}

func TestEvaluateField_EvalSourceError(t *testing.T) {
	engine := &ProfileEngine{
		sourceBuilders: map[string]SourceBuilder{"b": testBuilderNotEmpty(nil, errors.New("fail"))},
		requestHandler: testHandler,
	}
	hist := &EvaluationHistory{Requests: map[string]map[string]map[string]interface{}{}, Responses: map[string]map[string]map[string]interface{}{"": {}}}

	field := map[string]interface{}{"eval_source": "b", "eval_type": "string"}
	var dest string
	err := engine.evaluateField(context.Background(), hist, field, &dest)
	if err == nil || !strings.Contains(err.Error(), "fail") {
		t.Fatalf("expected evaluation error, got %v", err)
	}
}

func TestEvaluateTypedField_UnknownSource(t *testing.T) {
	eng := &ProfileEngine{sourceBuilders: map[string]SourceBuilder{}}
	hist := &EvaluationHistory{Requests: map[string]map[string]map[string]interface{}{}, Responses: map[string]map[string]map[string]interface{}{}}
	_, err := eng.evaluateTypedField(context.Background(), hist, nil, "nope", "")
	if err == nil || !strings.Contains(err.Error(), "unknown value for 'eval_source': nope") {
		t.Fatalf("expected unknown-source error, got: %v", err)
	}
}

func TestEvaluateTypedField_InitError(t *testing.T) {
	builder := func(ctx context.Context, _ *ProfileEngine, obj map[string]interface{}) Source {
		return &minimalSource{
			validateFunc: func(context.Context) ([]string, []string, error) {
				return nil, nil, errors.New("init fail")
			},
			evalFunc: func(context.Context, *EvaluationHistory) (interface{}, error) {
				return nil, nil
			},
		}
	}

	eng := &ProfileEngine{
		sourceBuilders: map[string]SourceBuilder{
			"src": builder,
		},
	}
	hist := &EvaluationHistory{
		Requests:  map[string]map[string]map[string]interface{}{},
		Responses: map[string]map[string]map[string]interface{}{},
	}

	_, err := eng.evaluateTypedField(context.Background(), hist, nil, "src", "")
	if err == nil || !strings.Contains(err.Error(), "failed to validate source 'src'") {
		t.Fatalf("expected validate-error, got: %v", err)
	}
}

func TestEvaluateTypedField_ValidateError(t *testing.T) {
	builder := func(ctx context.Context, _ *ProfileEngine, obj map[string]interface{}) Source {
		return &minimalSource{
			validateFunc: func(ctx context.Context) ([]string, []string, error) {
				return nil, nil, errors.New("bad validate")
			},
			evalFunc: func(ctx context.Context, hist *EvaluationHistory) (interface{}, error) {
				return nil, nil
			},
		}
	}
	eng := &ProfileEngine{
		sourceBuilders: map[string]SourceBuilder{
			"src": builder,
		},
	}
	hist := &EvaluationHistory{
		Requests:  map[string]map[string]map[string]interface{}{},
		Responses: map[string]map[string]map[string]interface{}{},
	}
	_, err := eng.evaluateTypedField(context.Background(), hist, nil, "src", "")
	if err == nil || !strings.Contains(err.Error(), "failed to validate source 'src'") {
		t.Fatalf("expected validate-error, got: %v", err)
	}
}

func TestEvaluateTypedField_EvaluateError(t *testing.T) {
	builder := testBuilderNotEmpty(nil, errors.New("eval fail"))
	eng := &ProfileEngine{sourceBuilders: map[string]SourceBuilder{"src": builder}}

	obj := map[string]interface{}{}
	_, err := eng.evaluateTypedField(context.Background(), &EvaluationHistory{}, obj, "src", "string")

	if err == nil {
		t.Fatalf("expected evaluate-error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "eval fail") {
		t.Fatalf("expected evaluate-error, got: %v", err)
	}
}

func TestEvaluateTypedField_HistoryInconsistency(t *testing.T) {
	builder := testBuilderNotEmpty("test", nil)
	eng := &ProfileEngine{sourceBuilders: map[string]SourceBuilder{"src": builder}}
	hist := &EvaluationHistory{
		Requests:  map[string]map[string]map[string]interface{}{"outer": {"req": {}}},
		Responses: map[string]map[string]map[string]interface{}{"outer": {}},
	}
	result, err := eng.evaluateTypedField(context.Background(), hist, nil, "src", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatalf("expected non-nil result, got nil")
	}
}

func TestEvaluateTypedField_ConversionError(t *testing.T) {
	createMockSource := func(validateReqs, validateResps []string, evalResult interface{}, evalErr error) SourceBuilder {
		return func(ctx context.Context, _ *ProfileEngine, obj map[string]interface{}) Source {
			return &minimalSource{
				validateFunc: func(ctx context.Context) ([]string, []string, error) {
					return validateReqs, validateResps, nil
				},
				evalFunc: func(ctx context.Context, h *EvaluationHistory) (interface{}, error) {
					return evalResult, evalErr
				},
			}
		}
	}
	builder := createMockSource(
		[]string{"req1"},
		[]string{"resp1"},
		"notInt",
		nil,
	)

	eng := &ProfileEngine{
		sourceBuilders: map[string]SourceBuilder{"src": builder},
	}

	obj := map[string]interface{}{}
	_, err := eng.evaluateTypedField(context.Background(), &EvaluationHistory{}, obj, "src", "int")

	if err == nil || !strings.Contains(err.Error(), "conversion") {
		t.Fatalf("expected conversion-error, got: %v", err)
	}
}

func TestEvaluateTypedField_SuccessConversion(t *testing.T) {
	builder := testBuilderNotEmpty(123, nil)
	eng := &ProfileEngine{sourceBuilders: map[string]SourceBuilder{"src": builder}}

	obj := map[string]interface{}{}
	result, err := eng.evaluateTypedField(context.Background(), &EvaluationHistory{}, obj, "src", "int")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if result != 123 {
		t.Fatalf("expected 123, got: %v", result)
	}
}

func TestConvertToType_Cases(t *testing.T) {
	engine := &ProfileEngine{}

	tests := []struct {
		name    string
		val     interface{}
		objType string
		want    interface{}
		wantErr bool
	}{
		{"To string pass", "foo", "string", "foo", false},
		{"To string fail", []interface{}{}, "string", nil, true},

		{"To int pass", 42, "int", 42, false},
		{"To int fail", "notanint", "int", nil, true},

		{"To float64 pass", 2.71, "float64", 2.71, false},
		{"To float64 fail", "pi", "float64", nil, true},

		{"To bool pass", true, "bool", true, false},
		{"To bool fail", []interface{}{}, "bool", nil, true},

		{"To []string pass", []interface{}{"a", "b"}, "[]string", []string{"a", "b"}, false},

		{"To map[string]interface{} pass", map[string]interface{}{"x": 1}, "map[string]interface{}", map[string]interface{}{"x": 1}, false},
		{"To map[string]interface{} fail", "notamap", "map[string]interface{}", nil, true},

		{"Any to interface{} pass", 123, "interface{}", 123, false},

		{"unsupportedxs fail", "foo", "customType", nil, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := engine.convertToType(tc.val, tc.objType)
			if tc.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got %v (%T); want %v (%T)", got, got, tc.want, tc.want)
			}
		})
	}
}

func TestConvertToType_ObjTypeEmpty_ReturnsOriginal(t *testing.T) {
	engine := &ProfileEngine{}

	valInt := 123
	gotInt, err := engine.convertToType(valInt, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotInt != valInt {
		t.Errorf("got %v; want original %v", gotInt, valInt)
	}
}
