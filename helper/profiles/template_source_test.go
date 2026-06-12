package profiles

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTemplateSourceBuilder_EvaluateAndClose(t *testing.T) {
	ctx := t.Context()
	engine := &ProfileEngine{sourceBuilders: map[string]SourceBuilder{
		"request":  RequestSourceBuilder,
		"response": ResponseSourceBuilder,
	}}

	field := map[string]interface{}{"template": "{{ .requests.test.value }}"}
	src := TemplateSourceBuilder(engine, field, nil)
	require.NotNil(t, src)
	require.IsType(t, &TemplateSource{}, src)

	_, _, err := src.Validate()
	require.NoError(t, err, "failed to validate")

	history := &EvaluationHistory{}
	err = history.AddRequestData("", "test", map[string]interface{}{
		"value": 123,
	})
	require.NoError(t, err)

	result, err := src.Evaluate(ctx, history)
	require.NoError(t, err)
	require.Equal(t, result, "123")

	require.NoError(t, src.Close(ctx))
}

func TestTemplateSourceBuilder_RequestNotAllowed(t *testing.T) {
	ctx := t.Context()
	engine := &ProfileEngine{sourceBuilders: map[string]SourceBuilder{
		"response": ResponseSourceBuilder,
	}}

	field := map[string]interface{}{"template": "{{ .requests.test.value }}"}
	src := TemplateSourceBuilder(engine, field, nil)
	require.NotNil(t, src)

	_, _, err := src.Validate()
	require.NoError(t, err, "failure to validate")

	_, err = src.Evaluate(ctx, &EvaluationHistory{})
	require.Error(t, err, "expected failure to execute")
}

func TestTemplateSourceBuilder_ResponseNotAllowed(t *testing.T) {
	ctx := t.Context()
	engine := &ProfileEngine{sourceBuilders: map[string]SourceBuilder{}}

	field := map[string]interface{}{"template": "{{ .response.test.value }}"}
	src := TemplateSourceBuilder(engine, field, nil)
	require.NotNil(t, src)

	_, _, err := src.Validate()
	require.NoError(t, err, "failure to validate")

	_, err = src.Evaluate(ctx, &EvaluationHistory{})
	require.Error(t, err, "expected failure to execute")
}

func TestTemplateSourceBuilder_Constant(t *testing.T) {
	ctx := t.Context()
	engine := &ProfileEngine{sourceBuilders: map[string]SourceBuilder{}}

	field := map[string]interface{}{"template": "123"}
	src := TemplateSourceBuilder(engine, field, nil)
	require.NotNil(t, src)

	_, _, err := src.Validate()
	require.NoError(t, err, "failure to validate")

	_, err = src.Evaluate(ctx, &EvaluationHistory{})
	require.NoError(t, err, "failure to execute")
}

func TestTemplateSourceBuilder_EvaluateAdditionalData(t *testing.T) {
	ctx := t.Context()
	engine := &ProfileEngine{sourceBuilders: map[string]SourceBuilder{
		"request":  RequestSourceBuilder,
		"response": ResponseSourceBuilder,
	}}

	field := map[string]interface{}{
		"template": "{{ .alex }}",
		"data": map[string]interface{}{
			"alex": "test",
		},
	}
	src := TemplateSourceBuilder(engine, field, nil)
	require.NotNil(t, src)
	require.IsType(t, &TemplateSource{}, src)

	_, _, err := src.Validate()
	require.NoError(t, err, "failed to validate")

	result, err := src.Evaluate(ctx, &EvaluationHistory{})
	require.NoError(t, err)
	require.Equal(t, result, "test")
}
