package profiles

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCelSourceBuilder_EvaluateAndClose(t *testing.T) {
	ctx := t.Context()
	engine := &ProfileEngine{sourceBuilders: map[string]SourceBuilder{
		"request":  RequestSourceBuilder,
		"response": ResponseSourceBuilder,
	}}

	field := map[string]interface{}{"expression": "requests.test.value"}
	src := CELSourceBuilder(ctx, engine, field)
	require.NotNil(t, src)
	require.IsType(t, &CELSource{}, src)

	_, _, err := src.Validate(ctx)
	require.NoError(t, err, "failed to validate")

	history := &EvaluationHistory{}
	err = history.AddRequestData("", "test", map[string]interface{}{
		"value": 123,
	})
	require.NoError(t, err)

	result, err := src.Evaluate(ctx, history)
	require.NoError(t, err)
	require.Equal(t, result, int64(123))

	require.NoError(t, src.Close(ctx))
}

func TestCelSourceBuilder_RequestNotAllowed(t *testing.T) {
	ctx := t.Context()
	engine := &ProfileEngine{sourceBuilders: map[string]SourceBuilder{
		"response": ResponseSourceBuilder,
	}}

	field := map[string]interface{}{"expression": "requests.test.first.value"}
	src := CELSourceBuilder(ctx, engine, field)
	require.NotNil(t, src)

	_, _, err := src.Validate(ctx)
	require.Error(t, err, "expected failure to validate")
}

func TestCelSourceBuilder_ResponseNotAllowed(t *testing.T) {
	ctx := t.Context()
	engine := &ProfileEngine{sourceBuilders: map[string]SourceBuilder{}}

	field := map[string]interface{}{"expression": "response.test.first.value"}
	src := CELSourceBuilder(ctx, engine, field)
	require.NotNil(t, src)

	_, _, err := src.Validate(ctx)
	require.Error(t, err, "expected failure to validate")
}

func TestCelSourceBuilder_Constant(t *testing.T) {
	ctx := t.Context()
	engine := &ProfileEngine{sourceBuilders: map[string]SourceBuilder{}}

	field := map[string]interface{}{"expression": "123"}
	src := CELSourceBuilder(ctx, engine, field)
	require.NotNil(t, src)

	_, _, err := src.Validate(ctx)
	require.NoError(t, err, "failure to validate")
}
