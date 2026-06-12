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
	src := CELSourceBuilder(engine, field, nil)
	require.NotNil(t, src)
	require.IsType(t, &CELSource{}, src)

	_, _, err := src.Validate()
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
	engine := &ProfileEngine{sourceBuilders: map[string]SourceBuilder{
		"response": ResponseSourceBuilder,
	}}

	field := map[string]interface{}{"expression": "requests.test.value"}
	src := CELSourceBuilder(engine, field, nil)
	require.NotNil(t, src)

	_, _, err := src.Validate()
	require.Error(t, err, "expected failure to validate")
}

func TestCelSourceBuilder_ResponseNotAllowed(t *testing.T) {
	engine := &ProfileEngine{sourceBuilders: map[string]SourceBuilder{}}

	field := map[string]interface{}{"expression": "response.test.value"}
	src := CELSourceBuilder(engine, field, nil)
	require.NotNil(t, src)

	_, _, err := src.Validate()
	require.Error(t, err, "expected failure to validate")
}

func TestCelSourceBuilder_Constant(t *testing.T) {
	engine := &ProfileEngine{sourceBuilders: map[string]SourceBuilder{}}

	field := map[string]interface{}{"expression": "123"}
	src := CELSourceBuilder(engine, field, nil)
	require.NotNil(t, src)

	_, _, err := src.Validate()
	require.NoError(t, err, "failure to validate")
}

func TestCelSourceBuilder_ForEach(t *testing.T) {
	testCases := []struct {
		ic         *IterContext
		expression string
		expected   string
	}{
		{
			ic: &IterContext{
				This: &IterValue{
					Key:   "0",
					Value: "testing",
				},
			},
			expression: "this",
			expected:   "testing",
		},
		{
			ic: &IterContext{
				This: &IterValue{
					Key:   "0",
					Value: "testing",
				},
			},
			expression: "this_index",
			expected:   "0",
		},
		{
			ic: &IterContext{
				This: &IterValue{
					Key:   "0",
					Value: "testing",
				},
				Outer: &IterValue{
					Key:   "1",
					Value: "example",
				},
			},
			expression: "this",
			expected:   "testing",
		},
		{
			ic: &IterContext{
				This: &IterValue{
					Key:   "0",
					Value: "testing",
				},
				Outer: &IterValue{
					Key:   "1",
					Value: "example",
				},
			},
			expression: "this_index",
			expected:   "0",
		},
		{
			ic: &IterContext{
				This: &IterValue{
					Key:   "0",
					Value: "testing",
				},
				Outer: &IterValue{
					Key:   "1",
					Value: "example",
				},
			},
			expression: "outer_this",
			expected:   "example",
		},
		{
			ic: &IterContext{
				This: &IterValue{
					Key:   "0",
					Value: "testing",
				},
				Outer: &IterValue{
					Key:   "1",
					Value: "example",
				},
			},
			expression: "outer_this_index",
			expected:   "1",
		},
	}

	for index, tc := range testCases {
		t.Logf("test case: %v", index)

		ctx := t.Context()
		engine := &ProfileEngine{sourceBuilders: map[string]SourceBuilder{}}

		field := map[string]interface{}{"expression": tc.expression}
		src := CELSourceBuilder(engine, field, tc.ic)
		require.NotNil(t, src)
		require.IsType(t, &CELSource{}, src)

		_, _, err := src.Validate()
		require.NoError(t, err, "failed to validate")

		history := &EvaluationHistory{}
		result, err := src.Evaluate(ctx, history)
		require.NoError(t, err)
		require.Equal(t, result, tc.expected)

		require.NoError(t, src.Close(ctx))
	}
}
