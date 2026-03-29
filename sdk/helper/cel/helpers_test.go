package cel

import (
	"encoding/json"
	"testing"

	celgo "github.com/google/cel-go/cel"
	"github.com/google/cel-go/interpreter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCELHelpers tests CEL helper functions work as intended.
func TestCELHelpers(t *testing.T) {
	t.Parallel()

	// Initialize CEL environment with our custom functions
	env, err := celgo.NewEnv(
		CheckValidEmailFunction(),
		EncodeJSONFunction(),
		DecodeJSONFunction(),
	)
	require.NoError(t, err)
	env, err = env.Extend(CelGoExtFunctions()...)
	require.NoError(t, err)

	t.Run("check_valid_email", func(t *testing.T) {
		t.Parallel()

		tests := []struct {
			expr string
			want bool
		}{
			{"check_valid_email('foo@example.com')", true},
			{"check_valid_email('<foo@example.com>')", true},
			{"check_valid_email('<foo@example.com')", false},
			{"check_valid_email('invalid-email')", false},
			{"check_valid_email('user@domain..com')", false},
			{"check_valid_email('user@domain.com')", true},
		}

		for _, tc := range tests {
			tc := tc
			t.Run(tc.expr, func(t *testing.T) {
				t.Parallel()
				prog := buildTestProgram(t, env, tc.expr)
				val, _, err := prog.Eval(interpreter.EmptyActivation())
				require.NoError(t, err)
				isValid, ok := val.Value().(bool)
				require.True(t, ok)
				assert.Equal(t, tc.want, isValid)
			})
		}
	})

	t.Run("JSON_roundtrip", func(t *testing.T) {
		t.Parallel()

		expr := `decode_json(encode_json({'foo':'bar','num':42}))['foo'] == 'bar'`
		prog := buildTestProgram(t, env, expr)
		val, _, err := prog.Eval(interpreter.EmptyActivation())
		require.NoError(t, err)
		assert.Equal(t, true, val.Value())
	})

	t.Run("decode_json", func(t *testing.T) {
		t.Parallel()
		expr := `decode_json("{\"k\":\"v\"}")['k']`
		prog := buildTestProgram(t, env, expr)
		val, _, err := prog.Eval(interpreter.EmptyActivation())
		require.NoError(t, err)
		assert.Equal(t, "v", val.Value())
	})

	t.Run("encode_json", func(t *testing.T) {
		t.Parallel()
		expr := `encode_json({'a':1,'b':2})`
		prog := buildTestProgram(t, env, expr)
		val, _, err := prog.Eval(interpreter.EmptyActivation())
		require.NoError(t, err)

		// Unmarshal and compare
		var got map[string]int
		require.NoError(t, json.Unmarshal([]byte(val.Value().(string)), &got))
		assert.Equal(t, map[string]int{"a": 1, "b": 2}, got)
	})

	t.Run("cel_go_ext_functions", func(t *testing.T) {
		t.Parallel()

		tests := []struct {
			expr string
			want string
		}{
			// split
			{"'a,b,c'.split(',')[1]", "b"},
			// regex
			{"regex.extract('123abc456', r'([a-z]+)').orValue('')", "abc"},
			// base64
			{"base64.encode(b'hello')", "aGVsbG8="},
		}

		for _, tc := range tests {
			tc := tc
			t.Run(tc.expr, func(t *testing.T) {
				t.Parallel()
				prog := buildTestProgram(t, env, tc.expr)
				val, _, err := prog.Eval(interpreter.EmptyActivation())
				require.NoError(t, err)
				assert.Equal(t, tc.want, val.Value())
			})
		}
	})
}

// buildTestProgram compiles and runs CEL expressions in the test
func buildTestProgram(t *testing.T, env *celgo.Env, expr string) celgo.Program {
	t.Helper()
	ast, issues := env.Compile(expr)
	require.NoError(t, issues.Err(), "CEL compilation failed")
	prog, err := env.Program(ast)
	require.NoError(t, err, "CEL program creation failed")
	return prog
}
