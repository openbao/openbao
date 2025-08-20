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
		celgo.Lib(customLibrary{}), // Custom library with functions
	)
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

	t.Run("decode_json_roundtrip", func(t *testing.T) {
		t.Parallel()

		expr := `decode_json(encode_JSON({'foo':'bar','num':42}))['foo'] == 'bar'`
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

	t.Run("encode_JSON", func(t *testing.T) {
		t.Parallel()
		expr := `encode_JSON({'a':1,'b':2})`
		prog := buildTestProgram(t, env, expr)
		val, _, err := prog.Eval(interpreter.EmptyActivation())
		require.NoError(t, err)

		// Unmarshal and compare
		var got map[string]int
		require.NoError(t, json.Unmarshal([]byte(val.Value().(string)), &got))
		assert.Equal(t, map[string]int{"a": 1, "b": 2}, got)
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

// customLibrary implements a CEL library with our custom functions
type customLibrary struct{}

func (customLibrary) CompileOptions() []celgo.EnvOption {
	return []celgo.EnvOption{
		celgo.Function("check_valid_email",
			celgo.Overload("check_valid_email_string",
				[]*celgo.Type{celgo.StringType},
				celgo.BoolType,
				celgo.UnaryBinding(checkValidEmail),
			),
		),
		// decode_json
		celgo.Function("decode_json",
			celgo.Overload("decode_json_string",
				[]*celgo.Type{celgo.StringType},
				celgo.DynType,
				celgo.UnaryBinding(decodeJSON),
			),
		),
		// encode_JSON
		celgo.Function("encode_JSON",
			celgo.Overload("encode_JSON_dyn",
				[]*celgo.Type{celgo.DynType},
				celgo.StringType,
				celgo.UnaryBinding(encodeJSON),
			),
		),
	}
}

func (customLibrary) ProgramOptions() []celgo.ProgramOption {
	return nil
}
