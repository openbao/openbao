package cel

import (
	"fmt"
	"net/mail"

	celgo "github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
)

// checkValidEmail validates if the input is a properly formatted email address according to RFC 5322.
func checkValidEmail(value ref.Val) ref.Val {
	// Ensure the input is a string
	email, ok := value.Value().(string)
	if !ok {
		return types.Bool(false)
	}

	// Validate the email format
	if _, err := mail.ParseAddress(email); err != nil {
		return types.Bool(false)
	}

	return types.Bool(true)
}

// registerCheckValidEmailFunction registers the check_valid_email function in the CEL environment.
func registerCheckValidEmailFunction(env *celgo.Env) (*celgo.Env, error) {
	return env.Extend(
		celgo.Function("check_valid_email",
			celgo.Overload("check_valid_email_string",
				[]*celgo.Type{celgo.StringType}, // Takes a string input
				celgo.BoolType,                  // Returns a boolean
				celgo.UnaryBinding(checkValidEmail),
			),
		),
	)
}

// RegisterAllCelFunctions registers all custom CEL functions into the provided environment.
func RegisterAllCelFunctions(env *celgo.Env) (*celgo.Env, error) {
	var err error

	env, err = registerCheckValidEmailFunction(env)
	if err != nil {
		return nil, fmt.Errorf("failed to register check_valid_email function: %w", err)
	}

	return env, nil
}
