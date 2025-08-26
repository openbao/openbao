package cel

import (
	"fmt"
	"net/mail"

	celgo "github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/ext"
	"github.com/openbao/openbao/sdk/v2/logical"
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

// registerCelGoExtFunctions registers the cel-go/ext functions in the provided environment.
func registerCelGoExtFunctions(env *celgo.Env) (*celgo.Env, error) {
	return env.Extend(ext.Strings(), ext.Lists(), celgo.OptionalTypes(), ext.Regex(), ext.Math(), ext.Sets(), ext.Encoders())
}

// RegisterAllCelFunctions registers all custom CEL functions into the provided environment.
func RegisterAllCelFunctions(env *celgo.Env) (*celgo.Env, error) {
	var err error

	env, err = registerCheckValidEmailFunction(env)
	if err != nil {
		return nil, fmt.Errorf("failed to register check_valid_email function: %w", err)
	}

	env, err = registerCelGoExtFunctions(env)
	if err != nil {
		return nil, fmt.Errorf("failed to register cel-go/ext functions: %w", err)
	}

	return env, nil
}

// IdentityDeclarations adds declarations relevant to the identity subsystem,
// and is useful for secret engines.
func IdentityDeclarations() []celgo.EnvOption {
	return []celgo.EnvOption{
		celgo.Declarations(
			decls.NewVar("client_token", decls.String),
			decls.NewVar("entity_id", decls.String),
			decls.NewVar("entity_groups", decls.NewListType(decls.Dyn)),
			decls.NewVar("entity_info", decls.NewMapType(decls.String, decls.Dyn)),
		),
	}
}

// AddIdentity adds values for the identity system and is useful for secret
// engines. IdentityDeclarations must be called to add these definitions to
// to the environment first.
func AddIdentity(view logical.SystemView, req *logical.Request, data map[string]interface{}) error {
	data["client_token"] = req.ClientToken
	data["entity_id"] = req.EntityID

	if len(req.EntityID) > 0 {
		groups, err := view.GroupsForEntity(req.EntityID)
		if err != nil {
			return fmt.Errorf("unable to resolve groups: %w", err)
		}

		data["entity_groups"] = groups

		info, err := view.EntityInfo(req.EntityID)
		if err != nil {
			return fmt.Errorf("unable to resolve entity info: %w", err)
		}

		data["entity_info"] = info
	} else {
		data["entity_groups"] = nil
		data["entity_info"] = nil
	}

	return nil
}
