package cel

import (
	"encoding/json"
	"fmt"
	"net/mail"
	"reflect"

	"github.com/google/cel-go/cel"
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

// checkValidEmailFunction adds the check_valid_email function.
func CheckValidEmailFunction() cel.EnvOption {
	return cel.Function("check_valid_email",
		cel.Overload("check_valid_email_string",
			[]*cel.Type{cel.StringType}, // Takes a string input
			cel.BoolType,                // Returns a boolean
			cel.UnaryBinding(checkValidEmail),
		),
	)
}

func CelGoExtFunctions() []cel.EnvOption {
	var options []cel.EnvOption

	options = append(options, ext.Strings())
	options = append(options, ext.Lists())
	options = append(options, cel.OptionalTypes())
	options = append(options, ext.Regex())
	options = append(options, ext.Math())
	options = append(options, ext.Sets())
	options = append(options, ext.Encoders())

	return options
}

// IdentityDeclarations adds declarations relevant to the identity subsystem,
// and is useful for secret engines.
func IdentityDeclarations() []cel.EnvOption {
	return []cel.EnvOption{
		cel.Variable("client_token", types.DynType),
		cel.Variable("entity_id", types.StringType),
		cel.Variable("entity_groups", types.NewListType(types.DynType)),
		cel.Variable("entity_info", types.NewMapType(types.StringType, types.DynType)),
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

func encodeJSON(value ref.Val) ref.Val {
	native, err := value.ConvertToNative(
		reflect.TypeOf(map[string]any{}),
	)
	if err != nil {
		return types.Bool(false)
	}

	b, err := json.Marshal(native)
	if err != nil {
		return types.Bool(false)
	}
	return types.String(string(b))
}

func decodeJSON(value ref.Val) ref.Val {
	raw, ok := value.Value().(string)
	if !ok {
		return types.Bool(false)
	}
	var v any
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		return types.Bool(false)
	}
	return types.DefaultTypeAdapter.NativeToValue(v)
}

// EncodeJSONFunction adds the encode_json function.
func EncodeJSONFunction() cel.EnvOption {
	return cel.Function("encode_json",
		cel.Overload(
			"encode_json_dyn",
			[]*cel.Type{cel.DynType},
			cel.StringType,
			cel.UnaryBinding(encodeJSON),
		),
	)
}

// DecodeJSONFunction adds the decode_json function.
func DecodeJSONFunction() cel.EnvOption {
	return cel.Function("decode_json",
		cel.Overload(
			"decode_json_string",
			[]*cel.Type{cel.StringType},
			cel.DynType,
			cel.UnaryBinding(decodeJSON),
		),
	)
}
