package profiles

import (
	"fmt"

	"github.com/hashicorp/hcl"
	"github.com/hashicorp/hcl/hcl/ast"
	"github.com/openbao/openbao/internalshared/configutil"
)

// OuterConfig is a named configuration object that contains one or more request
// objects. This allows the splitting of a single large profile into smaller
// sub-profiles while still allowing references across the entire space.
type OuterConfig struct {
	UnusedKeys configutil.UnusedKeyMap `hcl:",unusedKeyPositions"`
	RawConfig  map[string]interface{}

	Type     string
	Requests []*RequestConfig `hcl:"-"`
}

// RequestConfig maps a single API request invocation.
type RequestConfig struct {
	UnusedKeys configutil.UnusedKeyMap `hcl:",unusedKeyPositions"`
	RawConfig  map[string]interface{}

	Type string

	Operation interface{} `hcl:"operation"`
	Path      interface{} `hcl:"path"`
	Token     interface{} `hcl:"token"`
	Data      interface{} `hcl:"data"`

	AllowFailure interface{} `hcl:"allow_failure"`
}

// ParseOuterConfig is a helper for profile systems which support multiple
// outer blocks (e.g., initialize in the case of the declarative
// self-initialization subsystem). Callers wishing to only have a single
// outer block but which may support multiple requests may directly call
// ParseRequestConfig(...) and assign the result via CreateOuterConfig(...).
func ParseOuterConfig(outerBlockType string, result []*OuterConfig, list *ast.ObjectList) ([]*OuterConfig, error) {
	result = make([]*OuterConfig, 0, len(list.Items))
	for index, item := range list.Items {
		var i OuterConfig
		if err := hcl.DecodeObject(&i, item.Val); err != nil {
			return result, fmt.Errorf("%v.%d: %w", outerBlockType, index, err)
		}

		var m map[string]interface{}
		if err := hcl.DecodeObject(&m, item.Val); err != nil {
			return result, fmt.Errorf("%v.%d: %w", outerBlockType, index, err)
		}
		i.RawConfig = m

		switch {
		case i.Type != "":
		case len(item.Keys) == 1:
			i.Type = item.Keys[0].Token.Value().(string)
		default:
			return result, fmt.Errorf("%v.%d: %v type must be specified: %#v", outerBlockType, index, outerBlockType, item)
		}

		objT, ok := item.Val.(*ast.ObjectType)
		if !ok {
			return result, fmt.Errorf("%v.%d: error parsing item: does not contain a root object (was of type %T)", outerBlockType, index, item.Val)
		}

		list := objT.List

		if o := list.Filter("request"); len(o.Items) > 0 {
			requests, err := ParseRequestConfig(nil, o)
			if err != nil {
				return result, fmt.Errorf("%v.%d: error parsing 'request': %w", outerBlockType, index, err)
			}

			i.Requests = requests
		}

		result = append(result, &i)
	}

	return result, nil
}

// CreateOuterConfig creates a new set of OuterConfig for a profile system
// without named outer blocks.
func CreateOuterConfig(requests []*RequestConfig) []*OuterConfig {
	return []*OuterConfig{
		{
			Requests: requests,
		},
	}
}

// ParseRequestConfig handles parsing of individual requests from an HCL AST.
func ParseRequestConfig(result []*RequestConfig, list *ast.ObjectList) ([]*RequestConfig, error) {
	result = make([]*RequestConfig, 0, len(list.Items))
	for i, item := range list.Items {
		var r RequestConfig
		if err := hcl.DecodeObject(&r, item.Val); err != nil {
			return result, fmt.Errorf("request.%d: %w", i, err)
		}

		var m map[string]interface{}
		if err := hcl.DecodeObject(&m, item.Val); err != nil {
			return result, fmt.Errorf("request.%d: %w", i, err)
		}
		r.RawConfig = m

		switch {
		case r.Type != "":
		case len(item.Keys) == 1:
			r.Type = item.Keys[0].Token.Value().(string)
		default:
			return result, fmt.Errorf("request.%d: initialize type must be specified", i)
		}

		result = append(result, &r)
	}

	return result, nil
}
