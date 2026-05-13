package profiles

import (
	"fmt"

	"github.com/hashicorp/hcl"
	"github.com/hashicorp/hcl/hcl/ast"
	"github.com/openbao/openbao/helper/configutil"
	"github.com/openbao/openbao/sdk/v2/framework"
)

// OuterConfig is a named configuration object that contains one or more request
// objects. This allows the splitting of a single large profile into smaller
// sub-profiles while still allowing references across the entire space.
type OuterConfig struct {
	UnusedKeys configutil.UnusedKeyMap `hcl:",unusedKeyPositions"`
	RawConfig  map[string]interface{}

	Type     string
	Requests []*RequestConfig `hcl:"-"`

	When interface{} `hcl:"when"`
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
	Headers   interface{} `hcl:"headers"`

	When         interface{} `hcl:"when"`
	AllowFailure interface{} `hcl:"allow_failure"`
}

// InputConfig is an untyped configuration object that contains one or more
// fields in a framework.FieldSchema format. This is used with the
// InputSource type to validate the request. Fields are fully static; the
// usual field evaluation/expansion is not taken into account here.
type InputConfig struct {
	UnusedKeys configutil.UnusedKeyMap `hcl:",unusedKeyPositions"`
	RawConfig  map[string]interface{}

	Fields []*FieldSchemaConfig `hcl:"-"`
}

// FieldSchemaConfig is the HCL equivalent of sdk/v2/framework.FieldSchema;
// updates there should be reflected here.
type FieldSchemaConfig struct {
	UnusedKeys configutil.UnusedKeyMap `hcl:",unusedKeyPositions"`
	RawConfig  map[string]interface{}

	Type          framework.FieldType `hcl:"-"`
	TypeRaw       string              `hcl:"type"`
	Name          string              `hcl:"name"`
	Default       interface{}         `hcl:"default"`
	Description   string              `hcl:"description"`
	Required      bool                `hcl:"required"`
	Deprecated    bool                `hcl:"deprecated"`
	Query         bool                `hcl:"query"`
	AllowedValues []interface{}       `hcl:"allowed_values"`
}

// OutputConfig is an untyped configuration object that controls the output
// format of the profile. Like requests, these can be fully dynamic.
type OutputConfig struct {
	UnusedKeys configutil.UnusedKeyMap `hcl:",unusedKeyPositions"`
	RawConfig  map[string]interface{}

	Data    interface{}              `hcl:"data"`
	Headers map[string][]interface{} `hcl:"headers"`
}

// ParseOuterConfig is a helper for profile systems which support multiple
// outer blocks (e.g., initialize in the case of the declarative
// self-initialization subsystem). Callers wishing to only have a single
// outer block but which may support multiple requests may directly call
// ParseRequestConfig(...) and assign the result via CreateOuterConfig(...).
func ParseOuterConfig(outerBlockType string, list *ast.ObjectList) ([]*OuterConfig, error) {
	result := make([]*OuterConfig, 0, len(list.Items))
	for index, item := range list.Items {
		var i OuterConfig
		if err := hcl.DecodeObject(&i, item.Val); err != nil {
			return result, fmt.Errorf("%v.%d: decoding into object failed with error: %w", outerBlockType, index, err)
		}

		var m map[string]interface{}
		if err := hcl.DecodeObject(&m, item.Val); err != nil {
			return result, fmt.Errorf("%v.%d: decoding into map failed with error: %w", outerBlockType, index, err)
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
			requests, err := ParseRequestConfig(o)
			if err != nil {
				return result, fmt.Errorf("%v.%d: error parsing 'request': %w", outerBlockType, index, err)
			}

			i.Requests = requests

			delete(i.UnusedKeys, "request")
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

func (o *OuterConfig) ValidateUnused(path string) []configutil.ConfigError {
	var errs []configutil.ConfigError
	errs = append(errs, configutil.ValidateUnusedFields(o.UnusedKeys, path)...)
	for _, request := range o.Requests {
		errs = append(errs, request.ValidateUnused(path)...)
	}
	return errs
}

// ParseRequestConfig handles parsing of individual requests from an HCL AST.
func ParseRequestConfig(list *ast.ObjectList) ([]*RequestConfig, error) {
	result := make([]*RequestConfig, 0, len(list.Items))
	for i, item := range list.Items {
		var r RequestConfig
		if err := hcl.DecodeObject(&r, item.Val); err != nil {
			return result, fmt.Errorf("request.%d: decoding into object failed with error: %w", i, err)
		}

		var m map[string]interface{}
		if err := hcl.DecodeObject(&m, item.Val); err != nil {
			return result, fmt.Errorf("request.%d: decoding into map failed with error: %w", i, err)
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

func (r *RequestConfig) ValidateUnused(path string) []configutil.ConfigError {
	return configutil.ValidateUnusedFields(r.UnusedKeys, path)
}

// ParseInputConfig is a helper for profile systems which support declaring
// request input blocks (e.g., to describe fields).
func ParseInputConfig(list *ast.ObjectList) (*InputConfig, error) {
	if len(list.Items) > 1 {
		return nil, fmt.Errorf("only a single 'input' block is allowed")
	}

	item := list.Items[0]

	var i InputConfig
	if err := hcl.DecodeObject(&i, item.Val); err != nil {
		return nil, fmt.Errorf("input: decoding into object failed with error: %w", err)
	}

	var m map[string]interface{}
	if err := hcl.DecodeObject(&m, item.Val); err != nil {
		return nil, fmt.Errorf("input: decoding into map failed with error: %w", err)
	}
	i.RawConfig = m

	switch {
	case len(item.Keys) > 1:
		return nil, fmt.Errorf("input: type must not be specified in the block definition: %#v", item)
	}

	objT, ok := item.Val.(*ast.ObjectType)
	if !ok {
		return nil, fmt.Errorf("input: error parsing item: does not contain a root object (was of type %T)", item.Val)
	}

	itemList := objT.List

	if o := itemList.Filter("field"); len(o.Items) > 0 {
		fields, err := ParseFieldSchemaConfig(o)
		if err != nil {
			return nil, fmt.Errorf("input: error parsing 'field': %w", err)
		}

		i.Fields = fields

		delete(i.UnusedKeys, "field")
	}

	return &i, nil
}

func (i *InputConfig) ValidateUnused(path string) []configutil.ConfigError {
	var errs []configutil.ConfigError
	errs = append(errs, configutil.ValidateUnusedFields(i.UnusedKeys, path)...)
	for _, field := range i.Fields {
		errs = append(errs, field.ValidateUnused(path)...)
	}
	return errs
}

// ParseFieldSchemaConfig handles parsing of individual field schemas from an
// HCL AST.
func ParseFieldSchemaConfig(list *ast.ObjectList) ([]*FieldSchemaConfig, error) {
	result := make([]*FieldSchemaConfig, 0, len(list.Items))
	for i, item := range list.Items {
		var r FieldSchemaConfig
		if err := hcl.DecodeObject(&r, item.Val); err != nil {
			return result, fmt.Errorf("field.%d: decoding into object failed with error: %w", i, err)
		}

		var m map[string]interface{}
		if err := hcl.DecodeObject(&m, item.Val); err != nil {
			return result, fmt.Errorf("field.%d: decoding into map failed with error: %w", i, err)
		}
		r.RawConfig = m

		switch {
		case r.TypeRaw != "" && r.Name != "":
		case r.TypeRaw != "" && r.Name == "" && len(item.Keys) == 1:
			r.Name = item.Keys[0].Token.Value().(string)
		case r.TypeRaw == "" && r.Name != "" && len(item.Keys) == 1:
			r.TypeRaw = item.Keys[0].Token.Value().(string)
		case r.TypeRaw == "" && r.Name == "" && len(item.Keys) == 2:
			r.TypeRaw = item.Keys[0].Token.Value().(string)
			r.Name = item.Keys[1].Token.Value().(string)
		default:
			return result, fmt.Errorf("field.%d: field type and name must be specified either as keys or block parameters", i)
		}

		var err error
		r.Type, err = framework.ParseFieldType(r.TypeRaw)
		if err != nil {
			return result, fmt.Errorf("field.%d: %w", i, err)
		}

		result = append(result, &r)
	}

	return result, nil
}

func (s *FieldSchemaConfig) ToSchema() *framework.FieldSchema {
	return &framework.FieldSchema{
		Type:          s.Type,
		Default:       s.Default,
		Description:   s.Description,
		Required:      s.Required,
		Deprecated:    s.Deprecated,
		Query:         s.Query,
		AllowedValues: s.AllowedValues,
	}
}

func (s *FieldSchemaConfig) ValidateUnused(path string) []configutil.ConfigError {
	return configutil.ValidateUnusedFields(s.UnusedKeys, path)
}

// ParseOutputConfig is a helper for profile systems which support declaring
// response output blocks so that the caller has information about the
// output.
func ParseOutputConfig(list *ast.ObjectList) (*OutputConfig, error) {
	if len(list.Items) > 1 {
		return nil, fmt.Errorf("only a single 'output' block is allowed")
	}

	item := list.Items[0]

	var i OutputConfig
	if err := hcl.DecodeObject(&i, item.Val); err != nil {
		return nil, fmt.Errorf("output: %w", err)
	}

	var m map[string]interface{}
	if err := hcl.DecodeObject(&m, item.Val); err != nil {
		return nil, fmt.Errorf("output: %w", err)
	}
	i.RawConfig = m

	switch {
	case len(item.Keys) > 1:
		return nil, fmt.Errorf("output: type must not be specified in the block definition: %#v", item)
	}

	return &i, nil
}

func (o *OutputConfig) ValidateUnused(path string) []configutil.ConfigError {
	return configutil.ValidateUnusedFields(o.UnusedKeys, path)
}
