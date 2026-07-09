package profiles

import (
	"context"
	"fmt"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const inputSourceName = "input"

// InputSource is fully dynamic requiring context outside of the profile
// engine to invoke. Each defined field from the schema gets added to the
// framework data and so will be validated and used with GetOk(...) for
// processing.
//
// This source requires the following parameters:
//
// - field_name, the name of the input field to read.
//
// Notably, whether field_name is required to be present or not is a
// function of the InputConfig schema (required boolean)
func WithInputSource(config *InputConfig, request *logical.Request, data *framework.FieldData) func(*ProfileEngine) {
	return func(p *ProfileEngine) {
		if config == nil {
			return
		}

		p.input = config
		p.request = request
		p.data = data.CloneSchema()

		p.sourceBuilders[inputSourceName] = func(engine *ProfileEngine, field map[string]interface{}, this *IterContext) Source {
			return &InputSource{
				config:  config,
				request: request,
				data:    p.data,

				field: field,
			}
		}
	}
}

func HasInputSource(engine *ProfileEngine) bool {
	_, ok := engine.sourceBuilders[inputSourceName]
	return ok
}

type InputSource struct {
	config  *InputConfig
	request *logical.Request
	data    *framework.FieldData
	field   map[string]interface{}

	fieldName string
}

var _ Source = &InputSource{}

func (s *InputSource) Validate() ([]string, []string, error) {
	rawFieldName, present := s.field["field_name"]
	if !present {
		return nil, nil, fmt.Errorf("input source is missing required field %q", "field_name")
	}

	fieldName, ok := rawFieldName.(string)
	if !ok {
		return nil, nil, fmt.Errorf("field 'field_name' is of wrong type: expected 'string' got '%T'", rawFieldName)
	}

	if _, present := s.data.Schema[fieldName]; !present {
		return nil, nil, fmt.Errorf("referenced field %q is missing from schema", fieldName)
	}

	s.fieldName = fieldName

	return nil, nil, nil
}

func (s *InputSource) Evaluate(_ context.Context, eh *EvaluationHistory) (interface{}, error) {
	return s.data.Get(s.fieldName), nil
}

func (s *InputSource) Close(_ context.Context) error {
	return nil
}
