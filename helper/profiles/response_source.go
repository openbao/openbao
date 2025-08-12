package profiles

import (
	"context"
	"fmt"
)

// ResponseSourceBuilder allows reading inputs from past responses.
func ResponseSourceBuilder(ctx context.Context, engine *ProfileEngine, field map[string]interface{}) Source {
	return &ResponseSource{
		outer: engine.outerBlockName,
		field: field,
	}
}

var _ SourceBuilder = ResponseSourceBuilder

func WithResponseSource() func(*ProfileEngine) {
	return func(p *ProfileEngine) {
		p.sourceBuilders["response"] = ResponseSourceBuilder
	}
}

type ResponseSource struct {
	outer string
	field map[string]interface{}

	outerName     string
	responseName  string
	fieldSelector interface{}
}

var _ Source = &ResponseSource{}

func (s *ResponseSource) Validate(_ context.Context) ([]string, []string, error) {
	var responseName string

	if s.outer != "" {
		outerFieldName := fmt.Sprintf("%v_name", s.outer)
		rawOuterName, present := s.field[outerFieldName]
		if !present {
			return nil, nil, fmt.Errorf("response source is missing required field %q", outerFieldName)
		}

		outerName, ok := rawOuterName.(string)
		if !ok {
			return nil, nil, fmt.Errorf("field %q is of wrong type: expected 'string' got '%T'", outerFieldName, rawOuterName)
		}

		responseName = outerName + "."
		s.outerName = outerName
	}

	rawReqName, present := s.field["response_name"]
	if !present {
		return nil, nil, fmt.Errorf("response source is missing required field '%v'", "response_name")
	}

	respName, ok := rawReqName.(string)
	if !ok {
		return nil, nil, fmt.Errorf("field 'response_name' is of wrong type: expected 'string' got '%T'", rawReqName)
	}

	s.responseName = respName
	responseName += respName

	rawFieldSelector := s.field["field_selector"]

	if present {
		switch rawFieldSelector.(type) {
		case string:
		case []string:
		default:
			return nil, nil, fmt.Errorf("unknown type for response source field 'field_selector': %T; expected either string or []string", rawFieldSelector)
		}

		s.fieldSelector = rawFieldSelector
	}

	return []string{responseName}, nil, nil
}

func (s *ResponseSource) Evaluate(_ context.Context, eh *EvaluationHistory) (interface{}, error) {
	if s.fieldSelector == nil {
		return eh.GetResponse(s.outerName, s.responseName)
	}

	return eh.GetResponseField(s.outerName, s.responseName, s.fieldSelector)
}

func (s *ResponseSource) Close(_ context.Context) error {
	return nil
}
