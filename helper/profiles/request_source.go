package profiles

import (
	"context"
	"fmt"
)

// RequestSourceBuilder allows reading inputs from past requests.
func RequestSourceBuilder(ctx context.Context, engine *ProfileEngine, field map[string]interface{}) Source {
	return &RequestSource{
		outer: engine.outerBlockName,
		field: field,
	}
}

var _ SourceBuilder = RequestSourceBuilder

func WithRequestSource() func(*ProfileEngine) {
	return func(p *ProfileEngine) {
		p.sourceBuilders["request"] = RequestSourceBuilder
	}
}

type RequestSource struct {
	outer string
	field map[string]interface{}

	outerName     string
	requestName   string
	fieldSelector []interface{}
}

var _ Source = &RequestSource{}

func (s *RequestSource) Validate(_ context.Context) ([]string, []string, error) {
	var requestName string

	if s.outer != "" {
		outerFieldName := fmt.Sprintf("%v_name", s.outer)
		rawOuterName, present := s.field[outerFieldName]
		if !present {
			return nil, nil, fmt.Errorf("request source is missing required field '%v'", outerFieldName)
		}

		outerName, ok := rawOuterName.(string)
		if !ok {
			return nil, nil, fmt.Errorf("field '%v' is of wrong type: expected 'string' got '%T'", outerFieldName, rawOuterName)
		}

		requestName = outerName + "."
		s.outerName = outerName
	}

	rawReqName, present := s.field["request_name"]
	if !present {
		return nil, nil, fmt.Errorf("request source is missing required field %q", "request_name")
	}

	reqName, ok := rawReqName.(string)
	if !ok {
		return nil, nil, fmt.Errorf("field 'request_name' is of wrong type: expected 'string' got '%T'", rawReqName)
	}

	s.requestName = reqName
	requestName += reqName

	rawFieldSelector := s.field["field_selector"]
	if present {
		switch fieldSelector := rawFieldSelector.(type) {
		case int, string:
			s.fieldSelector = []interface{}{fieldSelector}
		case []int:
			for _, item := range fieldSelector {
				s.fieldSelector = append(s.fieldSelector, item)
			}
		case []string:
			for _, item := range fieldSelector {
				s.fieldSelector = append(s.fieldSelector, item)
			}
		case []interface{}:
			s.fieldSelector = fieldSelector
		default:
			return nil, nil, fmt.Errorf("unknown type for request source field 'field_selector': %T; expected either string, []string, or []interface{}", rawFieldSelector)
		}
	}

	return []string{requestName}, nil, nil
}

func (s *RequestSource) Evaluate(_ context.Context, eh *EvaluationHistory) (interface{}, error) {
	if s.fieldSelector == nil {
		return eh.GetRequest(s.outerName, s.requestName)
	}

	return eh.GetRequestField(s.outerName, s.requestName, s.fieldSelector)
}

func (s *RequestSource) Close(_ context.Context) error {
	return nil
}
