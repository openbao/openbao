package profiles

import (
	"context"
	"errors"
	"fmt"

	"github.com/openbao/openbao/sdk/v2/helper/template"
)

// TemplateSourceBuilder allows reading inputs from the text/template engine,
// allowing for string interpolation and other operations.
//
// Fields:
//
//   - template (string): template to evaluate
//   - data (map[string]interface{}): additional context for the templating
//     engine.
//
// When allowed as sources, this already includes:
//
//   - requests
//   - responses
//   - input
//
// but additional context may be added manually.
func TemplateSourceBuilder(engine *ProfileEngine, field map[string]interface{}, this *IterContext) Source {
	return &TemplateSource{
		engine: engine,
		field:  field,
		this:   this,
	}
}

var _ SourceBuilder = TemplateSourceBuilder

func WithTemplateSource() func(*ProfileEngine) {
	return func(p *ProfileEngine) {
		p.sourceBuilders["template"] = TemplateSourceBuilder
	}
}

type TemplateSource struct {
	engine *ProfileEngine
	field  map[string]interface{}
	this   *IterContext

	data      map[string]interface{}
	template  string
	templator template.StringTemplate
}

var _ Source = &TemplateSource{}

func (s *TemplateSource) Validate() ([]string, []string, error) {
	rawTemplate, present := s.field["template"]
	if !present {
		return nil, nil, errors.New("template source is missing required field 'template'")
	}

	templateStr, ok := rawTemplate.(string)
	if !ok {
		return nil, nil, fmt.Errorf("field 'template' is of wrong type: expected 'string' got '%T'", rawTemplate)
	}

	s.template = templateStr

	rawData, present := s.field["data"]
	if !present {
		rawData = map[string]interface{}{}
	}

	data, ok := rawData.(map[string]interface{})
	if !ok {
		return nil, nil, fmt.Errorf("field 'data' is of wrong type: expected 'map[string]interface{}' got '%T'", rawData)
	}

	s.data = data

	templator, err := template.NewTemplate(template.Template(s.template), template.Option("missingkey=error"))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build new templator: %w", err)
	}

	s.templator = templator

	return nil, nil, nil
}

func (s *TemplateSource) Evaluate(_ context.Context, eh *EvaluationHistory) (interface{}, error) {
	s.this.IntoMap(s.data)

	// Inject request data if present as a source.
	if HasRequestSource(s.engine) {
		s.data["requests"] = eh.Requests
		if s.engine.outerBlockName == "" {
			s.data["requests"] = eh.Requests[""]
		}
	}

	// Inject response data if present as a source.
	if HasResponseSource(s.engine) {
		s.data["responses"] = eh.Responses
		if s.engine.outerBlockName == "" {
			s.data["responses"] = eh.Responses[""]
		}
	}

	// Inject input data if present as a source.
	if HasInputSource(s.engine) {
		s.data["input"] = s.engine.data.Raw
	}

	value, err := s.templator.Generate(s.data)
	if err != nil {
		return nil, fmt.Errorf("failed to execute templator: %w", err)
	}

	return value, nil
}

func (s *TemplateSource) Close(_ context.Context) error {
	return nil
}
