package profiles

import (
	"context"
	"errors"
	"fmt"
	"os"
)

// EnvSourceBuilder allows reading environment variables from the system.
func EnvSourceBuilder(ctx context.Context, engine *ProfileEngine, field map[string]interface{}) Source {
	return &EnvSource{
		field: field,
	}
}

var _ SourceBuilder = EnvSourceBuilder

func WithEnvSource() func(*ProfileEngine) {
	return func(p *ProfileEngine) {
		p.sourceBuilders["env"] = EnvSourceBuilder
	}
}

type EnvSource struct {
	field map[string]interface{}
	value string
}

var _ Source = &EnvSource{}

func (s *EnvSource) Validate(_ context.Context) ([]string, []string, error) {
	rawName, present := s.field["env_var"]
	if !present {
		return nil, nil, errors.New("env source is missing required field 'env_var'")
	}

	name, ok := rawName.(string)
	if !ok {
		return nil, nil, fmt.Errorf("field 'env_var' is of wrong type: expected 'string' got '%T'", rawName)
	}

	var mustBePresent bool
	rawMustBePresent, present := s.field["require_present"]
	if present {
		mustBePresent, ok = rawMustBePresent.(bool)
		if !ok {
			return nil, nil, fmt.Errorf("field 'require_present' is of wrong type: expecting 'bool' got '%T'", rawMustBePresent)
		}
	}

	value, present := os.LookupEnv(name)
	if !present && mustBePresent {
		return nil, nil, fmt.Errorf("env source required variable %v to be present but was missing", name)
	}

	s.value = value

	return nil, nil, nil
}

func (s *EnvSource) Evaluate(_ context.Context, _ *EvaluationHistory) (interface{}, error) {
	return s.value, nil
}

func (s *EnvSource) Close(_ context.Context) error {
	return nil
}
