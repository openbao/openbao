package profiles

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
)

// FileSourceBuilder allows reading files from disk.
func FileSourceBuilder(ctx context.Context, engine *ProfileEngine, field map[string]interface{}) Source {
	return &FileSource{
		field: field,
	}
}

var _ SourceBuilder = FileSourceBuilder

func WithFileSource() func(*ProfileEngine) {
	return func(p *ProfileEngine) {
		p.sourceBuilders["file"] = FileSourceBuilder
	}
}

type FileSource struct {
	field map[string]interface{}
	file  *os.File
	value []byte
}

var _ Source = &FileSource{}

func (s *FileSource) Validate(_ context.Context) ([]string, []string, error) {
	rawPath, present := s.field["path"]
	if !present {
		return nil, nil, errors.New("file source is missing required field 'path'")
	}

	path, ok := rawPath.(string)
	if !ok {
		return nil, nil, fmt.Errorf("field 'path' is of wrong type: expected 'string' got '%T'", rawPath)
	}

	var err error
	s.file, err = os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open file: %w", err)
	}

	return nil, nil, nil
}

func (s *FileSource) Evaluate(ctx context.Context, _ *EvaluationHistory) (interface{}, error) {
	if s.value != nil {
		return s.value, nil
	}

	data, err := io.ReadAll(s.file)
	if err != nil {
		return nil, fmt.Errorf("failed to read value: %w", err)
	}

	s.value = data

	if err := s.Close(ctx); err != nil {
		return nil, fmt.Errorf("failed to close file: %w", err)
	}

	return data, nil
}

func (s *FileSource) Close(_ context.Context) error {
	if s.file == nil {
		return nil
	}

	err := s.file.Close()
	s.file = nil
	return err
}
