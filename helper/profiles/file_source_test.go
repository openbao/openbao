package profiles

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestFileSourceBuilder_Success(t *testing.T) {
	ctx := context.Background()
	engine := &ProfileEngine{sourceBuilders: make(map[string]SourceBuilder)}
	field := map[string]interface{}{"path": "dummy"}
	src := FileSourceBuilder(ctx, engine, field)

	fs, ok := src.(*FileSource)
	if !ok {
		t.Fatalf("expected *FileSource, got %T", src)
	}
	if !reflect.DeepEqual(fs.field, field) {
		t.Errorf("expected field %v, got %v", field, fs.field)
	}
}

func TestWithFileSource_RegistersBuilder(t *testing.T) {
	engine := &ProfileEngine{sourceBuilders: make(map[string]SourceBuilder)}
	WithFileSource()(engine)
	builder, ok := engine.sourceBuilders["file"]
	if !ok {
		t.Fatal(`expected key "file" in sourceBuilders`)
	}
	if reflect.ValueOf(builder).Pointer() != reflect.ValueOf(FileSourceBuilder).Pointer() {
		t.Errorf("registered builder = %v; want FileSourceBuilder", builder)
	}
}

func TestFileSource_Validate_Success(t *testing.T) {
	tmpDir := t.TempDir()
	fname := filepath.Join(tmpDir, "test.txt")
	content := []byte("hello world")
	if err := os.WriteFile(fname, content, 0o600); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	src := &FileSource{field: map[string]interface{}{"path": fname}}
	deps, provides, err := src.Validate(context.Background())
	if err != nil {
		t.Fatalf("Validate, error: %v", err)
	}
	if deps != nil || provides != nil {
		t.Errorf("expected deps,provides=nil; got %v,%v", deps, provides)
	}
	if src.file == nil {
		t.Fatal("expected src.file to be set after Validate")
	}
	if err := src.Close(context.Background()); err != nil {
		t.Errorf("Close, error: %v", err)
	}
}

func TestFileSource_Validate_MissingPath(t *testing.T) {
	src := &FileSource{field: map[string]interface{}{}}
	_, _, err := src.Validate(context.Background())
	if err == nil || err.Error() != "file source is missing required field 'path'" {
		t.Fatalf("expected missing-path error, got %v", err)
	}
}

func TestFileSource_Validate_WrongType(t *testing.T) {
	src := &FileSource{field: map[string]interface{}{"path": 123}}
	_, _, err := src.Validate(context.Background())
	wantPrefix := "field 'path' is of wrong type"
	if err == nil || err.Error()[:len(wantPrefix)] != wantPrefix {
		t.Fatalf("expected type-error prefix %q, got %v", wantPrefix, err)
	}
}

func TestFileSource_Validate_OpenError(t *testing.T) {
	src := &FileSource{field: map[string]interface{}{"path": "/nonexistent/file"}}
	_, _, err := src.Validate(context.Background())
	if err == nil {
		t.Fatal("expected error opening non-existent file, got nil")
	}
	if !strings.HasPrefix(err.Error(), "failed to open file") {
		t.Fatalf("expected error starting with 'failed to open file', got %v", err)
	}
}

func TestFileSource_Evaluate_Read(t *testing.T) {
	tmpDir := t.TempDir()
	fname := filepath.Join(tmpDir, "eval.txt")
	content := []byte("data123")
	if err := os.WriteFile(fname, content, 0o600); err != nil {
		t.Fatalf("write file error: %v", err)
	}

	src := &FileSource{field: map[string]interface{}{"path": fname}}
	if _, _, err := src.Validate(context.Background()); err != nil {
		t.Fatalf("Validate returned %v", err)
	}

	out, err := src.Evaluate(context.Background(), nil)
	if err != nil {
		t.Fatalf("Evaluate returned error: %v", err)
	}
	got, ok := out.([]byte)
	if !ok {
		t.Fatalf("expected []byte result, got %T", out)
	}
	if string(got) != string(content) {
		t.Errorf("Evaluate read %q; want %q", got, content)
	}
	if src.file != nil {
		t.Error("expected src.file to be nil after Evaluate (closed)")
	}

	out2, err := src.Evaluate(context.Background(), nil)
	if err != nil {
		t.Fatalf("second Evaluate error: %v", err)
	}
	if !reflect.DeepEqual(out2, got) {
		t.Errorf("second Evaluate returned %v; want %v", out2, got)
	}
}

func TestFileSource_Close_NilFile(t *testing.T) {
	src := &FileSource{}
	if err := src.Close(context.Background()); err != nil {
		t.Errorf("Close(nil) returned error: %v", err)
	}
}

func TestFileSource_Close_OpenFile(t *testing.T) {
	tmpDir := t.TempDir()
	fname := filepath.Join(tmpDir, "close.txt")
	f, err := os.Create(fname)
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}

	src := &FileSource{file: f}
	if err := src.Close(context.Background()); err != nil {
		t.Errorf("Close returned error: %v", err)
	}
	if src.file != nil {
		t.Error("expected src.file to be nil after Close")
	}
}

func TestFileSource_Evaluate_ReadError(t *testing.T) {
	tmp, err := os.CreateTemp("", "errtest")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	err = tmp.Close()
	if err != nil {
		t.Fatalf("failed to close temp file: %v", err)
	}
	src := &FileSource{
		file: tmp,
	}

	_, err = src.Evaluate(context.Background(), nil)

	if err == nil {
		t.Fatal("expected error reading from closed file, got nil")
	}

	if !errors.Is(err, os.ErrInvalid) && !strings.Contains(err.Error(), "closed") {
		t.Fatalf("expected a file-closed error, got: %v", err)
	}
}
