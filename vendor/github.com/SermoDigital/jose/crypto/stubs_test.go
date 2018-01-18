package crypto

import (
	"fmt"
	"testing"
)

func Error(t *testing.T, want, got interface{}) {
	format := "\nWanted: %s\nGot: %s"

	switch want.(type) {
	case []byte, string, nil:
	default:
		format = fmt.Sprintf(format, "%v", "%v")
	}

	t.Errorf(format, want, got)
}

func ErrorTypes(t *testing.T, want, got interface{}) {
	t.Errorf("\nWanted: %T\nGot: %T", want, got)
}
