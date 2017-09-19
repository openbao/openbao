package jose

import "testing"

func Error(t *testing.T, want, got interface{}) {
	t.Errorf("Wanted: %q\n\t Got: %q", want, got)
}
