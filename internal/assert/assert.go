package assert

import (
	"errors"
	"reflect"
	"testing"
)

func isNil(v any) bool {
	if v == nil {
		return true
	}

	// Inspect underlying type of v, and return true when it is nullable, e.g.,
	// pointer, slice, map, with a value of nil.
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice, reflect.UnsafePointer:
		return rv.IsNil()
	}

	// Other types like bool, int string are never nil.
	return false
}

func isEqual[T any](actual, expectation T) bool {
	// Are both values actually nil?
	if isNil(actual) && isNil(expectation) {
		return true
	}

	// Are they truly the same?
	return reflect.DeepEqual(actual, expectation)
}

func Equal[T any](t *testing.T, actual, expectation T, msg ...string) {
	t.Helper()

	if !isEqual(actual, expectation) {
		defaultMsg := "actual: %v; expectation: %v"
		if msg != nil {
			defaultMsg = msg[0]
		}
		t.Errorf(defaultMsg, actual, expectation)
	}
}

func NotEqual[T any](t *testing.T, actual, expectation T) {
	t.Helper()

	if isEqual(actual, expectation) {
		t.Errorf("actual: %v; expected values to be different", actual)
	}
}

func True(t *testing.T, actual bool) {
	t.Helper()

	if !actual {
		t.Errorf("actual: %v; expectation: TRUE", actual)
	}
}

func Nil(t *testing.T, actual any) {
	t.Helper()

	if !isNil(actual) {
		t.Errorf("actual: %v; expectation: NIL", actual)
	}
}

func NotNil(t *testing.T, actual any) {
	t.Helper()

	if isNil(actual) {
		t.Errorf("actual: NIL; expectation: NOT NIL")
	}
}

// Ok fails the test when an err is not nil.
func Ok(t *testing.T, err error, msg ...string) {
	t.Helper()

	if err != nil {
		defaultMsg := "Error detected: %s"
		if msg != nil {
			defaultMsg = msg[0]
		}
		t.Errorf(defaultMsg, err)
	}
}

// DesiredError fails the test when an expected error is missing.
func DesiredError(t *testing.T, err error, actual any) {
	t.Helper()

	if err == nil {
		t.Errorf("expected an error; actual: %#v", actual)
	}
}

func ErrorIs(t *testing.T, actual, expectation error) {
	t.Helper()

	if !errors.Is(actual, expectation) {
		t.Errorf("actual: %v; expectation: %v", actual, expectation)
	}
}

func ErrorAs(t *testing.T, actual error, target any) {
	t.Helper()

	if actual == nil {
		t.Errorf("actual: NIL; expectation: assignable to: %T", target)
		return
	}

	if !errors.As(actual, target) {
		t.Errorf("actual: %v; expectation assignable to: %T", actual, target)
	}
}
