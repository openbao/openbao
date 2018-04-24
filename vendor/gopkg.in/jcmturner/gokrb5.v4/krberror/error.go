// Package krberror provides error type and functions for gokrb5.
package krberror

import (
	"fmt"
	"strings"
)

// Error type descriptions.
const (
	separator       = " < "
	EncodingError   = "Encoding_Error"
	NetworkingError = "Networking_Error"
	DecryptingError = "Decrypting_Error"
	EncryptingError = "Encrypting_Error"
	ChksumError     = "Checksum_Error"
	KRBMsgError     = "KRBMessage_Handling_Error"
	ConfigError     = "Configuration_Error"
)

// Krberror is an error type for gokrb5
type Krberror struct {
	RootCause string
	EText     []string
}

// Error function to implement the error interface.
func (e Krberror) Error() string {
	return fmt.Sprintf("[Root cause: %s] ", e.RootCause) + strings.Join(e.EText, separator)
}

// Add another error statement to the error.
func (e *Krberror) Add(et string, s string) {
	e.EText = append([]string{fmt.Sprintf("%s: %s", et, s)}, e.EText...)
}

// NewKrberror creates a new instance of Krberror.
func NewKrberror(et, s string) Krberror {
	return Krberror{
		RootCause: et,
		EText:     []string{s},
	}
}

// Errorf appends to or creates a new Krberror.
func Errorf(err error, et, format string, a ...interface{}) Krberror {
	if e, ok := err.(Krberror); ok {
		if len(a) > 0 {
			e.EText = append([]string{fmt.Sprintf("%s: "+format, et, a)}, e.EText...)
			return e
		}
		e.EText = append([]string{fmt.Sprintf("%s: "+format, et)}, e.EText...)
		return e
	}
	if len(a) > 0 {
		return NewErrorf(et, format+": %s", a, err)
	}
	return NewErrorf(et, format+": %s", err)
}

// NewErrorf creates a new Krberror from a formatted string.
func NewErrorf(et, format string, a ...interface{}) Krberror {
	var s string
	if len(a) > 0 {
		s = fmt.Sprintf("%s: %s", et, fmt.Sprintf(format, a...))
	} else {
		s = fmt.Sprintf("%s: %s", et, format)
	}
	return Krberror{
		RootCause: et,
		EText:     []string{s},
	}
}
