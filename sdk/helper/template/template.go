// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package template

import (
	"errors"
	"fmt"
	"strings"
	"text/template"

	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/go-secure-stdlib/base62"
)

type Opt func(*StringTemplate) error

func Template(rawTemplate string) Opt {
	return func(up *StringTemplate) error {
		up.rawTemplate = rawTemplate
		return nil
	}
}

// Function allows the user to specify functions for use in the template. If the name provided is a function that
// already exists in the function map, this will override the previously specified function.
func Function(name string, f interface{}) Opt {
	return func(up *StringTemplate) error {
		if name == "" {
			return errors.New("missing function name")
		}
		if f == nil {
			return errors.New("missing function")
		}
		up.funcMap[name] = f
		return nil
	}
}

// Option allows the user to specify options for the underlying
// text/template library. See https://pkg.go.dev/text/template#Template.Option
// for more information.
func Option(opts ...string) Opt {
	return func(up *StringTemplate) error {
		up.options = opts
		return nil
	}
}

// StringTemplate creates strings based on the provided template.
// This uses the go templating language, so anything that adheres to that language will function in this struct.
// There are several custom functions available for use in the template:
//
// - random
//   - Randomly generated characters. This uses the charset specified in RandomCharset. Must include a length.
//     Example: {{ rand 20 }}
//
// - truncate
//   - Truncates the previous value to the specified length. Must include a maximum length.
//     Example: {{ .DisplayName | truncate 10 }}
//
// - truncate_sha256
//   - Truncates the previous value to the specified length. If the original length is greater than the length
//     specified, the remaining characters will be sha256 hashed and appended to the end. The hash will be only the first 8 characters The maximum length will
//     be no longer than the length specified.
//     Example: {{ .DisplayName | truncate_sha256 30 }}
//
// - uppercase
//   - Uppercases the previous value.
//     Example: {{ .RoleName | uppercase }}
//
// - lowercase
//   - Lowercases the previous value.
//     Example: {{ .DisplayName | lowercase }}
//
// - replace
//   - Performs a string find & replace
//     Example: {{ .DisplayName | replace - _ }}
//
// - sha256
//   - SHA256 hashes the previous value.
//     Example: {{ .DisplayName | sha256 }}
//
// - base64
//   - base64 encodes the previous value.
//     Example: {{ .DisplayName | base64 }}
//
// - decode_base64
//   - decode_base64 decodes the previous value.
//     Example: {{ .DisplayName | decode_base64 }}
//
// - hex
//   - hex encodes the previous value.
//     Example: {{ .DisplayName | hex }}
//
// - decode_hex
//   - hex decodes the previous value.
//     Example: {{ .DisplayName | decode_hex }}
//
// - unix_time
//   - Provides the current unix time in seconds.
//     Example: {{ unix_time }}
//
// - unix_time_millis
//   - Provides the current unix time in milliseconds.
//     Example: {{ unix_time_millis }}
//
// - timestamp
//   - Provides the current time. Must include a standard Go format string
//
// - uuid
//   - Generates a UUID
//     Example: {{ uuid }}
//
// - glob
//   - Returns true if the second argument matches a glob (wildcard) pattern
//     in the first argument.
//     Example {{ if glob "release/*" .branch }}is_release_branch: true{{ end }}
type StringTemplate struct {
	rawTemplate string
	tmpl        *template.Template
	funcMap     template.FuncMap
	options     []string
}

// NewTemplate creates a StringTemplate. No arguments are required
// as this has reasonable defaults for all values.
// The default template is specified in the DefaultTemplate constant.
func NewTemplate(opts ...Opt) (up StringTemplate, err error) {
	up = StringTemplate{
		funcMap: map[string]interface{}{
			"random":           base62.Random,
			"truncate":         truncate,
			"truncate_sha256":  truncateSHA256,
			"uppercase":        uppercase,
			"lowercase":        lowercase,
			"replace":          replace,
			"sha256":           hashSHA256,
			"base64":           encodeBase64,
			"decode_base64":    decodeBase64,
			"hex":              encodeHex,
			"decode_hex":       decodeHex,
			"unix_time":        unixTime,
			"unix_time_millis": unixTimeMillis,
			"timestamp":        timestamp,
			"uuid":             uuid,
			"glob":             matchesGlob,
		},
	}

	merr := &multierror.Error{}
	for _, opt := range opts {
		merr = multierror.Append(merr, opt(&up))
	}

	err = merr.ErrorOrNil()
	if err != nil {
		return up, err
	}

	if up.rawTemplate == "" {
		return StringTemplate{}, errors.New("missing template")
	}

	tmpl, err := template.New("template").
		Funcs(up.funcMap).
		Option(up.options...).
		Parse(up.rawTemplate)
	if err != nil {
		return StringTemplate{}, fmt.Errorf("unable to parse template: %w", err)
	}
	up.tmpl = tmpl

	return up, nil
}

// Generate based on the provided template
func (up StringTemplate) Generate(data interface{}) (string, error) {
	if up.tmpl == nil || up.rawTemplate == "" {
		return "", errors.New("failed to generate: template not initialized")
	}
	str := &strings.Builder{}
	err := up.tmpl.Execute(str, data)
	if err != nil {
		return "", fmt.Errorf("unable to apply template: %w", err)
	}

	return str.String(), nil
}
