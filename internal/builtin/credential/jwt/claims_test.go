// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package jwtauth

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/go-test/deep"
	"github.com/hashicorp/go-hclog"
)

func TestGetClaim(t *testing.T) {
	data := `{
		"a": 42,
		"b": "bar",
		"c": {
			"d": 95,
			"e": [
				"dog",
				"cat",
				"bird"
			],
			"f": {
				"g": "zebra"
			}
		}
	}`
	var claims map[string]any
	if err := json.Unmarshal([]byte(data), &claims); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		claim string
		value any
	}{
		{"a", json.Number("42")},
		{"/a", json.Number("42")},
		{"b", "bar"},
		{"/c/d", json.Number("95")},
		{"/c/e/1", "cat"},
		{"/c/f/g", "zebra"},
		{"nope", nil},
		{"/c/f/h", nil},
		{"", nil},
		{"\\", nil},
	}

	for _, test := range tests {
		v := getClaim(hclog.NewNullLogger(), claims, test.claim)

		if diff := deep.Equal(v, test.value); diff != nil {
			t.Fatal(diff)
		}
	}
}

func TestSetClaim(t *testing.T) {
	data := `{
		"a": 42,
		"b": "bar",
		"c": {
			"d": 95,
			"e": [
				"dog",
				"cat",
				"bird"
			],
			"f": {
				"g": "zebra"
			}
		}
	}`
	var claims map[string]any
	if err := json.Unmarshal([]byte(data), &claims); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		claim string
		value any
	}{
		{"a", json.Number("43")},
		{"/a", json.Number("43")},
		{"b", "foo"},
		{"/c/d", json.Number("96")},
		{"/c/e/1", "dog"},
		{"/c/f/g", "elephant"},
	}

	for _, test := range tests {
		_ = setClaim(hclog.NewNullLogger(), claims, test.claim, test.value)

		v := getClaim(hclog.NewNullLogger(), claims, test.claim)

		if diff := deep.Equal(v, test.value); diff != nil {
			t.Fatal(diff)
		}
	}
}

func TestExtractMetadata(t *testing.T) {
	emptyMap := make(map[string]string)

	tests := []struct {
		testCase      string
		allClaims     map[string]any
		claimMappings map[string]string
		expected      map[string]string
		errExpected   bool
	}{
		{"empty", nil, nil, emptyMap, false},
		{
			"full match",
			map[string]any{
				"data1": "foo",
				"data2": "bar",
			},
			map[string]string{
				"data1": "val1",
				"data2": "val2",
			},
			map[string]string{
				"val1": "foo",
				"val2": "bar",
			},
			false,
		},
		{
			"partial match",
			map[string]any{
				"data1": "foo",
				"data2": "bar",
			},
			map[string]string{
				"data1": "val1",
				"data3": "val2",
			},
			map[string]string{
				"val1": "foo",
			},
			false,
		},
		{
			"no match",
			map[string]any{
				"data1": "foo",
				"data2": "bar",
			},
			map[string]string{
				"data8": "val1",
				"data9": "val2",
			},
			emptyMap,
			false,
		},
		{
			"nested data",
			map[string]any{
				"data1": "foo",
				"data2": map[string]any{
					"child": "bar",
				},
			},
			map[string]string{
				"data1":        "val1",
				"/data2/child": "val2",
			},
			map[string]string{
				"val1": "foo",
				"val2": "bar",
			},
			false,
		},
		{
			"error: non-string data",
			map[string]any{
				"data1": 42,
			},
			map[string]string{
				"data1": "val1",
			},
			nil,
			true,
		},
	}

	for _, test := range tests {
		actual, err := extractMetadata(hclog.NewNullLogger(), test.allClaims, test.claimMappings)
		if (err != nil) != test.errExpected {
			t.Fatalf("case '%s': expected error: %t, actual: %v", test.testCase, test.errExpected, err)
		}
		if diff := deep.Equal(actual, test.expected); diff != nil {
			t.Fatalf("case '%s': expected results: %v", test.testCase, diff)
		}
	}
}

func TestValidateAudience(t *testing.T) {
	tests := []struct {
		boundAudiences []string
		audience       []string
		strict         bool
		errExpected    bool
	}{
		{[]string{"a"}, []string{"a"}, false, false},
		{[]string{"a"}, []string{"b"}, false, true},
		{[]string{"a"}, []string{""}, false, true},
		{[]string{}, []string{"a"}, false, false},
		{[]string{}, []string{"a"}, true, true},
		{[]string{"a", "b"}, []string{"a"}, false, false},
		{[]string{"a", "b"}, []string{"b"}, false, false},
		{[]string{"a", "b"}, []string{"a", "b", "c"}, false, false},
		{[]string{"a", "b"}, []string{"c", "d"}, false, true},
	}

	for _, test := range tests {
		err := validateAudience(test.boundAudiences, test.audience, test.strict)
		if test.errExpected != (err != nil) {
			t.Fatalf("unexpected error result: boundAudiences %v, audience %v, strict %t, err: %v",
				test.boundAudiences, test.audience, test.strict, err)
		}
	}
}

func TestValidateBoundClaims(t *testing.T) {
	tests := []struct {
		name            string
		boundClaimsType string
		boundClaims     map[string]any
		allClaims       map[string]any
		errExpected     bool
	}{
		{
			name:            "valid",
			boundClaimsType: "string",
			boundClaims: map[string]any{
				"foo": "a",
				"bar": "b",
			},
			allClaims: map[string]any{
				"foo": "a",
				"bar": "b",
			},
			errExpected: false,
		},
		{
			name:            "valid - non-string claim",
			boundClaimsType: "string",
			boundClaims: map[string]any{
				"foo": []any{42},
			},
			allClaims: map[string]any{
				"foo": []any{42},
			},
			errExpected: false,
		},
		{
			name:            "valid - boolean claim",
			boundClaimsType: "string",
			boundClaims: map[string]any{
				"email_verified": []any{false},
			},
			allClaims: map[string]any{
				"email_verified": []any{false},
			},
			errExpected: false,
		},
		{
			name:            "valid - match within list",
			boundClaimsType: "string",
			boundClaims: map[string]any{
				"foo": "a",
			},
			allClaims: map[string]any{
				"foo": []any{"a", "b"},
			},
			errExpected: false,
		},
		{
			name:            "valid - match list against list",
			boundClaimsType: "string",
			boundClaims: map[string]any{
				"foo": []any{"a", "b", "c"},
			},
			allClaims: map[string]any{
				"foo": []any{"c", "d"},
			},
			errExpected: false,
		},
		{
			name:            "valid match with numeric claim conversion from float64",
			boundClaimsType: "string",
			boundClaims: map[string]any{
				// Numeric bound claims from Vault API are json.Number type
				"foo": json.Number("123"),
			},
			allClaims: map[string]any{
				"foo": float64(123),
			},
			errExpected: false,
		},
		{
			name:            "valid match with numeric claim conversion from float32",
			boundClaimsType: "string",
			boundClaims: map[string]any{
				// Numeric bound claims from Vault API are json.Number type
				"foo": json.Number("123"),
			},
			allClaims: map[string]any{
				"foo": float32(123),
			},
			errExpected: false,
		},
		{
			name:            "invalid match with numeric claim conversion from float64",
			boundClaimsType: "string",
			boundClaims: map[string]any{
				// Numeric bound claims from Vault API are json.Number type
				"foo": json.Number("456"),
			},
			allClaims: map[string]any{
				"foo": float64(123),
			},
			errExpected: true,
		},
		{
			name:            "invalid match with numeric claim conversion from float32",
			boundClaimsType: "string",
			boundClaims: map[string]any{
				// Numeric bound claims from Vault API are json.Number type
				"foo": json.Number("123"),
			},
			allClaims: map[string]any{
				"foo": float32(456),
			},
			errExpected: true,
		},
		{
			name:            "invalid - no match within list",
			boundClaimsType: "string",
			boundClaims: map[string]any{
				"foo": "c",
			},
			allClaims: map[string]any{
				"foo": []any{"a", "b"},
			},
			errExpected: true,
		},
		{
			name:            "invalid - no match list against list",
			boundClaimsType: "string",
			boundClaims: map[string]any{
				"foo": []any{"a", "b", "c"},
			},
			allClaims: map[string]any{
				"foo": []any{"d", "e"},
			},
			errExpected: true,
		},
		{
			name:            "valid - extra data",
			boundClaimsType: "string",
			boundClaims: map[string]any{
				"foo": "a",
				"bar": "b",
			},
			allClaims: map[string]any{
				"foo":   "a",
				"bar":   "b",
				"color": "green",
			},
			errExpected: false,
		},
		{
			name:            "mismatched value",
			boundClaimsType: "string",
			boundClaims: map[string]any{
				"foo": "a",
				"bar": "b",
			},
			allClaims: map[string]any{
				"foo": "a",
				"bar": "wrong",
			},
			errExpected: true,
		},
		{
			name:            "missing claim",
			boundClaimsType: "string",
			boundClaims: map[string]any{
				"foo": "a",
				"bar": "b",
			},
			allClaims: map[string]any{
				"foo": "a",
			},
			errExpected: true,
		},
		{
			name:            "valid - JSONPointer",
			boundClaimsType: "string",
			boundClaims: map[string]any{
				"foo":        "a",
				"/bar/baz/1": "y",
			},
			allClaims: map[string]any{
				"foo": "a",
				"bar": map[string]any{
					"baz": []string{"x", "y", "z"},
				},
			},
			errExpected: false,
		},
		{
			name:            "invalid - JSONPointer value mismatch",
			boundClaimsType: "string",
			boundClaims: map[string]any{
				"foo":        "a",
				"/bar/baz/1": "q",
			},
			allClaims: map[string]any{
				"foo": "a",
				"bar": map[string]any{
					"baz": []string{"x", "y", "z"},
				},
			},
			errExpected: true,
		},
		{
			name:            "invalid - JSONPointer not found",
			boundClaimsType: "string",
			boundClaims: map[string]any{
				"foo":           "a",
				"/bar/XXX/1243": "q",
			},
			allClaims: map[string]any{
				"foo": "a",
				"bar": map[string]any{
					"baz": []string{"x", "y", "z"},
				},
			},
			errExpected: true,
		},
		{
			name:            "valid - match alternates",
			boundClaimsType: "string",
			boundClaims: map[string]any{
				"email": []any{"a", "b", "c"},
				"color": "green",
			},
			allClaims: map[string]any{
				"email": "c",
				"color": "green",
			},
			errExpected: false,
		},
		{
			name:            "invalid - no match alternates",
			boundClaimsType: "string",
			boundClaims: map[string]any{
				"email": []any{"a", "b", "c"},
				"color": "green",
			},
			allClaims: map[string]any{
				"email": "d",
				"color": "green",
			},
			errExpected: true,
		},
		{
			name:            "invalid bound claim expected value",
			boundClaimsType: "string",
			boundClaims: map[string]any{
				"email": 42,
			},
			allClaims: map[string]any{
				"email": "d",
			},
			errExpected: true,
		},
		{
			name:            "invalid bound claim expected boolean value",
			boundClaimsType: "string",
			boundClaims: map[string]any{
				"email_verified": true,
			},
			allClaims: map[string]any{
				"email_verified": "true",
			},
			errExpected: true,
		},

		{
			name:            "invalid received claim expected value",
			boundClaimsType: "string",
			boundClaims: map[string]any{
				"email": "d",
			},
			allClaims: map[string]any{
				"email": 42,
			},
			errExpected: true,
		},

		{
			name:            "matching glob",
			boundClaimsType: "glob",
			boundClaims: map[string]any{
				"email": "4*",
			},
			allClaims: map[string]any{
				"email": "42",
			},
			errExpected: false,
		},
		{
			name:            "invalid string value",
			boundClaimsType: "glob",
			boundClaims: map[string]any{
				"email": "4*",
			},
			allClaims: map[string]any{
				"email": 42,
			},
			errExpected: true,
		},
		{
			name:            "not matching glob",
			boundClaimsType: "glob",
			boundClaims: map[string]any{
				"email": "4*",
			},
			allClaims: map[string]any{
				"email": "d42",
			},
			errExpected: true,
		},
		{
			name:            "not matching glob",
			boundClaimsType: "glob",
			boundClaims: map[string]any{
				"email": "*2",
			},
			allClaims: map[string]any{
				"email": "42x",
			},
			errExpected: true,
		},
		{
			name:            "matching glob in list",
			boundClaimsType: "glob",
			boundClaims: map[string]any{
				"email": []any{"4*d", "42*"},
			},
			allClaims: map[string]any{
				"email": "42x",
			},
			errExpected: false,
		},
		{
			name:            "not matching glob in list",
			boundClaimsType: "glob",
			boundClaims: map[string]any{
				"email": []any{"4*d", "42*"},
			},
			allClaims: map[string]any{
				"email": "43x",
			},
			errExpected: true,
		},
		{
			name:            "non matching integer glob",
			boundClaimsType: "glob",
			boundClaims: map[string]any{
				"email": 42,
			},
			allClaims: map[string]any{
				"email": "42x",
			},
			errExpected: true,
		},
		{
			name:            "valid complex glob",
			boundClaimsType: "glob",
			boundClaims: map[string]any{
				"email": `*@*.com`,
			},
			allClaims: map[string]any{
				"email": "test@example.com",
			},
			errExpected: false,
		},
		{
			name: "non matching complex glob",
			boundClaims: map[string]any{
				"email": `r*@*.com`,
			},
			allClaims: map[string]any{
				"email": "test@example.com",
			},
			errExpected: true,
		},
	}
	for _, tt := range tests {
		if err := validateBoundClaims(hclog.NewNullLogger(), tt.boundClaimsType, tt.boundClaims, tt.allClaims); (err != nil) != tt.errExpected {
			t.Errorf("validateBoundClaims(%s) error = %v, wantErr %v", tt.name, err, tt.errExpected)
		}
	}
}

func Test_normalizeList(t *testing.T) {
	tests := []struct {
		raw        any
		normalized []any
		ok         bool
	}{
		{
			raw:        []any{"green", 42},
			normalized: []any{"green", 42},
			ok:         true,
		},
		{
			raw:        []any{"green"},
			normalized: []any{"green"},
			ok:         true,
		},
		{
			raw:        []any{},
			normalized: []any{},
			ok:         true,
		},
		{
			raw:        "green",
			normalized: []any{"green"},
			ok:         true,
		},
		{
			raw:        "",
			normalized: []any{""},
			ok:         true,
		},
		{
			raw:        42,
			normalized: nil,
			ok:         false,
		},
		{
			raw:        nil,
			normalized: nil,
			ok:         false,
		},
	}
	for _, tt := range tests {
		normalized, ok := normalizeList(tt.raw)
		if !reflect.DeepEqual(normalized, tt.normalized) {
			t.Errorf("normalizeList() got normalized = %v, want %v", normalized, tt.normalized)
		}
		if ok != tt.ok {
			t.Errorf("normalizeList() got ok = %v, want %v", ok, tt.ok)
		}
	}
}
