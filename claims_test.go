package jwtauth

import (
	"encoding/json"
	"github.com/hashicorp/go-hclog"
	"testing"

	"github.com/go-test/deep"
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
	var claims map[string]interface{}
	if err := json.Unmarshal([]byte(data), &claims); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		claim string
		value interface{}
	}{
		{"a", float64(42)},
		{"/a", float64(42)},
		{"b", "bar"},
		{"/c/d", float64(95)},
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

func TestExtractMetadata(t *testing.T) {
	emptyMap := make(map[string]string)

	tests := []struct {
		testCase      string
		allClaims     map[string]interface{}
		claimMappings map[string]string
		expected      map[string]string
		errExpected   bool
	}{
		{"empty", nil, nil, emptyMap, false},
		{
			"full match",
			map[string]interface{}{
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
			map[string]interface{}{
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
			map[string]interface{}{
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
			map[string]interface{}{
				"data1": "foo",
				"data2": map[string]interface{}{
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
			map[string]interface{}{
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
