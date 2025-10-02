package structtomap

import (
	"testing"

	"github.com/stretchr/testify/require"
)

type (
	unexported struct {
		name string
		age  int
	}

	Exported struct {
		Name string
		Age  int
	}

	Tagged struct {
		Name string `json:"name"`
		Age  int    `json:"age"`
	}

	unexportedEmbedded struct {
		unexported
		Admin bool
	}

	ExportedEmbedded struct {
		Exported
		Admin bool
	}

	ExportedPointerEmbedded struct {
		*Exported
		Admin bool
	}

	Complex struct {
		Numbers []int
		Dict    map[string]int
	}
)

func TestMap(t *testing.T) {
	tcases := []struct {
		name string
		have any
		want map[string]any
	}{
		{
			name: "WithStructValue",
			have: Exported{Name: "Alice", Age: 30},
			want: map[string]any{"Name": "Alice", "Age": 30},
		},
		{
			name: "WithPointerToStruct",
			have: &Exported{Name: "Bob", Age: 25},
			want: map[string]any{"Name": "Bob", "Age": 25},
		},
		{
			name: "WithNonStructValue",
			have: 123,
			want: map[string]any{},
		},
		{
			name: "WithUnexportedFields",
			have: unexported{name: "hidden", age: 99},
			want: map[string]any{},
		},
		{
			name: "WithEmbeddedStruct",
			have: ExportedEmbedded{Exported: Exported{Name: "Bob", Age: 25}, Admin: true},
			want: map[string]any{"Name": "Bob", "Age": 25, "Admin": true},
		},
		{
			name: "WithPointerEmbeddedStruct",
			have: ExportedPointerEmbedded{Exported: &Exported{Name: "Bob", Age: 25}, Admin: true},
			want: map[string]any{"Name": "Bob", "Age": 25, "Admin": true},
		},
		{
			name: "WithNilPointer",
			have: (*Exported)(nil),
			want: map[string]any{},
		},
		{
			name: "WithStructContainingSliceAndMap",
			have: Complex{Numbers: []int{1, 2, 3}, Dict: map[string]int{"a": 1}},
			want: map[string]any{"Numbers": []int{1, 2, 3}, "Dict": map[string]int{"a": 1}},
		},
		{
			name: "WithAnonymousStruct",
			have: struct {
				X int
				Y string
			}{X: 7, Y: "anon"},
			want: map[string]any{"X": 7, "Y": "anon"},
		},
		{
			name: "WithZeroValueStruct",
			have: Exported{},
			want: map[string]any{"Name": "", "Age": 0},
		},
		{
			name: "WithStructHavingUnexportedEmbedded",
			have: unexportedEmbedded{unexported: unexported{name: "Alice", age: 30}, Admin: true},
			want: map[string]any{"Admin": true},
		},
		{
			name: "WithJSONTags",
			have: struct {
				Tagged
				Admin bool `json:"admin"`
			}{
				Tagged: Tagged{Name: "Bob", Age: 25},
				Admin:  true,
			},
			want: map[string]any{"name": "Bob", "age": 25, "admin": true},
		},
	}

	for _, tt := range tcases {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, Map(tt.have))
		})
	}
}
