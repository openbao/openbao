package structtomap

import (
	"reflect"
	"testing"
)

type TestStruct struct {
	Name  string
	Age   int
	Admin bool
}

type unexportedStruct struct {
	name string
	age  int
}

func TestMap_WithStructValue(t *testing.T) {
	s := TestStruct{Name: "Alice", Age: 30, Admin: true}
	stm := New(s)
	m := stm.Map()

	expected := map[string]any{
		"Name":  "Alice",
		"Age":   30,
		"Admin": true,
	}

	if !reflect.DeepEqual(m, expected) {
		t.Errorf("Map() = %v, want %v", m, expected)
	}
}

func TestMap_WithPointerToStruct(t *testing.T) {
	s := &TestStruct{Name: "Bob", Age: 25, Admin: false}
	m := New(s).Map()

	expected := map[string]any{
		"Name":  "Bob",
		"Age":   25,
		"Admin": false,
	}

	if !reflect.DeepEqual(m, expected) {
		t.Errorf("Map() = %v, want %v", m, expected)
	}
}

func TestMap_WithNonStructValue(t *testing.T) {
	stm := New(123)
	m := stm.Map()
	if len(m) != 0 {
		t.Errorf("Map() with non-struct value should return empty map, got %v", m)
	}
}

func TestMap_WithUnexportedFields(t *testing.T) {
	s := unexportedStruct{name: "hidden", age: 99}
	stm := New(s)
	m := stm.Map()
	if len(m) != 0 {
		t.Errorf("Map() should not include unexported fields, got %v", m)
	}
}

func TestMap_WithEmbeddedStruct(t *testing.T) {
	type Embedded struct {
		ID int
	}
	type Outer struct {
		Embedded
		Name string
	}
	s := Outer{Embedded: Embedded{ID: 42}, Name: "OuterName"}
	stm := New(s)
	m := stm.Map()

	expected := map[string]any{
		"ID":   42,
		"Name": "OuterName",
	}

	if !reflect.DeepEqual(m, expected) {
		t.Errorf("Map() = %v, want %v", m, expected)
	}
}

func TestMap_WithNilPointer(t *testing.T) {
	var s *TestStruct = nil
	stm := New(s)
	m := stm.Map()
	if len(m) != 0 {
		t.Errorf("Map() with nil pointer should return empty map, got %v", m)
	}
}

func TestMap_WithStructContainingSliceAndMap(t *testing.T) {
	type Complex struct {
		Numbers []int
		Dict    map[string]int
	}
	s := Complex{Numbers: []int{1, 2, 3}, Dict: map[string]int{"a": 1}}
	stm := New(s)
	m := stm.Map()

	expected := map[string]any{
		"Numbers": []int{1, 2, 3},
		"Dict":    map[string]int{"a": 1},
	}

	if !reflect.DeepEqual(m, expected) {
		t.Errorf("Map() = %v, want %v", m, expected)
	}
}

func TestMap_WithAnonymousStruct(t *testing.T) {
	s := struct {
		X int
		Y string
	}{X: 7, Y: "anon"}
	stm := New(s)
	m := stm.Map()

	expected := map[string]any{
		"X": 7,
		"Y": "anon",
	}

	if !reflect.DeepEqual(m, expected) {
		t.Errorf("Map() = %v, want %v", m, expected)
	}
}

func TestMap_WithZeroValueStruct(t *testing.T) {
	s := TestStruct{}
	stm := New(s)
	m := stm.Map()

	expected := map[string]any{
		"Name":  "",
		"Age":   0,
		"Admin": false,
	}

	if !reflect.DeepEqual(m, expected) {
		t.Errorf("Map() = %v, want %v", m, expected)
	}
}

func TestMap_WithStructHavingUnexportedEmbedded(t *testing.T) {
	type hidden struct {
		secret string
	}
	type Outer struct {
		hidden
		Public string
	}
	s := Outer{hidden: hidden{secret: "nope"}, Public: "yes"}
	stm := New(s)
	m := stm.Map()

	expected := map[string]any{
		"Public": "yes",
	}

	if !reflect.DeepEqual(m, expected) {
		t.Errorf("Map() = %v, want %v", m, expected)
	}
}
