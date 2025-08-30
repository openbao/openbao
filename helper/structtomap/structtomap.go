package structtomap

import (
	"maps"
	"reflect"
)

type StructToMap[T any] struct {
	value T
}

func Map(s any) map[string]any {
	return new(s).Map()
}

func new[T any](v T) *StructToMap[T] {
	return &StructToMap[T]{value: v}
}

// Map converts a reflect.Value representing a struct (or pointer to struct)
// into a map[string]any, mapping field names (using the "json" tag if present, otherwise
// the field name) to their values. Only exported fields are included. Embedded anonymous
// structs are recursively merged into the result. Non-struct values return an empty map.
func (s *StructToMap[T]) Map() map[string]any {
	val := reflect.ValueOf(s.value)
	// Handle pointer to struct
	if val.Kind() == reflect.Pointer && val.Elem().Kind() == reflect.Struct {
		val = val.Elem()
	}
	if val.Kind() != reflect.Struct {
		return map[string]any{}
	}
	return structToMap(val)
}

func structToMap(val reflect.Value) map[string]any {
	result := make(map[string]any)

	// If it's a pointer, dereference
	if val.Kind() == 2 { // reflect.Ptr == 2
		val = val.Elem()
	}

	if val.Kind() != reflect.Struct {
		return result
	}

	typ := val.Type()
	for i := 0; i < val.NumField(); i++ {
		field := typ.Field(i)
		// Only exportable fields
		if field.PkgPath != "" {
			continue
		}
		fieldVal := val.Field(i)
		if field.Anonymous && fieldVal.Kind() == reflect.Struct {
			embedded := structToMap(fieldVal)
			// Use maps.Copy to merge embedded struct fields
			maps.Copy(result, embedded)
		} else {
			// Use json tag if present, else field name
			tag := field.Tag.Get("json")
			if tag == "" || tag == "-" {
				tag = field.Name
			}
			result[tag] = fieldVal.Interface()
		}
	}
	return result
}
