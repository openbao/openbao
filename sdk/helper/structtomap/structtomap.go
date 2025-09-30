package structtomap

import (
	"maps"
	"reflect"
)

// Map converts a reflect.Value representing a struct (or pointer to struct)
// into a `map[string]any`, mapping field names (using the "json" tag if
// present, otherwise the field name) to their values. Only exported fields are
// included. Embedded structs are recursively merged into the result. Non-struct
// values return an empty map.
func Map(s any) map[string]any {
	return structToMap(reflect.ValueOf(s))
}

func structToMap(val reflect.Value) map[string]any {
	result := make(map[string]any)

	// If it's a pointer, dereference
	if val.Kind() == reflect.Pointer {
		val = val.Elem()
	}

	if val.Kind() != reflect.Struct {
		return result
	}

	typ := val.Type()
	for i := range val.NumField() {
		field := typ.Field(i)
		// Only exportable fields
		if field.PkgPath != "" {
			continue
		}
		fieldVal := val.Field(i)
		if field.Anonymous {
			maps.Copy(result, structToMap(fieldVal))
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
