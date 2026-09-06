package profiles

import "fmt"

func StringField(field map[string]any, parameter string) (string, bool, error) {
	rawValue, present := field[parameter]
	if !present {
		return "", false, nil
	}

	value, ok := rawValue.(string)
	if !ok {
		return "", true, fmt.Errorf("field %q is of wrong type: expected 'string' got '%T'", parameter, rawValue)
	}

	return value, true, nil
}

func RequiredStringField(field map[string]any, parameter string) (string, error) {
	value, present, err := StringField(field, parameter)
	if err != nil {
		return "", err
	}

	if !present {
		return "", fmt.Errorf("missing required field %q", parameter)
	}

	return value, nil
}

func ListField(field map[string]any, parameter string) ([]any, bool, error) {
	rawValue, present := field[parameter]
	if !present {
		return nil, false, nil
	}

	value, ok := rawValue.([]any)
	if !ok {
		return nil, true, fmt.Errorf("field %q is of wrong type: expected 'string' got '%T'", parameter, rawValue)
	}

	return value, true, nil
}
