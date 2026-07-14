package api

import (
	"encoding/json"
	"fmt"
	"strings"

	retryablehttp "github.com/hashicorp/go-retryablehttp"
)

const (
	ErrOutputProfileRequest = "output a profile, please"
)

var LastOutputProfileError *OutputProfileError

type OutputProfileError struct {
	*retryablehttp.Request
	finalProfile string
}

func (d *OutputProfileError) Error() string {
	if d.finalProfile == "" {
		cs, err := d.buildProfile()
		if err != nil {
			return err.Error()
		}
		d.finalProfile = cs
	}

	return ErrOutputProfileRequest
}

func (d *OutputProfileError) HCLString() (string, error) {
	if d.finalProfile == "" {
		cs, err := d.buildProfile()
		if err != nil {
			return "", err
		}
		d.finalProfile = cs
	}
	return d.finalProfile, nil
}

func (d *OutputProfileError) operation() string {
	switch d.Method {
	case "GET":
		params := d.URL.Query()
		switch {
		case params.Get("list") != "":
			return "list"
		case params.Get("scan") != "":
			return "scan"
		default:
			return "read"
		}
	case "POST", "PUT":
		// Cannot disambiguate create versus update here; default to update.
		return "update"
	case "DELETE":
		return "delete"
	case "PATCH":
		return "patch"
	}

	return "<unknown>"
}

func (d *OutputProfileError) path() string {
	return strings.TrimPrefix(d.URL.Path, "/v1")
}

func (d *OutputProfileError) token() string {
	return d.Header.Get(AuthHeaderName)
}

func (d *OutputProfileError) headers() (map[string]string, error) {
	headers := make(map[string]string, len(d.Header))
	for key, values := range d.Header {
		if key == AuthHeaderName || key == RequestHeaderName {
			// Token is specified via a dedicated field and the X-Vault-Request
			// header is unnecessary as we know we're not likely taking to the
			// agent.
			continue
		}

		output, err := json.Marshal(values)
		if err != nil {
			return nil, fmt.Errorf("while marshaling header %q: %w", key, err)
		}

		headers[key] = string(output)
	}

	return headers, nil
}

func (d *OutputProfileError) dataSource() (map[string]any, error) {
	data := make(map[string]any)
	if d.Method == "GET" {
		for key, values := range d.URL.Query() {
			if key == "list" || key == "scan" {
				// LIST or SCAN operation already handled.
				continue
			}

			if len(values) == 1 {
				data[key] = values[0]
			} else {
				data[key] = values
			}
		}

		return data, nil
	}

	body, err := d.BodyBytes()
	if err != nil {
		return nil, fmt.Errorf("failed to read request body: %w", err)
	}

	if err := json.Unmarshal(body, &data); err != nil {
		return nil, fmt.Errorf("failed to unmarshal request body as JSON: %w", err)
	}

	return data, nil
}

func (d *OutputProfileError) indent(prefix string, value string) string {
	return strings.TrimSuffix(strings.Join(strings.Split(value, "\n"), "\n"+prefix), prefix)
}

// formatHCL exists because hashicorp/hcl (on the v1 branch) lacks an encoder
// and github.com/hashicorp/hcl/v2/gohcl assumes using a struct with tags,
// which is not true of our CLI/API usage.
func (d *OutputProfileError) formatHCL(_value any) (string, error) {
	switch value := _value.(type) {
	case string:
		return fmt.Sprintf("%q", value), nil
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, bool:
		return fmt.Sprintf("%v", value), nil
	case []any:
		result := "[\n"
		for index, item := range value {
			formatted, err := d.formatHCL(item)
			if err != nil {
				return "", fmt.Errorf("at index %d: %w", index, err)
			}

			if index > 0 {
				result += ",\n"
			}
			result += "  " + d.indent("  ", formatted) + ",\n"
		}

		return result + "]", nil
	case map[string]any:
		result := "{\n"
		for key, item := range value {
			formatted, err := d.formatHCL(item)
			if err != nil {
				return "", fmt.Errorf("at key %q: %w", key, err)
			}

			equals := " = "
			if strings.HasPrefix(formatted, "{") {
				equals = " "
			}

			result += fmt.Sprintf("  %q%v%v\n", key, equals, d.indent("  ", formatted))
		}

		return result + "}", nil
	default:
		return "", fmt.Errorf("unknown type for field: %T", value)
	}
}

func (d *OutputProfileError) data() (map[string]string, error) {
	data, err := d.dataSource()
	if err != nil {
		return nil, err
	}

	result := make(map[string]string, len(data))
	for key, value := range data {
		formatted, err := d.formatHCL(value)
		if err != nil {
			return nil, fmt.Errorf("at top-level data key %q: %w", key, err)
		}

		result[key] = formatted
	}

	return result, nil
}

func (d *OutputProfileError) buildProfile() (string, error) {
	var profile strings.Builder
	profile.WriteString(`request "cli-generated-request" {`)
	profile.WriteByte('\n')

	fmt.Fprintf(&profile, "  operation = %q\n", d.operation())

	fmt.Fprintf(&profile, "  path = %q\n", d.path())

	if d.token() != "" {
		fmt.Fprintf(&profile, "  token = %q\n", d.token())
	}

	headers, err := d.headers()
	if err != nil {
		return "", err
	}

	if len(headers) > 0 {
		profile.WriteString("  headers = {\n")
		for header, value := range headers {
			fmt.Fprintf(&profile, "    %q = %v\n", header, value)
		}
		profile.WriteString("  }\n")
	}

	data, err := d.data()
	if err != nil {
		return "", err
	}

	if len(data) > 0 {
		profile.WriteString("  data = {\n")
		for key, value := range data {
			fmt.Fprintf(&profile, "    %q = %v\n", key, d.indent("    ", value))
		}
		profile.WriteString("  }\n")
	}

	profile.WriteString("}\n")

	return profile.String(), nil
}
