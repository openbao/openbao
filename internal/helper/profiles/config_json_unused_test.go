package profiles

import (
	"context"
	"errors"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
)

// jsonInitializeDocs is the JSON form of the initialize stanza as documented
// on the self-initialization page, in the multi-request shape operators
// actually write. hcl v1's JSON parser flattens nested objects so that the
// wrapper item's key list fuses the request block's key and each request's
// name (e.g. [request enable-audit]), which historically caused those names
// to be reported as unknown fields of the outer block.
const jsonInitializeDocs = `{
	"initialize": [
		{
			"audit": {
				"request": [
					{
						"enable-audit": {
							"operation": "update",
							"path": "sys/audit/stdout",
							"data": {
								"type": "file",
								"options": {
									"file_path": "stdout"
								}
							}
						}
					},
					{
						"enable-another": {
							"operation": "update",
							"path": "sys/audit/stderr",
							"allow_failure": true
						}
					}
				]
			}
		}
	]
}`

func TestParseOuterConfig_JSONRequestNamesNotUnused(t *testing.T) {
	list, err := parseBlockList(jsonInitializeDocs, "initialize")
	require.NoError(t, err)

	outers, err := ParseOuterConfig("initialize", list)
	require.NoError(t, err)
	require.Len(t, outers, 1)
	require.Equal(t, "audit", outers[0].Type)
	require.Len(t, outers[0].Requests, 2)

	// The request names are consumed as the requests' types and must not be
	// reported as unknown fields of the outer block.
	require.Empty(t, outers[0].UnusedKeys, "request names leaked into outer block unused keys: %v", outers[0].UnusedKeys)

	first := outers[0].Requests[0]
	require.Equal(t, "enable-audit", first.Type)
	require.Equal(t, "update", first.Operation)
	require.Equal(t, "sys/audit/stdout", first.Path)
	require.Empty(t, first.UnusedKeys, "request fields leaked into request unused keys: %v", first.UnusedKeys)

	second := outers[0].Requests[1]
	require.Equal(t, "enable-another", second.Type)
	require.Equal(t, "sys/audit/stderr", second.Path)
	require.Empty(t, second.UnusedKeys)

	// A genuinely unknown field at the outer block level must still be
	// reported, so the fix cannot silently swallow real typos.
	withTypo := `{
	"initialize": [
		{
			"audit": {
				"request": [
					{"enable-audit": {"operation": "update", "path": "sys/audit/stdout"}}
				],
				"reqeust_typo": true
			}
		}
	]
}`

	list, err = parseBlockList(withTypo, "initialize")
	require.NoError(t, err)
	outers, err = ParseOuterConfig("initialize", list)
	require.NoError(t, err)
	require.Len(t, outers, 1)
	require.NotEmpty(t, outers[0].UnusedKeys)
	require.Contains(t, outers[0].UnusedKeys, "reqeust_typo")
}

// jsonInputDocs is the JSON form of an input stanza: hcl v1's JSON parser
// fuses the field block's key and each field's name (e.g. [field username])
// into one wrapper item, which historically caused field names to be reported
// as unknown fields of the input block.
const jsonInputDocs = `{
	"input": [
		{
			"params": {
				"field": [
					{"username": {"type": "string", "required": true}},
					{"password": {"type": "string", "required": true}}
				]
			}
		}
	]
}`

func TestParseInputConfig_JSONFieldNamesNotUnused(t *testing.T) {
	list, err := parseBlockList(jsonInputDocs, "input")
	require.NoError(t, err)

	input, err := ParseInputConfig(list)
	require.NoError(t, err)
	require.NotNil(t, input)
	require.Len(t, input.Fields, 2)

	// The field names are consumed as the fields' names and must not be
	// reported as unknown fields of the input block.
	require.Empty(t, input.UnusedKeys, "field names leaked into input block unused keys: %v", input.UnusedKeys)

	require.Equal(t, "username", input.Fields[0].Name)
	require.Equal(t, "string", input.Fields[0].TypeRaw)
	require.Empty(t, input.Fields[0].UnusedKeys)

	require.Equal(t, "password", input.Fields[1].Name)
	require.Equal(t, "string", input.Fields[1].TypeRaw)
	require.Empty(t, input.Fields[1].UnusedKeys)

	// A genuinely unknown field at the input block level must still be
	// reported.
	withTypo := `{
	"input": [
		{
			"params": {
				"field": [
					{"username": {"type": "string"}}
				],
				"fild_typo": true
			}
		}
	]
}`

	list, err = parseBlockList(withTypo, "input")
	require.NoError(t, err)
	input, err = ParseInputConfig(list)
	require.NoError(t, err)
	require.NotEmpty(t, input.UnusedKeys)
	require.Contains(t, input.UnusedKeys, "fild_typo")
}

// The engine must surface the handler's specific failure reason from the
// response body when the handler also returns a generic error, instead of
// masking it with only the generic wrapper.
func TestEvaluateRequest_PrefersResponseErrorReason(t *testing.T) {
	requestBlock := &RequestConfig{
		Type:      "enable-audit",
		Operation: "update",
		Path:      "sys/audit/stdout",
	}
	outerBlock := &OuterConfig{Type: "audit", Requests: []*RequestConfig{requestBlock}}

	engine, err := NewEngine(
		WithDefaultToken("root"),
		WithOuterBlockName("initialize"),
		WithProfile([]*OuterConfig{outerBlock}),
		WithRequestHandler(func(ctx context.Context, req *logical.Request) (*logical.Response, error) {
			// Mirror the core's behavior on a rejected request: a response
			// carrying the handler's reason plus a generic error.
			return logical.ErrorResponse("cannot enable audit device via API; use declarative, config-based audit device management instead"), logical.ErrInvalidRequest
		}),
	)
	require.NoError(t, err)

	err = engine.Evaluate(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "cannot enable audit device via API")
	require.Contains(t, err.Error(), "invalid request")
}

// The engine must keep the handler's error verbatim when the response does
// not carry an additional reason.
func TestEvaluateRequest_HandlerErrorOnly(t *testing.T) {
	wantErr := errors.New("specific handler failure")
	requestBlock := &RequestConfig{
		Type:      "enable-audit",
		Operation: "update",
		Path:      "sys/audit/stdout",
	}
	outerBlock := &OuterConfig{Type: "audit", Requests: []*RequestConfig{requestBlock}}

	engine, err := NewEngine(
		WithDefaultToken("root"),
		WithOuterBlockName("initialize"),
		WithProfile([]*OuterConfig{outerBlock}),
		WithRequestHandler(func(ctx context.Context, req *logical.Request) (*logical.Response, error) {
			return nil, wantErr
		}),
	)
	require.NoError(t, err)

	err = engine.Evaluate(context.Background())
	require.Error(t, err)
	require.ErrorIs(t, err, wantErr)
}
