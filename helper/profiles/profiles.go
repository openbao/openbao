package profiles

import (
	"context"
	"errors"
	"fmt"
	"regexp"

	"github.com/go-viper/mapstructure/v2"
	"github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

/*
 * The profile system is a mechanism for embedding requests in a configuration
 * file. It supports configurable, extensible sources for request parameters,
 * defined by the `eval_source` parameter:
 *
 * - Environment variables
 * - Files
 * - Previous requests and responses
 * - CEL expressions
 *
 * The parameter type is converted via the `eval_type` flag.
 *
 * This type of system allows limited orchestration and should not be used in
 * scenarios where durability (retries, &c) are considered.
 *
 * The profile system allow the construction of a single, optional outer named
 * block (e.g., `initialization`, `profile`, &c) which has one or more
 * `request` blocks inside, executed in the given order.
 *
 * This is expected to work on regular API requests and responses and will not
 * work on special, raw responses like the direct PKI CRL path (/pki/crl/pem).
 */
type ProfileEngine struct {
	sourceBuilders map[string]SourceBuilder
	defaultToken   string
	profile        []*OuterConfig
	outerBlockName string
	requestHandler RequestHandlerFunc

	input   *InputConfig
	request *logical.Request
	data    *framework.FieldData

	output *OutputConfig
	logger hclog.Logger
}

// NewEngine creates a new profile evaluation engine for a given
// context.
func NewEngine(opts ...func(*ProfileEngine)) (*ProfileEngine, error) {
	profile := &ProfileEngine{
		sourceBuilders: map[string]SourceBuilder{},
		logger:         hclog.NewNullLogger(),
	}

	for _, opt := range opts {
		opt(profile)
	}

	if err := profile.validate(); err != nil {
		return nil, err
	}

	return profile, nil
}

// Adds a new source into the profile evaluation engine.
func WithSourceBuilder(name string, builder SourceBuilder) func(*ProfileEngine) {
	return func(p *ProfileEngine) {
		p.sourceBuilders[name] = builder
	}
}

// Sets the default token for the profile evaluation engine.
func WithDefaultToken(token string) func(*ProfileEngine) {
	return func(p *ProfileEngine) {
		p.defaultToken = token
	}
}

// Sets the profile.
func WithProfile(profile []*OuterConfig) func(*ProfileEngine) {
	return func(p *ProfileEngine) {
		p.profile = profile
	}
}

// Sets the name of the outer profile configuration block. Without this,
// only a single outer block is allowed, which may be empty.
func WithOuterBlockName(name string) func(*ProfileEngine) {
	return func(p *ProfileEngine) {
		p.outerBlockName = name
	}
}

// Sets the request handler for this profile.
func WithRequestHandler(helper RequestHandlerFunc) func(*ProfileEngine) {
	return func(p *ProfileEngine) {
		p.requestHandler = helper
	}
}

// Sets the logger to use for this engine.
func WithLogger(logger hclog.Logger) func(*ProfileEngine) {
	return func(p *ProfileEngine) {
		p.logger = logger
	}
}

// Sets the output configuration for this engine, allowing generating
// logical.Response objects.
func WithOutput(config *OutputConfig) func(*ProfileEngine) {
	return func(p *ProfileEngine) {
		p.output = config
	}
}

// SourceBuilder creates a new concrete source mapped to a particular
// instance of a field.
type SourceBuilder func(ctx context.Context, engine *ProfileEngine, field map[string]interface{}) Source

// RequestHandler takes logical requests and executes them.
type RequestHandlerFunc func(ctx context.Context, req *logical.Request) (*logical.Response, error)

// Source represents a dynamic value source. A source object is initialized
// once for each matching object and is alive throughout the history of the request.
type Source interface {
	Validate(ctx context.Context) (requestDeps, responseDeps []string, err error)
	Evaluate(ctx context.Context, history *EvaluationHistory) (value interface{}, err error)
	Close(ctx context.Context) error
}

// validate performs internal validation of the profile engine.
func (p *ProfileEngine) validate() error {
	for name, builder := range p.sourceBuilders {
		if name == "" {
			return fmt.Errorf("a source is missing a name")
		}

		if builder == nil {
			return fmt.Errorf("source '%v' has nil builder", name)
		}
	}

	if len(p.profile) > 1 && p.outerBlockName == "" {
		return fmt.Errorf("must have named outer block when providing more than one outer config")
	}

	if err := p.validateOuterBlockUniqueness(); err != nil {
		return err
	}

	if err := p.validateRequestNameUniqueness(); err != nil {
		return err
	}

	for _, outer := range p.profile {
		if err := validateNameConvention("outer block", outer.Type); err != nil {
			return err
		}
		for _, req := range outer.Requests {
			if err := validateNameConvention(fmt.Sprintf("request in block '%s'", outer.Type), req.Type); err != nil {
				return err
			}
		}
	}

	// 5. Ensure we've set a request handler.
	if p.requestHandler == nil {
		return errors.New("profile engine is missing a request handler; use WithRequestHandler(...) during engine construction")
	}

	// 6. Ensure all input source parameters are set.
	if p.input != nil || p.request != nil || p.data != nil {
		if p.input == nil {
			return errors.New("profile engine option WithInputSource(...) called without an input configuration")
		}
		if p.request == nil {
			return errors.New("profile engine option WithInputSource(...) called without a source request")
		}
		if p.data == nil {
			return errors.New("profile engine option WithInputSource(...) called without parsed request data")
		}

		for index, field := range p.input.Fields {
			if _, present := p.data.Schema[field.Name]; present {
				return fmt.Errorf("input.fields.%d [named %q] already present in request schema", index, field.Name)
			}

			p.data.Schema[field.Name] = field.ToSchema()
		}

		if err := p.data.Validate(); err != nil {
			return fmt.Errorf("failed input schema validation: %w", err)
		}

		if err := p.data.ValidateRequiredFields(); err != nil {
			return fmt.Errorf("failed input validation: %w", err)
		}
	}

	return nil
}

// 1. Outer blocks have unique names.
func (p *ProfileEngine) validateOuterBlockUniqueness() error {
	if len(p.profile) <= 1 {
		return nil
	}

	seenNames := make(map[string]int)

	for index, outerBlock := range p.profile {
		if outerBlock == nil {
			return fmt.Errorf("outer block at index %d is nil", index)
		}

		blockName := outerBlock.Type

		if blockName == "" {
			return fmt.Errorf("outer block at index %d has empty name", index)
		}

		if existingIndex, exists := seenNames[blockName]; exists {
			return fmt.Errorf("duplicate outer block name '%s' found at indices %d and %d",
				blockName, existingIndex, index)
		}

		seenNames[blockName] = index
	}

	return nil
}

// 2. Requests have unique names within their outer blocks.
func (p *ProfileEngine) validateRequestNameUniqueness() error {
	for index, outer := range p.profile {
		if outer == nil {
			return fmt.Errorf("outer block at index %d is nil", index)
		}
		seen := make(map[string]int)
		for reqIndex, req := range outer.Requests {
			if req == nil {
				return fmt.Errorf("request at index %d in outer block '%s' is nil", reqIndex, outer.Type)
			}

			name := req.Type
			if name == "" {
				return fmt.Errorf("empty request name at index %d in outer block '%s'", reqIndex, outer.Type)
			}
			if firstRequestIndex, exists := seen[name]; exists {
				return fmt.Errorf(
					"duplicate request name '%s' in outer block '%s' at indices %d and %d",
					name, outer.Type, firstRequestIndex, reqIndex,
				)
			}
			seen[name] = reqIndex
		}
	}
	return nil
}

// 3. All names conform exclude some special characters (.[](){}_ /-) or we limit to a-zA-Z0-9
func validateNameConvention(kind, name string) error {
	validName := regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]*$`)
	if !validName.MatchString(name) {
		return fmt.Errorf("%s name '%s' is invalid: must start with a letter or underscore and contain only letters, digits", kind, name)
	}
	return nil
}

// Evaluate performs evaluation of the profile described by this engine. In
// order of the configuration, it:
//
//  1. Evaluates all outer blocks.
//  2. Evaluates all requests within each outer block, sending it to the
//     handler.
func (p *ProfileEngine) Evaluate(ctx context.Context) error {
	if p.output != nil {
		return fmt.Errorf("cannot call ProfileEngine.Evaluate(...) when output is specified")
	}

	_, err := p.evaluateHistory(ctx)
	return err
}

// EvaluateResponse performs evaluation of the profile described in this
// engine, yielding a final combined output response.
func (p *ProfileEngine) EvaluateResponse(ctx context.Context) (*logical.Response, error) {
	if p.output == nil {
		return nil, fmt.Errorf("cannot call ProfileEngine.EvaluateResponse(...) when output is not specified")
	}

	history, err := p.evaluateHistory(ctx)
	if err != nil {
		return nil, err
	}

	return p.evaluateOutput(ctx, history)
}

// evaluateHistory evaluates all requests which occur in the profile, building
// up an evaluation history of these flows.
func (p *ProfileEngine) evaluateHistory(ctx context.Context) (*EvaluationHistory, error) {
	var history EvaluationHistory
	for outerIndex, outerBlock := range p.profile {
		if err := func() error {
			for requestIndex, requestBlock := range outerBlock.Requests {
				if err := func() error {
					return p.evaluateRequest(ctx, &history, outerIndex, outerBlock, requestIndex, requestBlock)
				}(); err != nil {
					return fmt.Errorf("request.[%v (%d)]: %w", requestBlock.Type, requestIndex, err)
				}
			}

			return nil
		}(); err != nil {
			if p.outerBlockName != "" {
				return nil, fmt.Errorf("%v.[%v (%d)]: %w", p.outerBlockName, outerBlock.Type, outerIndex, err)
			}

			return nil, err
		}
	}

	return &history, nil
}

// evaluateRequest evaluates a single request within the broader profile.
func (p *ProfileEngine) evaluateRequest(ctx context.Context, history *EvaluationHistory, outerIndex int, outerBlock *OuterConfig, requestIndex int, requestBlock *RequestConfig) error {
	// 1. Build logical request.
	req, allowFailure, err := p.buildRequest(ctx, history, outerIndex, outerBlock, requestIndex, requestBlock)
	if err != nil {
		return fmt.Errorf("in building request: %w", err)
	}

	p.logger.Trace("Performing profile request", "input", requestBlock, "request-id", req.ID)

	// 2. Call the request handler.
	resp, err := p.requestHandler(ctx, req)
	isFailure := err != nil || resp.IsError()
	if err == nil && resp.IsError() {
		err = resp.Error()
	}
	if !allowFailure && isFailure {
		if err != nil {
			return fmt.Errorf("failed to evaluate request: %w", err)
		}
	}

	// 3. Stash request & response for future use.
	if err := history.AddRequest(outerBlock.Type, requestBlock.Type, req); err != nil {
		return fmt.Errorf("failed to save request: %w", err)
	}

	if !isFailure {
		if err := history.AddResponse(outerBlock.Type, requestBlock.Type, resp); err != nil {
			return fmt.Errorf("failed to save response: %w", err)
		}
	}

	return nil
}

// buildRequest transforms an input configuration's request into a proper
// output
func (p *ProfileEngine) buildRequest(ctx context.Context, history *EvaluationHistory, outerIndex int, outerBlock *OuterConfig, requestIndex int, requestBlock *RequestConfig) (req *logical.Request, allowFailure bool, err error) {
	reqName := fmt.Sprintf("request[%d].%v", requestIndex, requestBlock.Type)
	if p.outerBlockName != "" {
		reqName = fmt.Sprintf("%v[%d].%v.%v", p.outerBlockName, outerIndex, outerBlock.Type, reqName)
	}

	req = &logical.Request{
		ID: reqName,
	}

	if err = p.evaluateField(ctx, history, requestBlock.Operation, &req.Operation); err != nil {
		err = fmt.Errorf("failed to evaluate operation: %w", err)
		return req, allowFailure, err
	}

	if err = p.evaluateField(ctx, history, requestBlock.Path, &req.Path); err != nil {
		err = fmt.Errorf("failed to evaluate path: %w", err)
		return req, allowFailure, err
	}

	// For the token, if our request block did not specify a token, we use the
	// default token, which may be empty. However, if one was specified, use
	// that even if it resolves to the empty string.
	if requestBlock.Token == nil {
		req.ClientToken = p.defaultToken
	} else {
		if err = p.evaluateField(ctx, history, requestBlock.Token, &req.ClientToken); err != nil {
			err = fmt.Errorf("failed to evaluate token: %w", err)
			return req, allowFailure, err
		}
	}

	if err = p.evaluateField(ctx, history, requestBlock.Data, &req.Data); err != nil {
		err = fmt.Errorf("failed to evaluate data: %w", err)
		return req, allowFailure, err
	}

	if err = p.evaluateField(ctx, history, requestBlock.AllowFailure, &allowFailure); err != nil {
		err = fmt.Errorf("failed to evaluate allow failure: %w", err)
		return req, allowFailure, err
	}

	return req, allowFailure, err
}

// evaluateField takes a single configuration field and evaluates it to the
// output destination, using mapstructure.WeakDecode(...) to handle type
// differences between input and output. This allows for e.g., a string
// environment variable to be used as an integer.
func (p *ProfileEngine) evaluateField(ctx context.Context, history *EvaluationHistory, _obj interface{}, destination interface{}) error {
	var err error
	var value interface{}

	switch obj := _obj.(type) {
	case map[string]interface{}:
		value, err = p.maybeEvaluateTypedField(ctx, history, obj)
		if err != nil {
			return err
		}
	case []map[string]interface{}:
		// HCL only ever yields a []map[string]interface{} when doing partial
		// (IMHO, failed) conversion of objects. Collapse all items in the map
		// down to a single item and re-evaluate.
		collapsed := map[string]interface{}{}
		for index, subobj := range obj {
			for key, value := range subobj {
				if existingValue, present := collapsed[key]; present && existingValue != value {
					return fmt.Errorf("bug in profile system: at index %d in collapsing object, duplicate key %v (%q != %q)", index, key, existingValue, value)
				}

				collapsed[key] = value
			}
		}

		value, err = p.maybeEvaluateTypedField(ctx, history, collapsed)
		if err != nil {
			return err
		}
	case []interface{}:
		var results []interface{}
		for index, orig := range obj {
			var dest interface{}
			if err := p.evaluateField(ctx, history, orig, &dest); err != nil {
				return fmt.Errorf("list.%d: %w", index, err)
			}

			results = append(results, dest)
		}

		value = results
	default:
		value = obj
	}

	if err := mapstructure.WeakDecode(value, destination); err != nil {
		return err
	}

	return nil
}

// maybeEvaluateTypedField checks if the field is one of our source fields,
// else returns the original value. Handles various nested structures.
//
// We implement a depth-first evaluation technique: this ensures that
// source evaluation is always predetermined as new keys cannot be
// net-created.
//
// Notably, evaluation must be constants and pre-determined; we do not
// support conditional evaluation types.
func (p *ProfileEngine) maybeEvaluateTypedField(ctx context.Context, history *EvaluationHistory, obj map[string]interface{}) (interface{}, error) {
	sourceRaw, sourcePresent := obj["eval_source"]
	objTypeRaw, objPresent := obj["eval_type"]

	// If we have one or the other, but not both, this is a fatal fault.
	if (sourcePresent || objPresent) && (!sourcePresent || !objPresent) {
		return nil, fmt.Errorf("malformed object; missing either 'eval_type' or 'eval_source': obj=%#v", obj)
	}

	// Even if no resolution needs to happen at this level, a lower level
	// might need to occur; recurse until we have primitive types.
	resolved := map[string]interface{}{}
	for key, value := range obj {
		var result interface{}

		// Parse the final value of this field.
		if err := p.evaluateField(ctx, history, value, &result); err != nil {
			return nil, fmt.Errorf("while evaluating map.%v: %w", key, err)
		}

		resolved[key] = result
	}

	// No evaluation needs to occur; return.
	if !sourcePresent && !objPresent {
		return resolved, nil
	}

	// Finally, dispatch the right source method.
	source, ok := sourceRaw.(string)
	if !ok {
		return nil, fmt.Errorf("malformed object; 'eval_source' was of wrong type; expected 'string' got '%T'", sourceRaw)
	}

	objType, ok := objTypeRaw.(string)
	if !ok {
		return nil, fmt.Errorf("malformed object; 'eval_type' was of wrong type; expected 'string' got '%T'", sourceRaw)
	}

	return p.evaluateTypedField(ctx, history, resolved, source, objType)
}

// evaluateTypedField actually performs the source builder-backed evaluation
// of fields from other data sources.
func (p *ProfileEngine) evaluateTypedField(ctx context.Context, history *EvaluationHistory, obj map[string]interface{}, source string, objType string) (interface{}, error) {
	sourceBuilder, present := p.sourceBuilders[source]
	if !present {
		return nil, fmt.Errorf("unknown value for 'eval_source': %v", source)
	}

	sourceEval := sourceBuilder(ctx, p, obj)

	defer sourceEval.Close(ctx)

	accessedRequests, accessedResponses, err := sourceEval.Validate(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to validate source '%v': %w", source, err)
	}

	for _, req := range accessedRequests {
		if req == "" {
			return nil, fmt.Errorf("invalid empty request name found")
		}
	}

	for _, resp := range accessedResponses {
		if resp == "" {
			return nil, fmt.Errorf("invalid empty response name found")
		}
	}

	val, err := sourceEval.Evaluate(ctx, history)
	if err != nil {
		return nil, fmt.Errorf("failed to evaluate source '%v': %w", source, err)
	}

	convertedVal, err := p.convertToType(val, objType)
	if err != nil {
		return nil, fmt.Errorf("failed to convert value to type '%s': %w", objType, err)
	}

	return convertedVal, nil
}

func (p *ProfileEngine) convertToType(val interface{}, objType string) (interface{}, error) {
	if objType == "" {
		return val, nil
	}

	switch objType {
	case "string":
		var result string
		if err := mapstructure.WeakDecode(val, &result); err != nil {
			return nil, fmt.Errorf("conversion-error: cannot convert value to type '%s'", objType)
		}
		return result, nil

	case "int":
		var result int
		if err := mapstructure.WeakDecode(val, &result); err != nil {
			return nil, fmt.Errorf("conversion-error: cannot convert value to type '%s'", objType)
		}
		return result, nil

	case "float64":
		var result float64
		if err := mapstructure.WeakDecode(val, &result); err != nil {
			return nil, fmt.Errorf("conversion-error: cannot convert value to type '%s'", objType)
		}
		return result, nil

	case "bool":
		var result bool
		if err := mapstructure.WeakDecode(val, &result); err != nil {
			return nil, fmt.Errorf("conversion-error: cannot convert value to type '%s'", objType)
		}
		return result, nil

	case "[]string":
		var result []string
		if err := mapstructure.WeakDecode(val, &result); err != nil {
			return nil, fmt.Errorf("cannot convert to []string: %w", err)
		}
		return result, nil

	case "map", "map[string]interface{}":
		var result map[string]interface{}
		if err := mapstructure.WeakDecode(val, &result); err != nil {
			return nil, fmt.Errorf("cannot convert to map[string]interface{}: %w", err)
		}
		return result, nil

	case "any", "interface{}":
		return val, nil

	default:
		return nil, fmt.Errorf("unsupported type conversion: %s", objType)
	}
}

func (p *ProfileEngine) evaluateOutput(ctx context.Context, history *EvaluationHistory) (*logical.Response, error) {
	resp := &logical.Response{
		Headers: map[string][]string{},
	}

	if err := p.evaluateField(ctx, history, p.output.Data, &resp.Data); err != nil {
		return nil, fmt.Errorf("failed to evaluate output data: %w", err)
	}

	for headerName, exprs := range p.output.Headers {
		var values []string
		for index, expr := range exprs {
			var value string
			if err := p.evaluateField(ctx, history, expr, &value); err != nil {
				return nil, fmt.Errorf("failed to evaluate response header [%v/%d]: %w", headerName, index, err)
			}

			values = append(values, value)
		}

		resp.Headers[headerName] = values
	}

	return resp, nil
}
