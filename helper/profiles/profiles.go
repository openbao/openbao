package profiles

import (
	"context"
	"errors"
	"fmt"
	"regexp"

	"github.com/go-viper/mapstructure/v2"
	"github.com/hashicorp/go-hclog"
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
	logger         hclog.Logger
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

// Sets the name of the outer profile configuration block. Without this,
// only a single outer block is allowed, which may be empty.
func WithLogger(logger hclog.Logger) func(*ProfileEngine) {
	return func(p *ProfileEngine) {
		p.logger = logger
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
		return fmt.Errorf("profile engine is missing a request handler; set p.requestHandler before Evaluate")
	}
	// XXX (ascheel) - additional validations:
	// 4. Validate and store all sources up-front, letting us simply call
	//    evaluate later.

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
				return fmt.Errorf("%v.[%v (%d)]: %w", p.outerBlockName, outerBlock.Type, outerIndex, err)
			}

			return err
		}
	}

	return nil
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
		return
	}

	if err = p.evaluateField(ctx, history, requestBlock.Path, &req.Path); err != nil {
		err = fmt.Errorf("failed to evaluate path: %w", err)
		return
	}

	// For the token, if our request block did not specify a token, we use the
	// default token, which may be empty. However, if one was specified, use
	// that even if it resolves to the empty string.
	if requestBlock.Token == nil {
		req.ClientToken = p.defaultToken
	} else {
		if err = p.evaluateField(ctx, history, requestBlock.Token, &req.ClientToken); err != nil {
			err = fmt.Errorf("failed to evaluate token: %w", err)
			return
		}
	}

	if err = p.evaluateField(ctx, history, requestBlock.Data, &req.Data); err != nil {
		err = fmt.Errorf("failed to evaluate data: %w", err)
		return
	}

	if err = p.evaluateField(ctx, history, requestBlock.AllowFailure, &allowFailure); err != nil {
		err = fmt.Errorf("failed to evaluate allow failure: %w", err)
		return
	}

	return
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
		resultMap := map[string]interface{}{}
		for index, item := range obj {
			evalValue, err := p.maybeEvaluateTypedField(ctx, history, item)
			if err != nil {
				return fmt.Errorf("in list item [%d]: %w", index, err)
			}

			switch v := evalValue.(type) {
			case map[string]interface{}:
				for fieldKey, fieldValue := range v {
					resultMap[fieldKey] = fieldValue
				}
			default:
				if len(obj) > 1 {
					return fmt.Errorf("got direct typed value (%T) when more than one outer item exist in list-map", v)
				}

				value = v
			}
		}

		if value == nil {
			value = resultMap
		}
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
func (p *ProfileEngine) maybeEvaluateTypedField(ctx context.Context, history *EvaluationHistory, obj map[string]interface{}) (interface{}, error) {
	sourceRaw, sourcePresent := obj["eval_source"]
	objTypeRaw, objPresent := obj["eval_type"]

	if !sourcePresent && !objPresent {
		// Walk object and see if any of its keys are typed objects.
		for key, value := range obj {
			if subObj, ok := value.(map[string]interface{}); ok {
				ret, err := p.maybeEvaluateTypedField(ctx, history, subObj)
				if err != nil {
					return nil, fmt.Errorf("in map item [%v]: %w", key, err)
				}

				obj[key] = ret
			} else if listObj, ok := value.([]map[string]interface{}); ok {
				var value interface{}
				resultMap := map[string]interface{}{}
				for index, item := range listObj {
					evalValue, err := p.maybeEvaluateTypedField(ctx, history, item)
					if err != nil {
						return nil, fmt.Errorf("in list item [%d]: %w", index, err)
					}

					switch v := evalValue.(type) {
					case map[string]interface{}:
						for fieldKey, fieldValue := range v {
							resultMap[fieldKey] = fieldValue
						}
					default:
						if len(obj) > 1 {
							return nil, fmt.Errorf("got direct typed value (%T) when more than one outer item exist in list-map", v)
						}

						value = v
					}
				}

				if value == nil {
					value = resultMap
				}

				obj[key] = value
			}
		}

		return obj, nil
	}

	if !sourcePresent || !objPresent {
		return nil, errors.New("malformed object; missing either 'eval_type' or 'eval_source'")
	}

	source, ok := sourceRaw.(string)
	if !ok {
		return nil, fmt.Errorf("malformed object; 'eval_source' was of wrong type; expected 'string' got '%T'", sourceRaw)
	}

	objType, ok := objTypeRaw.(string)
	if !ok {
		return nil, fmt.Errorf("malformed object; 'eval_type' was of wrong type; expected 'string' got '%T'", sourceRaw)
	}

	return p.evaluateTypedField(ctx, history, obj, source, objType)
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
