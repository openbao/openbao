package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"github.com/hashicorp/hcl"
	"github.com/hashicorp/hcl/hcl/ast"
	"github.com/openbao/openbao/internalshared/configutil"
)

// InitializationContext is used to build up history around req/resp pairs,
// allowing subsequent requests to reference past context to allow for a
// form of request chaining.
type InitializationContext struct {
	// These maps are multi-dimensional:
	//  - Name of initialization block
	//  - Name of request block
	//  - Actual data (usually map string->interface)

	Requests  map[string]map[string]map[string]interface{}
	Responses map[string]map[string]map[string]interface{}
}

func (ic *InitializationContext) AddRequest(initBlock string, requestBlock string, request map[string]interface{}) error {
	if ic.Requests == nil {
		ic.Requests = make(map[string]map[string]map[string]interface{})
	}
	if ic.Requests[initBlock] == nil {
		ic.Requests[initBlock] = make(map[string]map[string]interface{})
	}
	if ic.Requests[initBlock][requestBlock] != nil {
		return fmt.Errorf("existing request with same initialize (%v) and request (%v) block names", initBlock, requestBlock)
	}

	ic.Requests[initBlock][requestBlock] = request
	return nil
}

func (ic *InitializationContext) AddResponse(initBlock string, responseBlock string, response map[string]interface{}) error {
	if ic.Responses == nil {
		ic.Responses = make(map[string]map[string]map[string]interface{})
	}
	if ic.Responses[initBlock] == nil {
		ic.Responses[initBlock] = make(map[string]map[string]interface{})
	}
	if ic.Responses[initBlock][responseBlock] != nil {
		return fmt.Errorf("existing response with same initialize (%v) and response (%v) block names", initBlock, responseBlock)
	}

	ic.Responses[initBlock][responseBlock] = response
	return nil
}

func (ic *InitializationContext) GetRequest(initBlock string, requestBlock string, fieldSelector interface{}) (interface{}, error) {
	init, ok := ic.Requests[initBlock]
	if !ok {
		return nil, fmt.Errorf("missing initialize block '%v'", initBlock)
	}

	req, ok := init[requestBlock]
	if !ok {
		return nil, fmt.Errorf("missing request block '%v' inside initialize block '%v'", requestBlock, initBlock)
	}

	val, err := ic.getField(req, fieldSelector)
	if err != nil {
		return nil, fmt.Errorf("error resolving field; %w", err)
	}

	return val, nil
}

func (ic *InitializationContext) GetResponse(initBlock string, responseBlock string, fieldSelector interface{}) (interface{}, error) {
	init, ok := ic.Responses[initBlock]
	if !ok {
		return nil, fmt.Errorf("missing initialize block '%v'", initBlock)
	}

	req, ok := init[responseBlock]
	if !ok {
		return nil, fmt.Errorf("missing response block '%v' inside initialize block '%v'", responseBlock, initBlock)
	}

	val, err := ic.getField(req, fieldSelector)
	if err != nil {
		return nil, fmt.Errorf("error resolving field; %w", err)
	}

	return val, nil
}

func (ic *InitializationContext) getField(obj map[string]interface{}, fieldSelector interface{}) (interface{}, error) {
	switch typed := fieldSelector.(type) {
	case string:
		val, present := obj[typed]
		if !present {
			return nil, fmt.Errorf("field '%v' is missing", typed)
		}

		return val, nil
	case []string:
		for i, selector := range typed {
			val, present := obj[selector]
			if !present {
				return nil, fmt.Errorf("field '%v' at depth %v is missing", selector, i)
			}

			if i == len(typed)-1 {
				return val, nil
			}

			obj, present = val.(map[string]interface{})
			if !present {
				return nil, errors.New("object did not have sufficient depth for selector")
			}
		}

		return nil, errors.New("selector had zero length")
	default:
		return nil, fmt.Errorf("unknown type for selector: %T", fieldSelector)
	}
}

func (ic *InitializationContext) Evaluate(obj map[string]interface{}) (interface{}, error) {
	var err error
	source, sourcePresent := obj["eval_source"]
	objType, objPresent := obj["eval_type"]

	if !sourcePresent && !objPresent {
		// Walk object and see if any of its keys are typed objects.
		for key, value := range obj {
			if subObj, ok := value.(map[string]interface{}); ok {
				ret, err := ic.Evaluate(subObj)
				if err != nil {
					return nil, fmt.Errorf("[%v]: %w", key, err)
				}
				obj[key] = ret
			} else if listObj, ok := value.([]map[string]interface{}); ok {
				// If we have a single item, which satisfies the above, then
				// swap.
				if len(listObj) == 1 {
					subObj := listObj[0]
					_, sourcePresent := subObj["eval_source"]
					_, objPresent := subObj["eval_type"]
					if sourcePresent || objPresent {
						ret, err := ic.Evaluate(subObj)
						if err != nil {
							return nil, fmt.Errorf("[%v]: %w", key, err)
						}
						obj[key] = ret
					}
				}
			}
		}

		return obj, nil
	}

	if !sourcePresent || !objPresent {
		return nil, errors.New("malformed object; missing either 'eval_type' or 'eval_source'")
	}

	var val interface{}

	switch source {
	case "env":
		varName, present := obj["env_var"]
		if !present {
			return nil, errors.New("environment object is missing required field 'env_var'")
		}

		val, present = os.LookupEnv(varName.(string))
		if !present {
			return nil, fmt.Errorf("environment variable %v is not defined", varName)
		}
	case "file":
		path, present := obj["path"]
		if !present {
			return nil, errors.New("file object is missing required field 'path'")
		}

		val, err = os.ReadFile(path.(string))
		if err != nil {
			return nil, fmt.Errorf("failed reading file '%v': %w", path, err)
		}
	case "request":
		initName, present := obj["init_name"]
		if !present {
			return nil, errors.New("request object is missing required field 'init_name'")
		}

		requestName, present := obj["req_name"]
		if !present {
			return nil, errors.New("request object is missing required field 'req_name'")
		}

		fieldName, present := obj["field_selector"]
		if !present {
			return nil, errors.New("request object is missing required field 'field_selector'")
		}

		val, err = ic.GetRequest(initName.(string), requestName.(string), fieldName)
		if err != nil {
			return nil, fmt.Errorf("failed evaluating request object: %w", err)
		}
	case "response":
		initName, present := obj["init_name"]
		if !present {
			return nil, errors.New("response object is missing required field 'init_name'")
		}

		responseName, present := obj["req_name"]
		if !present {
			return nil, errors.New("response object is missing required field 'req_name'")
		}

		fieldName, present := obj["field_selector"]
		if !present {
			return nil, errors.New("response object is missing required field 'field_selector'")
		}

		val, err = ic.GetResponse(initName.(string), responseName.(string), fieldName)
		if err != nil {
			return nil, fmt.Errorf("failed evaluating response object: %w", err)
		}
	default:
		return nil, fmt.Errorf("unknown source: %v", source)
	}

	switch objType {
	case "string":
		// Coerce byte arrays automatically.
		if _, ok := val.([]byte); ok {
			val = string(val.([]byte))
		}

		// Otherwise enforce output is a string.
		if _, ok := val.(string); !ok {
			return nil, fmt.Errorf("expected output to be string but got %T", val)
		}
	case "int":
		val, err = parseutil.ParseInt(val)
		if err != nil {
			return nil, fmt.Errorf("failed to coerce output to string: %v", err)
		}
	default:
		return nil, fmt.Errorf("unknown type: %v", objType)
	}

	return val, nil
}

// Initialize is a configuration section that helps to initialize OpenBao. It
// contains various requests which occur in order, potentially chaining
// values from previous steps. When present, this runs after a call to
// sys/init with the root token for authentication unless overridden.
// At the end of all initialization steps, the root token is revoked.
type Initialize struct {
	UnusedKeys configutil.UnusedKeyMap `hcl:",unusedKeyPositions"`
	RawConfig  map[string]interface{}

	Type     string
	Requests []*InitializationRequest `hcl:"-"`
}

// InitializationRequest performs a single privileged API request, usually
// using the root token but optionally using some other token if desired.
type InitializationRequest struct {
	UnusedKeys configutil.UnusedKeyMap `hcl:",unusedKeyPositions"`
	RawConfig  map[string]interface{}

	Type string

	Operation string `hcl:"operation"`
	Path      string `hcl:"path"`

	TokenRaw interface{} `hcl:"token"`

	DataRaw interface{} `hcl:"data"`
}

func (ir *InitializationRequest) GetToken(root string, history InitializationContext) (string, error) {
	if ir.TokenRaw == nil {
		return root, nil
	}

	switch typed := ir.TokenRaw.(type) {
	case string:
		return typed, nil
	case []map[string]interface{}:
		if len(typed) == 0 {
			return root, nil
		}

		if len(typed) > 1 {
			return "", fmt.Errorf("got more than one entry for token: %v", ir.TokenRaw)
		}

		token, err := history.Evaluate(typed[0])
		if err != nil {
			return "", fmt.Errorf("error evaluating object: %w", err)
		}

		return token.(string), nil
	case map[string]interface{}:
		obj, err := history.Evaluate(typed)
		if err != nil {
			return nil, fmt.Errorf("error evaluating object: %w", err)
		}

		return obj.(map[string]interface{}), nil
	default:
		return "", fmt.Errorf("unknown type for field token: %T", ir.TokenRaw)
	}
}

func (ir *InitializationRequest) GetData(history InitializationContext) (map[string]interface{}, error) {
	switch typed := ir.DataRaw.(type) {
	case string:
		var result map[string]interface{}
		if err := json.Unmarshal([]byte(typed), &result); err != nil {
			return nil, fmt.Errorf("failed to unmarshal body: %w", err)
		}

		return result, nil
	case []map[string]interface{}:
		ret := make(map[string]interface{})
		for index, item := range typed {
			obj, err := history.Evaluate(item)
			if err != nil {
				return nil, fmt.Errorf("error evaluating object %d: %w", index, err)
			}

			for key, value := range obj.(map[string]interface{}) {
				ret[key] = value
			}
		}

		return ret, nil
	case map[string]interface{}:
		obj, err := history.Evaluate(typed)
		if err != nil {
			return nil, fmt.Errorf("error evaluating object: %w", err)
		}

		return obj.(map[string]interface{}), nil
	default:
		return nil, fmt.Errorf("unknown type for field data: %T", ir.TokenRaw)
	}
}

func parseInitialization(result *Config, list *ast.ObjectList) error {
	result.Initialization = make([]*Initialize, 0, len(list.Items))
	for index, item := range list.Items {
		var i Initialize
		if err := hcl.DecodeObject(&i, item.Val); err != nil {
			return fmt.Errorf("initialize.%d: %w", index, err)
		}

		var m map[string]interface{}
		if err := hcl.DecodeObject(&m, item.Val); err != nil {
			return fmt.Errorf("initialize.%d: %w", index, err)
		}
		i.RawConfig = m

		switch {
		case i.Type != "":
		case len(item.Keys) == 1:
			i.Type = item.Keys[0].Token.Value().(string)
		default:
			return fmt.Errorf("initialize.%d: initialize type must be specified", index)
		}

		objT, ok := item.Val.(*ast.ObjectType)
		if !ok {
			return fmt.Errorf("error parsing initialization: does not contain a root object (was of type %T)", item.Val)
		}

		list := objT.List

		if o := list.Filter("request"); len(o.Items) > 0 {
			if err := parseInitializationRequest(&i, o); err != nil {
				return fmt.Errorf("initialize.%d: error parsing 'request': %w", index, err)
			}
		}

		result.Initialization = append(result.Initialization, &i)
	}

	return nil
}

func parseInitializationRequest(result *Initialize, list *ast.ObjectList) error {
	result.Requests = make([]*InitializationRequest, 0, len(list.Items))
	for i, item := range list.Items {
		var r InitializationRequest
		if err := hcl.DecodeObject(&r, item.Val); err != nil {
			return fmt.Errorf("request.%d: %w", i, err)
		}

		var m map[string]interface{}
		if err := hcl.DecodeObject(&m, item.Val); err != nil {
			return fmt.Errorf("request.%d: %w", i, err)
		}
		r.RawConfig = m

		switch {
		case r.Type != "":
		case len(item.Keys) == 1:
			r.Type = item.Keys[0].Token.Value().(string)
		default:
			return fmt.Errorf("request.%d: initialize type must be specified", i)
		}

		result.Requests = append(result.Requests, &r)
	}

	return nil
}
