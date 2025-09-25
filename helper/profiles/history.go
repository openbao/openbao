package profiles

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/openbao/openbao/sdk/v2/logical"
)

// EvaluationHistory is used to build up history around req/resp pairs,
// allowing subsequent requests to reference past context to allow for
// response->request chaining.
//
// This is accessible to sources so that they can in turn expose history
// to their callers.
type EvaluationHistory struct {
	// These maps are multi-dimensional:
	//
	//  - Name of outer block
	//  - Name of request block
	//  - Actual data (usually map string->interface)

	Requests  map[string]map[string]map[string]interface{}
	Responses map[string]map[string]map[string]interface{}
}

func (eh *EvaluationHistory) AddRequest(outerBlock string, requestBlock string, request *logical.Request) error {
	var data map[string]interface{}
	encoded, err := json.Marshal(request)
	if err != nil {
		return err
	}

	if err := json.Unmarshal(encoded, &data); err != nil {
		return err
	}

	return eh.AddRequestData(outerBlock, requestBlock, data)
}

func (eh *EvaluationHistory) AddRequestData(outerBlock string, requestBlock string, request map[string]interface{}) error {
	if eh.Requests == nil {
		eh.Requests = make(map[string]map[string]map[string]interface{})
	}

	return eh.addValue(eh.Requests, outerBlock, requestBlock, request)
}

func (eh *EvaluationHistory) AddResponse(outerBlock string, requestBlock string, response *logical.Response) error {
	var data map[string]interface{}
	encoded, err := json.Marshal(response)
	if err != nil {
		return err
	}

	if err := json.Unmarshal(encoded, &data); err != nil {
		return err
	}

	return eh.AddResponseData(outerBlock, requestBlock, data)
}

func (eh *EvaluationHistory) AddResponseData(outerBlock string, requestBlock string, request map[string]interface{}) error {
	if eh.Responses == nil {
		eh.Responses = make(map[string]map[string]map[string]interface{})
	}

	return eh.addValue(eh.Responses, outerBlock, requestBlock, request)
}

func (eh *EvaluationHistory) addValue(block map[string]map[string]map[string]interface{}, outerBlock string, requestBlock string, value map[string]interface{}) error {
	if block[outerBlock] == nil {
		block[outerBlock] = make(map[string]map[string]interface{})
	}

	if block[outerBlock][requestBlock] != nil {
		err := fmt.Errorf("detected duplicate with same block name (%v)", requestBlock)
		if outerBlock != "" {
			err = fmt.Errorf("in outer block (%v): %w", outerBlock, err)
		}

		return err
	}

	block[outerBlock][requestBlock] = value
	return nil
}

func (eh *EvaluationHistory) GetRequest(outerBlock string, requestBlock string) (map[string]interface{}, error) {
	return eh.getValue(eh.Requests, outerBlock, requestBlock)
}

func (eh *EvaluationHistory) GetResponse(outerBlock string, requestBlock string) (map[string]interface{}, error) {
	return eh.getValue(eh.Responses, outerBlock, requestBlock)
}

func (eh *EvaluationHistory) GetRequestField(outerBlock string, requestBlock string, fieldSelector []interface{}) (interface{}, error) {
	values, err := eh.getValue(eh.Requests, outerBlock, requestBlock)
	if err != nil {
		return nil, err
	}

	val, err := eh.getField(values, fieldSelector)
	if err != nil {
		return nil, fmt.Errorf("error resolving field: %w", err)
	}

	return val, nil
}

func (eh *EvaluationHistory) GetResponseField(outerBlock string, requestBlock string, fieldSelector []interface{}) (interface{}, error) {
	values, err := eh.getValue(eh.Responses, outerBlock, requestBlock)
	if err != nil {
		return nil, err
	}

	val, err := eh.getField(values, fieldSelector)
	if err != nil {
		return nil, fmt.Errorf("error resolving field: %w", err)
	}

	return val, nil
}

func (eh *EvaluationHistory) getValue(block map[string]map[string]map[string]interface{}, outerBlock string, requestBlock string) (map[string]interface{}, error) {
	if block == nil {
		return nil, fmt.Errorf("no values written")
	}

	data, ok := block[outerBlock]
	if !ok {
		return nil, fmt.Errorf("missing outer block '%v'", outerBlock)
	}

	req, ok := data[requestBlock]
	if !ok {
		err := fmt.Errorf("missing inner block '%v'", requestBlock)
		if outerBlock != "" {
			err = fmt.Errorf("in outer block '%v': %w", outerBlock, err)
		}

		return nil, err
	}

	return req, nil
}

// getField operates on the premise that the outer request object is always a
// map; this is true even of list responses as they're contained in a regular
// response map. However, inner items may be lists; in this case, a selector
// of type []interface{} must be used to index arrays.
func (eh *EvaluationHistory) getField(obj interface{}, rawFieldSelector []interface{}) (interface{}, error) {
	for i, rawSelector := range rawFieldSelector {
		switch selector := rawSelector.(type) {
		case string:
			mapBase, ok := obj.(map[string]interface{})
			if !ok {
				return nil, fmt.Errorf("object at depth %d (selector %q) was of wrong type: %T (expected map[string]interface{})", i, selector, obj)
			}

			val, present := mapBase[selector]
			if !present {
				return nil, fmt.Errorf("field %q at depth %v is missing:\n\tavailable keys: %v\n\tobj: %#v", selector, i, presentKeys(mapBase), mapBase)
			}

			if i == len(rawFieldSelector)-1 {
				return val, nil
			}

			obj = val
		case int:
			listBase, ok := obj.([]interface{})
			if !ok {
				return nil, fmt.Errorf("object at depth %d (selector %q) was of wrong type: %T (expected []interface{})", i, selector, obj)
			}

			if selector >= len(listBase) || selector < 0 {
				return nil, fmt.Errorf("selector (%v) out of bounds at depth %v", selector, i)
			}

			val := listBase[selector]

			if i == len(rawFieldSelector)-1 {
				return val, nil
			}

			obj = val
		default:
			return nil, fmt.Errorf("unknown type for selector %T at depth %d; expected int or string", selector, i)
		}
	}

	return nil, errors.New("selector had zero length")
}

func presentKeys(obj map[string]interface{}) []string {
	keys := make([]string, 0, len(obj))
	for key := range obj {
		keys = append(keys, key)
	}
	return keys
}
