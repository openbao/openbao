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

func (eh *EvaluationHistory) GetRequestField(outerBlock string, requestBlock string, fieldSelector interface{}) (interface{}, error) {
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

func (eh *EvaluationHistory) GetResponseField(outerBlock string, requestBlock string, fieldSelector interface{}) (interface{}, error) {
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

func (eh *EvaluationHistory) getField(obj map[string]interface{}, fieldSelector interface{}) (interface{}, error) {
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
