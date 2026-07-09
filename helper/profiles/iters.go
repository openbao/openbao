package profiles

import (
	"context"
	"fmt"

	"github.com/go-viper/mapstructure/v2"
)

// IterValue is the output of indexing the `for` iteration on an OuterBlock
// or request.
type IterValue struct {
	Key   any `json:"key"`
	Value any `json:"value"`
}

// We support at most two levels of nesting (outer block -> request); this
// means we have at most two values of this.
type IterContext struct {
	This  *IterValue `json:"this"`
	Outer *IterValue `json:"outer"`
}

// WithIter takes the existing iteration context and adds a single iterator
// into it, pushing any existing iterator back one.
func WithIter(ic *IterContext, iter *IterValue) *IterContext {
	if iter == nil {
		return ic
	}

	if ic != nil && ic.This != nil {
		return &IterContext{
			This:  iter,
			Outer: ic.This,
		}
	}

	return &IterContext{
		This: iter,
	}
}

func (ic *IterContext) IntoMap(data map[string]interface{}) {
	if ic == nil || ic.This == nil {
		return
	}

	data["this_index"] = ic.This.Key
	data["this"] = ic.This.Value

	if ic.Outer != nil {
		data["outer_this_index"] = ic.Outer.Key
		data["outer_this"] = ic.Outer.Value
	}
}

func (ic *IterContext) MaybeCloneOuter(outer *OuterConfig) *OuterConfig {
	if ic == nil || ic.This == nil {
		return outer
	}

	return outer.CloneWithIter(fmt.Sprintf("%s", ic.This.Key))
}

func (ic *IterContext) MaybeCloneRequest(req *RequestConfig) *RequestConfig {
	if ic == nil || ic.This == nil {
		return req
	}

	return req.CloneWithIter(fmt.Sprintf("%v", ic.This.Key))
}

func (p *ProfileEngine) DoForEach(ctx context.Context, history *EvaluationHistory, ic *IterContext, forEach interface{}, do func(this *IterContext) error) error {
	ics, err := p.evaluateForEach(ctx, history, ic, forEach)
	if err != nil {
		return err
	}

	for index, this := range ics {
		if err := ctx.Err(); err != nil {
			return err
		}

		if err := do(this); err != nil {
			return fmt.Errorf("foreach.[%v]: %w", index, err)
		}
	}

	return nil
}

func generalizeIter(value interface{}) (interface{}, error) {
	var listResult []interface{}
	listErr := mapstructure.WeakDecode(value, &listResult)
	if listErr == nil {
		return listResult, nil
	}

	var mapResult map[interface{}]interface{}
	mapErr := mapstructure.WeakDecode(value, &mapResult)
	if mapErr == nil {
		return mapResult, nil
	}

	return nil, fmt.Errorf("error decoding as list: [%v] / error decoding as map: [%w]", listErr, mapErr)
}

func (p *ProfileEngine) evaluateForEach(ctx context.Context, history *EvaluationHistory, ic *IterContext, forEach interface{}) ([]*IterContext, error) {
	var value interface{}

	if err := p.evaluateField(ctx, history, ic, forEach, &value); err != nil {
		return nil, fmt.Errorf("failed to evaluate `for` block: %w", err)
	}

	if value == nil {
		return []*IterContext{ic}, nil
	}

	// We should have at most a few valid types for value:
	//
	// []interface{}
	// map[interface{}]interface{}
	//
	// But we first need to generalize concrete types to any types.
	iterableValue, err := generalizeIter(value)
	if err != nil {
		return nil, fmt.Errorf("failed to type decode value of type %T: %v", value, err)
	}

	switch typed := iterableValue.(type) {
	case []interface{}:
		result := make([]*IterContext, 0, len(typed))
		for index, subvalue := range typed {
			result = append(result, WithIter(ic, &IterValue{
				Key:   index,
				Value: subvalue,
			}))
		}

		return result, nil
	case map[interface{}]interface{}:
		result := make([]*IterContext, 0, len(typed))
		for index, subvalue := range typed {
			result = append(result, WithIter(ic, &IterValue{
				Key:   index,
				Value: subvalue,
			}))
		}

		return result, nil
	default:
		return nil, fmt.Errorf("unsupported type for output of `for` block: %T", value)
	}
}
