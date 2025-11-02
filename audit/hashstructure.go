// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"time"

	"github.com/mitchellh/copystructure"
	"github.com/mitchellh/reflectwalk"
	"github.com/openbao/openbao/sdk/v2/helper/salt"
	"github.com/openbao/openbao/sdk/v2/helper/wrapping"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// HashString hashes the given opaque string and returns it
func HashString(salter *salt.Salt, data string) string {
	return salter.GetIdentifiedHMAC(data)
}

// HashAuth returns a hashed copy of the logical.Auth input.
func HashAuth(salter *salt.Salt, in *logical.Auth, HMACAccessor bool) (*logical.Auth, error) {
	if in == nil {
		return nil, nil
	}

	fn := salter.GetIdentifiedHMAC
	auth := *in

	if auth.ClientToken != "" {
		auth.ClientToken = fn(auth.ClientToken)
	}
	if HMACAccessor && auth.Accessor != "" {
		auth.Accessor = fn(auth.Accessor)
	}
	return &auth, nil
}

// HashRequest returns a hashed copy of the logical.Request input.
func HashRequest(salter *salt.Salt, in *logical.Request, HMACAccessor bool, nonHMACDataKeys []string) (*logical.Request, error) {
	if in == nil {
		return nil, nil
	}

	fn := salter.GetIdentifiedHMAC
	req := *in

	if req.Auth != nil {
		cp, err := copystructure.Copy(req.Auth)
		if err != nil {
			return nil, err
		}

		req.Auth, err = HashAuth(salter, cp.(*logical.Auth), HMACAccessor)
		if err != nil {
			return nil, err
		}
	}

	if req.ClientToken != "" {
		req.ClientToken = fn(req.ClientToken)
	}
	if HMACAccessor && req.ClientTokenAccessor != "" {
		req.ClientTokenAccessor = fn(req.ClientTokenAccessor)
	}

	if req.Data != nil {
		reqData, err := getUnmarshaledCopy(req.Data)
		if err != nil {
			return nil, err
		}

		err = hashMap(fn, reqData, nonHMACDataKeys, false)
		if err != nil {
			return nil, err
		}

		req.Data = reqData
	}

	return &req, nil
}

func hashMap(fn func(string) string, data map[string]interface{}, nonHMACDataKeys []string, elideListResponseData bool) error {
	return HashStructure(data, fn, nonHMACDataKeys, elideListResponseData)
}

// HashResponse returns a hashed copy of the logical.Request input.
func HashResponse(
	salter *salt.Salt,
	in *logical.Response,
	HMACAccessor bool,
	nonHMACDataKeys []string,
	elideListResponseData bool,
) (*logical.Response, error) {
	if in == nil {
		return nil, nil
	}

	fn := salter.GetIdentifiedHMAC
	resp := *in

	if resp.Auth != nil {
		cp, err := copystructure.Copy(resp.Auth)
		if err != nil {
			return nil, err
		}

		resp.Auth, err = HashAuth(salter, cp.(*logical.Auth), HMACAccessor)
		if err != nil {
			return nil, err
		}
	}

	if resp.Data != nil {
		respData, err := getUnmarshaledCopy(resp.Data)
		if err != nil {
			return nil, err
		}

		// When we JSON marshal resp.Data into respData, we base64 encode the
		// raw response body. This breaks compatibility with earlier Vault
		// versions, so revert to the direct string form here.
		if b, ok := resp.Data[logical.HTTPRawBody].([]byte); ok {
			respData[logical.HTTPRawBody] = string(b)
		}

		// Processing list response data elision takes place at this point
		// in the code for performance reasons:
		// - take advantage of the deep copy of resp.Data that was going to
		//   be done anyway for hashing
		// - but elide data before potentially spending time hashing it
		if elideListResponseData {
			doElideListResponseData(respData)
		}

		err = hashMap(fn, respData, nonHMACDataKeys, elideListResponseData)
		if err != nil {
			return nil, err
		}
		resp.Data = respData
	}

	if resp.WrapInfo != nil {
		var err error
		resp.WrapInfo, err = HashWrapInfo(salter, resp.WrapInfo, HMACAccessor)
		if err != nil {
			return nil, err
		}
	}

	return &resp, nil
}

// Creates a deep copy of the data by marshalling to and unmarshalling from json.
// This transformation inherently changes all structs to maps, which makes
// each of the structs fields addressable through reflection in the copy,
// (which is now a map).  This will allow us to write into all fields.
func getUnmarshaledCopy(data interface{}) (map[string]interface{}, error) {
	marshaledData, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	unmarshaledCopy := map[string]interface{}{}
	if err := json.Unmarshal(marshaledData, &unmarshaledCopy); err != nil {
		return nil, err
	}
	return unmarshaledCopy, nil
}

// HashWrapInfo returns a hashed copy of the wrapping.ResponseWrapInfo input.
func HashWrapInfo(salter *salt.Salt, in *wrapping.ResponseWrapInfo, HMACAccessor bool) (*wrapping.ResponseWrapInfo, error) {
	if in == nil {
		return nil, nil
	}

	fn := salter.GetIdentifiedHMAC
	wrapinfo := *in

	wrapinfo.Token = fn(wrapinfo.Token)

	if HMACAccessor {
		wrapinfo.Accessor = fn(wrapinfo.Accessor)

		if wrapinfo.WrappedAccessor != "" {
			wrapinfo.WrappedAccessor = fn(wrapinfo.WrappedAccessor)
		}
	}

	return &wrapinfo, nil
}

// HashStructure takes an interface and hashes all the values within
// the structure. Only _values_ are hashed: keys of objects are not.
//
// The interface is walked with the reflectwalk.Walk() method below.
//
// For the HashCallback, see the built-in HashCallbacks below.
func HashStructure(data interface{}, cb HashCallback, ignoredKeys []string, elideListResponseData bool) error {
	walker := &hashWalker{
		Callback:    cb,
		IgnoredKeys: ignoredKeys,
	}
	return reflectwalk.Walk(data, walker)
}

// HashCallback is the callback called for HashStructure to hash
// a value.
type HashCallback func(string) string

// hashWalker implements interfaces for the reflectwalk package
// (github.com/mitchellh/reflectwalk) that can be used to automatically
// replace primitives with a hashed value.
type hashWalker struct {
	// Callback is the function to call with the primitive that is
	// to be hashed. If there is an error, walking will be halted
	// immediately and the error returned.
	Callback HashCallback

	// IgnoreKeys are the keys that wont have the HashCallback applied.
	IgnoredKeys []string

	// MapElem appends the key itself (not the reflect.Value) to key.
	// The last element in key is the most recently entered map key.
	// Since Exit pops the last element of key, only nesting to another
	// structure increases the size of this slice.
	//
	// Key is not updated for non-maps; this allows IgnoredKeys to
	// reference the last map key and ignore intermediate slices.
	key []string

	// Enter appends to loc and exit pops loc. The last element of loc is thus
	// the current location.
	loc []reflectwalk.Location

	// Map and Slice append to cs, Exit pops the last element off cs so length
	// is only impacted by maximum object depth.
	//
	// The last element in cs is the most recently entered map or slice.
	cs []reflect.Value

	// MapElem and SliceElem append to csKey. The last element in csKey is the
	// most recently entered key or slice index. Since Exit pops the last
	// element of csKey, only nesting to another structure increases the size of
	// this slice.
	csKey []reflect.Value
}

func (w *hashWalker) Enter(loc reflectwalk.Location) error {
	switch loc {
	case reflectwalk.Struct:
		return errors.New("unexpected struct remaining in JSON decoded value")
	case reflectwalk.Array:
		return errors.New("unexpected array remaining in JSON decoded value")
	}

	w.loc = append(w.loc, loc)
	return nil
}

func (w *hashWalker) Exit(loc reflectwalk.Location) error {
	w.loc = w.loc[:len(w.loc)-1]

	switch loc {
	case reflectwalk.Map:
		w.cs = w.cs[:len(w.cs)-1]
	case reflectwalk.MapValue:
		w.key = w.key[:len(w.key)-1]
		w.csKey = w.csKey[:len(w.csKey)-1]
	case reflectwalk.Slice:
		w.cs = w.cs[:len(w.cs)-1]
	case reflectwalk.SliceElem:
		w.csKey = w.csKey[:len(w.csKey)-1]
	}

	return nil
}

func (w *hashWalker) Map(m reflect.Value) error {
	w.cs = append(w.cs, m)
	return nil
}

func (w *hashWalker) MapElem(m, k, v reflect.Value) error {
	if k.Type().Kind() != reflect.String {
		return fmt.Errorf("unknown map key type: %v", k.Type().String())
	}

	w.csKey = append(w.csKey, k)
	w.key = append(w.key, k.String())
	return nil
}

func (w *hashWalker) Slice(s reflect.Value) error {
	w.cs = append(w.cs, s)
	return nil
}

func (w *hashWalker) SliceElem(i int, elem reflect.Value) error {
	w.csKey = append(w.csKey, reflect.ValueOf(i))
	return nil
}

// Primitive calls Callback to transform strings in-place, except for map keys.
// Strings hiding within interfaces are also transformed.
func (w *hashWalker) Primitive(v reflect.Value) error {
	if w.Callback == nil {
		return nil
	}

	// We don't touch map keys
	if w.loc[len(w.loc)-1] == reflectwalk.MapKey {
		return nil
	}

	// We only care about strings
	if v.Kind() == reflect.Interface {
		v = v.Elem()
	}
	if v.Kind() != reflect.String {
		return nil
	}

	value := v.String()

	// Marshaling a time in an object will result in a RFC3339 string
	// decodable by UnmarshalText. When this does not return an error,
	// we know we strictly have a valid timestamp and nothing else.
	var t time.Time
	if err := t.UnmarshalText([]byte(value)); err == nil {
		return nil
	}

	// See if the current key is part of the ignored keys; notably, this may
	// be some child ancestor of the current reference. Consider:
	//
	// map[string]interface{}{
	//   "ignored": []string{ "<we-are-here>" },
	// }
	currentKey := w.key[len(w.key)-1]
	if slices.Contains(w.IgnoredKeys, currentKey) {
		return nil
	}

	replacement := w.Callback(value)
	replaceVal := reflect.ValueOf(replacement)

	switch w.loc[len(w.loc)-1] {
	case reflectwalk.MapValue:
		m := w.cs[len(w.cs)-1]
		mk := w.csKey[len(w.cs)-1]
		m.SetMapIndex(mk, replaceVal)
	case reflectwalk.SliceElem:
		s := w.cs[len(w.cs)-1]
		si := int(w.csKey[len(w.cs)-1].Int())
		s.Index(si).Set(replaceVal)
	default:
		return fmt.Errorf("reached HMAC value in object of type %v", w.loc[len(w.loc)-1])
	}

	return nil
}
