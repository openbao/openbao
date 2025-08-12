// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package audit

import (
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strconv"
	"strings"
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
		copy, err := getUnmarshaledCopy(req.Data)
		if err != nil {
			return nil, err
		}

		err = hashMap(fn, req.Data, copy.(map[string]interface{}), nonHMACDataKeys, false)
		if err != nil {
			return nil, err
		}
		req.Data = copy.(map[string]interface{})
	}

	return &req, nil
}

func hashMap(fn func(string) string, origData map[string]interface{}, data map[string]interface{}, nonHMACDataKeys []string, elideListResponseData bool) error {
	return HashStructure(origData, data, fn, nonHMACDataKeys, elideListResponseData)
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
		copy, err := getUnmarshaledCopy(resp.Data)
		if err != nil {
			return nil, err
		}

		mapCopy := copy.(map[string]interface{})
		if b, ok := mapCopy[logical.HTTPRawBody].([]byte); ok {
			mapCopy[logical.HTTPRawBody] = string(b)
		}

		// Processing list response data elision takes place at this point in the code for performance reasons:
		// - take advantage of the deep copy of resp.Data that was going to be done anyway for hashing
		// - but elide data before potentially spending time hashing it
		if elideListResponseData {
			doElideListResponseDataWithCopy(resp.Data, mapCopy)
		}

		err = hashMap(fn, resp.Data, mapCopy, nonHMACDataKeys, elideListResponseData)
		if err != nil {
			return nil, err
		}
		resp.Data = mapCopy
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
func getUnmarshaledCopy(data interface{}) (interface{}, error) {
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
// Note that the function takes both the original data structure and
// an unmarshaled json copy.  The hashed values are written to the copy
// but because the json transform has changed the type info the original
// must also be walked to get that type info.
//
// The original is walked with the reflectwalk.Walk() method below.
// That method leaves a trail in w.loc[]/w.csKey[] which is then used
// by getValueFromCopy() to walk the copy.
//
// For the HashCallback, see the built-in HashCallbacks below.
func HashStructure(original interface{}, copy interface{}, cb HashCallback,
	ignoredKeys []string, elideListResponseData bool,
) error {
	walker := &hashWalker{
		UnmarshalledCopy: copy, Callback: cb,
		IgnoredKeys: ignoredKeys, ElideListResponseData: elideListResponseData,
	}
	return reflectwalk.Walk(original, walker)
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
	// IgnoreKeys are the keys that wont have the HashCallback applied
	IgnoredKeys []string
	// MapElem appends the key itself (not the reflect.Value) to key.
	// The last element in key is the most recently entered map key.
	// Since Exit pops the last element of key, only nesting to another
	// structure increases the size of this slice.
	key       []string
	lastValue reflect.Value
	// Enter appends to loc and exit pops loc. The last element of loc is thus
	// the current location.
	loc []reflectwalk.Location
	// Map, Struct and Slice append to cs, Exit pops the last element off cs.
	// The last element in cs is the most recently entered map or slice.
	cs []reflect.Value
	// MapElem, StructField and SliceElem append to csKey. The last element in csKey is the
	// most recently entered key or slice index. Since Exit pops the last
	// element of csKey, only nesting to another structure increases the size of
	// this slice.
	csKey                 []reflect.Value
	UnmarshalledCopy      interface{}
	ElideListResponseData bool
}

// hashTimeType stores a pre-computed reflect.Type for a time.Time so
// we can quickly compare in hashWalker.Struct. We create an empty/invalid
// time.Time{} so we don't need to incur any additional startup cost vs.
// Now() or Unix().
var hashTimeType = reflect.TypeOf(time.Time{})

func (w *hashWalker) Enter(loc reflectwalk.Location) error {
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
	case reflectwalk.Struct:
		w.cs = w.cs[:len(w.cs)-1]
	case reflectwalk.StructField:
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
	// Json marshalling converts int keys to strings, so
	// we need to handle those here.
	if _, ok := k.Interface().(int); ok {
		kString := strconv.FormatInt(k.Int(), 10)
		w.csKey = append(w.csKey, reflect.ValueOf(kString))
		w.key = append(w.key, kString)
		return nil
	}
	w.csKey = append(w.csKey, k)
	w.key = append(w.key, k.String())
	w.lastValue = v
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

func (w *hashWalker) Struct(v reflect.Value) error {
	// We are looking for time values. If it isn't one, handle it later.
	if v.Type() != hashTimeType {
		w.cs = append(w.cs, v)
		return nil
	}

	if len(w.loc) < 3 {
		// The last element of w.loc is reflectwalk.Struct, by definition.
		// If len(w.loc) < 3 that means hashWalker.Walk was given a struct
		// value and this is the very first step in the walk, and we don't
		// currently support structs as inputs,
		return errors.New("structs as direct inputs not supported")
	}

	// Second to last element of w.loc is location that contains this struct.
	switch w.loc[len(w.loc)-2] {
	case reflectwalk.MapValue:
		// Create a string value of the time. IMPORTANT: this must never change
		// across Vault versions or the hash value of equivalent time.Time will
		// change.
		strVal := v.Interface().(time.Time).Format(time.RFC3339Nano)

		// Set the map value to the string instead of the time.Time object
		m := w.getMapFromCopy()
		mk := w.csKey[len(w.cs)-1].String()
		m[mk] = strVal
	case reflectwalk.SliceElem:
		// Create a string value of the time. IMPORTANT: this must never change
		// across Vault versions or the hash value of equivalent time.Time will
		// change.
		strVal := v.Interface().(time.Time).Format(time.RFC3339Nano)

		// Set the map value to the string instead of the time.Time object
		s := w.getSliceFromCopy()
		si := int(w.csKey[len(w.cs)-1].Int())
		s[si] = strVal
	}

	// Skip this entry so that we don't walk the struct, but
	//  append it to w.cs so that it gets properly handled on
	//  Exit()
	w.cs = append(w.cs, v)
	return reflectwalk.SkipEntry
}

// Update the name of the field if it has a json struct tag
func (w *hashWalker) StructField(s reflect.StructField, v reflect.Value) error {
	if !s.IsExported() {
		return reflectwalk.SkipEntry
	}
	name := s.Name
	if tag := s.Tag.Get("json"); tag != "" {
		parts := strings.Split(tag, ",")
		if parts[0] != "" {
			name = parts[0]
		}
	}
	w.csKey = append(w.csKey, reflect.ValueOf(name))
	w.key = append(w.key, name)
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

	// See if the current key is part of the ignored keys
	currentKey := w.key[len(w.key)-1]
	if slices.Contains(w.IgnoredKeys, currentKey) {
		return nil
	}

	// The copy does not have elided fields so don't
	//  try to overwrite them.
	if w.isElided() {
		return nil
	}

	replaceVal := w.Callback(v.String())

	switch w.loc[len(w.loc)-1] {
	case reflectwalk.MapValue:
		fallthrough
	case reflectwalk.StructField:
		// If we're in a map, then the only way to set a map value is
		// to set it directly.
		m := w.getMapFromCopy()
		mk := w.csKey[len(w.cs)-1].String()
		m[mk] = replaceVal
	case reflectwalk.SliceElem:
		s := w.getSliceFromCopy()
		si := int(w.csKey[len(w.cs)-1].Int())
		s[si] = replaceVal

	default:
		panic("Found unsupported value.")
	}

	return nil
}

// get current value from copy to be written to.
func (w *hashWalker) getValueFromCopy() interface{} {
	size := len(w.cs)
	currentValue := w.UnmarshalledCopy
	startKey := 2  // First key in w.csKey maps to w.loc[2]
	keyFactor := 2 // Each key in w.csKey is every other entry in w.loc
	for i := 0; i < size-1; i++ {
		switch w.loc[startKey+(keyFactor*i)] {
		case reflectwalk.MapValue:
			fallthrough
		case reflectwalk.StructField:
			currentValue = getMap(currentValue)[w.csKey[i].String()]
		case reflectwalk.SliceElem:
			index := w.csKey[i].Int()
			currentValue = getSlice(currentValue)[int(index)]
		default:
			panic("invalid location")
		}
	}
	return currentValue
}

func (w *hashWalker) getMapFromCopy() map[string]interface{} {
	return getMap(w.getValueFromCopy())
}

func getMap(inputData interface{}) map[string]interface{} {
	var value map[string]interface{}
	if v, ok := inputData.(map[string]interface{}); ok {
		value = v
	} else {
		panic("bad map")
	}
	return value
}

func (w *hashWalker) getSliceFromCopy() []interface{} {
	return getSlice(w.getValueFromCopy())
}

func getSlice(inputData interface{}) []interface{} {
	var value []interface{}
	if v, ok := inputData.([]interface{}); ok {
		value = v
	} else {
		panic("bad slice")
	}
	return value
}

// Skip elided data because they don't exist in the
// UnmarshalledCopy.  This code is based on:
// audit.doElideListResponseDataWithCopy()
// if that method changes, this one will have to as well
func (w *hashWalker) isElided() bool {
	if !w.ElideListResponseData {
		return false
	}

	currentLoc := len(w.loc) - 1
	currentCs := len(w.cs) - 1
	currentCsKey := len(w.csKey) - 1

	if currentLoc <= 3 {
		return false
	}

	// Based on audit.doElideListResponseDataWithCopy
	// we are lookinfor a map[string]interface{} which
	// contains a "keys" field of type []string
	// or a "key_info" field of type map[string]interface{}
	if w.loc[currentLoc-3] != reflectwalk.Map ||
		w.loc[currentLoc-2] != reflectwalk.MapValue {
		return false
	}

	m := w.cs[currentCs-1]
	mk := w.csKey[currentCsKey-1]
	k := mk.String()
	v := m.MapIndex(mk)

	// a "keys" field of type []string?
	if w.loc[currentLoc-1] == reflectwalk.Slice &&
		w.loc[currentLoc] == reflectwalk.SliceElem &&
		k == "keys" {
		_, vOk := v.Interface().([]string)
		if vOk {
			return true
		}
	}

	// a "key_info" field of type map[string]interface{} ?
	if w.loc[currentLoc-1] == reflectwalk.Map &&
		w.loc[currentLoc] == reflectwalk.MapValue &&
		k == "key_info" {
		_, vOk := v.Interface().(map[string]interface{})
		if vOk {
			return true
		}
	}

	return false
}
