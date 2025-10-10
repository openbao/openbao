// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package audit

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/go-test/deep"

	"github.com/mitchellh/copystructure"
	"github.com/openbao/openbao/sdk/v2/helper/certutil"
	"github.com/openbao/openbao/sdk/v2/helper/salt"
	"github.com/openbao/openbao/sdk/v2/helper/wrapping"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func TestCopy_auth(t *testing.T) {
	// Make a non-pointer one so that it can't be modified directly
	expected := logical.Auth{
		LeaseOptions: logical.LeaseOptions{
			TTL: 1 * time.Hour,
		},

		ClientToken: "foo",
	}
	auth := expected

	// Copy it
	dup, err := copystructure.Copy(&auth)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	// Check equality
	auth2 := dup.(*logical.Auth)
	if !reflect.DeepEqual(*auth2, expected) {
		t.Fatalf("bad:\n\n%#v\n\n%#v", *auth2, expected)
	}
}

func TestCopy_request(t *testing.T) {
	// Make a non-pointer one so that it can't be modified directly
	expected := logical.Request{
		Data: map[string]interface{}{
			"foo": "bar",
		},
		WrapInfo: &logical.RequestWrapInfo{
			TTL: 60 * time.Second,
		},
	}
	arg := expected

	// Copy it
	dup, err := copystructure.Copy(&arg)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	// Check equality
	arg2 := dup.(*logical.Request)
	if !reflect.DeepEqual(*arg2, expected) {
		t.Fatalf("bad:\n\n%#v\n\n%#v", *arg2, expected)
	}
}

func TestCopy_response(t *testing.T) {
	// Make a non-pointer one so that it can't be modified directly
	expected := logical.Response{
		Data: map[string]interface{}{
			"foo": "bar",
		},
		WrapInfo: &wrapping.ResponseWrapInfo{
			TTL:             60,
			Token:           "foo",
			CreationTime:    time.Now(),
			WrappedAccessor: "abcd1234",
		},
	}
	arg := expected

	// Copy it
	dup, err := copystructure.Copy(&arg)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	// Check equality
	arg2 := dup.(*logical.Response)
	if !reflect.DeepEqual(*arg2, expected) {
		t.Fatalf("bad:\n\n%#v\n\n%#v", *arg2, expected)
	}
}

func TestHashString(t *testing.T) {
	inmemStorage := &logical.InmemStorage{}
	err := inmemStorage.Put(context.Background(), &logical.StorageEntry{
		Key:   "salt",
		Value: []byte("foo"),
	})
	if err != nil {
		t.Fatalf("Error storing salt: %s", err)
	}
	localSalt, err := salt.NewSalt(context.Background(), inmemStorage, &salt.Config{
		HMAC:     sha256.New,
		HMACType: "hmac-sha256",
	})
	if err != nil {
		t.Fatalf("Error instantiating salt: %s", err)
	}
	out := HashString(localSalt, "foo")
	if out != "hmac-sha256:08ba357e274f528065766c770a639abf6809b39ccfd37c2a3157c7f51954da0a" {
		t.Fatal("err: HashString output did not match expected")
	}
}

func TestHashAuth(t *testing.T) {
	cases := []struct {
		Input        *logical.Auth
		Output       *logical.Auth
		HMACAccessor bool
	}{
		{
			&logical.Auth{ClientToken: "foo"},
			&logical.Auth{ClientToken: "hmac-sha256:08ba357e274f528065766c770a639abf6809b39ccfd37c2a3157c7f51954da0a"},
			false,
		},
		{
			&logical.Auth{
				LeaseOptions: logical.LeaseOptions{
					TTL: 1 * time.Hour,
				},

				ClientToken: "foo",
			},
			&logical.Auth{
				LeaseOptions: logical.LeaseOptions{
					TTL: 1 * time.Hour,
				},

				ClientToken: "hmac-sha256:08ba357e274f528065766c770a639abf6809b39ccfd37c2a3157c7f51954da0a",
			},
			false,
		},
	}

	inmemStorage := &logical.InmemStorage{}
	err := inmemStorage.Put(context.Background(), &logical.StorageEntry{
		Key:   "salt",
		Value: []byte("foo"),
	})
	if err != nil {
		t.Fatalf("Error storing salt: %s", err)
	}
	localSalt, err := salt.NewSalt(context.Background(), inmemStorage, &salt.Config{
		HMAC:     sha256.New,
		HMACType: "hmac-sha256",
	})
	if err != nil {
		t.Fatalf("Error instantiating salt: %s", err)
	}
	for _, tc := range cases {
		input := fmt.Sprintf("%#v", tc.Input)
		out, err := HashAuth(localSalt, tc.Input, tc.HMACAccessor)
		if err != nil {
			t.Fatalf("err: %s\n\n%s", err, input)
		}
		if !reflect.DeepEqual(out, tc.Output) {
			t.Fatalf("bad:\nInput:\n%s\nOutput:\n%#v\nExpected output:\n%#v", input, out, tc.Output)
		}
	}
}

type testOptMarshaler struct {
	S string
	I int
}

func (o *testOptMarshaler) MarshalJSONWithOptions(options *logical.MarshalOptions) ([]byte, error) {
	return json.Marshal(&testOptMarshaler{S: options.ValueHasher(o.S), I: o.I})
}

var _ logical.OptMarshaler = &testOptMarshaler{}

func TestHashRequest(t *testing.T) {
	cases := []struct {
		Input           *logical.Request
		Output          *logical.Request
		NonHMACDataKeys []string
		HMACAccessor    bool
	}{
		{
			&logical.Request{
				Data: map[string]interface{}{
					"foo":              "bar",
					"baz":              "foobar",
					"private_key_type": certutil.PrivateKeyType("rsa"),
				},
			},
			&logical.Request{
				Data: map[string]interface{}{
					"foo":              "hmac-sha256:f9320baf0249169e73850cd6156ded0106e2bb6ad8cab01b7bbbebe6d1065317",
					"baz":              "foobar",
					"private_key_type": "hmac-sha256:995230dca56fffd310ff591aa404aab52b2abb41703c787cfa829eceb4595bf1",
				},
			},
			[]string{"baz"},
			false,
		},
	}

	inmemStorage := &logical.InmemStorage{}
	err := inmemStorage.Put(context.Background(), &logical.StorageEntry{
		Key:   "salt",
		Value: []byte("foo"),
	})
	if err != nil {
		t.Fatalf("Error storing salt: %s", err)
	}
	localSalt, err := salt.NewSalt(context.Background(), inmemStorage, &salt.Config{
		HMAC:     sha256.New,
		HMACType: "hmac-sha256",
	})
	if err != nil {
		t.Fatalf("Error instantiating salt: %s", err)
	}
	for _, tc := range cases {
		input := fmt.Sprintf("%#v", tc.Input)
		out, err := HashRequest(localSalt, tc.Input, tc.HMACAccessor, tc.NonHMACDataKeys)
		if err != nil {
			t.Fatalf("err: %s\n\n%s", err, input)
		}
		if diff := deep.Equal(out, tc.Output); len(diff) > 0 {
			t.Fatalf("bad:\nInput:\n%s\nDiff:\n%#v", input, diff)
		}
	}
}

func TestHashResponse(t *testing.T) {
	now := time.Now()
	type testTopicPermission struct {
		Write string `json:"write_json"`
		Read  string `json:"read_json"`
	}

	cases := []struct {
		Input           *logical.Response
		Output          *logical.Response
		NonHMACDataKeys []string
		HMACAccessor    bool
	}{
		// Confirm nested struct doesn't generate panic
		{
			&logical.Response{
				Data: map[string]interface{}{
					"foo": testTopicPermission{Write: "bar", Read: "baz"},
				},
				WrapInfo: &wrapping.ResponseWrapInfo{
					TTL:             60,
					Token:           "bar",
					Accessor:        "flimflam",
					CreationTime:    now,
					WrappedAccessor: "bar",
				},
			},
			&logical.Response{
				Data: map[string]interface{}{
					"foo": map[string]interface{}{
						"write_json": "hmac-sha256:f9320baf0249169e73850cd6156ded0106e2bb6ad8cab01b7bbbebe6d1065317",
						"read_json":  "baz",
					},
				},
				WrapInfo: &wrapping.ResponseWrapInfo{
					TTL:             60,
					Token:           "hmac-sha256:f9320baf0249169e73850cd6156ded0106e2bb6ad8cab01b7bbbebe6d1065317",
					Accessor:        "hmac-sha256:7c9c6fe666d0af73b3ebcfbfabe6885015558213208e6635ba104047b22f6390",
					CreationTime:    now,
					WrappedAccessor: "hmac-sha256:f9320baf0249169e73850cd6156ded0106e2bb6ad8cab01b7bbbebe6d1065317",
				},
			},
			[]string{"read_json"},
			true,
		},
		// Confirm int keys are converted to string keys
		{
			&logical.Response{
				Data: map[string]interface{}{
					"foo": map[int]interface{}{
						100: "bar",
					},
				},
				WrapInfo: &wrapping.ResponseWrapInfo{
					TTL:             60,
					Token:           "bar",
					Accessor:        "flimflam",
					CreationTime:    now,
					WrappedAccessor: "bar",
				},
			},
			&logical.Response{
				Data: map[string]interface{}{
					"foo": map[string]interface{}{
						"100": "hmac-sha256:f9320baf0249169e73850cd6156ded0106e2bb6ad8cab01b7bbbebe6d1065317",
					},
				},
				WrapInfo: &wrapping.ResponseWrapInfo{
					TTL:             60,
					Token:           "hmac-sha256:f9320baf0249169e73850cd6156ded0106e2bb6ad8cab01b7bbbebe6d1065317",
					Accessor:        "hmac-sha256:7c9c6fe666d0af73b3ebcfbfabe6885015558213208e6635ba104047b22f6390",
					CreationTime:    now,
					WrappedAccessor: "hmac-sha256:f9320baf0249169e73850cd6156ded0106e2bb6ad8cab01b7bbbebe6d1065317",
				},
			},
			[]string{},
			true,
		},
		{
			&logical.Response{
				Data: map[string]interface{}{
					"foo": "bar",
					"baz": "foobar",
					// Responses can contain time values, so test that with
					// a known fixed value.
					"bar": now,
				},
				WrapInfo: &wrapping.ResponseWrapInfo{
					TTL:             60,
					Token:           "bar",
					Accessor:        "flimflam",
					CreationTime:    now,
					WrappedAccessor: "bar",
				},
			},
			&logical.Response{
				Data: map[string]interface{}{
					"foo": "hmac-sha256:f9320baf0249169e73850cd6156ded0106e2bb6ad8cab01b7bbbebe6d1065317",
					"baz": "foobar",
					"bar": now.Format(time.RFC3339Nano),
				},
				WrapInfo: &wrapping.ResponseWrapInfo{
					TTL:             60,
					Token:           "hmac-sha256:f9320baf0249169e73850cd6156ded0106e2bb6ad8cab01b7bbbebe6d1065317",
					Accessor:        "hmac-sha256:7c9c6fe666d0af73b3ebcfbfabe6885015558213208e6635ba104047b22f6390",
					CreationTime:    now,
					WrappedAccessor: "hmac-sha256:f9320baf0249169e73850cd6156ded0106e2bb6ad8cab01b7bbbebe6d1065317",
				},
			},
			[]string{"baz"},
			true,
		},
	}

	inmemStorage := &logical.InmemStorage{}
	inmemStorage.Put(context.Background(), &logical.StorageEntry{
		Key:   "salt",
		Value: []byte("foo"),
	})
	localSalt, err := salt.NewSalt(context.Background(), inmemStorage, &salt.Config{
		HMAC:     sha256.New,
		HMACType: "hmac-sha256",
	})
	if err != nil {
		t.Fatalf("Error instantiating salt: %s", err)
	}
	for _, tc := range cases {
		input := fmt.Sprintf("%#v", tc.Input)
		out, err := HashResponse(localSalt, tc.Input, tc.HMACAccessor, tc.NonHMACDataKeys, false)
		if err != nil {
			t.Fatalf("err: %s\n\n%s", err, input)
		}
		if diff := deep.Equal(out, tc.Output); len(diff) > 0 {
			t.Fatalf("bad:\nInput:\n%s\nDiff:\n%#v", input, diff)
		}
	}
}

func TestHashWalker(t *testing.T) {
	replaceText := "foo"

	cases := []struct {
		Input  map[string]interface{}
		Output map[string]interface{}
	}{
		{
			map[string]interface{}{
				"hello": "foo",
			},
			map[string]interface{}{
				"hello": replaceText,
			},
		},

		{
			map[string]interface{}{
				"hello": []interface{}{"world"},
			},
			map[string]interface{}{
				"hello": []interface{}{replaceText},
			},
		},
	}

	for _, tc := range cases {
		copy, _ := getUnmarshaledCopy(tc.Input)
		err := HashStructure(tc.Input, copy, func(string) string {
			return replaceText
		}, nil, false)
		if err != nil {
			t.Fatalf("err: %s\n\n%#v", err, tc.Input)
		}
		if !reflect.DeepEqual(copy, tc.Output) {
			t.Fatalf("bad:\n\n%#v\n\n%#v", copy, tc.Output)
		}
	}
}

func TestHashWalker_TimeStructs(t *testing.T) {
	replaceText := "bar"

	now := time.Now()
	cases := []struct {
		Input  map[string]interface{}
		Output map[string]interface{}
	}{
		// Should handle map values of type time.Time.
		{
			map[string]interface{}{
				"hello": now,
			},
			map[string]interface{}{
				"hello": now.Format(time.RFC3339Nano),
			},
		},
		// Should handle slice values of type time.Time.
		{
			map[string]interface{}{
				"hello": []interface{}{"foo", now, "foo2"},
			},
			map[string]interface{}{
				"hello": []interface{}{"foobar", now.Format(time.RFC3339Nano), "foo2bar"},
			},
		},
	}

	for _, tc := range cases {
		copy, _ := getUnmarshaledCopy(tc.Input)
		err := HashStructure(tc.Input, copy, func(s string) string {
			return s + replaceText
		}, nil, false)
		if err != nil {
			t.Fatalf("err: %v\n\n%#v", err, tc.Input)
		}
		if !reflect.DeepEqual(copy, tc.Output) {
			t.Fatalf("bad:\n\n%#v\n\n%#v", copy, tc.Output)
		}
	}
}
