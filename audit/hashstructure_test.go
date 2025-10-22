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
		{
			&logical.Response{
				Data: map[string]interface{}{
					"foo": map[string]interface{}{
						"first": testTopicPermission{Write: "bar", Read: "baz"},
						"second": map[string]interface{}{
							"nested": testTopicPermission{Write: "war", Read: "waz"},
						},
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
						"first": map[string]interface{}{
							"write_json": "bar",
							"read_json":  "hmac-sha256:57fe23dcea29b442ce536b9486b53999513079c8850b2c4ac83bb48529a00bfe",
						},
						"second": map[string]interface{}{
							"nested": map[string]interface{}{
								"write_json": "war",
								"read_json":  "hmac-sha256:5c69f2a46b323680e94d5a0f50b3347a5dfeb8382db7ff38dfaae1516f8a142c",
							},
						},
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
			[]string{"write_json"},
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
		{
			&logical.Response{
				Data: map[string]interface{}{
					"key_info": map[string]interface{}{
						"random_string": map[string]interface{}{
							"name":                "test",
							"num_member_entities": 0,
							"num_parent_groups":   0,
							"deeply_nested_map": map[string]interface{}{
								"random_array": []string{"item", "another_item"},
							},
						},
					},
					"keys": "random_string",
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
					"key_info": map[string]interface{}{
						"random_string": map[string]interface{}{
							"deeply_nested_map": map[string]interface{}{
								"random_array": []interface{}{
									"hmac-sha256:5a4325952fec282c8dbfd0242cca5d018a210bb629e9ebc9278f58b5f4d73db1",
									"hmac-sha256:0176bac06c07b7ccb59bda70be3cf50f5560d25328bf8043796d24be71177d2d",
								},
							},
							"name":                "hmac-sha256:3a5c1437614283a4c557670f3196c56d34dbc5109f2bf3db73e631cb1370a4e2",
							"num_member_entities": float64(0),
							"num_parent_groups":   float64(0),
						},
					},
					"keys": "hmac-sha256:c735e47de746c4b6607851f5aa107ebac9c53d8af0c807009c150672d6388609",
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
					logical.HTTPRawBody: []byte("Response"),
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
					logical.HTTPRawBody: "hmac-sha256:cf0faf58d6106e1f46cdfaf93353ae0fe08b21948de64a402ae9b77dbd9b07d1",
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
			t.Fatalf("bad:\nOutput:\n%#v\nExpected:\n%#v\nDiff:\n%#v", tc.Output, out, diff)
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
		data, _ := getUnmarshaledCopy(tc.Input)
		err := HashStructure(data, func(string) string {
			return replaceText
		}, nil, false)
		if err != nil {
			t.Fatalf("err: %s\n\n%#v", err, tc.Input)
		}
		if !reflect.DeepEqual(data, tc.Output) {
			t.Fatalf("bad:\n\n%#v\n\n%#v", data, tc.Output)
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
		data, _ := getUnmarshaledCopy(tc.Input)
		err := HashStructure(data, func(s string) string {
			return s + replaceText
		}, nil, false)
		if err != nil {
			t.Fatalf("err: %v\n\n%#v", err, tc.Input)
		}
		if !reflect.DeepEqual(data, tc.Output) {
			t.Fatalf("bad:\n\n%#v\n\n%#v", data, tc.Output)
		}
	}
}
