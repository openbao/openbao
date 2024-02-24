// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package signals

import (
	"fmt"
	"os"
	"reflect"
	"syscall"
	"testing"

	"github.com/mitchellh/mapstructure"
)

func TestStringToSignalFunc(t *testing.T) {
	f := StringToSignalFunc()
	sigType := reflect.ValueOf(&os.Interrupt).Elem()

	cases := []struct {
		name     string
		f, t     reflect.Value
		expected interface{}
		err      bool
	}{
		{"sigterm", reflect.ValueOf("SIGTERM"), sigType, syscall.SIGTERM, false},
		{"sigint", reflect.ValueOf("SIGINT"), sigType, syscall.SIGINT, false},

		// Invalid signal name
		{"bad", reflect.ValueOf("BACON"), sigType, nil, true},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			actual, err := mapstructure.DecodeHookExec(f, tc.f, tc.t)
			if (err != nil) != tc.err {
				t.Errorf("case %d: %v", i, err)
			}
			if !reflect.DeepEqual(actual, tc.expected) {
				t.Errorf("case %d: expected %#v (%T) to be %#v (%T)",
					i, actual, actual, tc.expected, tc.expected)
			}
		})
	}
}
