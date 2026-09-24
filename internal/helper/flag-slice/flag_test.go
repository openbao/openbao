// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package sliceflag

import (
	"flag"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStringFlag_implements(t *testing.T) {
	var raw any = new(StringFlag)
	if _, ok := raw.(flag.Value); !ok {
		t.Fatal("StringFlag should be a Value")
	}
}

func TestStringFlagSet(t *testing.T) {
	sv := new(StringFlag)
	err := sv.Set("foo")
	require.NoError(t, err)

	err = sv.Set("bar")
	require.NoError(t, err)

	expected := []string{"foo", "bar"}
	if !reflect.DeepEqual([]string(*sv), expected) {
		t.Fatalf("Bad: %#v", sv)
	}
}
