// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package config

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const FixturePath = "../test-fixtures"

func TestLoadConfig(t *testing.T) {
	config, err := LoadConfig(filepath.Join(FixturePath, "config.hcl"))
	require.NoError(t, err)

	expected := &DefaultConfig{
		TokenHelper: "foo",
	}
	if !reflect.DeepEqual(expected, config) {
		t.Fatalf("bad: %#v", config)
	}
}

func TestLoadConfig_noExist(t *testing.T) {
	config, err := LoadConfig("nope/not-once/.never")
	require.NoError(t, err)

	if config.TokenHelper != "" {
		t.Errorf("expected %q to be %q", config.TokenHelper, "")
	}
}

func TestParseConfig_badKeys(t *testing.T) {
	_, err := ParseConfig(`
token_helper = "/token"
nope = "true"
`)
	if err == nil {
		t.Fatal("expected error")
	}

	if !strings.Contains(err.Error(), `invalid key "nope" on line 3`) {
		t.Errorf("bad error: %s", err.Error())
	}
}
