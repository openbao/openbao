// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package server

import (
	"testing"
)

func TestLoadConfigFile_topLevel(t *testing.T) {
	testLoadConfigFile_topLevel(t, nil)
}

func TestLoadConfigFile_json2(t *testing.T) {
	testLoadConfigFile_json2(t, nil)
}
