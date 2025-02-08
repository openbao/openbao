// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package cryptoutil

import "testing"

func TestBlake2b256Hash(t *testing.T) {
	hashVal := Blake2b256Hash("sampletext")

	if string(hashVal) == "" || string(hashVal) == "sampletext" {
		t.Fatal("failed to hash the text")
	}
}
