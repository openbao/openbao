// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package roottoken

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNamespaceBase64OTPGeneration(t *testing.T) {
	token, err := GenerateOTP(0, true)
	assert.Len(t, token, 33)
	assert.Nil(t, err)
}

func TestBase64OTPGeneration(t *testing.T) {
	token, err := GenerateOTP(0, false)
	assert.Len(t, token, 24)
	assert.Nil(t, err)
}

func TestBase62OTPGeneration(t *testing.T) {
	token, err := GenerateOTP(20, false)
	assert.Len(t, token, 20)
	assert.Nil(t, err)
}
