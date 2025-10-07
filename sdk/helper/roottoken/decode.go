// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package roottoken

import (
	"encoding/base64"
	"fmt"

	"github.com/openbao/openbao/sdk/v2/helper/xor"
)

// DecodeToken will decode the root token returned by the Vault API
// The algorithm was initially used in the generate root command
func DecodeToken(encoded, otp string, otpLength int) (string, error) {
	tokenBytes, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("error decoding base64'd token: %v", err)
	}

	tokenBytes, err = xor.XORBytes(tokenBytes, []byte(otp))
	if err != nil {
		return "", fmt.Errorf("error xoring token: %v", err)
	}
	return string(tokenBytes), nil
}
