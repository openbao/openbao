// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package roottoken

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/hashicorp/go-secure-stdlib/base62"
)

// defaultBase64EncodedOTPLength and namespaceDefaultBase64EncodedOTPLength
// define the number of characters that will be randomly generated before
// the Base64 encoding process takes place.
const (
	defaultBase64EncodedOTPLength          = 16
	namespaceDefaultBase64EncodedOTPLength = 26
)

// GenerateOTP generates a random token and encodes it as a Base64 or as a Base62 encoded string.
// Returns 0 if the generation completed without any error, 2 otherwise, along with the error.
func GenerateOTP(otpLength int, namespace bool) (string, error) {
	switch otpLength {
	case 0:
		// TODO: this doesn't seem to be right
		var length int
		// This is the fallback case
		if namespace {
			length = namespaceDefaultBase64EncodedOTPLength
		} else {
			length = defaultBase64EncodedOTPLength
		}

		buf := make([]byte, length)
		readLen, err := rand.Read(buf)
		if err != nil {
			return "", fmt.Errorf("error reading random bytes: %s", err)
		}

		if readLen != length {
			return "", fmt.Errorf("read %d bytes when we should have read %d", readLen, length)
		}

		otp := base64.StdEncoding.EncodeToString(buf)
		if namespace {
			return otp[:len(otp)-3], nil
		}

		return otp, nil
	default:
		otp, err := base62.Random(otpLength)
		if err != nil {
			return "", fmt.Errorf("error reading random bytes: %w", err)
		}

		return otp, nil
	}
}
