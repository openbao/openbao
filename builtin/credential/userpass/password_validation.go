// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package userpass

import (
	"errors"

	"github.com/openbao/openbao/sdk/v2/framework"
)

// validatePasswordInput checks that exactly one of password or password_hash
// is provided and non-empty. Both present or both absent are rejected as invalid input.
func validatePasswordInput(d *framework.FieldData) error {
	password, hasPassword := d.GetOk("password")
	passwordHash, hasPasswordHash := d.GetOk("password_hash")
	// checking the password exists but is empty
	// so we can reject empty strings
	hasPassword = hasPassword && password.(string) != ""
	hasPasswordHash = hasPasswordHash && passwordHash.(string) != ""

	switch {
	case hasPassword && hasPasswordHash:
		return errors.New("only one of password or password_hash may be provided")
	case !hasPassword && !hasPasswordHash:
		return errors.New("must provide either password or password_hash")
	}

	return nil
}
