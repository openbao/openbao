// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package config

import (
	"github.com/openbao/openbao/command/token"
)

// DefaultTokenHelper returns the token helper that is configured for Vault.
// This helper should only be used for non-server CLI commands.
func DefaultTokenHelper(vaultAddr string) (token.TokenHelper, error) {
	config, err := LoadConfig("")
	if err != nil {
		return nil, err
	}

	path := config.TokenHelper
	if path == "" {
		return token.NewInternalTokenHelper()
	}

	path, err = token.ExternalTokenHelperPath(path)
	if err != nil {
		return nil, err
	}

	// If the user specified the address to connect to on the command line instead
	// of through an environment variable, we propagate the address to the token
	// helper through an environment variable. Otherwise the token helper may
	// read BAO_ADDR and assume a different address than the one we are using.
	env := []string{"BAO_ADDR=" + vaultAddr, "VAULT_ADDR=" + vaultAddr}

	return &token.ExternalTokenHelper{BinaryPath: path, Env: env}, nil
}
