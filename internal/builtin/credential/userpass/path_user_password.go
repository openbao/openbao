// Copyright (c) HashiCorp, Inc.
// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package userpass

import (
	"context"
	"errors"
	"fmt"

	"golang.org/x/crypto/bcrypt"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func pathUserPassword(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "users/" + framework.GenericNameRegex("username") + "/password$",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixUserpass,
			OperationVerb:   "reset",
			OperationSuffix: "password",
		},

		Fields: map[string]*framework.FieldSchema{
			"username": {
				Type:        framework.TypeString,
				Description: "Username for this user.",
			},

			"password": {
				Type:        framework.TypeString,
				Description: "Password for this user.",
				DisplayAttrs: &framework.DisplayAttributes{
					Sensitive: true,
				},
			},

			"password_hash": {
				Type:        framework.TypeString,
				Description: "Pre-hashed bcrypt password for this user. Mutually exclusive with password.",
				DisplayAttrs: &framework.DisplayAttributes{
					Sensitive: true,
				},
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathUserPasswordUpdate,
			},
		},

		HelpSynopsis:    pathUserPasswordHelpSyn,
		HelpDescription: pathUserPasswordHelpDesc,
	}
}

func (b *backend) pathUserPasswordUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	txRollback, err := logical.StartTxStorage(ctx, req)
	if err != nil {
		return nil, err
	}
	defer txRollback()

	username := d.Get("username").(string)
	userEntry, err := b.user(ctx, req.Storage, username)
	if err != nil {
		return nil, err
	}
	if userEntry == nil {
		return nil, errors.New("username does not exist")
	}

	password := d.Get("password").(string)
	passwordHash := d.Get("password_hash").(string)

	userErr, intErr := b.updateUserPassword(password, passwordHash, userEntry)
	if intErr != nil {
		return nil, intErr
	}
	if userErr != nil {
		return logical.ErrorResponse(userErr.Error()), logical.ErrInvalidRequest
	}

	if err := b.setUser(ctx, req.Storage, username, userEntry); err != nil {
		return nil, err
	}

	if err := logical.EndTxStorage(ctx, req); err != nil {
		return nil, err
	}

	return nil, nil
}

// validatePasswordInput checks that exactly one of password or passwordHash
// is provided and non-empty. Both present or both absent are rejected.
func validatePasswordInput(password, passwordHash string) error {
	hasPassword := password != ""
	hasPasswordHash := passwordHash != ""

	switch {
	case hasPassword && hasPasswordHash:
		return errors.New("only one of password or password_hash may be provided")
	case !hasPassword && !hasPasswordHash:
		return errors.New("must provide either password or password_hash")
	}

	return nil
}

// updateUserPassword sets PasswordHash on userEntry from either a plaintext
// password hashed with bcrypt, or a pre-hashed bcrypt string stored directly.
func (b *backend) updateUserPassword(password, passwordHash string, userEntry *UserEntry) (error, error) {
	if err := validatePasswordInput(password, passwordHash); err != nil {
		return err, nil
	}

	const (
		// minCost is the minimum bcrypt cost enforced when passing a pre-hashed
		// password to avoid accidentally setting a weakly hashed password. 5 is
		// picked as the lower bound as this is the default in `htpasswd -B`.
		minCost = 5

		// maxCost is the maximum bcrypt cost accepted when passing a pre-hashed
		// password to avoid DoS. Notably, bcrypt.DefaultCost is 10, we pick 12
		// to allow for some leeway. If this is insufficient, open an issue and
		// suggest a configuration path.
		maxCost = 12
	)

	if password != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			return nil, err
		}
		userEntry.PasswordHash = hash
	} else {
		cost, err := bcrypt.Cost([]byte(passwordHash))
		switch {
		case err != nil:
			return errors.New("password_hash is not a valid bcrypt hash"), nil
		case cost < minCost:
			return fmt.Errorf("bcrypt cost of %d is too low, want %d at minimum", cost, minCost), nil
		case cost > maxCost:
			return fmt.Errorf("bcrypt cost of %d exceeds maximum cost of %d", cost, maxCost), nil
		}
		userEntry.PasswordHash = []byte(passwordHash)
	}

	return nil, nil
}

const pathUserPasswordHelpSyn = `
Reset user's password.
`

const pathUserPasswordHelpDesc = `
This endpoint allows resetting the user's password by providing either
a plaintext password (which will be hashed with bcrypt) or a pre-hashed
bcrypt string via password_hash. One of two must be provided, but not both.
`
