// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package token

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/helper/homedir"
)

var _ TokenHelper = (*InternalTokenHelper)(nil)

// InternalTokenHelper fulfills the TokenHelper interface when no external
// token-helper is configured, and avoids shelling out
type InternalTokenHelper struct {
	tokenPath string
}

func NewInternalTokenHelper() (*InternalTokenHelper, error) {
	if tokenPath := api.ReadBaoVariable(api.EnvTokenPath); tokenPath != "" {
		return &InternalTokenHelper{tokenPath: tokenPath}, nil
	}
	tokenPath, err := homedir.Expand("~/.vault-token")
	if err != nil {
		return nil, fmt.Errorf("could not expand home directory: %w", err)
	}
	return &InternalTokenHelper{tokenPath: tokenPath}, err
}

func (i *InternalTokenHelper) Path() string {
	return i.tokenPath
}

// Get gets the value of the stored token, if any
func (i *InternalTokenHelper) Get() (value string, err error) {
	f, err := os.Open(i.tokenPath)
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	defer func() {
		err = errors.Join(err, f.Close())
	}()

	buf := bytes.NewBuffer(nil)
	if _, err := io.Copy(buf, f); err != nil {
		return "", err
	}

	return strings.TrimSpace(buf.String()), nil
}

// Store stores the value of the token to the file.  We always overwrite any
// existing file atomically to ensure that ownership and permissions are set
// appropriately.
func (i *InternalTokenHelper) Store(input string) error {
	tmpFile := i.tokenPath + ".tmp"
	f, err := os.OpenFile(tmpFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer os.Remove(tmpFile) //nolint:errcheck // tmp file will have been moved if successful

	_, err = io.WriteString(f, input)
	if err != nil {
		return errors.Join(err, f.Close())
	}
	err = f.Close()
	if err != nil {
		return err
	}

	// We don't have a portable way of verifying that the target file is owned
	// by the correct user. The simplest way of ensuring that is to simply
	// re-write it, and the simplest way to ensure that we don't damage an
	// existing working file due to error is the write-rename pattern.
	return os.Rename(tmpFile, i.tokenPath)
}

// Erase erases the value of the token
func (i *InternalTokenHelper) Erase() error {
	if err := os.Remove(i.tokenPath); err != nil && !os.IsNotExist(err) {
		return err
	}

	return nil
}
