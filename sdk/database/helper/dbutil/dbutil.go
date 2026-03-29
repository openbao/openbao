// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package dbutil

import (
	"errors"
	"fmt"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	ErrEmptyCreationStatement = errors.New("empty creation statements")
	ErrEmptyRotationStatement = errors.New("empty rotation statements")
)

// Query templates a query for us.
func QueryHelper(tpl string, data map[string]string) string {
	for k, v := range data {
		tpl = strings.ReplaceAll(tpl, fmt.Sprintf("{{%s}}", k), v)
	}

	return tpl
}

// Unimplemented returns a gRPC error with the Unimplemented code
func Unimplemented() error {
	return status.Error(codes.Unimplemented, "Not yet implemented")
}
