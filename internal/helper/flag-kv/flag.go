// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package kvFlag

import (
	"fmt"
	"strings"
)

// Flag is a flag.Value implementation for parsing user variables
// from the command-line in the format of '-var key=value'.
type Flag map[string]string

func (v *Flag) String() string {
	return ""
}

func (v *Flag) Set(raw string) error {
	before, after, ok := strings.Cut(raw, "=")
	if !ok {
		return fmt.Errorf("no '=' value in arg: %q", raw)
	}

	if *v == nil {
		*v = make(map[string]string)
	}

	key, value := before, after
	(*v)[key] = value
	return nil
}
