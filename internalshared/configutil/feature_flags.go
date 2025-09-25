// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package configutil

import (
	"errors"
	"fmt"

	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/hcl"
	"github.com/hashicorp/hcl/hcl/ast"
)

// FeatureFlags is a set of toggles to enable or disable experimental features
type FeatureFlags struct {
	FoundKeys  []string     `hcl:",decodedFields"`
	UnusedKeys UnusedKeyMap `hcl:",unusedKeyPositions"`

	DisableStandbyReads bool `hcl:"disable_standby_reads"`
}

func (ff *FeatureFlags) Validate(source string) []ConfigError {
	return ValidateUnusedFields(ff.UnusedKeys, source)
}

func (ff *FeatureFlags) GoString() string {
	return fmt.Sprintf("*%#v", *ff)
}

func parseFeatureFlags(result *SharedConfig, list *ast.ObjectList) error {
	if len(list.Items) > 1 {
		return errors.New("only one 'feature_flags' block is permitted")
	}

	// Get our one item
	item := list.Items[0]

	if err := hcl.DecodeObject(&result.FeatureFlags, item.Val); err != nil {
		return multierror.Prefix(err, "feature_flags:")
	}

	return nil
}
