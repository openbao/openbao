// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package hclutil

import (
	"fmt"
	"strings"

	multierror "github.com/hashicorp/go-multierror"
	"github.com/hashicorp/hcl/hcl/ast"
	hclParser "github.com/hashicorp/hcl/hcl/parser"
	jsonParser "github.com/hashicorp/hcl/json/parser"
)

// CheckHCLKeys checks whether the keys in the AST list contains any of the valid keys provided.
func CheckHCLKeys(node ast.Node, valid []string) error {
	var list *ast.ObjectList
	switch n := node.(type) {
	case *ast.ObjectList:
		list = n
	case *ast.ObjectType:
		list = n.List
	default:
		return fmt.Errorf("cannot check HCL keys of type %T", n)
	}

	validMap := make(map[string]struct{}, len(valid))
	for _, v := range valid {
		validMap[v] = struct{}{}
	}

	var result error
	for _, item := range list.Items {
		key := item.Keys[0].Token.Value().(string)
		if _, ok := validMap[key]; !ok {
			result = multierror.Append(result, fmt.Errorf("invalid key %q on line %d", key, item.Assign.Line))
		}
	}

	return result
}

// isJson determines if the input is JSON, i.e if it starts with '{'
func isJson(data []byte) bool {
	// Trim whitespace and check if it starts with '{'
	trimmed := strings.TrimSpace(string(data))
	return strings.HasPrefix(trimmed, "{")
}

// ParseConfig parses HCL or JSON configuration data into an AST.
// It automatically detects the format and uses the appropriate parser.
// For HCL format, it uses ParseDontErrorOnDuplicateKeys to maintain
// backward compatibility with duplicate keys.
func ParseConfig(data []byte) (*ast.File, error) {
	if isJson(data) {
		// JSON format
		return jsonParser.Parse(data)
	} else {
		// HCL format
		return hclParser.ParseDontErrorOnDuplicateKeys(data)
	}
}
