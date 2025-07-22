// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"github.com/openbao/openbao/tools/codechecker/pkg/gonilnilfunctions"
	"golang.org/x/tools/go/analysis/multichecker"
)

func main() {
	multichecker.Main(gonilnilfunctions.Analyzer)
}
