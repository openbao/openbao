// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package main // import "github.com/openbao/openbao"

import (
	"os"

	"github.com/openbao/openbao/command"
)

func main() {
	os.Exit(command.Run(os.Args[1:]))
}
