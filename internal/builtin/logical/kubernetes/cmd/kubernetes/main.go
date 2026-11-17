// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"os"

	"github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/sdk/v2/plugin"
	kubesecrets "github.com/openbao/openbao/v2/internal/builtin/logical/kubernetes"
)

func main() {
	err := plugin.ServeMultiplex(&plugin.ServeOpts{
		BackendFactoryFunc: kubesecrets.Factory,
	})
	if err != nil {
		logger := hclog.New(&hclog.LoggerOptions{})
		logger.Error("plugin shutting down", "error", err)
		os.Exit(1)
	}
}
