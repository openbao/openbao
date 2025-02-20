// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"os"

	hclog "github.com/hashicorp/go-hclog"
	redis "github.com/openbao/openbao/plugins/database/redis"
	dbplugin "github.com/openbao/openbao/sdk/v2/database/dbplugin/v5"
)

func main() {
	err := Run()
	if err != nil {
		logger := hclog.New(&hclog.LoggerOptions{})

		logger.Error("plugin shutting down", "error", err)
		os.Exit(1)
	}
}

// Run instantiates a RedisDB object, and runs the RPC server for the plugin
func Run() error {
	db, err := redis.New()
	if err != nil {
		return err
	}

	dbplugin.Serve(db.(dbplugin.Database))

	return nil
}
