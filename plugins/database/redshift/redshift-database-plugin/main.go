// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"log"
	"os"

	"github.com/openbao/openbao/plugins/database/redshift"
	"github.com/openbao/openbao/sdk/database/dbplugin/v5"
)

func main() {
	if err := Run(); err != nil {
		log.Println(err)
		os.Exit(1)
	}
}

// Run instantiates a RedShift object, and runs the RPC server for the plugin
func Run() error {
	dbplugin.ServeMultiplex(redshift.New)

	return nil
}
