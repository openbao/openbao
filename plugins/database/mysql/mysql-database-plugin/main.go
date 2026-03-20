// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"log"
	"os"

	"github.com/openbao/openbao/plugins/database/mysql"
	"github.com/openbao/openbao/sdk/v2/database/dbplugin/v5"
)

func main() {
	err := Run()
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
}

// Run instantiates a MySQL object, and runs the RPC server for the plugin
func Run() error {
	dbplugin.ServeMultiplex(mysql.New(mysql.DefaultUserNameTemplate))

	return nil
}
