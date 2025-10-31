// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"log"
	"os"

	"github.com/openbao/openbao/plugins/database/mysql"
	dbplugin "github.com/openbao/openbao/sdk/v2/database/dbplugin/v5"
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
	dbType, err := mysql.New(mysql.DefaultLegacyUserNameTemplate)()
	if err != nil {
		return err
	}

	dbplugin.Serve(dbType.(dbplugin.Database))

	return nil
}
