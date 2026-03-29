// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

type Inspectable interface {
	// Returns a record view of a particular subsystem
	GetRecords(tag string) ([]map[string]interface{}, error)
}
