// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package client

import (
	"testing"
)

func TestFieldRegistryEqualityComparisonsWork(t *testing.T) {
	fields := FieldRegistry.List()

	foundDisplayName := false
	foundCommonName := false
	for _, field := range fields {
		if field == FieldRegistry.DisplayName {
			foundDisplayName = true
		}
		if field == FieldRegistry.CommonName {
			foundCommonName = true
		}
	}

	if !foundDisplayName || !foundCommonName {
		t.Fatal("the field registry's equality comparisons are not working")
	}
}

func TestFieldRegistryParsesFieldsByString(t *testing.T) {
	field := FieldRegistry.Parse("ou")
	if field == nil {
		t.Fatal("field not found")
	}
	if field != FieldRegistry.OrganizationalUnit {
		t.Fatal("the field registry is unable to parse registry fields from their string representations")
	}
}
