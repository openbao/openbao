// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package api

import (
	"testing"
)

func TestReadBaoVariable_Vault(t *testing.T) {
	actual := "example_value"
	t.Setenv("VAULT_TEST", actual)
	expected := ReadBaoVariable("BAO_TEST")
	if actual != expected {
		t.Fatalf("bad: Failed to Read Environment Variable actual: %s expected: %s", actual, expected)
	}
}

func TestReadBaoVariable_Bao(t *testing.T) {
	actual := "example_value"
	t.Setenv("BAO_TEST", actual)
	expected := ReadBaoVariable("BAO_TEST")
	if actual != expected {
		t.Fatalf("bad: Failed to Read Environment Variable actual: %s expected: %s", actual, expected)
	}
}

func TestReadBaoVariable_BothSame(t *testing.T) {
	actual := "example_value"
	t.Setenv("VAULT_TEST", actual)
	t.Setenv("BAO_TEST", actual)
	expected := ReadBaoVariable("BAO_TEST")
	if actual != expected {
		t.Fatalf("bad: Failed to Read Environment Variable actual: %s expected: %s", actual, expected)
	}
}

func TestReadBaoVariable_BaoWins(t *testing.T) {
	actual := "example_value"
	t.Setenv("VAULT_TEST", actual+"not_valid")
	t.Setenv("BAO_TEST", actual)
	expected := ReadBaoVariable("BAO_TEST")
	if actual != expected {
		t.Fatalf("bad: Failed to Read Environment Variable actual: %s expected: %s", actual, expected)
	}
}
