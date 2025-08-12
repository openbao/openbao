package api

import (
	"os"
	"testing"
)

func TestReadBaoVariable_Vault(t *testing.T) {
	actual := "example_value"
	os.Setenv("VAULT_TEST", actual)
	expected := ReadBaoVariable("BAO_TEST")
	if actual != expected {
		t.Fatalf("bad: Failed to Read Environment Variable actual: %s expected: %s", actual, expected)
	}
}

func TestReadBaoVariable_Bao(t *testing.T) {
	actual := "example_value"
	os.Setenv("BAO_TEST", actual)
	expected := ReadBaoVariable("BAO_TEST")
	if actual != expected {
		t.Fatalf("bad: Failed to Read Environment Variable actual: %s expected: %s", actual, expected)
	}
}

func TestReadBaoVariable_BothSame(t *testing.T) {
	actual := "example_value"
	os.Setenv("VAULT_TEST", actual)
	os.Setenv("BAO_TEST", actual)
	expected := ReadBaoVariable("BAO_TEST")
	if actual != expected {
		t.Fatalf("bad: Failed to Read Environment Variable actual: %s expected: %s", actual, expected)
	}
}

func TestReadBaoVariable_BoaWins(t *testing.T) {
	actual := "example_value"
	os.Setenv("VAULT_TEST", actual+"not_valid")
	os.Setenv("BAO_TEST", actual)
	expected := ReadBaoVariable("BAO_TEST")
	if actual != expected {
		t.Fatalf("bad: Failed to Read Environment Variable actual: %s expected: %s", actual, expected)
	}
}
