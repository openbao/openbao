package api

import (
	"os"
	"strings"
)

func ReadBaoVariable(name string) string {
	if !strings.HasPrefix(name, "BAO_") {
		return os.Getenv(name)
	}

	// If the BAO_ version is present but set to the empty string, still
	// prefer that over the VAULT_ prefixed version.
	if baoValue, baoPresent := os.LookupEnv(name); baoPresent {
		return baoValue
	}

	nonPrefixedName := strings.Replace(name, "BAO_", "", 1)
	return os.Getenv("VAULT_" + nonPrefixedName)
}

func LookupBaoVariable(name string) (string, bool) {
	if !strings.HasPrefix(name, "BAO_") {
		return os.LookupEnv(name)
	}

	if baoValue, baoPresent := os.LookupEnv(name); baoPresent {
		return baoValue, baoPresent
	}

	nonPrefixedName := strings.Replace(name, "BAO_", "", 1)
	return os.LookupEnv("VAULT_" + nonPrefixedName)
}
