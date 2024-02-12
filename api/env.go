package api

import (
	"os"
	"strings"
)

func ReadBaoVariable(name string) string {
	nonPrefixedName := strings.Replace(name, "BAO_", "", 1)
	prefixes := [2]string{"BAO_", "VAULT_"}
	for _, prefix := range prefixes {
		searchName := prefix + nonPrefixedName
		result := os.Getenv(searchName)
		if result != "" {
			return result
		}
	}
	return ""
}
