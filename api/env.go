package api

import (
	"os"
	"strings"
)

const (
	OpenBaoEnvPrefix  = "BAO_"
	UpstreamEnvPrefix = "VAULT_"
)

func UpstreamVariableName(name string) string {
	if !strings.HasPrefix(name, OpenBaoEnvPrefix) {
		return name
	}

	nonPrefixedName := strings.Replace(name, OpenBaoEnvPrefix, "", 1)
	return UpstreamEnvPrefix + nonPrefixedName
}

func ReadBaoVariable(name string) string {
	if !strings.HasPrefix(name, OpenBaoEnvPrefix) {
		return os.Getenv(name)
	}

	// If the BAO_ version is present but set to the empty string, still
	// prefer that over the VAULT_ prefixed version.
	if baoValue, baoPresent := os.LookupEnv(name); baoPresent {
		return baoValue
	}

	return os.Getenv(UpstreamVariableName(name))
}

func LookupBaoVariable(name string) (string, bool) {
	if !strings.HasPrefix(name, OpenBaoEnvPrefix) {
		return os.LookupEnv(name)
	}

	if baoValue, baoPresent := os.LookupEnv(name); baoPresent {
		return baoValue, baoPresent
	}

	return os.LookupEnv(UpstreamVariableName(name))
}
