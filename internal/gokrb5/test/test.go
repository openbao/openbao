// Package test provides useful resources for the testing of gokrb5.
package test

import (
	"os"
	"testing"
)

// Test enabling environment variable key values.
const (
	IntegrationEnvVar     = "INTEGRATION"
	ADIntegrationEnvVar   = "TESTAD"
	PrivIntegrationEnvVar = "TESTPRIVILEGED"
)

// Integration skips the test unless the integration test environment variable is set.
func Integration(t *testing.T) {
	if os.Getenv(IntegrationEnvVar) != "1" {
		t.Skip("Skipping integration test")
	}
}

// AD skips the test unless the AD test environment variable is set.
func AD(t *testing.T) {
	if os.Getenv(ADIntegrationEnvVar) != "1" {
		t.Skip("Skipping AD integration test")
	}
}

// Privileged skips the test that require local root privilege.
func Privileged(t *testing.T) {
	if os.Getenv(PrivIntegrationEnvVar) != "1" {
		t.Skip("Skipping DNS integration test")
	}
}
