// Copyright (c) 2024 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package pki

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/openbao/openbao/api/v2"
	vaulthttp "github.com/openbao/openbao/http"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/vault"

	"github.com/stretchr/testify/require"
)

func TestListCertificatesWithDetails(t *testing.T) {
	t.Parallel()

	// Set up the test cluster
	coreConfig := &vault.CoreConfig{
		LogicalBackends: map[string]logical.Factory{
			"pki": Factory,
		},
		EnableRaw: true,
	}
	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
	})
	cluster.Start()
	defer cluster.Cleanup()
	client := cluster.Cores[0].Client

	// Mount PKI
	err := client.Sys().Mount("pki", &api.MountInput{
		Type: "pki",
		Config: api.MountConfigInput{
			DefaultLeaseTTL: "10m",
			MaxLeaseTTL:     "60m",
		},
	})
	require.NoError(t, err)

	// Generate a root certificate
	RootCN := "Root"
	resp, err := client.Logical().Write("pki/root/generate/internal", map[string]interface{}{
		"ttl":         "40h",
		"common_name": RootCN,
		"key_type":    "rsa",
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotEmpty(t, resp.Data)
	rootCert := parseCert(t, resp.Data["certificate"].(string))

	// Set up a role for issuing certificates
	_, err = client.Logical().Write("pki/roles/test-role", map[string]interface{}{
		"allow_any_name":    true,
		"enforce_hostnames": false,
		"key_type":          "ec",
	})
	require.NoError(t, err)

	// Issue leaf certificate
	leafCN := "example.com"
	altLeafNames := []string{"example.com", "www.example.com", "www.example1.com", "example1.com", "www.example2.com"}
	resp, err = client.Logical().Write("pki/issue/test-role", map[string]interface{}{
		"common_name": leafCN,
		"ttl":         "10m",
		// put > 5 names to check only 5 DNS names are detailed
		"alt_names": strings.Join(altLeafNames, ",") + ",www.example3.com,www.example4.com ",
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotEmpty(t, resp.Data)
	leafCert := parseCert(t, resp.Data["certificate"].(string))

	// Expected certificate details for Root and Leaf certificates
	expectedRootCertDetails := map[string]interface{}{
		"common_name": RootCN,
		"issuer":      "CN=Root",
		"key_type":    "rsa",
		"key_bits":    2048,
		"not_after":   rootCert.NotAfter.Format(time.RFC3339),
		"not_before":  rootCert.NotBefore.Format(time.RFC3339),
		"dns_names":   []string{RootCN},
	}
	expectedLeafCertDetails := map[string]interface{}{
		"common_name": leafCN,
		"issuer":      "CN=Root",
		"key_type":    "ec",
		"key_bits":    256,
		"not_after":   leafCert.NotAfter.Format(time.RFC3339),
		"not_before":  leafCert.NotBefore.Format(time.RFC3339),
		"dns_names":   append([]string{leafCN}, altLeafNames...),
	}

	// List certificates with details
	storageRespDetailed, err := client.Logical().List("pki/certs/detailed/")
	require.NoError(t, err, "unable to retrieve storage contents")
	require.NotNil(t, storageRespDetailed, "expected non-nil storage response, but got nil")
	keyInfo, ok := storageRespDetailed.Data["key_info"].(map[string]interface{})
	require.True(t, ok, "Expected 'key_info' to be a map")

	// Assert certificate details for both root and leaf certificates
	for _, certInfo := range keyInfo {
		certData, ok := certInfo.(map[string]interface{})
		require.True(t, ok, "Expected cert info to be a map")

		// Determine if the certificate is root or leaf based on the common name
		commonName := certData["common_name"].(string)
		switch commonName {
		case RootCN:
			checkCertificateDetails(t, certData, expectedRootCertDetails)
		case leafCN:
			checkCertificateDetails(t, certData, expectedLeafCertDetails)
		default:
			t.Fatalf("Unexpected common name found: %s", commonName)
		}
	}
}

func checkCertificateDetails(t *testing.T, certData, expectedDetails map[string]interface{}) {
	actualDNSNames, ok := certData["dns_names"].([]interface{})
	require.True(t, ok, "Expected dns_names to be a list")

	// Convert actual DNS names to a string slice for comparison
	actualDNSNamesStr := make([]string, len(actualDNSNames))
	for i, name := range actualDNSNames {
		actualDNSNamesStr[i] = name.(string)
	}

	// Check that each expected DNS name is contained within the actual DNS names
	for _, expectedDNSName := range expectedDetails["dns_names"].([]string) {
		require.Contains(t, actualDNSNamesStr, expectedDNSName, "Expected DNS name not found")
	}

	// Convert key_bits to int before checking
	keyBits, err := certData["key_bits"].(json.Number).Int64()
	require.NoError(t, err, "Failed to convert key_bits to int")
	require.Equal(t, expectedDetails["key_bits"], int(keyBits), "Mismatch in key bits")

	// Check the rest of the details match
	require.Equal(t, expectedDetails["common_name"], certData["common_name"], "Mismatch in common name")
	require.Equal(t, expectedDetails["issuer"], certData["issuer"], "Mismatch in issuer")
	require.Equal(t, expectedDetails["key_type"], certData["key_type"], "Mismatch in key type")
	require.Equal(t, expectedDetails["not_after"], certData["not_after"], "Mismatch in not after")
	require.Equal(t, expectedDetails["not_before"], certData["not_before"], "Mismatch in not before")
}
