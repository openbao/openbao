package transit

import (
	"context"
	cryptoRand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/builtin/logical/pki"
	vaulthttp "github.com/openbao/openbao/http"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/vault"
	"github.com/stretchr/testify/require"
)

const (
	templateCSR = `
-----BEGIN CERTIFICATE REQUEST-----
MIIC5zCCAc8CAQAwaDELMAkGA1UEBhMCVVMxDjAMBgNVBAgMBVN0YXRlMQ0wCwYD
VQQHDARDaXR5MRUwEwYDVQQKDAxPcmdhbml6YXRpb24xDTALBgNVBAsMBFVuaXQx
FDASBgNVBAMMC2V4YW1wbGUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEAtqoiFEAdvKtBe5LdhPXddsQBGfq2wU7oLRjg85ow6TeDFCP4X/QvKWqk
/oaZuy7RENQ8rZZML5XN1zlwRyxyqYUoIwLJrvZUHKyBVDp7axQ4X6RzSl++A6KI
vlMAiOzn0ByaI/qrTzpMvKyn/Y2AaIM0SdSczVBczmcfrthYikzWzphvYFqsCTRn
01E1hBiqk5/JoaFgljzQp7Xv+fl3E0grnuLPjc1p6gDJDG/5QNIQt144ahwt8you
rpryjYmRWlFX0UhK5X4aywLGtGP8pEZcxmMvslziqeKt1YfzYcI0zsWkOeLXtjVd
pkBT9r2tz/Df6d5+RtmtNrketXN1AQIDAQABoDowOAYJKoZIhvcNAQkOMSswKTAn
BgNVHREEIDAeggtleGFtcGxlLmNvbYIPd3d3LmV4YW1wbGUuY29tMA0GCSqGSIb3
DQEBCwUAA4IBAQAmGyhKkDbTs156EiXhXUim8/eoB5+Gp+2lldNhh3/jUqj487CG
vR0ArKx2xGBQNwBOR5Z+rMRh5Xg+OQaK7uMeQM0El4hW4VL4GEXRbqrAy1ixYk9s
hvZTQD5XGxkJM0ffKsyxk5t/tQWcCDPWwoBv+R5ikkABFzCcwRq+IHvOUxB59cgC
VldIH29XCpF71qiIbpg9Y+LJI9skdE3x/Ufa9h9Z8ioHhPu1xXCaKKjaZ3lv8t1+
9iWpATejh7Av9o/8y+vpRN8vrxNcprbj0ItJ5jcg6pnA7DEqW7QNIKYtWg2YjKBd
Bgw5bMA6qRI09cxO4pN2diD2KYI+YuioXtYl
-----END CERTIFICATE REQUEST-----
`
)

func TestTransit_Certificates_CreateCSR(t *testing.T) {
	t.Parallel()

	testTransit_Certificates_CreateCSR(t, "rsa-2048", templateCSR)
	testTransit_Certificates_CreateCSR(t, "rsa-3072", templateCSR)
	testTransit_Certificates_CreateCSR(t, "rsa-4096", templateCSR)
	testTransit_Certificates_CreateCSR(t, "ecdsa-p256", templateCSR)
	testTransit_Certificates_CreateCSR(t, "ecdsa-p384", templateCSR)
	testTransit_Certificates_CreateCSR(t, "ecdsa-p521", templateCSR)
	testTransit_Certificates_CreateCSR(t, "ed25519", templateCSR)
	testTransit_Certificates_CreateCSR(t, "aes256-gcm96", templateCSR)
}

func testTransit_Certificates_CreateCSR(t *testing.T, keyType string, pemTemplateCSR string) {
	keyName := "test-key"
	var resp *logical.Response
	var err error
	b, s := createBackendWithStorage(t)

	// create a policy
	policyReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      fmt.Sprintf("keys/%s", keyName),
		Storage:   s,
		Data: map[string]interface{}{
			"type": keyType,
		},
	}

	// request creation of key
	resp, err = b.HandleRequest(context.Background(), policyReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("resp: %#v\nerr:%v", resp, err)
	}

	csrSignReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      fmt.Sprintf("keys/%s/csr", keyName),
		Storage:   s,
		Data: map[string]interface{}{
			"csr": pemTemplateCSR,
		},
	}

	// request the CSR
	resp, err = b.HandleRequest(context.Background(), csrSignReq)
	switch keyType {
	case "rsa-2048", "rsa-3072", "rsa-4096", "ecdsa-p256", "ecdsa-p384", "ecdsa-p521", "ed25519":
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("failed to sign CSR, err:%v resp:%#v", err, resp)
		}

		signedCSRBytes, ok := resp.Data["csr"]
		if !ok {
			t.Fatal("expected response data to hold a 'csr' key")
		}

		signedCSR, err := parseCSR(signedCSRBytes.(string))
		if err != nil {
			t.Fatalf("failed to parse returned CSR, err:%v", err)
		}

		templateCSR, err := parseCSR(pemTemplateCSR)
		if err != nil {
			t.Fatalf("failed to parse returned template CSR, err:%v", err)
		}

		if !reflect.DeepEqual(signedCSR.Subject, templateCSR.Subject) {
			t.Fatal("CSR subjects should have matched")
		}

		if !reflect.DeepEqual(signedCSR.DNSNames, templateCSR.DNSNames) {
			t.Fatal("CSR DNS names should have matched")
		}

		if !reflect.DeepEqual(signedCSR.EmailAddresses, templateCSR.EmailAddresses) {
			t.Fatal("CSR email addresses should have matched")
		}

		if !reflect.DeepEqual(signedCSR.IPAddresses, templateCSR.IPAddresses) {
			t.Fatal("CSR IP addresses should have matched")
		}

		if !reflect.DeepEqual(signedCSR.URIs, templateCSR.URIs) {
			t.Fatal("CSR URIs should have matched")
		}
	default:
		if err == nil || (resp != nil && !resp.IsError()) {
			t.Fatalf("should have failed to sign CSR, provided key type (%s) does not support signing", keyType)
		}
	}
}

func TestTransit_Certificates_ImportCertChain(t *testing.T) {
	// create cluster
	coreConfig := &vault.CoreConfig{
		LogicalBackends: map[string]logical.Factory{
			"transit": Factory,
			"pki":     pki.Factory,
		},
	}

	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
	})
	cluster.Start()
	defer cluster.Cleanup()

	cores := cluster.Cores
	vault.TestWaitActive(t, cores[0].Core)
	client := cores[0].Client

	// mount transit backend
	err := client.Sys().Mount("transit", &api.MountInput{
		Type: "transit",
	})
	require.NoError(t, err)

	// mount PKI backend
	err = client.Sys().Mount("pki", &api.MountInput{
		Type: "pki",
	})
	require.NoError(t, err)

	t.Parallel()
	testTransit_Certificates_ImportCertChain(t, client, "rsa-2048")
	testTransit_Certificates_ImportCertChain(t, client, "rsa-3072")
	testTransit_Certificates_ImportCertChain(t, client, "rsa-4096")
	testTransit_Certificates_ImportCertChain(t, client, "ecdsa-p256")
	testTransit_Certificates_ImportCertChain(t, client, "ecdsa-p384")
	testTransit_Certificates_ImportCertChain(t, client, "ecdsa-p521")
	testTransit_Certificates_ImportCertChain(t, client, "ed25519")
}

func testTransit_Certificates_ImportCertChain(t *testing.T, apiClient *api.Client, keyType string) {
	keyName := keyType
	issuerName := fmt.Sprintf("%s-issuer", keyType)

	// create transit key
	_, err := apiClient.Logical().Write(fmt.Sprintf("transit/keys/%s", keyName), map[string]interface{}{
		"type": keyType,
	})
	require.NoError(t, err)

	// setup a new CSR
	privKey, err := rsa.GenerateKey(cryptoRand.Reader, 3072)
	require.NoError(t, err)

	var csrTemplate x509.CertificateRequest
	csrTemplate.Subject.CommonName = "example.com"
	reqCsrBytes, err := x509.CreateCertificateRequest(cryptoRand.Reader, &csrTemplate, privKey)
	require.NoError(t, err)

	pemTemplateCsr := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: reqCsrBytes,
	})
	t.Logf("csr: %v", string(pemTemplateCsr))

	// create CSR from template CSR fields and key in transit
	resp, err := apiClient.Logical().Write(fmt.Sprintf("transit/keys/%s/csr", keyName), map[string]interface{}{
		"csr": string(pemTemplateCsr),
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	pemCsr := resp.Data["csr"].(string)

	// generate PKI root
	resp, err = apiClient.Logical().Write("pki/root/generate/internal", map[string]interface{}{
		"issuer_name": issuerName,
		"common_name": "PKI Root X1",
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	rootCertPEM := resp.Data["certificate"].(string)
	pemBlock, _ := pem.Decode([]byte(rootCertPEM))
	require.NotNil(t, pemBlock)

	rootCert, err := x509.ParseCertificate(pemBlock.Bytes)
	require.NoError(t, err)

	// create role to be used in the certificate issuing
	resp, err = apiClient.Logical().Write("pki/roles/example-dot-com", map[string]interface{}{
		"issuer_ref":                         issuerName,
		"allowed_domains":                    "example.com",
		"allow_bare_domains":                 true,
		"basic_constraints_valid_for_non_ca": true,
		"key_type":                           "any",
	})
	require.NoError(t, err)

	// sign the CSR
	resp, err = apiClient.Logical().Write("pki/sign/example-dot-com", map[string]interface{}{
		"issuer_ref": issuerName,
		"csr":        pemCsr,
		"ttl":        "10m",
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	leafCertPEM := resp.Data["certificate"].(string)
	pemBlock, _ = pem.Decode([]byte(leafCertPEM))
	require.NotNil(t, pemBlock)

	leafCert, err := x509.ParseCertificate(pemBlock.Bytes)
	require.NoError(t, err)

	require.NoError(t, leafCert.CheckSignatureFrom(rootCert))
	t.Logf("root: %v", rootCertPEM)
	t.Logf("leaf: %v", leafCertPEM)

	certificateChain := strings.Join([]string{leafCertPEM, rootCertPEM}, "\n")

	// Import root as leaf; this should fail.
	resp, err = apiClient.Logical().Write(fmt.Sprintf("transit/keys/%s/set-certificate", keyName), map[string]interface{}{
		"certificate_chain": rootCertPEM,
	})
	require.Error(t, err)
	require.Nil(t, resp)

	// Import root->leaf; this should fail.
	resp, err = apiClient.Logical().Write(fmt.Sprintf("transit/keys/%s/set-certificate", keyName), map[string]interface{}{
		"certificate_chain": strings.Join([]string{rootCertPEM, leafCertPEM}, "\n"),
	})
	require.Error(t, err)
	require.Nil(t, resp)

	// import certificate chain to transit key version
	resp, err = apiClient.Logical().Write(fmt.Sprintf("transit/keys/%s/set-certificate", keyName), map[string]interface{}{
		"certificate_chain": certificateChain,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	resp, err = apiClient.Logical().Read(fmt.Sprintf("transit/keys/%s", keyName))
	require.NoError(t, err)
	require.NotNil(t, resp)
	keys, ok := resp.Data["keys"].(map[string]interface{})
	if !ok {
		t.Fatal("could not cast Keys value")
	}
	keyData, ok := keys["1"].(map[string]interface{})
	if !ok {
		t.Fatal("could not cast key version 1 from keys")
	}
	_, present := keyData["certificate_chain"]
	if !present {
		t.Fatal("certificate chain not present in key version 1")
	}
}
