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
MIICRTCCAS0CAQAwADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAM49
McW7u3ILuAJfSFLUtGOMGBytHmMFcjTiX+5JcajFj0Uszb+HQ7eIsJJNXhVc/7fg
Z01DZvcCqb9ChEWE3xi4GEkPMXay7p7G1ooSLnQp6Z0lL5CuIFfMVOTvjfhTwRaJ
l9v2mMlm80BeiAUBqeoyGVrIh5fKASxaE0jrhjAxhGzqrXdDnL8A4na6ArprV4iS
aEAziODd2WmplSKgUwEaFdeG1t1bJf3o5ZQRCnKNtQcAk8UmgtvFEO8ohGMln/Fj
O7u7s6iRhOGf1g1NCAP5pGqxNx3bjz5f/CUcTSIGAReEomg41QTIhD9muCTL8qnm
6lS87wkGTv7qbeIGB7sCAwEAAaAAMA0GCSqGSIb3DQEBCwUAA4IBAQAfjE+jNqIk
4V1tL3g5XPjxr2+QcwddPf8opmbAzgt0+TiIHcDGBAxsXyi7sC9E5AFfFp7W07Zv
r5+v4i529K9q0BgGtHFswoEnhd4dC8Ye53HtSoEtXkBpZMDrtbS7eZa9WccT6zNx
4taTkpptZVrmvPj+jLLFkpKJJ3d+Gbrp6hiORPadT+igLKkqvTeocnhOdAtt427M
RXTVgN14pV3tqO+5MXzNw5tGNPcwWARWwPH9eCRxLwLUuxE4Qu73pUeEFjDEfGkN
iBnlTsTXBOMqSGryEkmRaZslWDvblvYeObYw+uc3kCbJ7jRy9soVwkbb5FueF/yC
O1aQIm23HrrG
-----END CERTIFICATE REQUEST-----
`
)

func TestTransit_CreateCSR(t *testing.T) {
	t.Parallel()

	testTransitCreateCSR(t, "rsa-2048", templateCSR)
	testTransitCreateCSR(t, "rsa-3072", templateCSR)
	testTransitCreateCSR(t, "rsa-4096", templateCSR)
	testTransitCreateCSR(t, "ecdsa-p256", templateCSR)
	testTransitCreateCSR(t, "ecdsa-p384", templateCSR)
	testTransitCreateCSR(t, "ecdsa-p521", templateCSR)
	testTransitCreateCSR(t, "ed25519", templateCSR)
	testTransitCreateCSR(t, "aes256-gcm96", templateCSR)
}

func testTransitCreateCSR(t *testing.T, keyType string, pemTemplateCSR string) {
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
		Operation: logical.CreateOperation,
		Path:      fmt.Sprintf("keys/%s/csr", keyName),
		Storage:   s,
		Data: map[string]interface{}{
			"csr": pemTemplateCSR,
		},
	}

	// request creation of CSR
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

		// NOTE: Check other fields?
		if !reflect.DeepEqual(signedCSR.Subject, templateCSR.Subject) {
			t.Fatalf("subjects should have matched:%v", err)
		}
	default:
		if err == nil || (resp != nil && !resp.IsError()) {
			t.Fatalf("should have failed to sign CSR, provided key type (%s) does not support signing", keyType)
		}
	}
}

// NOTE: Tests are using two 'different' methods of checking for errors, which one should we prefer?
func TestTransit_ImportCertChain(t *testing.T) {
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
	require.NoError(t, err) // NOTE: These functions accept a message

	t.Parallel() // NOTE: Can it be called here?

	testTransit_ImportCertChain(t, client, "rsa-2048")
	testTransit_ImportCertChain(t, client, "rsa-3072")
	testTransit_ImportCertChain(t, client, "rsa-4096")
	testTransit_ImportCertChain(t, client, "ecdsa-p256")
	testTransit_ImportCertChain(t, client, "ecdsa-p384")
	testTransit_ImportCertChain(t, client, "ecdsa-p521")
	testTransit_ImportCertChain(t, client, "ed25519")
}

func testTransit_ImportCertChain(t *testing.T, apiClient *api.Client, keyType string) {
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
	// import certificate chain to transit key version
	resp, err = apiClient.Logical().Write(fmt.Sprintf("transit/keys/%s/set-certificate", keyName), map[string]interface{}{
		"certificate_chain": certificateChain,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	// resp, err = apiClient.Logical().Read(fmt.Sprintf("transit/keys/%s", keyName))
	// require.NotNil(t, resp)
	// keys, ok := resp.Data["keys"].(map[string]interface{})
	// if !ok {
	// 	t.Fatalf("could not cast Keys value")
	// }
	// keyData, ok := keys["1"].(map[string]interface{})
	// if !ok {
	// 	t.Fatalf("could not cast key version 1 from keys")
	// }
	// _, present := keyData["certificate_chain"]
	// if !present {
	// 	t.Fatalf("certificate chain not present in key version 1")
	// }
}
