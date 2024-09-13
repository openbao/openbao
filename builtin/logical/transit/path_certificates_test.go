package transit

import (
	"context"
	"fmt"
	"reflect"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
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
