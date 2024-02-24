// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

// go:build ignore

package dependency

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/hashicorp/consul-template/renderer"
	"github.com/hashicorp/vault/api"
)

func Test_VaultPKI_uniqueID(t *testing.T) {
	d1, _ := NewVaultPKIQuery("pki/issue/example-dot-com", "/unique_1", nil)
	id1 := d1.String()
	d2, _ := NewVaultPKIQuery("pki/issue/example-dot-com", "/unique_2", nil)
	id2 := d2.String()
	if id1 == id2 {
		t.Errorf("IDs should be unique.\n%s\n%s", id1, id2)
	}
}

func Test_VaultPKI_notGoodFor(t *testing.T) {
	tests := map[string]struct {
		input []byte
	}{
		"valid cert": {input: []byte(validCert)},
		"empty cert": {input: make([]byte, 0)},
	}

	for name, tc := range tests {
		// only test the negation, postive is tested below with pemsificates
		// fetched in Vault integration tests (creating pemss is non-trivial)
		_, cert, err := pemsCert(tc.input)
		if err != nil {
			t.Error(err)
		}
		dur, ok := goodFor(cert)
		if ok != false {
			t.Errorf("%v: should be false", name)
		}
		// duration should be negative as pems has already expired
		// but still tests pems time parsing (it'd be 0 if there was an issue)
		if dur > 0 {
			t.Errorf("%v: duration shouldn't be positive (old cert)", name)
		}
	}
}

func Test_VaultPKI_pemsCert(t *testing.T) {
	// tests w/ valid pems, and having it hidden behind various things
	want := strings.TrimRight(strings.TrimSpace(validCert), "\n")
	for k, testpems := range validPermutations() {
		t.Run(k, func(t *testing.T) {
			pems, cert, err := pemsCert([]byte(testpems))
			if err != nil {
				t.Fatal(err) // Fatal to avoid panic's below
			}
			if cert == nil {
				t.Fatal("cert should not be nil")
			}
			for k, p := range map[string]string{
				"cert": pems.Cert, "key": pems.Key, "ca": pems.CA,
			} {
				if p == "" {
					t.Error("Missing PEM:", k)
				}
			}
			got := strings.TrimRight(pems.Cert, "\n")
			if got != want {
				t.Errorf("pemss didn't match:\ngot: %v\nwant: %v", got, want)
			}
			if err := cert.VerifyHostname("foo.example.com"); err != nil {
				t.Error(err)
			}
		})
	}
	// tests w/o valid pems (test error)
	expectedErr := "x509: malformed certificate"
	for name, badpems := range map[string]string{"bad": badCert, "bad+gar": badPlusGarbo} {
		_, _, err := pemsCert([]byte(badpems))
		switch {
		case err == nil:
			t.Errorf("error should not be nil for %s", name)
		case !strings.Contains(err.Error(), expectedErr):
			t.Errorf("wrong error; wanted: '%s', got: '%s'", expectedErr, err)
		}
	}
}

func Test_VaultPKI_fetchPEM(t *testing.T) {
	clients := testClients

	data := map[string]interface{}{
		"common_name": "foo.example.com",
		"ttl":         "2h",
		"ip_sans":     "127.0.0.1,192.168.2.2",
	}
	d, err := NewVaultPKIQuery("pki/issue/example-dot-com", "/dev/null", data)
	if err != nil {
		t.Error(err)
	}
	encPEM, err := d.fetchPEMs(clients)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Contains(encPEM, []byte("CERTIFICATE")) {
		t.Errorf("pemsificate not fetched, got: %s", string(encPEM))
	}
	// test path error
	d, err = NewVaultPKIQuery("pki/issue/does-not-exist", "/dev/null", data)
	if err != nil {
		t.Error(err)
	}
	_, err = d.fetchPEMs(clients)
	var respErr *api.ResponseError
	if !errors.As(err, &respErr) {
		t.Error(err)
	}
}

func Test_VaultPKI_refetch(t *testing.T) {
	t.Parallel() // have time waits, so parallel might help

	f, err := os.CreateTemp("", "")
	if err != nil {
		t.Fatal(err)
	}
	os.Remove(f.Name())
	defer os.Remove(f.Name())

	clients := testClients
	/// above is prep work
	data := map[string]interface{}{
		"common_name": "foo.example.com",
		"ttl":         "3s",
		"ip_sans":     "127.0.0.1,192.168.2.2",
	}
	d, err := NewVaultPKIQuery("pki/issue/example-dot-com", f.Name(), data)
	if err != nil {
		t.Fatal(err)
	}
	act1, rm, err := d.Fetch(clients, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rm == nil {
		t.Error("Fetch returned nil for response metadata.")
	}

	pems1, ok := act1.(PemEncoded)
	if !ok || !strings.Contains(pems1.Cert, "BEGIN CERTIFICATE") {
		t.Fatalf("expected a pems but found: %s", pems1)
	}

	// Fake template rendering file to disk
	allPems1 := strings.Join([]string{pems1.Cert, pems1.Key, pems1.CA}, "\n")
	_, err = renderer.Render(&renderer.RenderInput{
		Contents: []byte(allPems1),
		Path:     f.Name(),
	})
	if err != nil {
		t.Fatal(err)
	}

	// re-fetch, should be the same pems pulled from the file
	// if re-fetched from Vault it will be different
	<-d.sleepCh // drain sleepCh to trigger reusing the cached copy
	act2, rm, err := d.Fetch(clients, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rm == nil {
		t.Error("Fetch returned nil for response metadata.")
	}

	pems2, ok := act2.(PemEncoded)
	if !ok || !strings.Contains(pems2.Cert, "BEGIN CERTIFICATE") {
		t.Fatalf("expected a pems but found: %s", pems2)
	}
	// using cached copy, so should be a match
	if pems1 != pems2 {
		t.Errorf("pemss don't match and should.")
	}

	// Don't pre-drain here as we want it to get a new pems
	act3, rm, err := d.Fetch(clients, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rm == nil {
		t.Error("Fetch returned nil for response metadata.")
	}

	pems3, ok := act3.(PemEncoded)
	if !ok || !strings.Contains(pems3.Cert, "BEGIN CERTIFICATE") {
		t.Fatalf("expected a pems but found: %s", pems2)
	}

	if pems2 == pems3 {
		t.Errorf("pemss match and shouldn't.")
	}
}

const validCert = `-----BEGIN CERTIFICATE-----
MIIDWTCCAkGgAwIBAgIUaawVY56cY+a0GUYJaL2zsHFBgqQwDQYJKoZIhvcNAQEL
BQAwFjEUMBIGA1UEAxMLZXhhbXBsZS5jb20wHhcNMjIwNjIxMjEyODIxWhcNMjIw
NjIxMjEyODI1WjAaMRgwFgYDVQQDEw9mb28uZXhhbXBsZS5jb20wggEiMA0GCSqG
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDJ3NK6SeJQdxAmXXRcPt5xHYVuUWLjtvHp
8wAUtMYSvLFrC0XD9YGKxScbLLcnlZdSvD72LYh9R4h7kLjyP9JQnUSPqhixUk2A
RYuiUTNieppsM7pBMM0UYkyOtb8pLNSnrV4u6ga1iSGZd/3qxSbDd9K0ku9A75qC
zVLvcO7LqPw6RI8hRDU6Z1qE3MK9upqu/YE8HdhR7og8hZzhU8f7GcuGowNYezBi
J/hmBW6oxyi0FC9rmZ7SIX3oYyxkW1v/xSM3zw4EKw1JaDFgceyuhQXW0QmgUyTW
0p7I2DUIccRV7W1w7biERiDfrqzCJaUzTEg2E728269fHpaYa3OpAgMBAAGjgZow
gZcwDgYDVR0PAQH/BAQDAgOoMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcD
AjAdBgNVHQ4EFgQUyivSsb/skEc07dXBKtI2X6+IvfowHwYDVR0jBBgwFoAUOrWo
wCGHOQKRtIXbtzWHxaGaW00wJgYDVR0RBB8wHYIPZm9vLmV4YW1wbGUuY29thwR/
AAABhwTAqAICMA0GCSqGSIb3DQEBCwUAA4IBAQCecPeIR2SN+yVqfvURDgH/ZiFB
xGCTQOv3Chi9M9UeIHhOmfLCkyKrZ6glZHUllXGLDDIrGjwS/a3bshr60hQRISST
Kcn5zHURLgCFTw4uFrC3hsR9by/PytE5mvMe8arpkiboUYrUIT5OlQmsZNpksbB9
34fBi72qhhwYC1kzoBkFRMQQtwAgpmLM46pAIbZza7d+vnQRXngb6n/pFnq7gOOM
KHy/moLj0fK4dmlrjbrvkLJTZt/IFxLNWvj8wGmnLSuIuBt08Rc1McY4gbTySats
8lpG3zQS6aqGJjLEqjXkvfzWAAS5Xrvcc59a2dc6GZ01Y1ZP6krQ2rJBUEAO
-----END CERTIFICATE-----`

const validKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAydzSukniUHcQJl10XD7ecR2FblFi47bx6fMAFLTGEryxawtF
w/WBisUnGyy3J5WXUrw+9i2IfUeIe5C48j/SUJ1Ej6oYsVJNgEWLolEzYnqabDO6
QTDNFGJMjrW/KSzUp61eLuoGtYkhmXf96sUmw3fStJLvQO+ags1S73Duy6j8OkSP
IUQ1OmdahNzCvbqarv2BPB3YUe6IPIWc4VPH+xnLhqMDWHswYif4ZgVuqMcotBQv
a5me0iF96GMsZFtb/8UjN88OBCsNSWgxYHHsroUF1tEJoFMk1tKeyNg1CHHEVe1t
cO24hEYg366swiWlM0xINhO9vNuvXx6WmGtzqQIDAQABAoIBAEJGcxVgnqJGhRHj
iwmiRowi4iUXKX2UGhbyhmtF8uZB94oqmEw/NbnnAvDkHHotnhI25gETcAWZz9Cp
8l7u31FCYTk94n+Ngw6DRtYTDOjfUgYGcbdnm11+7J3KRCnzoxouTIbgpTVDAboO
cFp9Qj3ZAF/zAgRy5mrdmMYucOiCTDlNIZtWQz/kW2TUZlukFWDlkqNY2ri+r8aN
B6ahHmjxCew+VRJ9O2cndM81kx28ex4B7FnLDt7RAyc5JfJ+lefZEzV/vsauy0sS
BTYZTNpDjBOymvpCUkDpqC26lvamcZdACtGVojfWxVtV5w4lwJi0mdKaWdItJyBo
RDlfjMUCgYEA8ybFv/OXvyK9PXfavxshW2WNxfV+4U4A18K8Pog8JE/kN7G0aiz2
m5VZqd2sdC0002LWjm5P7s+wRWMRyiJhiUuWZB8TltLny7+fBDmk49IWZRMtiiVp
vKoetbGyGGxEV+6gFiNm+UupDPy75/ZkCrdGp/66LOxhsryLqoVTvA8CgYEA1IeE
JwM5hhfDrY50tFx1Cu0HUvJwll1AJS0Y4KqIsIeC4Km0gritzr+c982ldsv01cH4
P/fVeeCJHIjuYdJezgv2jbcBlisqFL7YY9fg1S7mveYAq/RxHczVTk9zcA6IMvQs
d5vzItuQFU0SUQIYQanlizDW/yh1l9H+Me3zfMcCgYAuAITjNwPbnoftDDLvewOJ
liIHdNXHbImOSIJy1jWCrTbBLraya8VQVCY9k/nflPnskEOFeOtYhCSWTBL+ihin
8AwI7zQ2kbpW+u7rzrgafhHMl59DBqcFka3ztCW8pyca98ODzLjbq2vVUC+AyEXP
HTOZ7wBsJWCqfy9xWH4qEwKBgC1Hzi0tr7TVHVi98Dl5NWqlg5j1lG1E4uTIzfMY
AlVyGb1aCt6LEGTrSDs3slg0Li7Yy9Z9LBtybmQI/JkU5CQMQnSBGDJxcd7Hpnzn
QrzI6FpvRZddVjheKtgrb1Hhlr0cbtjw/gVgODuBlzRxOM/Mrd5RAo2MhjlZgUoM
A4ODAoGAb9QJ4NlahKEX68ooC/FToiiUpJ33lAxFXVo0Nl/M8XsjcKDsKVsVDZkt
/sWSUr3HJ54XMgsTybG9l7poeM6lWN/B+q1O05688Bp3h1Jx4uKCDjouS+u1xViJ
iUV6/HfQYsykAni+pF6Zomu7ViIpl2u9bXExReB9UDI7LfHU4cg=
-----END RSA PRIVATE KEY-----`

const validCA = `-----BEGIN CERTIFICATE-----
MIIDNTCCAh2gAwIBAgIURRe+G6nEMYhVGqXpsIyIKVAzqBwwDQYJKoZIhvcNAQEL
BQAwFjEUMBIGA1UEAxMLZXhhbXBsZS5jb20wHhcNMjIwNjIxMjEyNzUyWhcNMjIw
NjIzMjEyODIyWjAWMRQwEgYDVQQDEwtleGFtcGxlLmNvbTCCASIwDQYJKoZIhvcN
AQEBBQADggEPADCCAQoCggEBAMcgv07tmQWfqONmhPcrh8bspesCqKsI3S31+jCh
sMONB1fjTqTw4CU6ii3BVL+O4Q5Bxi+sRSHunfRPSZE6wCytZrYiJsA2VsEOvBTC
FKDZ0ieManszb5zw1liaK/IW8yhAM3739Wvz+CJO/Ji1cy3bLaYVQr7hJgNdnexb
c1gNqR985QrexRF/ftp5YHnopgAmH45Au+CxMuXZqrP4zWvvm/RPvX5gscRj5sA5
8e1+325EmIFXf6zYuMjx0K9sryuDDKvIDO9KZ1FMkQSj2rXIO81PNz5XCKYl886m
HO1A9qVHNRHRrfdZfg9xi9naCFxudC7RyuEW5v1pvxKxTVsCAwEAAaN7MHkwDgYD
VR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFDq1qMAhhzkC
kbSF27c1h8WhmltNMB8GA1UdIwQYMBaAFDq1qMAhhzkCkbSF27c1h8WhmltNMBYG
A1UdEQQPMA2CC2V4YW1wbGUuY29tMA0GCSqGSIb3DQEBCwUAA4IBAQC0HcXeqKls
+fWZzNPIkroiBAonRLStXI3R/xcEfT1zOnAOTQUqC75v4HnHFbQdqdikRwuNYDCj
Okq7idvya6tYyVawJfinXNk7hbZG9NagmdIpAnufl5vrAW/Q3z2yLE0lwwEbByDi
3s6JegVPnZIaZgDl5+381CdMJebP5L7Xvunp01iJURWAY1t3OyXLxcF7zR1l/HOZ
m/xetJzhoO/acy/PVOPK+llLLRNTuRCYjCvA2BO73t4IA233rHfycPV7sAtP/BIL
WMd2uXhevQmufC8kPWlHXlTo3X5gxrEsyBeO3BzjEz76eYq+VdimmkV8qm/Zbccj
ceJ0WflHmKDF
-----END CERTIFICATE-----`

var validPems = map[string]string{
	"ca": validCA, "cert": validCert, "key": validKey,
}

func validPermutations() map[string]string {
	result := make(map[string]string, 6)
	for k, v := range validPems {
		for k1, v1 := range validPems {
			if v1 != v {
				for k2, v2 := range validPems {
					if v2 != v && v2 != v1 {
						result[k+k1+k2] = v + v1 + v2
					}
				}
			}
		}
	}
	for k, v := range embedded {
		result[k] = v
	}
	return result
}

var allPEMs = strings.Join([]string{validCert, validKey, validCA}, "\n")

var embedded = map[string]string{
	"spaces":     " " + allPEMs + " ",
	"brackets":   "{{ " + allPEMs + " }}",
	"null":       "\x00" + allPEMs + "\x00",
	"tabs":       "\t" + allPEMs + "\t",
	"assignment": "\tCerts='" + allPEMs + "'",
}

const badCert = `-----BEGIN CERTIFICATE-----
MIIDWTCCAkGgAwIBAgIUUARA+vQExU8zjdsX/YXMMu1K5FkwDQYJKoZIhvcNAQEL
eB01bl42Y5WwHl0IrjfbEevzoW0+uhlUlZ6keZHr7bLn/xuRCUkVfj3PRlMl
-----END CERTIFICATE-----`

const (
	badPlusGarbo = `
aa983w4;/amndsfm908q26035vc;ng902338(%@%!@QY!&DVLMNSALX>PT(RQ!QO*%@
X` + badCert + `X
!Q)(*@^YUO!Q#MN%$#WP(G^&+_!%)!+^%$Y	:!#QLKENFVJ)	!#*&%YHTM
`
)
