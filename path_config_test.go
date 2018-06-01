package kubeauth

import (
	"context"
	"reflect"
	"testing"

	"github.com/hashicorp/vault/logical"
)

func TestConfig_Read(t *testing.T) {
	b, storage := getBackend(t)

	data := map[string]interface{}{
		"pem_keys":           []string{testRSACert, testECCert},
		"kubernetes_host":    "host",
		"kubernetes_ca_cert": testCACert,
		"token_reviewer_jwt": jwtData, // this isn't being returned
	}

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      configPath,
		Storage:   storage,
		Data:      data,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      configPath,
		Storage:   storage,
		Data:      nil,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	if !reflect.DeepEqual(resp.Data, data) {
		t.Fatalf("Expected did not equal actual: expected %#v\n got %#v\n", data, resp.Data)
	}
}

func TestConfig(t *testing.T) {
	b, storage := getBackend(t)

	// test no certificate
	data := map[string]interface{}{
		"kubernetes_host": "host",
	}

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      configPath,
		Storage:   storage,
		Data:      data,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error")
	}
	if resp.Error().Error() != "one of pem_keys or kubernetes_ca_cert must be set" {
		t.Fatalf("got unexpected error: %v", resp.Error())
	}

	// test no host
	data = map[string]interface{}{
		"pem_keys": testRSACert,
	}

	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      configPath,
		Storage:   storage,
		Data:      data,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error")
	}
	if resp.Error().Error() != "no host provided" {
		t.Fatalf("got unexpected error: %v", resp.Error())
	}

	// test invalid cert
	data = map[string]interface{}{
		"pem_keys":        "bad",
		"kubernetes_host": "host",
	}

	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      configPath,
		Storage:   storage,
		Data:      data,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error")
	}
	if resp.Error().Error() != "data does not contain any valid RSA or ECDSA public keys" {
		t.Fatalf("got unexpected error: %v", resp.Error())
	}

	// Test success with no certs
	data = map[string]interface{}{
		"kubernetes_host":    "host",
		"kubernetes_ca_cert": testCACert,
	}

	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      configPath,
		Storage:   storage,
		Data:      data,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	cert, err := parsePublicKeyPEM([]byte(testRSACert))
	if err != nil {
		t.Fatal(err)
	}

	expected := &kubeConfig{
		PublicKeys: []interface{}{},
		PEMKeys:    []string{},
		Host:       "host",
		CACert:     testCACert,
	}

	conf, err := b.(*kubeAuthBackend).config(context.Background(), storage)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(expected, conf) {
		t.Fatalf("expected did not match actual: expected %#v\n got %#v\n", expected, conf)
	}

	// Test success TokenReviewer
	data = map[string]interface{}{
		"kubernetes_host":    "host",
		"kubernetes_ca_cert": testCACert,
		"token_reviewer_jwt": jwtData,
	}

	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      configPath,
		Storage:   storage,
		Data:      data,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	cert, err = parsePublicKeyPEM([]byte(testRSACert))
	if err != nil {
		t.Fatal(err)
	}

	expected = &kubeConfig{
		PublicKeys:       []interface{}{},
		PEMKeys:          []string{},
		Host:             "host",
		CACert:           testCACert,
		TokenReviewerJWT: jwtData,
	}

	conf, err = b.(*kubeAuthBackend).config(context.Background(), storage)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(expected, conf) {
		t.Fatalf("expected did not match actual: expected %#v\n got %#v\n", expected, conf)
	}

	// Test success with one cert
	data = map[string]interface{}{
		"pem_keys":           testRSACert,
		"kubernetes_host":    "host",
		"kubernetes_ca_cert": testCACert,
	}

	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      configPath,
		Storage:   storage,
		Data:      data,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	cert, err = parsePublicKeyPEM([]byte(testRSACert))
	if err != nil {
		t.Fatal(err)
	}

	expected = &kubeConfig{
		PublicKeys: []interface{}{cert},
		PEMKeys:    []string{testRSACert},
		Host:       "host",
		CACert:     testCACert,
	}

	conf, err = b.(*kubeAuthBackend).config(context.Background(), storage)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(expected, conf) {
		t.Fatalf("expected did not match actual: expected %#v\n got %#v\n", expected, conf)
	}

	// Test success with two certs
	data = map[string]interface{}{
		"pem_keys":           []string{testRSACert, testECCert},
		"kubernetes_host":    "host",
		"kubernetes_ca_cert": testCACert,
	}

	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      configPath,
		Storage:   storage,
		Data:      data,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	cert, err = parsePublicKeyPEM([]byte(testRSACert))
	if err != nil {
		t.Fatal(err)
	}

	cert2, err := parsePublicKeyPEM([]byte(testECCert))
	if err != nil {
		t.Fatal(err)
	}

	expected = &kubeConfig{
		PublicKeys: []interface{}{cert, cert2},
		PEMKeys:    []string{testRSACert, testECCert},
		Host:       "host",
		CACert:     testCACert,
	}

	conf, err = b.(*kubeAuthBackend).config(context.Background(), storage)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(expected, conf) {
		t.Fatalf("expected did not match actual: expected %#v\n got %#v\n", expected, conf)
	}
}

var testRSACert string = `-----BEGIN CERTIFICATE-----
MIIDcjCCAlqgAwIBAgIBAjANBgkqhkiG9w0BAQsFADAVMRMwEQYDVQQDEwptaW5p
a3ViZUNBMB4XDTE3MDgzMDE5MDgzNloXDTE4MDgzMDE5MDgzNlowLDEXMBUGA1UE
ChMOc3lzdGVtOm1hc3RlcnMxETAPBgNVBAMTCG1pbmlrdWJlMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxD3eM3+WNc4phxAeQxNOmcybKlNJWowuC12u
v+cGJWxxpDx/OoEIxKI5wmgHxEwFCZL545sjfLqyBcgxQR2xSCib+bYzjBtfA6uV
6d/35nurzz21okcMffc5xKMyZhEwt98WAvYWD71Bihz7iGBq5Sw9md6pqnkNoScR
Hhi3Vl94a6D6shwb6nXA2hlwYLcnoKtpe3Ptq6MW6CpfBA8C11q5eeW4xdvrwKt3
Vd1TgFeEnnqwzUWGapU2uwwUfbRkLTDvrp6791uq0Vo7mzz00xYhV1PLCeAdpJEK
3Vr74FT7jHIbPlzi/qjRBVFKf9IRXnhbjrCl7S0Ayev1Fao4TQIDAQABo4G1MIGy
MA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIw
DAYDVR0TAQH/BAIwADBzBgNVHREEbDBqgiRrdWJlcm5ldGVzLmRlZmF1bHQuc3Zj
LmNsdXN0ZXIubG9jYWyCFmt1YmVybmV0ZXMuZGVmYXVsdC5zdmOCEmt1YmVybmV0
ZXMuZGVmYXVsdIIKa3ViZXJuZXRlc4cEwKhjZIcECgAAATANBgkqhkiG9w0BAQsF
AAOCAQEAIw8rKuryhhl527wf9q/VrWixzZ1jCLvyc/60z9rWpXxKFxT8AyCsHirM
F4fHXW4Brcoh/Dc2ci36cUbuywIyxHjgVUG45D4jPPWskY1++ZSfJfSXAuA8eFew
c+No3WPkmZB6ZOZ6q5iPY+FOgDZC7ddWmGuZrle51gBL347cU7H1BrTm6Lm6kXRs
fHRZJX2+B8lnsXsS3QF2BTU0ymuCxCCQxub/GhPZVz3nNNtro1z7/szLUVP1c1/8
p7HP3k7caxfp346TZ/HgbV9sJEkHP7Ym7n9E7LSyUTSxXwBRPraH1WQzEgFNPSUV
V0n6FBLiejOTPKapJ2F0tIqAyJHFug==
-----END CERTIFICATE-----`

var testECCert string = `-----BEGIN CERTIFICATE-----
MIICZDCCAeugAwIBAgIJALM9NbK8WRuBMAkGByqGSM49BAEwRTELMAkGA1UEBhMC
dXMxEzARBgNVBAgTClNvbWUtU3RhdGUxITAfBgNVBAoTGEludGVybmV0IFdpZGdp
dHMgUHR5IEx0ZDAeFw0xNzA5MTExNzQ2NDNaFw0yNzA5MDkxNzQ2NDNaMEUxCzAJ
BgNVBAYTAnVzMRMwEQYDVQQIEwpTb21lLVN0YXRlMSEwHwYDVQQKExhJbnRlcm5l
dCBXaWRnaXRzIFB0eSBMdGQwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAATcqsBLxKP+
UHk7Y6ktGGFvfrIfIXHxeZe3Xwt691CWfdmJFvrGzyzW5/AbJIuO1utdOsqUStAm
W/Scfxop/FGadKqR4nAWLNBI4intgnf0r1rzBCSOmanolHqxQPqQ0UOjgacwgaQw
HQYDVR0OBBYEFHxh1pTd8ApEzg0gKMwwt01aA10TMHUGA1UdIwRuMGyAFHxh1pTd
8ApEzg0gKMwwt01aA10ToUmkRzBFMQswCQYDVQQGEwJ1czETMBEGA1UECBMKU29t
ZS1TdGF0ZTEhMB8GA1UEChMYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkggkAsz01
srxZG4EwDAYDVR0TBAUwAwEB/zAJBgcqhkjOPQQBA2gAMGUCMCR+CvAoNBhqSe2M
4qWWD/9XX/0qmf0O442Qowcg5MWH1+mwl1s7ozinvbTPDPaYDwIxAM54qKhuL6xt
GxqJpa7Onn15Hu8zTsdzeYBqUUXA6wtn+Pa7197CgUkfty9yc2eeQw==
-----END CERTIFICATE-----`

var testCACert string = `
-----BEGIN CERTIFICATE-----
MIIC5zCCAc+gAwIBAgIBATANBgkqhkiG9w0BAQsFADAVMRMwEQYDVQQDEwptaW5p
a3ViZUNBMB4XDTE3MDgxMDIzMTQ1NVoXDTI3MDgwODIzMTQ1NVowFTETMBEGA1UE
AxMKbWluaWt1YmVDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAN8d
w2p/KXRkm+vzOO0eT1vYBWP7fKsnng9/g5nnXAJlt9NxpOSolRcyItm/04R0E1jx
jpgsdzkybc+QU5ZiszOYN833/D5hCNVAABVivpDd2P8wVKXN46cB99e24etUVBqG
5aR0Ku3IBsJjCN9efhF+XRCA2gy/KaXMdKJhHfdtc8hCr7G9+2wO2G58FLmIfEyH
owviOGt0BSnCtMpsA8ZgGQyfqgSd5u466aCv6oj0MyzsMnfS38niM53Rlv4IY6ol
taYbWXtCNndQ2S687qE0qTCxhE95Bm2Nfkqct4R1798sJz83xNv8hALvxr/vPK/J
2XkIm3oo3YKG4n/CHXcCAwEAAaNCMEAwDgYDVR0PAQH/BAQDAgKkMB0GA1UdJQQW
MBQGCCsGAQUFBwMCBggrBgEFBQcDATAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3
DQEBCwUAA4IBAQCSkrhE1PczqeqXfRaWayJUbXWPwKFbszO0MhGB1zwnPZq39qjY
ySQiGvnjV3fP+N5CTQAwMNe79Xiw31fSoexgceCPJpraWrTOLdCv04SbGDBapMFM
aezBu9jzZm0CNt60jHXWXuHHVPFX6u7ZR8W+RiBvsT8GZ5U6sNs3aN3M9Vym06BL
aSphIw1v+hRlPfnrlJwUnQp158DRgkt/9ncTa/k88KoIoZAbulaiGB4zHxxkbura
GSlgpZzhHSrBDLuXf65GHwwGxSExhgY5AA/n8rumGVvE8IYohS9yg/jOG0xP2WQH
u/ABoYtOyseO+lgElA8R4PB9MtwgN6c/b0xH
-----END CERTIFICATE-----`
