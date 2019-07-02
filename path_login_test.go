package kubeauth

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"testing"

	"github.com/hashicorp/errwrap"
	multierror "github.com/hashicorp/go-multierror"
	"github.com/hashicorp/vault/sdk/logical"
)

var (
	testNamespace   = "default"
	testName        = "vault-auth"
	testUID         = "d77f89bc-9055-11e7-a068-0800276d99bf"
	testMockFactory = mockTokenReviewFactory(testName, testNamespace, testUID)

	testGlobbedNamespace = "def*"
	testGlobbedName      = "vault-*"

	// Projected ServiceAccount tokens have name "default", and require a
	// different mock token reviewer
	testProjectedName        = "default"
	testProjectedUID         = "b389b3b2-d302-11e8-b14c-080027e55ea8"
	testProjectedMockFactory = mockTokenReviewFactory(testProjectedName, testNamespace, testProjectedUID)

	testDefaultPEMs = []string{testECCert, testRSACert}
	testNoPEMs      = []string{testECCert, testRSACert}
)

func setupBackend(t *testing.T, pems []string, saName string, saNamespace string) (logical.Backend, logical.Storage) {
	b, storage := getBackend(t)

	// pems := []string{testECCert, testRSACert, testMinikubePubKey}
	// pems := []string{testECCert, testRSACert}
	// if noPEMs {
	// 	pems = []string{}
	// }

	// test no certificate
	data := map[string]interface{}{
		"pem_keys":           pems,
		"kubernetes_host":    "host",
		"kubernetes_ca_cert": testCACert,
	}

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   storage,
		Data:      data,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	data = map[string]interface{}{
		"bound_service_account_names":      saName,
		"bound_service_account_namespaces": saNamespace,
		"policies":                         "test",
		"period":                           "3s",
		"ttl":                              "1s",
		"num_uses":                         12,
		"max_ttl":                          "5s",
	}

	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/plugin-test",
		Storage:   storage,
		Data:      data,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	b.(*kubeAuthBackend).reviewFactory = testMockFactory
	return b, storage
}

func TestLogin(t *testing.T) {
	b, storage := setupBackend(t, testDefaultPEMs, testName, testNamespace)

	// Test bad inputs
	data := map[string]interface{}{
		"jwt": jwtData,
	}

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Storage:   storage,
		Data:      data,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error")
	}
	if resp.Error().Error() != "missing role" {
		t.Fatalf("unexpected error: %s", resp.Error())
	}

	data = map[string]interface{}{
		"role": "plugin-test",
	}

	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Storage:   storage,
		Data:      data,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error")
	}
	if resp.Error().Error() != "missing jwt" {
		t.Fatalf("unexpected error: %s", resp.Error())
	}

	// test bad role name
	data = map[string]interface{}{
		"role": "plugin-test-bad",
		"jwt":  jwtData,
	}
	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Storage:   storage,
		Data:      data,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error")
	}
	if resp.Error().Error() != "invalid role name \"plugin-test-bad\"" {
		t.Fatalf("unexpected error: %s", resp.Error())
	}

	// test bad jwt service account
	data = map[string]interface{}{
		"role": "plugin-test",
		"jwt":  jwtBadServiceAccount,
	}
	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Storage:   storage,
		Data:      data,
		Connection: &logical.Connection{
			RemoteAddr: "127.0.0.1",
		},
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err == nil {
		t.Fatal("expected error")
	}
	if err.Error() != "service account name not authorized" {
		t.Fatalf("unexpected error: %s", err)
	}

	// test bad jwt key
	data = map[string]interface{}{
		"role": "plugin-test",
		"jwt":  jwtWithBadSigningKey,
	}
	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Storage:   storage,
		Data:      data,
		Connection: &logical.Connection{
			RemoteAddr: "127.0.0.1",
		},
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err == nil {
		t.Fatal("expected error")
	}
	var expectedErr error
	expectedErr = multierror.Append(expectedErr, errwrap.Wrapf("failed to validate JWT: {{err}}", errMismatchedSigningMethod), errwrap.Wrapf("failed to validate JWT: {{err}}", rsa.ErrVerification))
	if err.Error() != expectedErr.Error() {
		t.Fatalf("unexpected error: %s", err)
	}

	// test successful login
	data = map[string]interface{}{
		"role": "plugin-test",
		"jwt":  jwtData,
	}

	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Storage:   storage,
		Data:      data,
		Connection: &logical.Connection{
			RemoteAddr: "127.0.0.1",
		},
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	// test successful login for globbed name
	b, storage = setupBackend(t, testDefaultPEMs, testGlobbedName, testNamespace)

	data = map[string]interface{}{
		"role": "plugin-test",
		"jwt":  jwtData,
	}

	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Storage:   storage,
		Data:      data,
		Connection: &logical.Connection{
			RemoteAddr: "127.0.0.1",
		},
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	// test successful login for globbed namespace
	b, storage = setupBackend(t, testDefaultPEMs, testName, testGlobbedNamespace)

	data = map[string]interface{}{
		"role": "plugin-test",
		"jwt":  jwtData,
	}

	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Storage:   storage,
		Data:      data,
		Connection: &logical.Connection{
			RemoteAddr: "127.0.0.1",
		},
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}
}

func TestLogin_ECDSA_PEM(t *testing.T) {
	b, storage := setupBackend(t, testNoPEMs, testName, testNamespace)

	// test no certificate
	data := map[string]interface{}{
		"pem_keys":           []string{ecdsaKey},
		"kubernetes_host":    "host",
		"kubernetes_ca_cert": testCACert,
	}

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   storage,
		Data:      data,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	// test successful login
	data = map[string]interface{}{
		"role": "plugin-test",
		"jwt":  jwtECDSASigned,
	}

	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Storage:   storage,
		Data:      data,
		Connection: &logical.Connection{
			RemoteAddr: "127.0.0.1",
		},
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}
}

func TestLogin_NoPEMs(t *testing.T) {
	b, storage := setupBackend(t, testNoPEMs, testName, testNamespace)

	// test bad jwt service account
	data := map[string]interface{}{
		"role": "plugin-test",
		"jwt":  jwtBadServiceAccount,
	}
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Storage:   storage,
		Data:      data,
		Connection: &logical.Connection{
			RemoteAddr: "127.0.0.1",
		},
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err == nil {
		t.Fatal("expected error")
	}
	if err.Error() != "service account name not authorized" {
		t.Fatalf("unexpected error: %s", err)
	}

	// test successful login
	data = map[string]interface{}{
		"role": "plugin-test",
		"jwt":  jwtData,
	}

	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Storage:   storage,
		Data:      data,
		Connection: &logical.Connection{
			RemoteAddr: "127.0.0.1",
		},
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}
}

func TestAliasLookAhead(t *testing.T) {
	b, storage := setupBackend(t, testDefaultPEMs, testName, testNamespace)

	// Test bad inputs
	data := map[string]interface{}{
		"jwt": jwtData,
	}

	req := &logical.Request{
		Operation: logical.AliasLookaheadOperation,
		Path:      "login",
		Storage:   storage,
		Data:      data,
		Connection: &logical.Connection{
			RemoteAddr: "127.0.0.1",
		},
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	if resp.Auth.Alias.Name != testUID {
		t.Fatalf("Unexpected UID: %s", resp.Auth.Alias.Name)
	}
}

var jwtData = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJkZWZhdWx0Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZWNyZXQubmFtZSI6InZhdWx0LWF1dGgtdG9rZW4tdDVwY24iLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC5uYW1lIjoidmF1bHQtYXV0aCIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50LnVpZCI6ImQ3N2Y4OWJjLTkwNTUtMTFlNy1hMDY4LTA4MDAyNzZkOTliZiIsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDpkZWZhdWx0OnZhdWx0LWF1dGgifQ.HKUcqgrvan5ZC_mnpaMEx4RW3KrhfyH_u8G_IA2vUfkLK8tH3T7fJuJaPr7W6K_BqCrbeM5y3owszOzb4NR0Lvw6GBt2cFcen2x1Ua4Wokr0bJjTT7xQOIOw7UvUDyVS17wAurlfUnmWMwMMMOebpqj5K1t6GnyqghH1wPdHYRGX-q5a6C323dBCgM5t6JY_zTTaBgM6EkFq0poBaifmSMiJRPrdUN_-IgyK8fgQRiFYYkgS6DMIU4k4nUOb_sUFf5xb8vMs3SMteKiuWFAIt4iszXTj5IyBUNqe0cXA3zSY3QiNCV6bJ2CWW0Qf9WDtniT79VAqcR4GYaTC_gxjNA"

var jwtBadServiceAccount = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJkZWZhdWx0Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZWNyZXQubmFtZSI6InZhdWx0LWludmFsaWQtdG9rZW4tZ3ZxcHQiLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC5uYW1lIjoidmF1bHQtaW52YWxpZCIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50LnVpZCI6IjA0NGZkNGYxLTk3NGQtMTFlNy05YTE1LTA4MDAyNzZkOTliZiIsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDpkZWZhdWx0OnZhdWx0LWludmFsaWQifQ.BcoOdu5BrIchp66Zl8-dY7HcGHJrVXrUh4SNTlIHR6vDaNH29B7JuI_-B1pvW9GpzQnc-XjZyua_wfSssqe-KYJcq--Qh0yQfbbLE5rvEipBCHH341IqGaTHaBVip8zXqYE-bt-7J6vAH8Azvw46iatDC73tKxh46xDuxK0gKjdprW4cOklDx6ZSxEHpu63ftLYgAgk9c0MUJxKWhu9Jk0aye5pTj_iyBbBy8llZNGaw2gxvhPzFVUEHZUlTRiSIbmPmNqep48RiJoWrq6FM1lijvrtT5y-E7aFk6TpW2BH3VDHy8k10sMIxuRAYrGB3tpUKNyVDI3tJOi_xY7iJvw"

var jwtWithBadSigningKey = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJkZWZhdWx0Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZWNyZXQubmFtZSI6InZhdWx0LWludmFsaWQtdG9rZW4tZ3ZxcHQiLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC5uYW1lIjoidmF1bHQtYXV0aCIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50LnVpZCI6IjA0NGZkNGYxLTk3NGQtMTFlNy05YTE1LTA4MDAyNzZkOTliZiIsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDpkZWZhdWx0OnZhdWx0LWF1dGgifQ.hv4O-T9XPtV3Smy55TrA2qCjRJJEQqeifqzbV1kyb8hr7o7kSqhBRy0fSWHi8rkrnBXjibB0yTDDHR1UvkHLWD2Ddi9tKeXZahaKLxGh5GJI8TSxZizX3ilZB9A5LBpW_VberSxcazhGA1u3VEPaL_nPsxWcdF9kxZR3hwSlyEA"

var jwtECDSASigned = "eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCIsImtpZCI6ImlUcVhYSTB6YkFuSkNLRGFvYmZoa00xZi02ck1TcFRmeVpNUnBfMnRLSTgifQ.eyJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L25hbWVzcGFjZSI6ImRlZmF1bHQiLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC5uYW1lIjoidmF1bHQtYXV0aCIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50LnVpZCI6ImQ3N2Y4OWJjLTkwNTUtMTFlNy1hMDY4LTA4MDAyNzZkOTliZiIsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDpkZWZhdWx0OnZhdWx0LWF1dGgiLCJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50In0.JYxQVgAJQhEIa1lIZ1s9SQ4IrW3FUsl7IfykYBflTgHz0CExAe5BcJ90g1eErVi1RZB1mh2pl9SjIrfFgDeRwqOYwZ4tqCr5dhcZAX5F7yt_RBuuVOvX-EGAklMo0usp"

var ecdsaKey = `-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEC1uWSXj2czCDwMTLWV5BFmwxdM6PX9p+
Pk9Yf9rIf374m5XP1U8q79dBhLSIuaojsvOT39UUcPJROSD1FqYLued0rXiooIii
1D3jaW6pmGVJFhodzC31cy5sfOYotrzF
-----END PUBLIC KEY-----`

func TestLoginProjectedToken(t *testing.T) {
	b, storage := setupBackend(t, append(testDefaultPEMs, testMinikubePubKey), testName, testNamespace)

	// update backend to accept "default" bound account name
	data := map[string]interface{}{
		"bound_service_account_names":      fmt.Sprintf("%s,default", testName),
		"bound_service_account_namespaces": testNamespace,
		"policies":                         "test",
		"period":                           "3s",
		"ttl":                              "1s",
		"num_uses":                         12,
		"max_ttl":                          "5s",
	}

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/plugin-test",
		Storage:   storage,
		Data:      data,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	var roleNameError = fmt.Errorf("invalid role name \"%s\"", "plugin-test-x")

	testCases := map[string]struct {
		role        string
		jwt         string
		tokenReview tokenReviewFactory
		e           error
	}{
		"normal": {
			role:        "plugin-test",
			jwt:         jwtData,
			tokenReview: testMockFactory,
		},
		"fail": {
			role:        "plugin-test-x",
			jwt:         jwtData,
			tokenReview: testMockFactory,
			e:           roleNameError,
		},
		"projected-token": {
			role:        "plugin-test",
			jwt:         jwtProjectedData,
			tokenReview: testProjectedMockFactory,
		},
		"projected-token-expired": {
			role:        "plugin-test",
			jwt:         jwtProjectedDataExpired,
			tokenReview: testProjectedMockFactory,
			e:           errors.New("token is expired"), // jwt.ErrTokenIsExpired,
		},
		"projected-token-invalid-role": {
			role:        "plugin-test-x",
			jwt:         jwtProjectedData,
			tokenReview: testProjectedMockFactory,
			e:           roleNameError,
		},
	}

	for k, tc := range testCases {
		t.Run(k, func(t *testing.T) {

			data := map[string]interface{}{
				"role": tc.role,
				"jwt":  tc.jwt,
			}

			req := &logical.Request{
				Operation: logical.UpdateOperation,
				Path:      "login",
				Storage:   storage,
				Data:      data,
				Connection: &logical.Connection{
					RemoteAddr: "127.0.0.1",
				},
			}

			b.(*kubeAuthBackend).reviewFactory = tc.tokenReview

			resp, err := b.HandleRequest(context.Background(), req)
			if err != nil && tc.e == nil {
				t.Fatalf("unexpected err: (%s) resp:%#v\n", err, resp)
			}
			if resp != nil && resp.IsError() {
				if tc.e == nil {
					t.Fatalf("unexpected err: (%s)\n", resp.Error())
				}
				if tc.e.Error() != resp.Error().Error() {
					t.Fatalf("error mismatch, expected (%s) got (%s)", tc.e, resp.Error())
				}
			}
		})
	}
}

// jwtProjectedData is a Projected Service Account jwt with expiration set to
// October 19, 2020
//
// {
//   "aud": [
//     "kubernetes.default.svc"
//   ],
//   "exp": 1603053563,
//   "iat": 1539981563,
//   "iss": "kubernetes/serviceaccount",
//   "kubernetes.io": {
//     "namespace": "default",
//     "pod": {
//       "name": "vault",
//       "uid": "1006a06c-d3df-11e8-8fe2-080027e55ea8"
//     },
//     "serviceaccount": {
//       "name": "default",
//       "uid": "b389b3b2-d302-11e8-b14c-080027e55ea8"
//     }
//   },
//   "nbf": 1539981563,
//   "sub": "system:serviceaccount:default:default"
// }
var jwtProjectedData = "eyJhbGciOiJSUzI1NiIsImtpZCI6IiJ9.eyJhdWQiOlsia3ViZXJuZXRlcy5kZWZhdWx0LnN2YyJdLCJleHAiOjE2MDMwNTM1NjMsImlhdCI6MTUzOTk4MTU2MywiaXNzIjoia3ViZXJuZXRlcy9zZXJ2aWNlYWNjb3VudCIsImt1YmVybmV0ZXMuaW8iOnsibmFtZXNwYWNlIjoiZGVmYXVsdCIsInBvZCI6eyJuYW1lIjoidmF1bHQiLCJ1aWQiOiIxMDA2YTA2Yy1kM2RmLTExZTgtOGZlMi0wODAwMjdlNTVlYTgifSwic2VydmljZWFjY291bnQiOnsibmFtZSI6ImRlZmF1bHQiLCJ1aWQiOiJiMzg5YjNiMi1kMzAyLTExZTgtYjE0Yy0wODAwMjdlNTVlYTgifX0sIm5iZiI6MTUzOTk4MTU2Mywic3ViIjoic3lzdGVtOnNlcnZpY2VhY2NvdW50OmRlZmF1bHQ6ZGVmYXVsdCJ9.byu3BpCbs0tzQvEBCRTayXF3-kV1Ey7YvStBcCwovfSl6evBze43FFaDps78HtdDAMszjE_yn55_1BMN87EzOZYsF3GBoPLWxkofxhPIy88wmPTpurBsSx-nCKdjf4ayXhTpqGG9gy0xlkUc_xL4pM3Q8XZiqYqwq_T0PHXOpSfdzVy1oabFSZXr5QTZ377v8bvrMgAVWJF_4vZsSMG3XVCK8KBWNRw4_wt6yOelVKE5OGLPJvNu1CFjEKh4HBFBcQnB_Sgpe1nPlnm5utp-1-OVfd7zopOGDAp_Pk_Apu8OPDdPSafn6HpzIeuhMtWXcv1K8ZhZYDLC1wLywZPNyw"

// jwtProjectedDataExpired is a Projected Service Account jwt with expiration
// set to October 19, 2018
//
// {
//   "aud": [
//     "kubernetes.default.svc"
//   ],
//   "exp": 1539903397,
//   "iat": 1539896197,
//   "iss": "kubernetes/serviceaccount",
//   "kubernetes.io": {
//     "namespace": "default",
//     "pod": {
//       "name": "vault",
//       "uid": "78b924ad-d303-11e8-b14c-080027e55ea8"
//     },
//     "serviceaccount": {
//       "name": "default",
//       "uid": "b389b3b2-d302-11e8-b14c-080027e55ea8"
//     }
//   },
//   "nbf": 1539896197,
//   "sub": "system:serviceaccount:default:default"
// }
var jwtProjectedDataExpired = "eyJhbGciOiJSUzI1NiIsImtpZCI6IiJ9.eyJhdWQiOlsia3ViZXJuZXRlcy5kZWZhdWx0LnN2YyJdLCJleHAiOjE1Mzk5NzA1NzUsImlhdCI6MTUzOTk2MzM3NSwiaXNzIjoia3ViZXJuZXRlcy9zZXJ2aWNlYWNjb3VudCIsImt1YmVybmV0ZXMuaW8iOnsibmFtZXNwYWNlIjoiZGVmYXVsdCIsInBvZCI6eyJuYW1lIjoidmF1bHQiLCJ1aWQiOiJiNmMyNThmNS1kM2I0LTExZTgtOGVmNC0wODAwMjdlNTVlYTgifSwic2VydmljZWFjY291bnQiOnsibmFtZSI6ImRlZmF1bHQiLCJ1aWQiOiJiMzg5YjNiMi1kMzAyLTExZTgtYjE0Yy0wODAwMjdlNTVlYTgifX0sIm5iZiI6MTUzOTk2MzM3NSwic3ViIjoic3lzdGVtOnNlcnZpY2VhY2NvdW50OmRlZmF1bHQ6ZGVmYXVsdCJ9.C0waXVzwShlLM3ahJkU9LH5qcFhZ2E_p7zUCkTNf0aOtu25CpF7ARsiUty_smQhLizC5wTj7GUMzXzDSkDMh6ZJEciac6UW4g2Nz9HSh3X1DS8bvP3hX_QP_TYip7DoA4mvl7ThzFbbfmRZAfjnAdJBhKX_NxJWxEfxflYwI71CMtGAu4P7IR1Dlj5tdkUR7crQl9Q7vP4nH_s0f695RkDEJT17J6ynGYVr8VMLsHbEKEJ_JqUYFVdGnYVy-Q2hQ-4JTk-5vwug72mdrDDalSSx3KPqkIJklv0kjbLmCUPyge3cpiEvhr5M79TNHNEnlRDA5xLgMNp--HcjzXNdajQ"

// testMinikubePubKey is the public key of the minikube instance used to
// generate the projected token signature for jwtProjectedData and
// jwtProjectedDataExpired above.
//
// To setup a minikube instance to replicate or re-generate keys if needed, use
// this invocation:
//
// minikube start --kubernetes-version v1.12.1  \
//   --feature-gates="TokenRequest=true,TokenRequestProjection=true" \
//   --extra-config=apiserver.service-account-signing-key-file=/var/lib/minikube/certs/sa.key \
//   --extra-config=apiserver.service-account-issuer="kubernetes/serviceaccount" \
//   --extra-config=apiserver.service-account-api-audiences="kubernetes.default.svc" \
//   --extra-config=apiserver.service-account-key-file=/var/lib/minikube/certs/sa.pub
//
// When Minikube is up, use `minikube ssh` to connect and extract the contents
// of sa.pub for use here.
//
var testMinikubePubKey = `
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnz2IA2XKkdKqcRI1AfBi
Q836H1vrYWjwh96m5b1TgOzZXx+xZfsZ+7csJP7Umn3Q5wlLI1rokrJHuoEoQEmQ
lsShMkmPGEXpXctYU4rk3s6xd9Iqp6zq1kZnoPz2Q3w1k3SrcePZFEe2PaYtvdv9
C5Y4sXsAuPACyaMtCWDVROpGD4c4V5TpenGSUR4Pv7IVeoH1rSaPc5gdkF2JDwgD
ubAfMIRxlN3nY+KHsSGyzFuaXrLbKVI+EzDY22INN5S1qHH7ytKIM2mZ52kTRK/D
0mZ7PLuq6qRuokHTkUiCY3y2OEcXNHroqxuiZGyUKKzYcRDO67Ai0Nqf6waCm0YC
kQIDAQAB
-----END PUBLIC KEY-----`
