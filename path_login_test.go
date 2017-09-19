package kubeauth

import (
	"crypto/rsa"
	"testing"

	multierror "github.com/hashicorp/go-multierror"
	"github.com/hashicorp/vault/logical"
)

var (
	testNamespace string = "default"
	testName      string = "vault-auth"
	testUID       string = "d77f89bc-9055-11e7-a068-0800276d99bf"
)

func setupBackend(t *testing.T) (logical.Backend, logical.Storage) {
	b, storage := getBackend(t)

	// test no certificate
	data := map[string]interface{}{
		"pem_keys":           []string{testECCert, testRSACert},
		"kubernetes_host":    "host",
		"kubernetes_ca_cert": testCACert,
	}

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   storage,
		Data:      data,
	}

	resp, err := b.HandleRequest(req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	data = map[string]interface{}{
		"bound_service_account_names":      testName,
		"bound_service_account_namespaces": testNamespace,
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

	resp, err = b.HandleRequest(req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	return b, storage
}

func TestLogin(t *testing.T) {
	b, storage := setupBackend(t)
	b.(*kubeAuthBackend).reviewFactory = mockTokenReviewFactory(testName, testNamespace, testUID)

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

	resp, err := b.HandleRequest(req)
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

	resp, err = b.HandleRequest(req)
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

	resp, err = b.HandleRequest(req)
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
	}

	resp, err = b.HandleRequest(req)
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
	}

	resp, err = b.HandleRequest(req)
	if err == nil {
		t.Fatal("expected error")
	}
	var expectedErr error
	expectedErr = multierror.Append(expectedErr, errMismatchedSigningMethod, rsa.ErrVerification)
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
	}

	resp, err = b.HandleRequest(req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}
}

func TestPersonaLookAhead(t *testing.T) {
	b, storage := setupBackend(t)

	// Test bad inputs
	data := map[string]interface{}{
		"jwt": jwtData,
	}

	req := &logical.Request{
		Operation: logical.PersonaLookaheadOperation,
		Path:      "login",
		Storage:   storage,
		Data:      data,
	}

	resp, err := b.HandleRequest(req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	if resp.Auth.Persona.Name != testUID {
		t.Fatalf("Unexpected UID: %s", resp.Auth.Persona.Name)
	}
}

var jwtData string = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJkZWZhdWx0Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZWNyZXQubmFtZSI6InZhdWx0LWF1dGgtdG9rZW4tdDVwY24iLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC5uYW1lIjoidmF1bHQtYXV0aCIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50LnVpZCI6ImQ3N2Y4OWJjLTkwNTUtMTFlNy1hMDY4LTA4MDAyNzZkOTliZiIsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDpkZWZhdWx0OnZhdWx0LWF1dGgifQ.HKUcqgrvan5ZC_mnpaMEx4RW3KrhfyH_u8G_IA2vUfkLK8tH3T7fJuJaPr7W6K_BqCrbeM5y3owszOzb4NR0Lvw6GBt2cFcen2x1Ua4Wokr0bJjTT7xQOIOw7UvUDyVS17wAurlfUnmWMwMMMOebpqj5K1t6GnyqghH1wPdHYRGX-q5a6C323dBCgM5t6JY_zTTaBgM6EkFq0poBaifmSMiJRPrdUN_-IgyK8fgQRiFYYkgS6DMIU4k4nUOb_sUFf5xb8vMs3SMteKiuWFAIt4iszXTj5IyBUNqe0cXA3zSY3QiNCV6bJ2CWW0Qf9WDtniT79VAqcR4GYaTC_gxjNA"

var jwtBadServiceAccount string = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJkZWZhdWx0Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZWNyZXQubmFtZSI6InZhdWx0LWludmFsaWQtdG9rZW4tZ3ZxcHQiLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC5uYW1lIjoidmF1bHQtaW52YWxpZCIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50LnVpZCI6IjA0NGZkNGYxLTk3NGQtMTFlNy05YTE1LTA4MDAyNzZkOTliZiIsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDpkZWZhdWx0OnZhdWx0LWludmFsaWQifQ.BcoOdu5BrIchp66Zl8-dY7HcGHJrVXrUh4SNTlIHR6vDaNH29B7JuI_-B1pvW9GpzQnc-XjZyua_wfSssqe-KYJcq--Qh0yQfbbLE5rvEipBCHH341IqGaTHaBVip8zXqYE-bt-7J6vAH8Azvw46iatDC73tKxh46xDuxK0gKjdprW4cOklDx6ZSxEHpu63ftLYgAgk9c0MUJxKWhu9Jk0aye5pTj_iyBbBy8llZNGaw2gxvhPzFVUEHZUlTRiSIbmPmNqep48RiJoWrq6FM1lijvrtT5y-E7aFk6TpW2BH3VDHy8k10sMIxuRAYrGB3tpUKNyVDI3tJOi_xY7iJvw"

var jwtWithBadSigningKey string = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJkZWZhdWx0Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZWNyZXQubmFtZSI6InZhdWx0LWludmFsaWQtdG9rZW4tZ3ZxcHQiLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC5uYW1lIjoidmF1bHQtaW52YWxpZCIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50LnVpZCI6IjA0NGZkNGYxLTk3NGQtMTFlNy05YTE1LTA4MDAyNzZkOTliZiIsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDpkZWZhdWx0OnZhdWx0LWludmFsaWQifQ.QksgZ6da6-W_9lPZ0cdcZzz45MivigwdQnVbBrmPjCAfntkVlYhkPbKTBEuRK3WD6uBt_RJkhQnAF1xiy4rUqawbPqJzU_1i8mLMejc5FdDUrci7nJybKGVBLQe1UA_AMl3a97WqXuLOjav9aIG0f_blCTd9BfIvnfgquPwf23U"
