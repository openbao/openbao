// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ssh

import (
	"context"
	"strings"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
	"golang.org/x/crypto/ssh"
)

func TestSSH_ConfigCASubmitDefaultIssuer(t *testing.T) {
	// create backend config
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}

	// create and initialize backend
	b, err := Factory(context.Background(), config)
	if err != nil {
		t.Fatalf("Cannot create backend: %s", err)
	}

	// create a role to issue against
	roleName := "ca-issuance"
	roleOptions := map[string]interface{}{
		"allow_user_certificates": true,
		"allowed_users":           "*",
		"key_type":                "ca",
		"ttl":                     "30s",
		"not_before_duration":     "2h",
	}
	roleReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/" + roleName,
		Data:      roleOptions,
		Storage:   config.StorageView,
	}
	_, err = b.HandleRequest(context.Background(), roleReq)
	if err != nil {
		t.Fatalf("cannot create role to issue against: %s", err)
	}

	// create a default CA issuer to sign with
	createDefaultCaOptions := map[string]interface{}{
		"key_type":             "rsa",
		"key_bits":             2048,
		"generate_signing_key": true,
	}
	defaultCaReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/ca",
		Data:      createDefaultCaOptions,
		Storage:   config.StorageView,
	}
	resp, err := b.HandleRequest(context.Background(), defaultCaReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("cannot create CA issuer to perform signing operations: err: %v, resp: %v", err, resp)
	}

	if !strings.Contains(resp.Data["public_key"].(string), defaultCaReq.Data["key_type"].(string)) {
		t.Fatalf("expected public key of type %v but was %v", resp.Data["key_type"], defaultCaReq.Data["public_key"])
	}

	caPublicKey := resp.Data["public_key"].(string)
	if caPublicKey == "" {
		t.Fatal("expected a public key but got none")
	}

	// issue a signed key
	issueOptions := map[string]interface{}{
		"public_key": testCAPublicKeyEd25519,
	}
	issueReq := &logical.Request{
		Path:      "sign/" + roleName,
		Operation: logical.UpdateOperation,
		Storage:   config.StorageView,
		Data:      issueOptions,
	}
	resp, err = b.HandleRequest(context.Background(), issueReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err: %v, resp: %v", err, resp)
	}

	signedKey := resp.Data["signed_key"].(string)
	if signedKey == "" {
		t.Fatal("expected a signed key but got none")
	}

	// prepare test container
	cleanup, sshAddress := prepareTestContainer(t, dockerImageTagSupportsRSA1, caPublicKey)
	defer cleanup()

	privKey, err := ssh.ParsePrivateKey([]byte(testCAPrivateKeyEd25519))
	if err != nil {
		t.Fatalf("error parsing private key: %v", err)
	}

	parsedKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(signedKey))
	if err != nil {
		t.Fatalf("error parsing signed key: %v", err)
	}

	certSigner, err := ssh.NewCertSigner(parsedKey.(*ssh.Certificate), privKey)
	if err != nil {
		t.Fatalf("error creating cert signer: %v", err)
	}

	err = testSSH(testUserName, sshAddress, ssh.PublicKeys(certSigner), "date")
	if err == nil {
		t.Fatalf("did not expect error but but got: %v", err)
	}
}

func TestSSH_ConfigCAKeyTypes(t *testing.T) {
	var err error
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}

	b, err := Factory(context.Background(), config)
	if err != nil {
		t.Fatalf("Cannot create backend: %s", err)
	}

	cases := []struct {
		keyType string
		keyBits int
	}{
		{"ssh-rsa", 2048},
		{"ssh-rsa", 4096},
		{"ssh-rsa", 0},
		{"rsa", 2048},
		{"rsa", 4096},
		{"ecdsa-sha2-nistp256", 0},
		{"ecdsa-sha2-nistp384", 0},
		{"ecdsa-sha2-nistp521", 0},
		{"ec", 256},
		{"ec", 384},
		{"ec", 521},
		{"ec", 0},
		{"ssh-ed25519", 0},
		{"ed25519", 0},
	}

	// Create a role for ssh signing.
	roleOptions := map[string]interface{}{
		"allow_user_certificates": true,
		"allowed_users":           "*",
		"key_type":                "ca",
		"ttl":                     "30s",
		"not_before_duration":     "2h",
	}
	roleReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/ca-issuance",
		Data:      roleOptions,
		Storage:   config.StorageView,
	}
	_, err = b.HandleRequest(context.Background(), roleReq)
	if err != nil {
		t.Fatalf("Cannot create role to issue against: %s", err)
	}

	for index, scenario := range cases {
		createDeleteHelper(t, b, config, index, scenario.keyType, scenario.keyBits)
	}
}

func TestSSH_ConfigCAPurgeIssuers(t *testing.T) {
	// create backend config
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}

	// create and initialize backend
	b, err := Factory(context.Background(), config)
	if err != nil {
		t.Fatalf("Cannot create backend: %s", err)
	}

	// submit multiple CA issuers
	caIssuerOptions := []struct {
		keyType string
		keyBits int
	}{
		{"rsa", 2048},
		{"rsa", 4096},
		{"ed25519", 0},
	}

	for id, caIssuerOption := range caIssuerOptions {
		createDefaultCaOptions := map[string]interface{}{
			"key_type":             caIssuerOption.keyType,
			"key_bits":             caIssuerOption.keyBits,
			"generate_signing_key": true,
		}
		defaultCaReq := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "config/ca",
			Data:      createDefaultCaOptions,
			Storage:   config.StorageView,
		}
		resp, err := b.HandleRequest(context.Background(), defaultCaReq)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("issuer %d: cannot create CA issuer to perform signing operations: err: %v, resp: %v", id, err, resp)
		}
	}

	// list all isuers make sure all are present
	listReq := &logical.Request{
		Operation: logical.ListOperation,
		Path:      "issuers",
		Storage:   config.StorageView,
	}
	resp, err := b.HandleRequest(context.Background(), listReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("cannot list issuers: err: %v, resp: %v", err, resp)
	}

	if len(resp.Data["keys"].([]string)) != 3 {
		t.Fatalf("expected three issuers but got %d", len(resp.Data))
	}

	// purge all issuers
	purgeReq := &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "config/ca",
		Storage:   config.StorageView,
	}
	resp, err = b.HandleRequest(context.Background(), purgeReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("cannot purge CA issuers: err: %v, resp: %v", err, resp)
	}

	// list all isuers make sure none are present
	resp, err = b.HandleRequest(context.Background(), listReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("cannot list issuers: err: %v, resp: %v", err, resp)
	}

	if len(resp.Data) > 0 && len(resp.Data["keys"].([]string)) != 0 {
		t.Fatalf("expected no issuers but got %d", len(resp.Data))
	}
}

func TestSSH_ConfigCAReadDefaultIssuer(t *testing.T) {
	// create backend config
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}

	// create and initialize backend
	b, err := Factory(context.Background(), config)
	if err != nil {
		t.Fatalf("Cannot create backend: %s", err)
	}

	// submit an issuer and set as default
	createCaIssuerOptions := map[string]interface{}{
		"set_as_default": true,
	}
	createCaIssuerReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "issuers/import",
		Data:      createCaIssuerOptions,
		Storage:   config.StorageView,
	}
	resp, err := b.HandleRequest(context.Background(), createCaIssuerReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("cannot submit CA issuer as default: err: %v, resp: %v", err, resp)
	}

	// override existing 'default with 'config/ca' endpoint
	configDefaultCAOptions := map[string]interface{}{
		"private_key": testCAPrivateKey,
		"public_key":  testCAPublicKey,
	}
	configDefaultCARequest := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/ca",
		Data:      configDefaultCAOptions,
		Storage:   config.StorageView,
	}
	resp, err = b.HandleRequest(context.Background(), configDefaultCARequest)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("cannot submit a new CA and override existing 'default': err: %v, resp: %v", err, resp)
	}

	// read the 'default' issuer
	readDefaultIssuerRequest := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config/ca",
		Storage:   config.StorageView,
	}
	resp, err = b.HandleRequest(context.Background(), readDefaultIssuerRequest)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("cannot read default issuer: err: %v, resp: %v", err, resp)
	}

	if resp.Data["public_key"] == "" {
		t.Fatal("expected a public key but got none")
	}

	if resp.Data["public_key"] != testCAPublicKey {
		t.Fatalf("expected public key %v but got %v", testCAPublicKey, resp.Data["public_key"])
	}
}

func createDeleteHelper(t *testing.T, b logical.Backend, config *logical.BackendConfig, index int, keyType string, keyBits int) {
	// Check that we can create a new key of the specified type
	caReq := &logical.Request{
		Path:      "config/ca",
		Operation: logical.UpdateOperation,
		Storage:   config.StorageView,
	}
	caReq.Data = map[string]interface{}{
		"generate_signing_key": true,
		"key_type":             keyType,
		"key_bits":             keyBits,
	}
	resp, err := b.HandleRequest(context.Background(), caReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad case %v: err: %v, resp: %v", index, err, resp)
	}
	if !strings.Contains(resp.Data["public_key"].(string), caReq.Data["key_type"].(string)) {
		t.Fatalf("bad case %v: expected public key of type %v but was %v", index, caReq.Data["key_type"], resp.Data["public_key"])
	}

	issueOptions := map[string]interface{}{
		"public_key":       testCAPublicKeyEd25519,
		"valid_principals": "toor",
	}
	issueReq := &logical.Request{
		Path:      "sign/ca-issuance",
		Operation: logical.UpdateOperation,
		Storage:   config.StorageView,
		Data:      issueOptions,
	}
	resp, err = b.HandleRequest(context.Background(), issueReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad case %v: err: %v, resp: %v", index, err, resp)
	}

	// Delete the configured keys
	caReq.Operation = logical.DeleteOperation
	resp, err = b.HandleRequest(context.Background(), caReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad case %v: err: %v, resp: %v", index, err, resp)
	}
}
