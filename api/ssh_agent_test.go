// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package api

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func TestSSH_CreateTLSClient(t *testing.T) {
	// load the default configuration
	config, err := LoadSSHHelperConfig("./test-fixtures/agent_config.hcl")
	if err != nil {
		t.Fatalf("error loading agent's config file: %s", err)
	}

	_, err = config.NewClient()
	if err != nil {
		t.Errorf("error creating the client: %s", err)
	}

	// Provide a certificate and enforce setting of transport
	config.CACert = "./test-fixtures/vault.crt"

	client, err := config.NewClient()
	if err != nil {
		t.Fatalf("error creating the client: %s", err)
	}
	if client.config.HttpClient.Transport == nil {
		t.Fatal("error creating client with TLS transport")
	}
}

func TestSSH_CreateTLSClient_tlsServerName(t *testing.T) {
	// Ensure that the HTTP client is associated with the configured TLS server name.
	tlsServerName := "tls.server.name"

	config, err := ParseSSHHelperConfig(fmt.Sprintf(`
vault_addr = "1.2.3.4"
tls_server_name = "%s"
`, tlsServerName))
	if err != nil {
		t.Fatalf("error loading config: %s", err)
	}

	client, err := config.NewClient()
	if err != nil {
		t.Fatalf("error creating the client: %s", err)
	}

	actualTLSServerName := client.config.HttpClient.Transport.(*http.Transport).TLSClientConfig.ServerName
	if actualTLSServerName != tlsServerName {
		t.Fatalf("incorrect TLS server name. expected: %s actual: %s", tlsServerName, actualTLSServerName)
	}
}

func TestParseSSHHelperConfig(t *testing.T) {
	config, err := ParseSSHHelperConfig(`
		vault_addr = "1.2.3.4"
`)
	if err != nil {
		t.Fatal(err)
	}

	if config.SSHMountPoint != SSHHelperDefaultMountPoint {
		t.Errorf("expected %q to be %q", config.SSHMountPoint, SSHHelperDefaultMountPoint)
	}
}

func TestParseSSHHelperConfig_missingVaultAddr(t *testing.T) {
	_, err := ParseSSHHelperConfig("")
	if err == nil {
		t.Fatal("expected error")
	}

	if !strings.Contains(err.Error(), `missing config "vault_addr"`) {
		t.Errorf("bad error: %s", err)
	}
}

func TestParseSSHHelperConfig_badKeys(t *testing.T) {
	_, err := ParseSSHHelperConfig(`
vault_addr = "1.2.3.4"
nope = "bad"
`)
	if err == nil {
		t.Fatal("expected error")
	}

	if !strings.Contains(err.Error(), `ssh_helper: invalid key "nope" on line 3`) {
		t.Errorf("bad error: %s", err)
	}
}

func TestParseSSHHelperConfig_tlsServerName(t *testing.T) {
	tlsServerName := "tls.server.name"

	config, err := ParseSSHHelperConfig(fmt.Sprintf(`
vault_addr = "1.2.3.4"
tls_server_name = "%s"
`, tlsServerName))
	if err != nil {
		t.Fatal(err)
	}

	if config.TLSServerName != tlsServerName {
		t.Errorf("incorrect TLS server name. expected: %s actual: %s", tlsServerName, config.TLSServerName)
	}
}
