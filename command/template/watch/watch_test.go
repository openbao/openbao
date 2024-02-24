// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package watch

import (
	"encoding/json"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	dep "github.com/hashicorp/consul-template/dependency"
	"github.com/hashicorp/vault/api"
)

const (
	vaultAddr  = "http://127.0.0.1:8200"
	vaultToken = "a_token"
)

var (
	testVault   *vaultServer
	testClients *dep.ClientSet
	tokenRoleId string
)

func TestMain(m *testing.M) {
	os.Exit(main(m))
}

// sub-main so I can use defer
func main(m *testing.M) int {
	log.SetOutput(io.Discard)
	testVault = newTestVault()
	defer func() { testVault.Stop() }()

	clients := dep.NewClientSet()
	if err := clients.CreateVaultClient(&dep.CreateVaultClientInput{
		Address: vaultAddr,
		Token:   vaultToken,
	}); err != nil {
		panic(err)
	}

	testClients = clients
	tokenRoleId = vaultTokenSetup(clients)

	return m.Run()
}

type vaultServer struct {
	cmd *exec.Cmd
}

func (v vaultServer) Stop() error {
	if v.cmd != nil && v.cmd.Process != nil {
		return v.cmd.Process.Signal(os.Interrupt)
	}
	return nil
}

func newTestVault() *vaultServer {
	path, err := exec.LookPath("vault")
	if err != nil || path == "" {
		panic("vault not found on $PATH")
	}
	args := []string{
		"server", "-dev", "-dev-root-token-id", vaultToken,
		"-dev-no-store-token",
	}
	cmd := exec.Command("vault", args...)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard

	if err := cmd.Start(); err != nil {
		panic("vault failed to start: " + err.Error())
	}
	return &vaultServer{
		cmd: cmd,
	}
}

// Sets up approle auto-auth for token generation/testing
func vaultTokenSetup(clients *dep.ClientSet) string {
	vc := clients.Vault()

	// vault auth enable approle
	err := vc.Sys().EnableAuthWithOptions("approle",
		&api.MountInput{
			Type: "approle",
		})
	if err != nil && !strings.Contains(err.Error(), "path is already in use") {
		panic(err)
	}

	// vault policy write foo 'path ...'
	err = vc.Sys().PutPolicy("foo",
		`path "secret/data/foo" { capabilities = ["read"] }`)
	if err != nil {
		panic(err)
	}

	// vault write auth/approle/role/foo ...
	_, err = vc.Logical().Write("auth/approle/role/foo",
		map[string]interface{}{
			"token_policies":     "foo",
			"secret_id_num_uses": 100,
			"secret_id_ttl":      "5m",
			"token_num_users":    10,
			"token_ttl":          "7m",
			"token_max_ttl":      "10m",
		})
	if err != nil {
		panic(err)
	}

	var sec *api.Secret
	// vault read -field=role_id auth/approle/role/foo/role-id
	sec, err = vc.Logical().Read("auth/approle/role/foo/role-id")
	if err != nil {
		panic(err)
	}
	role_id := sec.Data["role_id"]
	return role_id.(string)
}

// returns path to token file (which is created by the agent run)
// token file isn't cleaned, so use returned path to remove it when done
func runVaultAgent(clients *dep.ClientSet, role_id string) string {
	dir, err := os.MkdirTemp("", "consul-template-test")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	tokenFile := filepath.Join("", "vatoken.txt")

	role_idPath := filepath.Join(dir, "roleid")
	secret_idPath := filepath.Join(dir, "secretid")
	vaconf := filepath.Join(dir, "vault-agent-config.json")

	// Generate secret_id, need new one for each agent run
	// vault write -f -field secret_id auth/approle/role/foo/secret-id
	vc := clients.Vault()
	sec, err := vc.Logical().Write("auth/approle/role/foo/secret-id", nil)
	if err != nil {
		panic(err)
	}
	secret_id := sec.Data["secret_id"].(string)
	err = os.WriteFile(secret_idPath, []byte(secret_id), 0o444)
	if err != nil {
		panic(err)
	}
	err = os.WriteFile(role_idPath, []byte(role_id), 0o444)
	if err != nil {
		panic(err)
	}

	type obj map[string]interface{}
	type list []obj
	va := obj{
		"vault": obj{"address": vaultAddr},
		"auto_auth": obj{
			"method": obj{
				"type": "approle",
				"config": obj{
					"role_id_file_path":   role_idPath,
					"secret_id_file_path": secret_idPath,
				},
				"wrap_ttl": "5m",
			},
			"sinks": list{
				{"sink": obj{"type": "file", "config": obj{"path": tokenFile}}},
			},
		},
	}
	txt, err := json.Marshal(va)
	if err != nil {
		panic(err)
	}
	err = os.WriteFile(vaconf, txt, 0o644)
	if err != nil {
		panic(err)
	}

	args := []string{
		"agent", "-exit-after-auth", "-config=" + vaconf,
	}
	cmd := exec.Command("vault", args...)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard

	if err := cmd.Run(); err != nil {
		panic("vault agent failed to run: " + err.Error())
	}
	return tokenFile
}
