// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package dependency

import (
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"reflect"
	"runtime"
	"testing"

	vapi "github.com/openbao/openbao/api"
	"github.com/openbao/openbao/command/template/test"
)

const (
	vaultAddr  = "http://127.0.0.1:8200"
	vaultToken = "a_token"
)

var (
	testVault   *vaultServer
	testClients *ClientSet
)

func TestMain(m *testing.M) {
	log.SetOutput(io.Discard)
	runTestVault()
	tb := &test.TestingTB{}
	clients := NewClientSet()
	if err := clients.CreateVaultClient(&CreateVaultClientInput{
		Address: vaultAddr,
		Token:   vaultToken,
	}); err != nil {
		testVault.Stop()
		Fatalf("failed to create vault client: %v\n", err)
	}
	testClients = clients

	setupVaultPKI(clients)

	exitCh := make(chan int, 1)
	func() {
		defer func() {
			// Attempt to recover from a panic and stop the server. If we don't
			// stop it, the panic will cause the server to remain running in
			// the background. Here we catch the panic and the re-raise it.
			if r := recover(); r != nil {
				testVault.Stop()
				panic(r)
			}
		}()

		exitCh <- m.Run()
	}()

	exit := <-exitCh

	tb.DoCleanup()
	testVault.Stop()
	os.Exit(exit)
}

type vaultServer struct {
	secretsPath string
	cmd         *exec.Cmd
}

func runTestVault() {
	// TODO: convert to vault.NewTestCluster(...) instead.
	path, err := exec.LookPath("bao")
	if err != nil || path == "" {
		Fatalf("bao not found on $PATH")
	}
	args := []string{
		"server", "-dev", "-dev-root-token-id", vaultToken,
		"-dev-no-store-token",
	}
	cmd := exec.Command("bao", args...)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard

	if err := cmd.Start(); err != nil {
		Fatalf("bao failed to start: %v", err)
	}
	testVault = &vaultServer{
		cmd: cmd,
	}
}

func (v vaultServer) Stop() error {
	if v.cmd != nil && v.cmd.Process != nil {
		return v.cmd.Process.Signal(os.Interrupt)
	}
	return nil
}

func testVaultServer(t *testing.T, secrets_path, version string,
) (*ClientSet, *vaultServer) {
	vc := testClients.Vault()
	if err := vc.Sys().Mount(secrets_path, &vapi.MountInput{
		Type:        "kv",
		Description: "test mount",
		Options:     map[string]string{"version": version},
	}); err != nil {
		t.Fatalf("Error creating secrets engine: %s", err)
	}
	return testClients, &vaultServer{secretsPath: secrets_path}
}

func (v *vaultServer) CreateSecret(path string, data map[string]interface{},
) error {
	q, err := NewVaultWriteQuery(v.secretsPath+"/"+path, data)
	if err != nil {
		return err
	}
	_, err = q.writeSecret(testClients, &QueryOptions{})
	if err != nil {
		fmt.Println(err)
	}
	return err
}

// deleteSecret lets us delete keys as needed for tests
func (v *vaultServer) deleteSecret(path string) error {
	_, err := testClients.Vault().Logical().Delete(v.secretsPath + "/" + path)
	if err != nil {
		fmt.Println(err)
	}
	return err
}

func TestCanShare(t *testing.T) {
	deps := []Dependency{
		&FileQuery{},
		&VaultListQuery{},
		&VaultReadQuery{},
		&VaultTokenQuery{},
		&VaultWriteQuery{},
	}

	for _, d := range deps {
		if d.CanShare() {
			t.Errorf("should not share %s", d)
		}
	}
}

func TestDeepCopyAndSortTags(t *testing.T) {
	tags := []string{"hello", "world", "these", "are", "tags", "foo:bar", "baz=qux"}
	expected := []string{"are", "baz=qux", "foo:bar", "hello", "tags", "these", "world"}

	result := deepCopyAndSortTags(tags)
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("expected %#v to be %#v", result, expected)
	}
}

func Fatalf(format string, args ...interface{}) {
	fmt.Printf(format, args...)
	runtime.Goexit()
}
