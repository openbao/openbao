// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package dependency

import (
	"os"
	"strings"
	"testing"

	"github.com/hashicorp/consul-template/renderer"
	"github.com/stretchr/testify/assert"
)

func TestVaultAgentTokenQuery_Fetch(t *testing.T) {
	// Don't use t.Parallel() here as the SetToken() calls are global and break
	// other tests if run in parallel

	// Set up the Vault token file.
	tokenFile, err := os.CreateTemp("", "token1")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tokenFile.Name())
	renderer.AtomicWrite(tokenFile.Name(), false, []byte("token"), 0o644, false)

	d, err := NewVaultAgentTokenQuery(tokenFile.Name())
	if err != nil {
		t.Fatal(err)
	}

	clientSet := testClients
	token, _, err := d.Fetch(clientSet, nil)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "token", token)

	// Update the contents.
	renderer.AtomicWrite(
		tokenFile.Name(), false, []byte("another_token"), 0o644, false)
	token, _, err = d.Fetch(clientSet, nil)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "another_token", token)
}

func TestVaultAgentTokenQuery_Fetch_missingFile(t *testing.T) {
	// Use a non-existant token file path.
	d, err := NewVaultAgentTokenQuery("/tmp/invalid-file")
	if err != nil {
		t.Fatal(err)
	}

	clientSet := NewClientSet()
	clientSet.CreateVaultClient(&CreateVaultClientInput{
		Token: "foo",
	})
	_, _, err = d.Fetch(clientSet, nil)
	if err == nil || !strings.Contains(err.Error(), "no such file") {
		t.Fatal(err)
	}

	// Token should be unaffected.
	assert.Equal(t, "foo", clientSet.Vault().Token())
}
