// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package command

import (
	"bytes"
	"encoding/base64"
	"os"
	"testing"

	"github.com/openbao/openbao/helper/pgpkeys"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

func getPubKeyFiles(t *testing.T) (string, []string, error) {
	tempDir, err := os.MkdirTemp("", "vault-test")
	if err != nil {
		t.Fatalf("Error creating temporary directory: %s", err)
	}

	pubFiles := []string{
		tempDir + "/pubkey1",
		tempDir + "/pubkey2",
		tempDir + "/pubkey3",
		tempDir + "/aapubkey1",
	}
	decoder := base64.StdEncoding
	pub1Bytes, err := decoder.DecodeString(pgpkeys.TestPubKey1)
	if err != nil {
		t.Fatalf("Error decoding bytes for public key 1: %s", err)
	}
	err = os.WriteFile(pubFiles[0], pub1Bytes, 0o755)
	if err != nil {
		t.Fatalf("Error writing pub key 1 to temp file: %s", err)
	}
	pub2Bytes, err := decoder.DecodeString(pgpkeys.TestPubKey2)
	if err != nil {
		t.Fatalf("Error decoding bytes for public key 2: %s", err)
	}
	err = os.WriteFile(pubFiles[1], pub2Bytes, 0o755)
	if err != nil {
		t.Fatalf("Error writing pub key 2 to temp file: %s", err)
	}
	pub3Bytes, err := decoder.DecodeString(pgpkeys.TestPubKey3)
	if err != nil {
		t.Fatalf("Error decoding bytes for public key 3: %s", err)
	}
	err = os.WriteFile(pubFiles[2], pub3Bytes, 0o755)
	if err != nil {
		t.Fatalf("Error writing pub key 3 to temp file: %s", err)
	}
	err = os.WriteFile(pubFiles[3], []byte(pgpkeys.TestAAPubKey1), 0o755)
	if err != nil {
		t.Fatalf("Error writing aa pub key 1 to temp file: %s", err)
	}

	return tempDir, pubFiles, nil
}

func testPGPDecrypt(tb testing.TB, privKey, enc string) string {
	tb.Helper()

	privKeyBytes, err := base64.StdEncoding.DecodeString(privKey)
	if err != nil {
		tb.Fatal(err)
	}

	ptBuf := bytes.NewBuffer(nil)
	entity, err := openpgp.ReadEntity(packet.NewReader(bytes.NewBuffer(privKeyBytes)))
	if err != nil {
		tb.Fatal(err)
	}

	var rootBytes []byte
	rootBytes, err = base64.StdEncoding.DecodeString(enc)
	if err != nil {
		tb.Fatal(err)
	}

	entityList := &openpgp.EntityList{entity}
	md, err := openpgp.ReadMessage(bytes.NewBuffer(rootBytes), entityList, nil, nil)
	if err != nil {
		tb.Fatal(err)
	}
	ptBuf.ReadFrom(md.UnverifiedBody)
	return ptBuf.String()
}
