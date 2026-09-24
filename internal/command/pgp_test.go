// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package command

import (
	"bytes"
	"encoding/base64"
	"os"
	"testing"

	"github.com/openbao/openbao/v2/internal/helper/pgpkeys"
	"github.com/stretchr/testify/require"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

func getPubKeyFiles(t *testing.T) ([]string, error) {
	tempDir := t.TempDir()

	pubFiles := []string{
		tempDir + "/pubkey1",
		tempDir + "/pubkey2",
		tempDir + "/pubkey3",
		tempDir + "/aapubkey1",
	}
	decoder := base64.StdEncoding
	pub1Bytes, err := decoder.DecodeString(pgpkeys.TestPubKey1)
	require.NoError(t, err)
	err = os.WriteFile(pubFiles[0], pub1Bytes, 0o755)
	require.NoError(t, err)
	pub2Bytes, err := decoder.DecodeString(pgpkeys.TestPubKey2)
	require.NoError(t, err)
	err = os.WriteFile(pubFiles[1], pub2Bytes, 0o755)
	require.NoError(t, err)
	pub3Bytes, err := decoder.DecodeString(pgpkeys.TestPubKey3)
	require.NoError(t, err)
	err = os.WriteFile(pubFiles[2], pub3Bytes, 0o755)
	require.NoError(t, err)
	err = os.WriteFile(pubFiles[3], []byte(pgpkeys.TestAAPubKey1), 0o755)
	require.NoError(t, err)

	return pubFiles, nil
}

func testPGPDecrypt(tb testing.TB, privKey, enc string) string {
	tb.Helper()

	privKeyBytes, err := base64.StdEncoding.DecodeString(privKey)
	require.NoError(tb, err)

	ptBuf := bytes.NewBuffer(nil)
	entity, err := openpgp.ReadEntity(packet.NewReader(bytes.NewBuffer(privKeyBytes)))
	require.NoError(tb, err)

	var rootBytes []byte
	rootBytes, err = base64.StdEncoding.DecodeString(enc)
	require.NoError(tb, err)

	entityList := &openpgp.EntityList{entity}
	md, err := openpgp.ReadMessage(bytes.NewBuffer(rootBytes), entityList, nil, nil)
	require.NoError(tb, err)
	ptBuf.ReadFrom(md.UnverifiedBody)
	return ptBuf.String()
}
