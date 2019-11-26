package pac

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"log"
	"testing"

	"github.com/hashicorp/vault-plugin-auth-kerberos/internal/gokrb5/keytab"
	"github.com/hashicorp/vault-plugin-auth-kerberos/internal/gokrb5/test/testdata"
	"github.com/hashicorp/vault-plugin-auth-kerberos/internal/gokrb5/types"
	"github.com/stretchr/testify/assert"
)

func TestPACTypeVerify(t *testing.T) {
	t.Parallel()
	b, err := hex.DecodeString(testdata.MarshaledPAC_AD_WIN2K_PAC)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}
	var pac PACType
	err = pac.Unmarshal(b)
	if err != nil {
		t.Fatalf("Error unmarshaling test data: %v", err)
	}

	b, _ = hex.DecodeString(testdata.SYSHTTP_KEYTAB)
	kt := keytab.New()
	kt.Unmarshal(b)
	pn, _ := types.ParseSPNString("sysHTTP")
	key, err := kt.GetEncryptionKey(pn, "TEST.GOKRB5", 2, 18)
	if err != nil {
		t.Fatalf("Error getting key: %v", err)
	}
	w := bytes.NewBufferString("")
	l := log.New(w, "", 0)
	err = pac.ProcessPACInfoBuffers(key, l)
	if err != nil {
		t.Fatalf("Processing reference pac error: %v", err)
	}

	pacInvalidServerSig := pac
	// Check the signature to force failure
	pacInvalidServerSig.ServerChecksum.Signature[0] ^= 0xFF
	pacInvalidNilKerbValidationInfo := pac
	pacInvalidNilKerbValidationInfo.KerbValidationInfo = nil
	pacInvalidNilServerSig := pac
	pacInvalidNilServerSig.ServerChecksum = nil
	pacInvalidNilKdcSig := pac
	pacInvalidNilKdcSig.KDCChecksum = nil
	pacInvalidClientInfo := pac
	pacInvalidClientInfo.ClientInfo = nil

	var pacs = []struct {
		pac PACType
	}{
		{pacInvalidServerSig},
		{pacInvalidNilKerbValidationInfo},
		{pacInvalidNilServerSig},
		{pacInvalidNilKdcSig},
		{pacInvalidClientInfo},
	}
	for i, s := range pacs {
		v, _ := s.pac.verify(key)
		assert.False(t, v, fmt.Sprintf("Validation should have failed for test %v", i))
	}

}
