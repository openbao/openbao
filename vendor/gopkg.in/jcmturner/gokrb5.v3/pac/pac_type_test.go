package pac

import (
	"encoding/hex"
	"fmt"
	"github.com/stretchr/testify/assert"
	"gopkg.in/jcmturner/gokrb5.v3/keytab"
	"gopkg.in/jcmturner/gokrb5.v3/testdata"
	"testing"
)

func TestPACTypeValidate(t *testing.T) {
	v := "PAC_AD_WIN2K_PAC"
	b, err := hex.DecodeString(testdata.TestVectors[v])
	if err != nil {
		t.Fatalf("Test vector read error of %s: %v\n", v, err)
	}
	var pac PACType
	err = pac.Unmarshal(b)
	if err != nil {
		t.Fatalf("Error unmarshaling test data: %v", err)
	}

	b, _ = hex.DecodeString(testdata.SYSHTTP_KEYTAB)
	kt, _ := keytab.Parse(b)
	key, err := kt.GetEncryptionKey([]string{"sysHTTP"}, "TEST.GOKRB5", 2, 18)
	if err != nil {
		t.Fatalf("Error getting key: %v", err)
	}
	err = pac.ProcessPACInfoBuffers(key)
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
		v, _ := s.pac.validate(key)
		assert.False(t, v, fmt.Sprintf("Validation should have failed for test %v", i))
	}

}
