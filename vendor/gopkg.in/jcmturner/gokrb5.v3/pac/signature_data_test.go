package pac

import (
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"gopkg.in/jcmturner/gokrb5.v3/iana/chksumtype"
	"gopkg.in/jcmturner/gokrb5.v3/testdata"
	"testing"
)

func TestPAC_SignatureData_Unmarshal_Server_Signature(t *testing.T) {
	b, err := hex.DecodeString(testdata.TestVectors["PAC_Server_Signature"])
	if err != nil {
		t.Fatal("Could not decode test data hex string")
	}
	var k SignatureData
	bz, err := k.Unmarshal(b)
	if err != nil {
		t.Fatalf("Error unmarshaling test data: %v", err)
	}
	sig, _ := hex.DecodeString("1e251d98d552be7df384f550")
	zeroed, _ := hex.DecodeString("10000000000000000000000000000000")
	assert.Equal(t, uint32(chksumtype.HMAC_SHA1_96_AES256), k.SignatureType, "Server signature type not as expected")
	assert.Equal(t, sig, k.Signature, "Server signature not as expected")
	assert.Equal(t, uint16(0), k.RODCIdentifier, "RODC Identifier not as expected")
	assert.Equal(t, zeroed, bz, "Returned bytes with zeroed signature not as expected")
}

func TestPAC_SignatureData_Unmarshal_KDC_Signature(t *testing.T) {
	b, err := hex.DecodeString(testdata.TestVectors["PAC_KDC_Signature"])
	if err != nil {
		t.Fatal("Could not decode test data hex string")
	}
	var k SignatureData
	bz, err := k.Unmarshal(b)
	if err != nil {
		t.Fatalf("Error unmarshaling test data: %v", err)
	}
	sig, _ := hex.DecodeString("340be28b48765d0519ee9346cf53d822")
	zeroed, _ := hex.DecodeString("76ffffff00000000000000000000000000000000")
	assert.Equal(t, uint32(chksumtype.KERB_CHECKSUM_HMAC_MD5_UNSIGNED), k.SignatureType, "Server signature type not as expected")
	assert.Equal(t, sig, k.Signature, "Server signature not as expected")
	assert.Equal(t, uint16(0), k.RODCIdentifier, "RODC Identifier not as expected")
	assert.Equal(t, zeroed, bz, "Returned bytes with zeroed signature not as expected")
}
