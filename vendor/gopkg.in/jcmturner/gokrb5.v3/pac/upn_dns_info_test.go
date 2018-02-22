package pac

import (
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"gopkg.in/jcmturner/gokrb5.v3/testdata"
	"testing"
)

func TestUPN_DNSInfo_Unmarshal(t *testing.T) {
	b, err := hex.DecodeString(testdata.TestVectors["PAC_UPN_DNS_Info"])
	if err != nil {
		t.Fatal("Could not decode test data hex string")
	}
	var k UPNDNSInfo
	err = k.Unmarshal(b)
	if err != nil {
		t.Fatalf("Error unmarshaling test data: %v", err)
	}
	assert.Equal(t, uint16(42), k.UPNLength, "UPN Length not as expected")
	assert.Equal(t, uint16(16), k.UPNOffset, "UPN Offset not as expected")
	assert.Equal(t, uint16(22), k.DNSDomainNameLength, "DNS Domain Length not as expected")
	assert.Equal(t, uint16(64), k.DNSDomainNameOffset, "DNS Domain Offset not as expected")
	assert.Equal(t, "testuser1@test.gokrb5", k.UPN, "UPN not as expected")
	assert.Equal(t, "TEST.GOKRB5", k.DNSDomain, "DNS Domain not as expected")
	assert.Equal(t, uint32(0), k.Flags, "DNS Domain not as expected")
}
