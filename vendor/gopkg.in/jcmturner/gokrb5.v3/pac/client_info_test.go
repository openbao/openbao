package pac

import (
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"gopkg.in/jcmturner/gokrb5.v3/testdata"
	"testing"
	"time"
)

func TestPAC_ClientInfo_Unmarshal(t *testing.T) {
	b, err := hex.DecodeString(testdata.TestVectors["PAC_Client_Info"])
	if err != nil {
		t.Fatal("Could not decode test data hex string")
	}
	var k ClientInfo
	err = k.Unmarshal(b)
	if err != nil {
		t.Fatalf("Error unmarshaling test data: %v", err)
	}
	assert.Equal(t, time.Date(2017, 5, 6, 15, 53, 11, 000000000, time.UTC), k.ClientID.Time(), "Client ID time not as expected.")
	assert.Equal(t, uint16(18), k.NameLength, "Client name length not as expected")
	assert.Equal(t, "testuser1", k.Name, "Client name not as expected")
}
