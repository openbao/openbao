package keytab

import (
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

//Keytab data generated from ktutil
const keytabDataHexStr = "0502000000320001000b4558414d504c452e434f4d00047573657200000001586aa82d01001700100c61039f010b2fbb88fe449fbf262477000000420001000b4558414d504c452e434f4d00047573657200000001586aa82d010012002053142f614ee6c39823710d9f31ff2984ed0bd9074d6e542e8468137f7b909c17000000320001000b4558414d504c452e434f4d00047573657200000001586beaad01001700100c61039f010b2fbb88fe449fbf262477000000420001000b4558414d504c452e434f4d00047573657200000001586beaae010012002053142f614ee6c39823710d9f31ff2984ed0bd9074d6e542e8468137f7b909c17000000430001000b4a544c414e2e434f2e554b000562696c6c7900000001586beaae1f00120020508dd2b209064e101bf209caef5fda236875706a5e9ad47c157db5907778785f"

func TestParse(t *testing.T) {
	dat, _ := hex.DecodeString(keytabDataHexStr)
	kt, err := Parse(dat)
	if err != nil {
		t.Fatalf("Error parsing keytab data: %v\n", err)
	}
	assert.Equal(t, uint16(2), kt.Version, "Keytab version not as expected")
	assert.Equal(t, uint32(1), kt.Entries[0].KVNO, "KVNO not as expected")
	assert.Equal(t, uint8(1), kt.Entries[0].KVNO8, "KVNO8 not as expected")
	assert.Equal(t, time.Unix(1483384877, 0), kt.Entries[0].Timestamp, "Timestamp not as expected")
	assert.Equal(t, 23, kt.Entries[0].Key.KeyType, "Key's EType not as expected")
	assert.Equal(t, "0c61039f010b2fbb88fe449fbf262477", hex.EncodeToString(kt.Entries[0].Key.KeyValue), "Key material not as expected")
	assert.Equal(t, int16(1), kt.Entries[0].Principal.NumComponents, "Number of components in principal not as expected")
	assert.Equal(t, int32(1), kt.Entries[0].Principal.NameType, "Name type of principal not as expected")
	assert.Equal(t, "EXAMPLE.COM", kt.Entries[0].Principal.Realm, "Realm of principal not as expected")
	assert.Equal(t, "user", kt.Entries[0].Principal.Components[0], "Component in principal not as expected")
}
