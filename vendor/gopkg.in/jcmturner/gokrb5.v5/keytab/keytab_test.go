package keytab

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"gopkg.in/jcmturner/gokrb5.v5/testdata"
)

func TestParse(t *testing.T) {
	t.Parallel()
	dat, _ := hex.DecodeString(testdata.TESTUSER1_KEYTAB)
	kt, err := Parse(dat)
	if err != nil {
		t.Fatalf("Error parsing keytab data: %v\n", err)
	}
	assert.Equal(t, uint8(2), kt.Version, "Keytab version not as expected")
	assert.Equal(t, uint32(1), kt.Entries[0].KVNO, "KVNO not as expected")
	assert.Equal(t, uint8(1), kt.Entries[0].KVNO8, "KVNO8 not as expected")
	assert.Equal(t, time.Unix(1505669592, 0), kt.Entries[0].Timestamp, "Timestamp not as expected")
	assert.Equal(t, int32(17), kt.Entries[0].Key.KeyType, "Key's EType not as expected")
	assert.Equal(t, "698c4df8e9f60e7eea5a21bf4526ad25", hex.EncodeToString(kt.Entries[0].Key.KeyValue), "Key material not as expected")
	assert.Equal(t, int16(1), kt.Entries[0].Principal.NumComponents, "Number of components in principal not as expected")
	assert.Equal(t, int32(1), kt.Entries[0].Principal.NameType, "Name type of principal not as expected")
	assert.Equal(t, "TEST.GOKRB5", kt.Entries[0].Principal.Realm, "Realm of principal not as expected")
	assert.Equal(t, "testuser1", kt.Entries[0].Principal.Components[0], "Component in principal not as expected")
}

func TestMarshal(t *testing.T) {
	t.Parallel()
	dat, _ := hex.DecodeString(testdata.TESTUSER1_KEYTAB)
	kt, err := Parse(dat)
	if err != nil {
		t.Fatalf("Error parsing keytab data: %v\n", err)
	}
	b, err := kt.Marshal()
	if err != nil {
		t.Fatalf("Error marshaling: %v", err)
	}
	assert.Equal(t, dat, b, "Marshaled bytes not the same as input bytes")
	_, err = Parse(b)
	if err != nil {
		t.Fatalf("Error parsing marshaled bytes: %v", err)
	}
}
