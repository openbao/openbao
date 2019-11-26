package keytab

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hashicorp/vault-plugin-auth-kerberos/internal/gokrb5/test/testdata"
	"github.com/stretchr/testify/assert"
)

func TestUnmarshal(t *testing.T) {
	t.Parallel()
	b, _ := hex.DecodeString(testdata.TESTUSER1_KEYTAB)
	kt := New()
	err := kt.Unmarshal(b)
	if err != nil {
		t.Fatalf("Error parsing keytab data: %v\n", err)
	}
	assert.Equal(t, uint8(2), kt.version, "Keytab version not as expected")
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
	b, _ := hex.DecodeString(testdata.TESTUSER1_KEYTAB)
	kt := New()
	err := kt.Unmarshal(b)
	if err != nil {
		t.Fatalf("Error parsing keytab data: %v\n", err)
	}
	mb, err := kt.Marshal()
	if err != nil {
		t.Fatalf("Error marshaling: %v", err)
	}
	assert.Equal(t, b, mb, "Marshaled bytes not the same as input bytes")
	err = kt.Unmarshal(mb)
	if err != nil {
		t.Fatalf("Error parsing marshaled bytes: %v", err)
	}
}

func TestLoad(t *testing.T) {
	t.Parallel()
	f := "test/testdata/testuser1.testtab"
	cwd, _ := os.Getwd()
	dir := os.Getenv("TRAVIS_BUILD_DIR")
	if dir != "" {
		f = dir + "/" + f
	} else if filepath.Base(cwd) == "keytab" {
		f = "../" + f
	}
	kt, err := Load(f)
	if err != nil {
		t.Fatalf("could not load keytab: %v", err)
	}
	assert.Equal(t, uint8(2), kt.version, "keytab version not as expected")
	assert.Equal(t, 12, len(kt.Entries), "keytab entry count not as expected: %+v", *kt)
	for _, e := range kt.Entries {
		if e.Principal.Realm != "TEST.GOKRB5" {
			t.Error("principal realm not as expected")
		}
		if e.Principal.NameType != int32(1) {
			t.Error("name type not as expected")
		}
		if e.Principal.NumComponents != int16(1) {
			t.Error("number of component not as expected")
		}
		if len(e.Principal.Components) != 1 {
			t.Error("number of component not as expected")
		}
		if e.Principal.Components[0] != "testuser1" {
			t.Error("principal components not as expected")
		}
		if e.Timestamp.IsZero() {
			t.Error("entry timestamp incorrect")
		}
		if e.KVNO == uint32(0) {
			t.Error("entry kvno not as expected")
		}
		if e.KVNO8 == uint8(0) {
			t.Error("entry kvno8 not as expected")
		}
	}
}

// This test provides inputs to readBytes that previously
// caused a panic.
func TestReadBytes(t *testing.T) {
	var endian binary.ByteOrder
	endian = binary.BigEndian
	p := 0

	if _, err := readBytes(nil, &p, 1, &endian); err == nil {
		t.Fatal("err should be populated because s was given that exceeds array length")
	}
	if _, err := readBytes(nil, &p, -1, &endian); err == nil {
		t.Fatal("err should be given because negative s was given")
	}
}

func TestUnmarshalPotentialPanics(t *testing.T) {
	kt := New()

	// Test a good keytab with bad bytes to unmarshal. These should
	// return errors, but not panic.
	if err := kt.Unmarshal(nil); err == nil {
		t.Fatal("should have errored, input is absent")
	}
	if err := kt.Unmarshal([]byte{}); err == nil {
		t.Fatal("should have errored, input is empty")
	}
	// Incorrect first byte.
	if err := kt.Unmarshal([]byte{4}); err == nil {
		t.Fatal("should have errored, input isn't long enough")
	}
	// First byte, but no further content.
	if err := kt.Unmarshal([]byte{5}); err == nil {
		t.Fatal("should have errored, input isn't long enough")
	}
}

// cxf testing stuff
func TestBadKeytabs(t *testing.T) {
	badPayloads := make([]string, 3)
	badPayloads = append(badPayloads, "BQIwMDAwMDA=")
	badPayloads = append(badPayloads, "BQIAAAAwAAEACjAwMDAwMDAwMDAAIDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAw")
	badPayloads = append(badPayloads, "BQKAAAAA")
	for _, v := range badPayloads {
		decodedKt, _ := base64.StdEncoding.DecodeString(v)
		parsedKt := new(Keytab)
		parsedKt.Unmarshal(decodedKt)
	}
}
