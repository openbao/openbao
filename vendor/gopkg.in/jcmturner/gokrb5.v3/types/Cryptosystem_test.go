package types

import (
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"gopkg.in/jcmturner/gokrb5.v3/testdata"
	"testing"
)

func TestUnmarshalEncryptedData(t *testing.T) {
	var a EncryptedData
	v := "encode_krb5_enc_data"
	b, err := hex.DecodeString(testdata.TestVectors[v])
	if err != nil {
		t.Fatalf("Test vector read error of %s: %v\n", v, err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error of %s: %v\n", v, err)
	}
	assert.Equal(t, testdata.TEST_ETYPE, a.EType, "Encrypted data Etype not as expected")
	assert.Equal(t, testdata.TEST_KVNO, a.KVNO, "Encrypted data KVNO not as expected")
	assert.Equal(t, []byte(testdata.TEST_CIPHERTEXT), a.Cipher, "Ecrypted data ciphertext not as expected")
}

func TestUnmarshalEncryptedData_MSBsetkvno(t *testing.T) {
	var a EncryptedData
	v := "encode_krb5_enc_data(MSB-setkvno)"
	b, err := hex.DecodeString(testdata.TestVectors[v])
	if err != nil {
		t.Fatalf("Test vector read error of %s: %v\n", v, err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error of %s: %v\n", v, err)
	}
	assert.Equal(t, testdata.TEST_ETYPE, a.EType, "Encrypted data Etype not as expected")
	assert.Equal(t, -16777216, a.KVNO, "Encrypted data KVNO not as expected")
	assert.Equal(t, []byte(testdata.TEST_CIPHERTEXT), a.Cipher, "Ecrypted data ciphertext not as expected")
}

func TestUnmarshalEncryptedData_kvno_neg1(t *testing.T) {
	var a EncryptedData
	v := "encode_krb5_enc_data(kvno= -1)"
	b, err := hex.DecodeString(testdata.TestVectors[v])
	if err != nil {
		t.Fatalf("Test vector read error of %s: %v\n", v, err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error of %s: %v\n", v, err)
	}
	assert.Equal(t, testdata.TEST_ETYPE, a.EType, "Encrypted data Etype not as expected")
	assert.Equal(t, -1, a.KVNO, "Encrypted data KVNO not as expected")
	assert.Equal(t, []byte(testdata.TEST_CIPHERTEXT), a.Cipher, "Ecrypted data ciphertext not as expected")
}

func TestUnmarshalEncryptionKey(t *testing.T) {
	var a EncryptionKey
	v := "encode_krb5_keyblock"
	b, err := hex.DecodeString(testdata.TestVectors[v])
	if err != nil {
		t.Fatalf("Test vector read error of %s: %v\n", v, err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error of %s: %v\n", v, err)
	}
	assert.Equal(t, 1, a.KeyType, "Key type not as expected")
	assert.Equal(t, []byte("12345678"), a.KeyValue, "Key value not as expected")
}

func TestMarshalEncryptedData(t *testing.T) {
	var a EncryptedData
	v := "encode_krb5_enc_data"
	b, err := hex.DecodeString(testdata.TestVectors[v])
	if err != nil {
		t.Fatalf("Test vector read error of %s: %v\n", v, err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error of %s: %v\n", v, err)
	}
	mb, err := a.Marshal()
	if err != nil {
		t.Fatalf("Marshal of ticket errored: %v", err)
	}
	assert.Equal(t, b, mb, "Marshal bytes of Encrypted Data not as expected")
}
