package types

import (
	"encoding/hex"
	"testing"

	"github.com/hashicorp/vault-plugin-auth-kerberos/internal/gokrb5/iana"
	"github.com/hashicorp/vault-plugin-auth-kerberos/internal/gokrb5/test/testdata"
	"github.com/stretchr/testify/assert"
)

func TestUnmarshalEncryptedData(t *testing.T) {
	t.Parallel()
	var a EncryptedData
	b, err := hex.DecodeString(testdata.MarshaledKRB5enc_data)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	assert.Equal(t, testdata.TEST_ETYPE, a.EType, "Encrypted data Etype not as expected")
	assert.Equal(t, iana.PVNO, a.KVNO, "Encrypted data KVNO not as expected")
	assert.Equal(t, []byte(testdata.TEST_CIPHERTEXT), a.Cipher, "Ecrypted data ciphertext not as expected")
}

func TestUnmarshalEncryptedData_MSBsetkvno(t *testing.T) {
	t.Parallel()
	var a EncryptedData
	b, err := hex.DecodeString(testdata.MarshaledKRB5enc_dataMSBSetkvno)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	assert.Equal(t, testdata.TEST_ETYPE, a.EType, "Encrypted data Etype not as expected")
	assert.Equal(t, -16777216, a.KVNO, "Encrypted data KVNO not as expected")
	assert.Equal(t, []byte(testdata.TEST_CIPHERTEXT), a.Cipher, "Ecrypted data ciphertext not as expected")
}

func TestUnmarshalEncryptedData_kvno_neg1(t *testing.T) {
	t.Parallel()
	var a EncryptedData
	b, err := hex.DecodeString(testdata.MarshaledKRB5enc_dataKVNONegOne)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	assert.Equal(t, testdata.TEST_ETYPE, a.EType, "Encrypted data Etype not as expected")
	assert.Equal(t, -1, a.KVNO, "Encrypted data KVNO not as expected")
	assert.Equal(t, []byte(testdata.TEST_CIPHERTEXT), a.Cipher, "Ecrypted data ciphertext not as expected")
}

func TestUnmarshalEncryptionKey(t *testing.T) {
	t.Parallel()
	var a EncryptionKey
	b, err := hex.DecodeString(testdata.MarshaledKRB5keyblock)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	assert.Equal(t, int32(1), a.KeyType, "Key type not as expected")
	assert.Equal(t, []byte("12345678"), a.KeyValue, "Key value not as expected")
}

func TestMarshalEncryptedData(t *testing.T) {
	t.Parallel()
	var a EncryptedData
	b, err := hex.DecodeString(testdata.MarshaledKRB5enc_data)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	mb, err := a.Marshal()
	if err != nil {
		t.Fatalf("Marshal of ticket errored: %v", err)
	}
	assert.Equal(t, b, mb, "Marshal bytes of Encrypted Data not as expected")
}
