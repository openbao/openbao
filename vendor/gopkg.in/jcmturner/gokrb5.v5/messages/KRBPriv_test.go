package messages

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"gopkg.in/jcmturner/gokrb5.v5/iana"
	"gopkg.in/jcmturner/gokrb5.v5/iana/addrtype"
	"gopkg.in/jcmturner/gokrb5.v5/iana/msgtype"
	"gopkg.in/jcmturner/gokrb5.v5/testdata"
	"gopkg.in/jcmturner/gokrb5.v5/types"
)

func TestUnmarshalKRBPriv(t *testing.T) {
	t.Parallel()
	var a KRBPriv
	v := "encode_krb5_priv"
	b, err := hex.DecodeString(testdata.TestVectors[v])
	if err != nil {
		t.Fatalf("Test vector read error of %s: %v\n", v, err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error of %s: %v\n", v, err)
	}
	assert.Equal(t, iana.PVNO, a.PVNO, "PVNO not as expected")
	assert.Equal(t, msgtype.KRB_PRIV, a.MsgType, "Message type not as expected")
	assert.Equal(t, iana.PVNO, a.EncPart.KVNO, "EncPart KVNO not as expected")
	assert.Equal(t, testdata.TEST_ETYPE, a.EncPart.EType, "EncPart etype not as expected")
	assert.Equal(t, []byte(testdata.TEST_CIPHERTEXT), a.EncPart.Cipher, "Cipher text of EncPart not as expected")
}

func TestUnmarshalEncPrivPart(t *testing.T) {
	t.Parallel()
	var a EncKrbPrivPart
	v := "encode_krb5_enc_priv_part"
	b, err := hex.DecodeString(testdata.TestVectors[v])
	if err != nil {
		t.Fatalf("Test vector read error of %s: %v\n", v, err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error of %s: %v\n", v, err)
	}
	//Parse the test time value into a time.Time type
	tt, _ := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)

	assert.Equal(t, "krb5data", string(a.UserData), "User data not as expected")
	assert.Equal(t, tt, a.Timestamp, "Timestamp not as expected")
	assert.Equal(t, 123456, a.Usec, "Microseconds not as expected")
	assert.Equal(t, int64(17), a.SequenceNumber, "Sequence number not as expected")
	assert.Equal(t, addrtype.IPv4, a.SAddress.AddrType, "SAddress type not as expected")
	assert.Equal(t, "12d00023", hex.EncodeToString(a.SAddress.Address), "Address not as expected for SAddress")
	assert.Equal(t, addrtype.IPv4, a.RAddress.AddrType, "RAddress type not as expected")
	assert.Equal(t, "12d00023", hex.EncodeToString(a.RAddress.Address), "Address not as expected for RAddress")
}

func TestUnmarshalEncPrivPart_optionalsNULL(t *testing.T) {
	t.Parallel()
	var a EncKrbPrivPart
	v := "encode_krb5_enc_priv_part(optionalsNULL)"
	b, err := hex.DecodeString(testdata.TestVectors[v])
	if err != nil {
		t.Fatalf("Test vector read error of %s: %v\n", v, err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error of %s: %v\n", v, err)
	}
	assert.Equal(t, "krb5data", string(a.UserData), "User data not as expected")
	assert.Equal(t, addrtype.IPv4, a.SAddress.AddrType, "SAddress type not as expected")
	assert.Equal(t, "12d00023", hex.EncodeToString(a.SAddress.Address), "Address not as expected for SAddress")
}

func TestMarshalKRBPriv(t *testing.T) {
	t.Parallel()
	var a KRBPriv
	v := "encode_krb5_priv"
	b, err := hex.DecodeString(testdata.TestVectors[v])
	if err != nil {
		t.Fatalf("Test vector read error of %s: %v", v, err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error of %s: %v", v, err)
	}
	mb, err := a.Marshal()
	if err != nil {
		t.Fatalf("error marshaling KRBPriv: %v", err)
	}
	assert.Equal(t, b, mb, "marshaled bytes not as expected")

	v = "encode_krb5_enc_priv_part"
	be, err := hex.DecodeString(testdata.TestVectors[v])
	if err != nil {
		t.Fatalf("Test vector read error of %s: %v", v, err)
	}
	err = a.DecryptedEncPart.Unmarshal(be)
	if err != nil {
		t.Fatalf("Unmarshal error of %s: %v", v, err)
	}
	mb, err = a.Marshal()
	if err != nil {
		t.Fatalf("error marshaling KRBPriv: %v", err)
	}
	assert.Equal(t, b, mb, "marshaled bytes not as expected when it has decrypted encpart")
}

func TestKRBPriv_EncryptEncPart(t *testing.T) {
	t.Parallel()
	var a KRBPriv
	v := "encode_krb5_priv"
	b, err := hex.DecodeString(testdata.TestVectors[v])
	if err != nil {
		t.Fatalf("Test vector read error of %s: %v", v, err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error of %s: %v", v, err)
	}
	v = "encode_krb5_enc_priv_part"
	b, err = hex.DecodeString(testdata.TestVectors[v])
	if err != nil {
		t.Fatalf("Test vector read error of %s: %v", v, err)
	}
	err = a.DecryptedEncPart.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error of %s: %v", v, err)
	}
	key := types.EncryptionKey{
		KeyType:  int32(18),
		KeyValue: []byte("12345678901234567890123456789012"),
	}
	err = a.EncryptEncPart(key)
	if err != nil {
		t.Fatalf("error encrypting encpart: %v", err)
	}
}
