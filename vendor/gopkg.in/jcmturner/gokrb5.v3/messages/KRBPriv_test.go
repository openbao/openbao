package messages

import (
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"gopkg.in/jcmturner/gokrb5.v3/iana/msgtype"
	"gopkg.in/jcmturner/gokrb5.v3/testdata"
	"testing"
	"time"
)

func TestUnmarshalKRBPriv(t *testing.T) {
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
	assert.Equal(t, testdata.TEST_KVNO, a.PVNO, "PVNO not as expected")
	assert.Equal(t, msgtype.KRB_PRIV, a.MsgType, "Message type not as expected")
	assert.Equal(t, testdata.TEST_KVNO, a.EncPart.KVNO, "EncPart KVNO not as expected")
	assert.Equal(t, testdata.TEST_ETYPE, a.EncPart.EType, "EncPart etype not as expected")
	assert.Equal(t, []byte(testdata.TEST_CIPHERTEXT), a.EncPart.Cipher, "Cipher text of EncPart not as expected")
}

func TestUnmarshalEncPrivPart(t *testing.T) {
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
	assert.Equal(t, 17, a.SequenceNumber, "Sequence number not as expected")
	assert.Equal(t, 2, a.SAddress.AddrType, "SAddress type not as expected")
	assert.Equal(t, "12d00023", hex.EncodeToString(a.SAddress.Address), "Address not as expected for SAddress")
	assert.Equal(t, 2, a.RAddress.AddrType, "RAddress type not as expected")
	assert.Equal(t, "12d00023", hex.EncodeToString(a.RAddress.Address), "Address not as expected for RAddress")
}

func TestUnmarshalEncPrivPart_optionalsNULL(t *testing.T) {
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
	assert.Equal(t, 2, a.SAddress.AddrType, "SAddress type not as expected")
	assert.Equal(t, "12d00023", hex.EncodeToString(a.SAddress.Address), "Address not as expected for SAddress")
}
