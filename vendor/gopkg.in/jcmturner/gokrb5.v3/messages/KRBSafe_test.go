package messages

import (
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"gopkg.in/jcmturner/gokrb5.v3/iana/msgtype"
	"gopkg.in/jcmturner/gokrb5.v3/testdata"
	"testing"
	"time"
)

func TestUnmarshalKRBSafe(t *testing.T) {
	var a KRBSafe
	v := "encode_krb5_safe"
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

	assert.Equal(t, testdata.TEST_KVNO, a.PVNO, "PVNO not as expected")
	assert.Equal(t, msgtype.KRB_SAFE, a.MsgType, "MsgType is not as expected")
	assert.Equal(t, []byte("krb5data"), a.SafeBody.UserData, "Safe body userdata not as expected")
	assert.Equal(t, tt, a.SafeBody.Timestamp, "Safe body timestamp not as expected")
	assert.Equal(t, 123456, a.SafeBody.Usec, "Safe body microseconds not as expected")
	assert.Equal(t, 17, a.SafeBody.SequenceNumber, "Safe body sequence number not as expected")
	assert.Equal(t, 2, a.SafeBody.SAddress.AddrType, "SAddress type not as expected")
	assert.Equal(t, "12d00023", hex.EncodeToString(a.SafeBody.SAddress.Address), "SAddress not as expected")
	assert.Equal(t, 2, a.SafeBody.RAddress.AddrType, "RAddress type not as expected")
	assert.Equal(t, "12d00023", hex.EncodeToString(a.SafeBody.RAddress.Address), "RAddress not as expected")
	assert.Equal(t, 1, a.Cksum.CksumType, "Checksum type not as expected")
	assert.Equal(t, []byte("1234"), a.Cksum.Checksum, "Checksum not as expected")
}

func TestUnmarshalKRBSafe_optionalsNULL(t *testing.T) {
	var a KRBSafe
	v := "encode_krb5_safe(optionalsNULL)"
	b, err := hex.DecodeString(testdata.TestVectors[v])
	if err != nil {
		t.Fatalf("Test vector read error of %s: %v\n", v, err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error of %s: %v\n", v, err)
	}

	assert.Equal(t, testdata.TEST_KVNO, a.PVNO, "PVNO not as expected")
	assert.Equal(t, msgtype.KRB_SAFE, a.MsgType, "MsgType is not as expected")
	assert.Equal(t, []byte("krb5data"), a.SafeBody.UserData, "Safe body userdata not as expected")
	assert.Equal(t, 2, a.SafeBody.SAddress.AddrType, "SAddress type not as expected")
	assert.Equal(t, "12d00023", hex.EncodeToString(a.SafeBody.SAddress.Address), "SAddress not as expected")
	assert.Equal(t, 1, a.Cksum.CksumType, "Checksum type not as expected")
	assert.Equal(t, []byte("1234"), a.Cksum.Checksum, "Checksum not as expected")
}
