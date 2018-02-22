package messages

import (
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"gopkg.in/jcmturner/gokrb5.v3/iana/msgtype"
	"gopkg.in/jcmturner/gokrb5.v3/testdata"
	"testing"
	"time"
)

func TestUnmarshalKRBError(t *testing.T) {
	var a KRBError
	v := "encode_krb5_error"
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

	assert.Equal(t, testdata.TEST_KVNO, a.PVNO, "PVNO is not as expected")
	assert.Equal(t, msgtype.KRB_ERROR, a.MsgType, "Message type is not as expected")
	assert.Equal(t, tt, a.CTime, "CTime not as expected")
	assert.Equal(t, 123456, a.Cusec, "Client microseconds not as expected")
	assert.Equal(t, tt, a.STime, "STime not as expected")
	assert.Equal(t, 123456, a.Susec, "Service microseconds not as expected")
	assert.Equal(t, 60, a.ErrorCode, "Error code not as expected")
	assert.Equal(t, testdata.TEST_REALM, a.CRealm, "CRealm not as expected")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMETYPE, a.CName.NameType, "CName NameType not as expected")
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.CName.NameString), "CName does not have the expected number of NameStrings")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.CName.NameString, "CName entries not as expected")
	assert.Equal(t, testdata.TEST_REALM, a.Realm, "Realm not as expected")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMETYPE, a.SName.NameType, "Ticket SName NameType not as expected")
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.SName.NameString), "Ticket SName does not have the expected number of NameStrings")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.SName.NameString, "Ticket SName name string entries not as expected")
	assert.Equal(t, "krb5data", a.EText, "EText not as expected")
	assert.Equal(t, []byte("krb5data"), a.EData, "EData not as expected")
}

func TestUnmarshalKRBError_optionalsNULL(t *testing.T) {
	var a KRBError
	v := "encode_krb5_error(optionalsNULL)"
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

	assert.Equal(t, testdata.TEST_KVNO, a.PVNO, "PVNO is not as expected")
	assert.Equal(t, msgtype.KRB_ERROR, a.MsgType, "Message type is not as expected")
	assert.Equal(t, 123456, a.Cusec, "Client microseconds not as expected")
	assert.Equal(t, tt, a.STime, "STime not as expected")
	assert.Equal(t, 123456, a.Susec, "Service microseconds not as expected")
	assert.Equal(t, 60, a.ErrorCode, "Error code not as expected")
	assert.Equal(t, testdata.TEST_REALM, a.Realm, "Realm not as expected")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMETYPE, a.SName.NameType, "Ticket SName NameType not as expected")
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.SName.NameString), "Ticket SName does not have the expected number of NameStrings")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.SName.NameString, "Ticket SName name string entries not as expected")
}
