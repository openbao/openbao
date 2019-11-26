package messages

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/hashicorp/vault-plugin-auth-kerberos/internal/gokrb5/iana"
	"github.com/hashicorp/vault-plugin-auth-kerberos/internal/gokrb5/iana/errorcode"
	"github.com/hashicorp/vault-plugin-auth-kerberos/internal/gokrb5/iana/msgtype"
	"github.com/hashicorp/vault-plugin-auth-kerberos/internal/gokrb5/iana/nametype"
	"github.com/hashicorp/vault-plugin-auth-kerberos/internal/gokrb5/test/testdata"
	"github.com/stretchr/testify/assert"
)

func TestUnmarshalKRBError(t *testing.T) {
	t.Parallel()
	var a KRBError
	b, err := hex.DecodeString(testdata.MarshaledKRB5error)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	//Parse the test time value into a time.Time type
	tt, _ := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)

	assert.Equal(t, iana.PVNO, a.PVNO, "PVNO is not as expected")
	assert.Equal(t, msgtype.KRB_ERROR, a.MsgType, "Message type is not as expected")
	assert.Equal(t, tt, a.CTime, "CTime not as expected")
	assert.Equal(t, 123456, a.Cusec, "Client microseconds not as expected")
	assert.Equal(t, tt, a.STime, "STime not as expected")
	assert.Equal(t, 123456, a.Susec, "Service microseconds not as expected")
	assert.Equal(t, errorcode.KRB_ERR_GENERIC, a.ErrorCode, "Error code not as expected")
	assert.Equal(t, testdata.TEST_REALM, a.CRealm, "CRealm not as expected")
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, a.CName.NameType, "CName NameType not as expected")
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.CName.NameString), "CName does not have the expected number of NameStrings")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.CName.NameString, "CName entries not as expected")
	assert.Equal(t, testdata.TEST_REALM, a.Realm, "Realm not as expected")
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, a.SName.NameType, "Ticket SName NameType not as expected")
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.SName.NameString), "Ticket SName does not have the expected number of NameStrings")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.SName.NameString, "Ticket SName name string entries not as expected")
	assert.Equal(t, "krb5data", a.EText, "EText not as expected")
	assert.Equal(t, []byte("krb5data"), a.EData, "EData not as expected")
}

func TestUnmarshalKRBError_optionalsNULL(t *testing.T) {
	t.Parallel()
	var a KRBError
	b, err := hex.DecodeString(testdata.MarshaledKRB5errorOptionalsNULL)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	//Parse the test time value into a time.Time type
	tt, _ := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)

	assert.Equal(t, iana.PVNO, a.PVNO, "PVNO is not as expected")
	assert.Equal(t, msgtype.KRB_ERROR, a.MsgType, "Message type is not as expected")
	assert.Equal(t, 123456, a.Cusec, "Client microseconds not as expected")
	assert.Equal(t, tt, a.STime, "STime not as expected")
	assert.Equal(t, 123456, a.Susec, "Service microseconds not as expected")
	assert.Equal(t, errorcode.KRB_ERR_GENERIC, a.ErrorCode, "Error code not as expected")
	assert.Equal(t, testdata.TEST_REALM, a.Realm, "Realm not as expected")
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, a.SName.NameType, "Ticket SName NameType not as expected")
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.SName.NameString), "Ticket SName does not have the expected number of NameStrings")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.SName.NameString, "Ticket SName name string entries not as expected")
}
