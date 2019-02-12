package messages

import (
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"gopkg.in/jcmturner/gokrb5.v5/iana"
	"gopkg.in/jcmturner/gokrb5.v5/iana/addrtype"
	"gopkg.in/jcmturner/gokrb5.v5/iana/msgtype"
	"gopkg.in/jcmturner/gokrb5.v5/iana/nametype"
	"gopkg.in/jcmturner/gokrb5.v5/iana/patype"
	"gopkg.in/jcmturner/gokrb5.v5/testdata"
)

func TestUnmarshalKDCReqBody(t *testing.T) {
	t.Parallel()
	var a KDCReqBody
	v := "encode_krb5_kdc_req_body"
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

	assert.Equal(t, "fedcba90", hex.EncodeToString(a.KDCOptions.Bytes), "Request body flags not as expected")
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, a.CName.NameType, "Request body CName NameType not as expected")
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.CName.NameString), "Request body CName does not have the expected number of NameStrings")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.CName.NameString, "Request body CName entries not as expected")
	assert.Equal(t, testdata.TEST_REALM, a.Realm, "Request body Realm not as expected")
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, a.SName.NameType, "Request body SName nametype not as expected")
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.SName.NameString), "Request body SName does not have the expected number of NameStrings")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.SName.NameString, "Request body SName entries not as expected")
	assert.Equal(t, tt, a.From, "Request body From time not as expected")
	assert.Equal(t, tt, a.Till, "Request body Till time not as expected")
	assert.Equal(t, tt, a.RTime, "Request body RTime time not as expected")
	assert.Equal(t, testdata.TEST_NONCE, a.Nonce, "Request body nounce not as expected")
	assert.Equal(t, []int32{0, 1}, a.EType, "Etype list not as expected")
	assert.Equal(t, 2, len(a.Addresses), "Number of client addresses not as expected")
	for i, addr := range a.Addresses {
		assert.Equal(t, addrtype.IPv4, addr.AddrType, fmt.Sprintf("Host address type not as expected for address item %d", i+1))
		assert.Equal(t, "12d00023", hex.EncodeToString(addr.Address), fmt.Sprintf("Host address not as expected for address item %d", i+1))
	}
	assert.Equal(t, testdata.TEST_ETYPE, a.EncAuthData.EType, "Etype of request body encrypted authorization data not as expected")
	assert.Equal(t, iana.PVNO, a.EncAuthData.KVNO, "KVNO of request body encrypted authorization data not as expected")
	assert.Equal(t, []byte(testdata.TEST_CIPHERTEXT), a.EncAuthData.Cipher, "Ciphertext of request body encrypted authorization data not as expected")
	assert.Equal(t, 2, len(a.AdditionalTickets), "Number of additional tickets not as expected")
	for i, tkt := range a.AdditionalTickets {
		assert.Equal(t, iana.PVNO, tkt.TktVNO, fmt.Sprintf("Additional ticket (%v) ticket-vno not as expected", i+1))
		assert.Equal(t, testdata.TEST_REALM, tkt.Realm, fmt.Sprintf("Additional ticket (%v) realm not as expected", i+1))
		assert.Equal(t, nametype.KRB_NT_PRINCIPAL, tkt.SName.NameType, fmt.Sprintf("Additional ticket (%v) SName NameType not as expected", i+1))
		assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(tkt.SName.NameString), fmt.Sprintf("Additional ticket (%v) SName does not have the expected number of NameStrings", i+1))
		assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, tkt.SName.NameString, fmt.Sprintf("Additional ticket (%v) SName name string entries not as expected", i+1))
		assert.Equal(t, testdata.TEST_ETYPE, tkt.EncPart.EType, fmt.Sprintf("Additional ticket (%v) encPart etype not as expected", i+1))
		assert.Equal(t, iana.PVNO, tkt.EncPart.KVNO, fmt.Sprintf("Additional ticket (%v) encPart KVNO not as expected", i+1))
		assert.Equal(t, []byte(testdata.TEST_CIPHERTEXT), tkt.EncPart.Cipher, fmt.Sprintf("Additional ticket (%v) encPart cipher not as expected", i+1))
	}
}

func TestUnmarshalKDCReqBody_optionalsNULLexceptsecond_ticket(t *testing.T) {
	t.Parallel()
	var a KDCReqBody
	v := "encode_krb5_kdc_req_body(optionalsNULLexceptsecond_ticket)"
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

	assert.Equal(t, "fedcba98", hex.EncodeToString(a.KDCOptions.Bytes), "Request body flags not as expected")
	assert.Equal(t, testdata.TEST_REALM, a.Realm, "Request body Realm not as expected")
	assert.Equal(t, tt, a.Till, "Request body Till time not as expected")
	assert.Equal(t, testdata.TEST_NONCE, a.Nonce, "Request body nounce not as expected")
	assert.Equal(t, []int32{0, 1}, a.EType, "Etype list not as expected")
	assert.Equal(t, 0, len(a.Addresses), "Number of client addresses not empty")
	assert.Equal(t, 0, len(a.EncAuthData.Cipher), "Ciphertext of request body encrypted authorization data not empty")
	assert.Equal(t, 2, len(a.AdditionalTickets), "Number of additional tickets not as expected")
	for i, tkt := range a.AdditionalTickets {
		assert.Equal(t, iana.PVNO, tkt.TktVNO, fmt.Sprintf("Additional ticket (%v) ticket-vno not as expected", i+1))
		assert.Equal(t, testdata.TEST_REALM, tkt.Realm, fmt.Sprintf("Additional ticket (%v) realm not as expected", i+1))
		assert.Equal(t, nametype.KRB_NT_PRINCIPAL, tkt.SName.NameType, fmt.Sprintf("Additional ticket (%v) SName NameType not as expected", i+1))
		assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(tkt.SName.NameString), fmt.Sprintf("Additional ticket (%v) SName does not have the expected number of NameStrings", i+1))
		assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, tkt.SName.NameString, fmt.Sprintf("Additional ticket (%v) SName name string entries not as expected", i+1))
		assert.Equal(t, testdata.TEST_ETYPE, tkt.EncPart.EType, fmt.Sprintf("Additional ticket (%v) encPart etype not as expected", i+1))
		assert.Equal(t, iana.PVNO, tkt.EncPart.KVNO, fmt.Sprintf("Additional ticket (%v) encPart KVNO not as expected", i+1))
		assert.Equal(t, []byte(testdata.TEST_CIPHERTEXT), tkt.EncPart.Cipher, fmt.Sprintf("Additional ticket (%v) encPart cipher not as expected", i+1))
	}
}

func TestUnmarshalKDCReqBody_optionalsNULLexceptserver(t *testing.T) {
	t.Parallel()
	var a KDCReqBody
	v := "encode_krb5_kdc_req_body(optionalsNULLexceptserver)"
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

	assert.Equal(t, "fedcba90", hex.EncodeToString(a.KDCOptions.Bytes), "Request body flags not as expected")
	assert.Equal(t, testdata.TEST_REALM, a.Realm, "Request body Realm not as expected")
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, a.SName.NameType, "Request body SName nametype not as expected")
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.SName.NameString), "Request body SName does not have the expected number of NameStrings")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.SName.NameString, "Request body SName entries not as expected")
	assert.Equal(t, tt, a.Till, "Request body Till time not as expected")
	assert.Equal(t, testdata.TEST_NONCE, a.Nonce, "Request body nounce not as expected")
	assert.Equal(t, []int32{0, 1}, a.EType, "Etype list not as expected")
	assert.Equal(t, 0, len(a.Addresses), "Number of client addresses not empty")
	assert.Equal(t, 0, len(a.EncAuthData.Cipher), "Ciphertext of request body encrypted authorization data not empty")
	assert.Equal(t, 0, len(a.AdditionalTickets), "Number of additional tickets not empty")
}

func TestUnmarshalASReq(t *testing.T) {
	t.Parallel()
	var a ASReq
	v := "encode_krb5_as_req"
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

	assert.Equal(t, iana.PVNO, a.PVNO, "PVNO not as expected")
	assert.Equal(t, msgtype.KRB_AS_REQ, a.MsgType, "Message ID not as expected")
	assert.Equal(t, 2, len(a.PAData), "Number of PAData items in the sequence not as expected")
	for i, pa := range a.PAData {
		assert.Equal(t, patype.PA_SAM_RESPONSE, pa.PADataType, fmt.Sprintf("PAData type for entry %d not as expected", i+1))
		assert.Equal(t, []byte(testdata.TEST_PADATA_VALUE), pa.PADataValue, fmt.Sprintf("PAData valye for entry %d not as expected", i+1))
	}
	assert.Equal(t, "fedcba90", hex.EncodeToString(a.ReqBody.KDCOptions.Bytes), "Request body flags not as expected")
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, a.ReqBody.CName.NameType, "Request body CName NameType not as expected")
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.ReqBody.CName.NameString), "Request body CName does not have the expected number of NameStrings")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.ReqBody.CName.NameString, "Request body CName entries not as expected")
	assert.Equal(t, testdata.TEST_REALM, a.ReqBody.Realm, "Request body Realm not as expected")
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, a.ReqBody.SName.NameType, "Request body SName nametype not as expected")
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.ReqBody.SName.NameString), "Request body SName does not have the expected number of NameStrings")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.ReqBody.SName.NameString, "Request body SName entries not as expected")
	assert.Equal(t, tt, a.ReqBody.From, "Request body From time not as expected")
	assert.Equal(t, tt, a.ReqBody.Till, "Request body Till time not as expected")
	assert.Equal(t, tt, a.ReqBody.RTime, "Request body RTime time not as expected")
	assert.Equal(t, testdata.TEST_NONCE, a.ReqBody.Nonce, "Request body nounce not as expected")
	assert.Equal(t, []int32{0, 1}, a.ReqBody.EType, "Etype list not as expected")
	assert.Equal(t, 2, len(a.ReqBody.Addresses), "Number of client addresses not as expected")
	for i, addr := range a.ReqBody.Addresses {
		assert.Equal(t, addrtype.IPv4, addr.AddrType, fmt.Sprintf("Host address type not as expected for address item %d", i+1))
		assert.Equal(t, "12d00023", hex.EncodeToString(addr.Address), fmt.Sprintf("Host address not as expected for address item %d", i+1))
	}
	assert.Equal(t, testdata.TEST_ETYPE, a.ReqBody.EncAuthData.EType, "Etype of request body encrypted authorization data not as expected")
	assert.Equal(t, iana.PVNO, a.ReqBody.EncAuthData.KVNO, "KVNO of request body encrypted authorization data not as expected")
	assert.Equal(t, []byte(testdata.TEST_CIPHERTEXT), a.ReqBody.EncAuthData.Cipher, "Ciphertext of request body encrypted authorization data not as expected")
	assert.Equal(t, 2, len(a.ReqBody.AdditionalTickets), "Number of additional tickets not as expected")
	for i, tkt := range a.ReqBody.AdditionalTickets {
		assert.Equal(t, iana.PVNO, tkt.TktVNO, fmt.Sprintf("Additional ticket (%v) ticket-vno not as expected", i+1))
		assert.Equal(t, testdata.TEST_REALM, tkt.Realm, fmt.Sprintf("Additional ticket (%v) realm not as expected", i+1))
		assert.Equal(t, nametype.KRB_NT_PRINCIPAL, tkt.SName.NameType, fmt.Sprintf("Additional ticket (%v) SName NameType not as expected", i+1))
		assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(tkt.SName.NameString), fmt.Sprintf("Additional ticket (%v) SName does not have the expected number of NameStrings", i+1))
		assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, tkt.SName.NameString, fmt.Sprintf("Additional ticket (%v) SName name string entries not as expected", i+1))
		assert.Equal(t, testdata.TEST_ETYPE, tkt.EncPart.EType, fmt.Sprintf("Additional ticket (%v) encPart etype not as expected", i+1))
		assert.Equal(t, iana.PVNO, tkt.EncPart.KVNO, fmt.Sprintf("Additional ticket (%v) encPart KVNO not as expected", i+1))
		assert.Equal(t, []byte(testdata.TEST_CIPHERTEXT), tkt.EncPart.Cipher, fmt.Sprintf("Additional ticket (%v) encPart cipher not as expected", i+1))
	}
}

func TestUnmarshalASReq_optionalsNULLexceptsecond_ticket(t *testing.T) {
	t.Parallel()
	var a ASReq
	v := "encode_krb5_as_req(optionalsNULLexceptsecond_ticket)"
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

	assert.Equal(t, iana.PVNO, a.PVNO, "PVNO not as expected")
	assert.Equal(t, msgtype.KRB_AS_REQ, a.MsgType, "Message ID not as expected")
	assert.Equal(t, 0, len(a.PAData), "Number of PAData items in the sequence not as expected")
	assert.Equal(t, "fedcba98", hex.EncodeToString(a.ReqBody.KDCOptions.Bytes), "Request body flags not as expected")
	assert.Equal(t, testdata.TEST_REALM, a.ReqBody.Realm, "Request body Realm not as expected")
	assert.Equal(t, tt, a.ReqBody.Till, "Request body Till time not as expected")
	assert.Equal(t, testdata.TEST_NONCE, a.ReqBody.Nonce, "Request body nounce not as expected")
	assert.Equal(t, []int32{0, 1}, a.ReqBody.EType, "Etype list not as expected")
	assert.Equal(t, 0, len(a.ReqBody.Addresses), "Number of client addresses not empty")
	assert.Equal(t, 0, len(a.ReqBody.EncAuthData.Cipher), "Ciphertext of request body encrypted authorization data not empty")
	assert.Equal(t, 2, len(a.ReqBody.AdditionalTickets), "Number of additional tickets not as expected")
	for i, tkt := range a.ReqBody.AdditionalTickets {
		assert.Equal(t, iana.PVNO, tkt.TktVNO, fmt.Sprintf("Additional ticket (%v) ticket-vno not as expected", i+1))
		assert.Equal(t, testdata.TEST_REALM, tkt.Realm, fmt.Sprintf("Additional ticket (%v) realm not as expected", i+1))
		assert.Equal(t, nametype.KRB_NT_PRINCIPAL, tkt.SName.NameType, fmt.Sprintf("Additional ticket (%v) SName NameType not as expected", i+1))
		assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(tkt.SName.NameString), fmt.Sprintf("Additional ticket (%v) SName does not have the expected number of NameStrings", i+1))
		assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, tkt.SName.NameString, fmt.Sprintf("Additional ticket (%v) SName name string entries not as expected", i+1))
		assert.Equal(t, testdata.TEST_ETYPE, tkt.EncPart.EType, fmt.Sprintf("Additional ticket (%v) encPart etype not as expected", i+1))
		assert.Equal(t, iana.PVNO, tkt.EncPart.KVNO, fmt.Sprintf("Additional ticket (%v) encPart KVNO not as expected", i+1))
		assert.Equal(t, []byte(testdata.TEST_CIPHERTEXT), tkt.EncPart.Cipher, fmt.Sprintf("Additional ticket (%v) encPart cipher not as expected", i+1))
	}
}

func TestUnmarshalASReq_optionalsNULLexceptserver(t *testing.T) {
	t.Parallel()
	var a ASReq
	v := "encode_krb5_as_req(optionalsNULLexceptserver)"
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

	assert.Equal(t, iana.PVNO, a.PVNO, "PVNO not as expected")
	assert.Equal(t, msgtype.KRB_AS_REQ, a.MsgType, "Message ID not as expected")
	assert.Equal(t, 0, len(a.PAData), "Number of PAData items in the sequence not as expected")
	assert.Equal(t, "fedcba90", hex.EncodeToString(a.ReqBody.KDCOptions.Bytes), "Request body flags not as expected")
	assert.Equal(t, testdata.TEST_REALM, a.ReqBody.Realm, "Request body Realm not as expected")
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, a.ReqBody.SName.NameType, "Request body SName nametype not as expected")
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.ReqBody.SName.NameString), "Request body SName does not have the expected number of NameStrings")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.ReqBody.SName.NameString, "Request body SName entries not as expected")
	assert.Equal(t, tt, a.ReqBody.Till, "Request body Till time not as expected")
	assert.Equal(t, testdata.TEST_NONCE, a.ReqBody.Nonce, "Request body nounce not as expected")
	assert.Equal(t, []int32{0, 1}, a.ReqBody.EType, "Etype list not as expected")
	assert.Equal(t, 0, len(a.ReqBody.Addresses), "Number of client addresses not empty")
	assert.Equal(t, 0, len(a.ReqBody.EncAuthData.Cipher), "Ciphertext of request body encrypted authorization data not empty")
	assert.Equal(t, 0, len(a.ReqBody.AdditionalTickets), "Number of additional tickets not empty")
}

func TestUnmarshalTGSReq(t *testing.T) {
	t.Parallel()
	var a TGSReq
	v := "encode_krb5_tgs_req"
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

	assert.Equal(t, iana.PVNO, a.PVNO, "PVNO not as expected")
	assert.Equal(t, msgtype.KRB_TGS_REQ, a.MsgType, "Message ID not as expected")
	assert.Equal(t, 2, len(a.PAData), "Number of PAData items in the sequence not as expected")
	for i, pa := range a.PAData {
		assert.Equal(t, patype.PA_SAM_RESPONSE, pa.PADataType, fmt.Sprintf("PAData type for entry %d not as expected", i+1))
		assert.Equal(t, []byte(testdata.TEST_PADATA_VALUE), pa.PADataValue, fmt.Sprintf("PAData valye for entry %d not as expected", i+1))
	}
	assert.Equal(t, "fedcba90", hex.EncodeToString(a.ReqBody.KDCOptions.Bytes), "Request body flags not as expected")
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, a.ReqBody.CName.NameType, "Request body CName NameType not as expected")
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.ReqBody.CName.NameString), "Request body CName does not have the expected number of NameStrings")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.ReqBody.CName.NameString, "Request body CName entries not as expected")
	assert.Equal(t, testdata.TEST_REALM, a.ReqBody.Realm, "Request body Realm not as expected")
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, a.ReqBody.SName.NameType, "Request body SName nametype not as expected")
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.ReqBody.SName.NameString), "Request body SName does not have the expected number of NameStrings")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.ReqBody.SName.NameString, "Request body SName entries not as expected")
	assert.Equal(t, tt, a.ReqBody.From, "Request body From time not as expected")
	assert.Equal(t, tt, a.ReqBody.Till, "Request body Till time not as expected")
	assert.Equal(t, tt, a.ReqBody.RTime, "Request body RTime time not as expected")
	assert.Equal(t, testdata.TEST_NONCE, a.ReqBody.Nonce, "Request body nounce not as expected")
	assert.Equal(t, []int32{0, 1}, a.ReqBody.EType, "Etype list not as expected")
	assert.Equal(t, 2, len(a.ReqBody.Addresses), "Number of client addresses not as expected")
	for i, addr := range a.ReqBody.Addresses {
		assert.Equal(t, addrtype.IPv4, addr.AddrType, fmt.Sprintf("Host address type not as expected for address item %d", i+1))
		assert.Equal(t, "12d00023", hex.EncodeToString(addr.Address), fmt.Sprintf("Host address not as expected for address item %d", i+1))
	}
	assert.Equal(t, testdata.TEST_ETYPE, a.ReqBody.EncAuthData.EType, "Etype of request body encrypted authorization data not as expected")
	assert.Equal(t, iana.PVNO, a.ReqBody.EncAuthData.KVNO, "KVNO of request body encrypted authorization data not as expected")
	assert.Equal(t, []byte(testdata.TEST_CIPHERTEXT), a.ReqBody.EncAuthData.Cipher, "Ciphertext of request body encrypted authorization data not as expected")
	assert.Equal(t, 2, len(a.ReqBody.AdditionalTickets), "Number of additional tickets not as expected")
	for i, tkt := range a.ReqBody.AdditionalTickets {
		assert.Equal(t, iana.PVNO, tkt.TktVNO, fmt.Sprintf("Additional ticket (%v) ticket-vno not as expected", i+1))
		assert.Equal(t, testdata.TEST_REALM, tkt.Realm, fmt.Sprintf("Additional ticket (%v) realm not as expected", i+1))
		assert.Equal(t, nametype.KRB_NT_PRINCIPAL, tkt.SName.NameType, fmt.Sprintf("Additional ticket (%v) SName NameType not as expected", i+1))
		assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(tkt.SName.NameString), fmt.Sprintf("Additional ticket (%v) SName does not have the expected number of NameStrings", i+1))
		assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, tkt.SName.NameString, fmt.Sprintf("Additional ticket (%v) SName name string entries not as expected", i+1))
		assert.Equal(t, testdata.TEST_ETYPE, tkt.EncPart.EType, fmt.Sprintf("Additional ticket (%v) encPart etype not as expected", i+1))
		assert.Equal(t, iana.PVNO, tkt.EncPart.KVNO, fmt.Sprintf("Additional ticket (%v) encPart KVNO not as expected", i+1))
		assert.Equal(t, []byte(testdata.TEST_CIPHERTEXT), tkt.EncPart.Cipher, fmt.Sprintf("Additional ticket (%v) encPart cipher not as expected", i+1))
	}
}

func TestUnmarshalTGSReq_optionalsNULLexceptsecond_ticket(t *testing.T) {
	t.Parallel()
	var a TGSReq
	v := "encode_krb5_tgs_req(optionalsNULLexceptsecond_ticket)"
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

	assert.Equal(t, iana.PVNO, a.PVNO, "PVNO not as expected")
	assert.Equal(t, msgtype.KRB_TGS_REQ, a.MsgType, "Message ID not as expected")
	assert.Equal(t, 0, len(a.PAData), "Number of PAData items in the sequence not as expected")
	assert.Equal(t, "fedcba98", hex.EncodeToString(a.ReqBody.KDCOptions.Bytes), "Request body flags not as expected")
	assert.Equal(t, testdata.TEST_REALM, a.ReqBody.Realm, "Request body Realm not as expected")
	assert.Equal(t, tt, a.ReqBody.Till, "Request body Till time not as expected")
	assert.Equal(t, testdata.TEST_NONCE, a.ReqBody.Nonce, "Request body nounce not as expected")
	assert.Equal(t, []int32{0, 1}, a.ReqBody.EType, "Etype list not as expected")
	assert.Equal(t, 0, len(a.ReqBody.Addresses), "Number of client addresses not empty")
	assert.Equal(t, 0, len(a.ReqBody.EncAuthData.Cipher), "Ciphertext of request body encrypted authorization data not empty")
	assert.Equal(t, 2, len(a.ReqBody.AdditionalTickets), "Number of additional tickets not as expected")
	for i, tkt := range a.ReqBody.AdditionalTickets {
		assert.Equal(t, iana.PVNO, tkt.TktVNO, fmt.Sprintf("Additional ticket (%v) ticket-vno not as expected", i+1))
		assert.Equal(t, testdata.TEST_REALM, tkt.Realm, fmt.Sprintf("Additional ticket (%v) realm not as expected", i+1))
		assert.Equal(t, nametype.KRB_NT_PRINCIPAL, tkt.SName.NameType, fmt.Sprintf("Additional ticket (%v) SName NameType not as expected", i+1))
		assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(tkt.SName.NameString), fmt.Sprintf("Additional ticket (%v) SName does not have the expected number of NameStrings", i+1))
		assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, tkt.SName.NameString, fmt.Sprintf("Additional ticket (%v) SName name string entries not as expected", i+1))
		assert.Equal(t, testdata.TEST_ETYPE, tkt.EncPart.EType, fmt.Sprintf("Additional ticket (%v) encPart etype not as expected", i+1))
		assert.Equal(t, iana.PVNO, tkt.EncPart.KVNO, fmt.Sprintf("Additional ticket (%v) encPart KVNO not as expected", i+1))
		assert.Equal(t, []byte(testdata.TEST_CIPHERTEXT), tkt.EncPart.Cipher, fmt.Sprintf("Additional ticket (%v) encPart cipher not as expected", i+1))
	}
}

func TestUnmarshalTGSReq_optionalsNULLexceptserver(t *testing.T) {
	t.Parallel()
	var a TGSReq
	v := "encode_krb5_tgs_req(optionalsNULLexceptserver)"
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

	assert.Equal(t, iana.PVNO, a.PVNO, "PVNO not as expected")
	assert.Equal(t, msgtype.KRB_TGS_REQ, a.MsgType, "Message ID not as expected")
	assert.Equal(t, 0, len(a.PAData), "Number of PAData items in the sequence not as expected")
	assert.Equal(t, "fedcba90", hex.EncodeToString(a.ReqBody.KDCOptions.Bytes), "Request body flags not as expected")
	assert.Equal(t, testdata.TEST_REALM, a.ReqBody.Realm, "Request body Realm not as expected")
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, a.ReqBody.SName.NameType, "Request body SName nametype not as expected")
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.ReqBody.SName.NameString), "Request body SName does not have the expected number of NameStrings")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.ReqBody.SName.NameString, "Request body SName entries not as expected")
	assert.Equal(t, tt, a.ReqBody.Till, "Request body Till time not as expected")
	assert.Equal(t, testdata.TEST_NONCE, a.ReqBody.Nonce, "Request body nounce not as expected")
	assert.Equal(t, []int32{0, 1}, a.ReqBody.EType, "Etype list not as expected")
	assert.Equal(t, 0, len(a.ReqBody.Addresses), "Number of client addresses not empty")
	assert.Equal(t, 0, len(a.ReqBody.EncAuthData.Cipher), "Ciphertext of request body encrypted authorization data not empty")
	assert.Equal(t, 0, len(a.ReqBody.AdditionalTickets), "Number of additional tickets not empty")
}

//// Marshal Tests ////

func TestMarshalKDCReqBody(t *testing.T) {
	t.Parallel()
	var a KDCReqBody
	v := "encode_krb5_kdc_req_body"
	b, err := hex.DecodeString(testdata.TestVectors[v])
	if err != nil {
		t.Fatalf("Test vector read error of %s: %v\n", v, err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error of %s: %v\n", v, err)
	}
	// Marshal and re-unmarshal the result nd then compare
	mb, err := a.Marshal()
	if err != nil {
		t.Fatalf("Unmarshal error of %s: %v\n", v, err)
	}
	assert.Equal(t, b, mb, "Marshal bytes of KDCReqBody not as expected")
}

func TestMarshalASReq(t *testing.T) {
	t.Parallel()
	var a ASReq
	v := "encode_krb5_as_req"
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
	assert.Equal(t, b, mb, "Marshal bytes of ASReq not as expected")
}

func TestMarshalTGSReq(t *testing.T) {
	t.Parallel()
	var a TGSReq
	v := "encode_krb5_tgs_req"
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
	assert.Equal(t, b, mb, "Marshal bytes of TGSReq not as expected")
}
