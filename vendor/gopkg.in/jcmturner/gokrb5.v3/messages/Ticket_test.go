package messages

import (
	"encoding/hex"
	"fmt"
	"github.com/stretchr/testify/assert"
	"gopkg.in/jcmturner/gokrb5.v3/keytab"
	"gopkg.in/jcmturner/gokrb5.v3/testdata"
	"gopkg.in/jcmturner/gokrb5.v3/types"
	"testing"
	"time"
)

func TestUnmarshalTicket(t *testing.T) {
	var a Ticket
	v := "encode_krb5_ticket"
	b, err := hex.DecodeString(testdata.TestVectors[v])
	if err != nil {
		t.Fatalf("Test vector read error of %s: %v\n", v, err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error of %s: %v\n", v, err)
	}

	assert.Equal(t, testdata.TEST_KVNO, a.TktVNO, "Ticket version number not as expected")
	assert.Equal(t, testdata.TEST_REALM, a.Realm, "Realm not as expected")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMETYPE, a.SName.NameType, "CName NameType not as expected")
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.SName.NameString), "SName does not have the expected number of NameStrings")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.SName.NameString, "SName name strings not as expected")
	assert.Equal(t, testdata.TEST_ETYPE, a.EncPart.EType, "Etype of Ticket EncPart not as expected")
	assert.Equal(t, testdata.TEST_KVNO, a.EncPart.KVNO, "KNVO of Ticket EncPart not as expected")
	assert.Equal(t, []byte(testdata.TEST_CIPHERTEXT), a.EncPart.Cipher, "Cipher of Ticket EncPart not as expected")
}

func TestUnmarshalEncTicketPart(t *testing.T) {
	var a EncTicketPart
	v := "encode_krb5_enc_tkt_part"
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

	assert.Equal(t, "fedcba98", hex.EncodeToString(a.Flags.Bytes), "Flags not as expected")
	assert.Equal(t, 1, a.Key.KeyType, "Key type not as expected")
	assert.Equal(t, []byte("12345678"), a.Key.KeyValue, "Key value not as expected")
	assert.Equal(t, testdata.TEST_REALM, a.CRealm, "CRealm not as expected")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMETYPE, a.CName.NameType, "CName type not as expected")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.CName.NameString, "CName string entries not as expected")
	assert.Equal(t, 1, a.Transited.TRType, "Transisted type not as expected")
	assert.Equal(t, []byte("EDU,MIT.,ATHENA.,WASHINGTON.EDU,CS."), a.Transited.Contents, "Transisted content not as expected")
	assert.Equal(t, tt, a.AuthTime, "Auth time not as expected")
	assert.Equal(t, tt, a.StartTime, "Start time not as expected")
	assert.Equal(t, tt, a.EndTime, "End time not as expected")
	assert.Equal(t, tt, a.RenewTill, "Renew Till time not as expected")
	assert.Equal(t, 2, len(a.CAddr), "Number of client addresses not as expected")
	for i, addr := range a.CAddr {
		assert.Equal(t, 2, addr.AddrType, fmt.Sprintf("Host address type not as expected for address item %d", i+1))
		assert.Equal(t, "12d00023", hex.EncodeToString(addr.Address), fmt.Sprintf("Host address not as expected for address item %d", i+1))
	}
	for i, ele := range a.AuthorizationData {
		assert.Equal(t, 1, ele.ADType, fmt.Sprintf("Authorization data type of element %d not as expected", i+1))
		assert.Equal(t, []byte(testdata.TEST_AUTHORIZATION_DATA_VALUE), ele.ADData, fmt.Sprintf("Authorization data of element %d not as expected", i+1))
	}
}

func TestUnmarshalEncTicketPart_optionalsNULL(t *testing.T) {
	var a EncTicketPart
	v := "encode_krb5_enc_tkt_part(optionalsNULL)"
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

	assert.Equal(t, "fedcba98", hex.EncodeToString(a.Flags.Bytes), "Flags not as expected")
	assert.Equal(t, 1, a.Key.KeyType, "Key type not as expected")
	assert.Equal(t, []byte("12345678"), a.Key.KeyValue, "Key value not as expected")
	assert.Equal(t, testdata.TEST_REALM, a.CRealm, "CRealm not as expected")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMETYPE, a.CName.NameType, "CName type not as expected")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.CName.NameString, "CName string entries not as expected")
	assert.Equal(t, 1, a.Transited.TRType, "Transisted type not as expected")
	assert.Equal(t, []byte("EDU,MIT.,ATHENA.,WASHINGTON.EDU,CS."), a.Transited.Contents, "Transisted content not as expected")
	assert.Equal(t, tt, a.AuthTime, "Auth time not as expected")
	assert.Equal(t, tt, a.EndTime, "End time not as expected")
}

func TestMarshalTicket(t *testing.T) {
	var a Ticket
	v := "encode_krb5_ticket"
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
	assert.Equal(t, b, mb, "Marshalled bytes not as expected")
}

func TestAuthorizationData_GetPACType_GOKRB5TestData(t *testing.T) {
	v := "PAC_AuthorizationData_GOKRB5"
	b, err := hex.DecodeString(testdata.TestVectors[v])
	if err != nil {
		t.Fatalf("Test vector read error of %s: %v\n", v, err)
	}
	var a types.AuthorizationData
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Error unmarshaling test data: %v", err)
	}
	tkt := Ticket{
		Realm: "TEST.GOKRB5",
		EncPart: types.EncryptedData{
			EType: 18,
			KVNO:  2,
		},
		DecryptedEncPart: EncTicketPart{
			AuthorizationData: a,
		},
	}
	b, _ = hex.DecodeString(testdata.SYSHTTP_KEYTAB)
	kt, _ := keytab.Parse(b)
	isPAC, pac, err := tkt.GetPACType(kt, "sysHTTP")
	if err != nil {
		t.Fatalf("Error getting PAC Type: %v\n", err)
	}
	assert.True(t, isPAC, "PAC should be present")
	assert.Equal(t, 5, len(pac.Buffers), "Number of buffers not as expected")
	assert.Equal(t, uint32(5), pac.CBuffers, "Count of buffers not as expected")
	assert.Equal(t, uint32(0), pac.Version, "PAC version not as expected")
	assert.NotNil(t, pac.KerbValidationInfo, "PAC Kerb Validation info is nil")
	assert.NotNil(t, pac.ClientInfo, "PAC Client Info info is nil")
	assert.NotNil(t, pac.UPNDNSInfo, "PAC UPN DNS Info info is nil")
	assert.NotNil(t, pac.KDCChecksum, "PAC KDC Checksum info is nil")
	assert.NotNil(t, pac.ServerChecksum, "PAC Server checksum info is nil")
}
