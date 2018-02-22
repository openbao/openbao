package messages

import (
	"encoding/hex"
	"fmt"
	"github.com/stretchr/testify/assert"
	"gopkg.in/jcmturner/gokrb5.v3/credentials"
	"gopkg.in/jcmturner/gokrb5.v3/iana/etypeID"
	"gopkg.in/jcmturner/gokrb5.v3/iana/msgtype"
	"gopkg.in/jcmturner/gokrb5.v3/keytab"
	"gopkg.in/jcmturner/gokrb5.v3/testdata"
	"testing"
	"time"
)

const (
	testuser1EType18Keytab = "05020000004b0001000b544553542e474f4b5242350009746573747573657231000000015898e0770100120020bbdc430aab7e2d4622a0b6951481453b0962e9db8e2f168942ad175cda6d9de900000001"
	testuser1EType18ASREP  = "6b8202f3308202efa003020105a10302010ba22e302c302aa103020113a2230421301f301da003020112a1161b14544553542e474f4b524235746573747573657231a30d1b0b544553542e474f4b524235a4163014a003020101a10d300b1b09746573747573657231a582015a6182015630820152a003020105a10d1b0b544553542e474f4b524235a220301ea003020102a11730151b066b72627467741b0b544553542e474f4b524235a382011830820114a003020112a103020101a28201060482010237e486e32cd18ab1ac9f8d42e93f8babd7b3497084cc5599f18ec61961c6d5242d350354d99d67a7604c451116188d16cb719e84377212eac2743440e8c504ef69c755e489cc6b65f935dd032bfc076f9b2c56d816197845b8fe857d738bc59712787631a50e86833d1b0e4732c8712c856417a6a257758e7d01d3182adb3233f0dde65d228c240ed26aa1af69f8d765dc0bc69096fdb037a75af220fea176839528d44b70f7dabfaa2ea506de1296f847176a60c501fd8cef8e0a51399bb6d5f753962d96292e93ffe344c6630db912931d46d88c0279f00719e22d0efcfd4ee33a702d0b660c1f13970a9beec12c0c8af3dda68bd81ac1fe3f126d2a24ebb445c5a682012c30820128a003020112a282011f0482011bb149cc16018072c4c18788d95a33aba540e52c11b54a93e67e788d05de75d8f3d4aa1afafbbfa6fde3eb40e5aa1890644cea2607efd5213a3fd00345b02eeb9ae1b589f36c74c689cd4ec1239dfe61e42ba6afa33f6240e3cfab291e4abb465d273302dbf7dbd148a299a9369044dd03377c1687e7dd36aa66501284a4ca50c0a7b08f4f87aecfa23b0dd0b11490e3ad330906dab715de81fc52f120d09c39990b8b5330d4601cc396b2ed258834329c4cc02c563a12de3ef9bf11e946258bc2ab5257f4caa4d443a7daf0fc25f6f531c2fcba88af8ca55c85300997cd05abbea52811fe2d038ba8f62fc8e3bc71ce04362d356ea2e1df8ac55c784c53cfb07817d48e39fe99fc8788040d98209c79dcf044d97e80de9f47824646"
	testRealm              = "TEST.GOKRB5"
	testUser               = "testuser1"
	testUserPassword       = "passwordvalue"
)

func TestUnmarshalASRep(t *testing.T) {
	var a ASRep
	v := "encode_krb5_as_rep"
	b, err := hex.DecodeString(testdata.TestVectors[v])
	if err != nil {
		t.Fatalf("Test vector read error of %s: %v\n", v, err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error of %s: %v\n", v, err)
	}
	assert.Equal(t, testdata.TEST_KVNO, a.PVNO, "PVNO not as expected")
	assert.Equal(t, msgtype.KRB_AS_REP, a.MsgType, "MsgType not as expected")
	assert.Equal(t, 2, len(a.PAData), "Number of PAData items in the sequence not as expected")
	for i, pa := range a.PAData {
		assert.Equal(t, testdata.TEST_PADATA_TYPE, pa.PADataType, fmt.Sprintf("PAData type for entry %d not as expected", i+1))
		assert.Equal(t, []byte(testdata.TEST_PADATA_VALUE), pa.PADataValue, fmt.Sprintf("PAData valye for entry %d not as expected", i+1))
	}
	assert.Equal(t, testdata.TEST_REALM, a.CRealm, "Client Realm not as expected")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMETYPE, a.CName.NameType, "CName NameType not as expected")
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.CName.NameString), "CName does not have the expected number of NameStrings")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.CName.NameString, "CName entries not as expected")
	assert.Equal(t, testdata.TEST_KVNO, a.Ticket.TktVNO, "TktVNO not as expected")
	assert.Equal(t, testdata.TEST_REALM, a.Ticket.Realm, "Ticket Realm not as expected")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMETYPE, a.Ticket.SName.NameType, "Ticket service nametype not as expected")
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.Ticket.SName.NameString), "SName in ticket does not have the expected number of NameStrings")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.Ticket.SName.NameString, "Ticket SName entries not as expected")
	assert.Equal(t, testdata.TEST_ETYPE, a.Ticket.EncPart.EType, "Etype of ticket encrypted part not as expected")
	assert.Equal(t, testdata.TEST_KVNO, a.Ticket.EncPart.KVNO, "Ticket encrypted part KVNO not as expected")
	assert.Equal(t, testdata.TEST_CIPHERTEXT, string(a.Ticket.EncPart.Cipher), "Ticket encrypted part cipher not as expected")
	assert.Equal(t, testdata.TEST_ETYPE, a.EncPart.EType, "Etype of encrypted part not as expected")
	assert.Equal(t, testdata.TEST_KVNO, a.EncPart.KVNO, "Encrypted part KVNO not as expected")
	assert.Equal(t, testdata.TEST_CIPHERTEXT, string(a.EncPart.Cipher), "Ticket encrypted part cipher not as expected")
}

func TestUnmarshalASRep_optionalsNULL(t *testing.T) {
	var a ASRep
	v := "encode_krb5_as_rep(optionalsNULL)"
	b, err := hex.DecodeString(testdata.TestVectors[v])
	if err != nil {
		t.Fatalf("Test vector read error of %s: %v\n", v, err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error of %s: %v\n", v, err)
	}
	assert.Equal(t, testdata.TEST_KVNO, a.PVNO, "PVNO not as expected")
	assert.Equal(t, msgtype.KRB_AS_REP, a.MsgType, "MsgType not as expected")
	assert.Equal(t, 0, len(a.PAData), "Number of PAData items in the sequence not as expected")
	assert.Equal(t, testdata.TEST_REALM, a.CRealm, "Client Realm not as expected")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMETYPE, a.CName.NameType, "CName NameType not as expected")
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.CName.NameString), "CName does not have the expected number of NameStrings")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.CName.NameString, "CName entries not as expected")
	assert.Equal(t, testdata.TEST_KVNO, a.Ticket.TktVNO, "TktVNO not as expected")
	assert.Equal(t, testdata.TEST_REALM, a.Ticket.Realm, "Ticket Realm not as expected")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMETYPE, a.Ticket.SName.NameType, "Ticket service nametype not as expected")
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.Ticket.SName.NameString), "SName in ticket does not have the expected number of NameStrings")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.Ticket.SName.NameString, "Ticket SName entries not as expected")
	assert.Equal(t, testdata.TEST_ETYPE, a.Ticket.EncPart.EType, "Etype of ticket encrypted part not as expected")
	assert.Equal(t, testdata.TEST_KVNO, a.Ticket.EncPart.KVNO, "Ticket encrypted part KVNO not as expected")
	assert.Equal(t, testdata.TEST_CIPHERTEXT, string(a.Ticket.EncPart.Cipher), "Ticket encrypted part cipher not as expected")
	assert.Equal(t, testdata.TEST_ETYPE, a.EncPart.EType, "Etype of encrypted part not as expected")
	assert.Equal(t, testdata.TEST_KVNO, a.EncPart.KVNO, "Encrypted part KVNO not as expected")
	assert.Equal(t, testdata.TEST_CIPHERTEXT, string(a.EncPart.Cipher), "Ticket encrypted part cipher not as expected")
}

func TestUnmarshalTGSRep(t *testing.T) {
	var a TGSRep
	v := "encode_krb5_tgs_rep"
	b, err := hex.DecodeString(testdata.TestVectors[v])
	if err != nil {
		t.Fatalf("Test vector read error of %s: %v\n", v, err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error of %s: %v\n", v, err)
	}
	assert.Equal(t, testdata.TEST_KVNO, a.PVNO, "PVNO not as expected")
	assert.Equal(t, msgtype.KRB_TGS_REP, a.MsgType, "MsgType not as expected")
	assert.Equal(t, 2, len(a.PAData), "Number of PAData items in the sequence not as expected")
	for i, pa := range a.PAData {
		assert.Equal(t, testdata.TEST_PADATA_TYPE, pa.PADataType, fmt.Sprintf("PAData type for entry %d not as expected", i+1))
		assert.Equal(t, []byte(testdata.TEST_PADATA_VALUE), pa.PADataValue, fmt.Sprintf("PAData valye for entry %d not as expected", i+1))
	}
	assert.Equal(t, testdata.TEST_REALM, a.CRealm, "Client Realm not as expected")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMETYPE, a.CName.NameType, "CName NameType not as expected")
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.CName.NameString), "CName does not have the expected number of NameStrings")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.CName.NameString, "CName entries not as expected")
	assert.Equal(t, testdata.TEST_KVNO, a.Ticket.TktVNO, "TktVNO not as expected")
	assert.Equal(t, testdata.TEST_REALM, a.Ticket.Realm, "Ticket Realm not as expected")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMETYPE, a.Ticket.SName.NameType, "Ticket service nametype not as expected")
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.Ticket.SName.NameString), "SName in ticket does not have the expected number of NameStrings")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.Ticket.SName.NameString, "Ticket SName entries not as expected")
	assert.Equal(t, testdata.TEST_ETYPE, a.Ticket.EncPart.EType, "Etype of ticket encrypted part not as expected")
	assert.Equal(t, testdata.TEST_KVNO, a.Ticket.EncPart.KVNO, "Ticket encrypted part KVNO not as expected")
	assert.Equal(t, testdata.TEST_CIPHERTEXT, string(a.Ticket.EncPart.Cipher), "Ticket encrypted part cipher not as expected")
	assert.Equal(t, testdata.TEST_ETYPE, a.EncPart.EType, "Etype of encrypted part not as expected")
	assert.Equal(t, testdata.TEST_KVNO, a.EncPart.KVNO, "Encrypted part KVNO not as expected")
	assert.Equal(t, testdata.TEST_CIPHERTEXT, string(a.EncPart.Cipher), "Ticket encrypted part cipher not as expected")
}

func TestUnmarshalTGSRep_optionalsNULL(t *testing.T) {
	var a TGSRep
	v := "encode_krb5_tgs_rep(optionalsNULL)"
	b, err := hex.DecodeString(testdata.TestVectors[v])
	if err != nil {
		t.Fatalf("Test vector read error of %s: %v\n", v, err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error of %s: %v\n", v, err)
	}
	assert.Equal(t, testdata.TEST_KVNO, a.PVNO, "PVNO not as expected")
	assert.Equal(t, msgtype.KRB_TGS_REP, a.MsgType, "MsgType not as expected")
	assert.Equal(t, 0, len(a.PAData), "Number of PAData items in the sequence not as expected")
	assert.Equal(t, testdata.TEST_REALM, a.CRealm, "Client Realm not as expected")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMETYPE, a.CName.NameType, "CName NameType not as expected")
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.CName.NameString), "CName does not have the expected number of NameStrings")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.CName.NameString, "CName entries not as expected")
	assert.Equal(t, testdata.TEST_KVNO, a.Ticket.TktVNO, "TktVNO not as expected")
	assert.Equal(t, testdata.TEST_REALM, a.Ticket.Realm, "Ticket Realm not as expected")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMETYPE, a.Ticket.SName.NameType, "Ticket service nametype not as expected")
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.Ticket.SName.NameString), "SName in ticket does not have the expected number of NameStrings")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.Ticket.SName.NameString, "Ticket SName entries not as expected")
	assert.Equal(t, testdata.TEST_ETYPE, a.Ticket.EncPart.EType, "Etype of ticket encrypted part not as expected")
	assert.Equal(t, testdata.TEST_KVNO, a.Ticket.EncPart.KVNO, "Ticket encrypted part KVNO not as expected")
	assert.Equal(t, testdata.TEST_CIPHERTEXT, string(a.Ticket.EncPart.Cipher), "Ticket encrypted part cipher not as expected")
	assert.Equal(t, testdata.TEST_ETYPE, a.EncPart.EType, "Etype of encrypted part not as expected")
	assert.Equal(t, testdata.TEST_KVNO, a.EncPart.KVNO, "Encrypted part KVNO not as expected")
	assert.Equal(t, testdata.TEST_CIPHERTEXT, string(a.EncPart.Cipher), "Ticket encrypted part cipher not as expected")
}

func TestUnmarshalEncKDCRepPart(t *testing.T) {
	var a EncKDCRepPart
	v := "encode_krb5_enc_kdc_rep_part"
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

	assert.Equal(t, 1, a.Key.KeyType, "Key type not as expected")
	assert.Equal(t, []byte("12345678"), a.Key.KeyValue, "Key value not as expected")
	assert.Equal(t, 2, len(a.LastReqs), "Number of last request entries not as expected")
	for i, r := range a.LastReqs {
		assert.Equal(t, -5, r.LRType, fmt.Sprintf("Last request typ not as expected for last request entry %d", i+1))
		assert.Equal(t, tt, r.LRValue, fmt.Sprintf("Last request time value not as expected for last request entry %d", i+1))
	}
	assert.Equal(t, testdata.TEST_NONCE, a.Nonce, "Nonce not as expected")
	assert.Equal(t, tt, a.KeyExpiration, "key expiration time not as expected")
	assert.Equal(t, "fedcba98", hex.EncodeToString(a.Flags.Bytes), "Flags not as expected")
	assert.Equal(t, tt, a.AuthTime, "Auth time not as expected")
	assert.Equal(t, tt, a.StartTime, "Start time not as expected")
	assert.Equal(t, tt, a.EndTime, "End time not as expected")
	assert.Equal(t, tt, a.RenewTill, "Renew Till time not as expected")
	assert.Equal(t, testdata.TEST_REALM, a.SRealm, "SRealm not as expected")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMETYPE, a.SName.NameType, "SName type not as expected")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.SName.NameString, "SName string entries not as expected")
	assert.Equal(t, 2, len(a.CAddr), "Number of client addresses not as expected")
	for i, addr := range a.CAddr {
		assert.Equal(t, 2, addr.AddrType, fmt.Sprintf("Host address type not as expected for address item %d", i+1))
		assert.Equal(t, "12d00023", hex.EncodeToString(addr.Address), fmt.Sprintf("Host address not as expected for address item %d", i+1))
	}
}

func TestUnmarshalEncKDCRepPart_optionalsNULL(t *testing.T) {
	var a EncKDCRepPart
	v := "encode_krb5_enc_kdc_rep_part(optionalsNULL)"
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

	assert.Equal(t, 1, a.Key.KeyType, "Key type not as expected")
	assert.Equal(t, []byte("12345678"), a.Key.KeyValue, "Key value not as expected")
	assert.Equal(t, 2, len(a.LastReqs), "Number of last request entries not as expected")
	for i, r := range a.LastReqs {
		assert.Equal(t, -5, r.LRType, fmt.Sprintf("Last request typ not as expected for last request entry %d", i+1))
		assert.Equal(t, tt, r.LRValue, fmt.Sprintf("Last request time value not as expected for last request entry %d", i+1))
	}
	assert.Equal(t, testdata.TEST_NONCE, a.Nonce, "Nonce not as expected")
	assert.Equal(t, "fe5cba98", hex.EncodeToString(a.Flags.Bytes), "Flags not as expected")
	assert.Equal(t, tt, a.AuthTime, "Auth time not as expected")
	assert.Equal(t, tt, a.EndTime, "End time not as expected")
	assert.Equal(t, testdata.TEST_REALM, a.SRealm, "SRealm not as expected")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMETYPE, a.SName.NameType, "SName type not as expected")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.SName.NameString, "SName string entries not as expected")
}

func TestUnmarshalASRepDecodeAndDecrypt(t *testing.T) {
	var asRep ASRep
	b, _ := hex.DecodeString(testuser1EType18ASREP)
	err := asRep.Unmarshal(b)
	if err != nil {
		t.Fatalf("AS REP Unmarshal error: %v\n", err)
	}
	assert.Equal(t, 5, asRep.PVNO, "PVNO not as expected")
	assert.Equal(t, 11, asRep.MsgType, "MsgType not as expected")
	assert.Equal(t, testRealm, asRep.CRealm, "Client Realm not as expected")
	assert.Equal(t, 1, asRep.CName.NameType, "CName NameType not as expected")
	assert.Equal(t, testUser, asRep.CName.NameString[0], "CName NameType not as expected")
	assert.Equal(t, 19, asRep.PAData[0].PADataType, "PADataType not as expected")
	assert.Equal(t, 5, asRep.Ticket.TktVNO, "TktVNO not as expected")
	assert.Equal(t, testRealm, asRep.Ticket.Realm, "Ticket Realm not as expected")
	assert.Equal(t, 2, asRep.Ticket.SName.NameType, "Ticket service nametype not as expected")
	assert.Equal(t, "krbtgt", asRep.Ticket.SName.NameString[0], "Ticket service name string not as expected")
	assert.Equal(t, testRealm, asRep.Ticket.SName.NameString[1], "Ticket service name string not as expected")
	assert.Equal(t, etypeID.ETypesByName["aes256-cts-hmac-sha1-96"], asRep.Ticket.EncPart.EType, "Etype of ticket encrypted part not as expected")
	assert.Equal(t, 1, asRep.Ticket.EncPart.KVNO, "Ticket encrypted part KVNO not as expected")
	assert.Equal(t, etypeID.ETypesByName["aes256-cts-hmac-sha1-96"], asRep.EncPart.EType, "Etype of encrypted part not as expected")
	assert.Equal(t, 0, asRep.EncPart.KVNO, "Encrypted part KVNO not as expected")
	//t.Log("Finished testing unecrypted parts of AS REP")
	ktb, _ := hex.DecodeString(testuser1EType18Keytab)
	kt, err := keytab.Parse(ktb)
	if err != nil {
		t.Fatalf("keytab parse error: %v\n", err)
	}
	cred := credentials.NewCredentials(testUser, testRealm)
	_, err = asRep.DecryptEncPart(cred.WithKeytab(kt))
	if err != nil {
		t.Fatalf("Decryption of AS_REP EncPart failed: %v", err)
	}
	assert.Equal(t, 18, asRep.DecryptedEncPart.Key.KeyType, "KeyType in decrypted EncPart not as expected")
	assert.IsType(t, time.Time{}, asRep.DecryptedEncPart.LastReqs[0].LRValue, "LastReqs did not have a time value")
	assert.Equal(t, 2069991465, asRep.DecryptedEncPart.Nonce, "Nonce value not as expected")
	assert.IsType(t, time.Time{}, asRep.DecryptedEncPart.KeyExpiration, "Key expiration not a time type")
	assert.IsType(t, time.Time{}, asRep.DecryptedEncPart.AuthTime, "AuthTime not a time type")
	assert.IsType(t, time.Time{}, asRep.DecryptedEncPart.StartTime, "StartTime not a time type")
	assert.IsType(t, time.Time{}, asRep.DecryptedEncPart.EndTime, "StartTime not a time type")
	assert.IsType(t, time.Time{}, asRep.DecryptedEncPart.RenewTill, "RenewTill not a time type")
	assert.Equal(t, testRealm, asRep.DecryptedEncPart.SRealm, "Service realm not as expected")
	assert.Equal(t, 2, asRep.DecryptedEncPart.SName.NameType, "Name type for AS_REP not as expected")
	assert.Equal(t, []string{"krbtgt", testRealm}, asRep.DecryptedEncPart.SName.NameString, "Service name string not as expected")
}

func TestUnmarshalASRepDecodeAndDecrypt_withPassword(t *testing.T) {
	var asRep ASRep
	b, _ := hex.DecodeString(testuser1EType18ASREP)
	err := asRep.Unmarshal(b)
	if err != nil {
		t.Fatalf("AS REP Unmarshal error: %v\n", err)
	}
	assert.Equal(t, 5, asRep.PVNO, "PVNO not as expected")
	assert.Equal(t, 11, asRep.MsgType, "MsgType not as expected")
	assert.Equal(t, testRealm, asRep.CRealm, "Client Realm not as expected")
	assert.Equal(t, 1, asRep.CName.NameType, "CName NameType not as expected")
	assert.Equal(t, testUser, asRep.CName.NameString[0], "CName NameType not as expected")
	assert.Equal(t, 19, asRep.PAData[0].PADataType, "PADataType not as expected")
	assert.Equal(t, 5, asRep.Ticket.TktVNO, "TktVNO not as expected")
	assert.Equal(t, testRealm, asRep.Ticket.Realm, "Ticket Realm not as expected")
	assert.Equal(t, 2, asRep.Ticket.SName.NameType, "Ticket service nametype not as expected")
	assert.Equal(t, "krbtgt", asRep.Ticket.SName.NameString[0], "Ticket service name string not as expected")
	assert.Equal(t, testRealm, asRep.Ticket.SName.NameString[1], "Ticket service name string not as expected")
	assert.Equal(t, etypeID.AES256_CTS_HMAC_SHA1_96, asRep.Ticket.EncPart.EType, "Etype of ticket encrypted part not as expected")
	assert.Equal(t, 1, asRep.Ticket.EncPart.KVNO, "Ticket encrypted part KVNO not as expected")
	assert.Equal(t, etypeID.AES256_CTS_HMAC_SHA1_96, asRep.EncPart.EType, "Etype of encrypted part not as expected")
	assert.Equal(t, 0, asRep.EncPart.KVNO, "Encrypted part KVNO not as expected")
	cred := credentials.NewCredentials(testUser, testRealm)
	_, err = asRep.DecryptEncPart(cred.WithPassword(testUserPassword))
	if err != nil {
		t.Fatalf("Decryption of AS_REP EncPart failed: %v", err)
	}
	assert.Equal(t, 18, asRep.DecryptedEncPart.Key.KeyType, "KeyType in decrypted EncPart not as expected")
	assert.IsType(t, time.Time{}, asRep.DecryptedEncPart.LastReqs[0].LRValue, "LastReqs did not have a time value")
	assert.Equal(t, 2069991465, asRep.DecryptedEncPart.Nonce, "Nonce value not as expected")
	assert.IsType(t, time.Time{}, asRep.DecryptedEncPart.KeyExpiration, "Key expiration not a time type")
	assert.IsType(t, time.Time{}, asRep.DecryptedEncPart.AuthTime, "AuthTime not a time type")
	assert.IsType(t, time.Time{}, asRep.DecryptedEncPart.StartTime, "StartTime not a time type")
	assert.IsType(t, time.Time{}, asRep.DecryptedEncPart.EndTime, "StartTime not a time type")
	assert.IsType(t, time.Time{}, asRep.DecryptedEncPart.RenewTill, "RenewTill not a time type")
	assert.Equal(t, testRealm, asRep.DecryptedEncPart.SRealm, "Service realm not as expected")
	assert.Equal(t, 2, asRep.DecryptedEncPart.SName.NameType, "Name type for AS_REP not as expected")
	assert.Equal(t, []string{"krbtgt", testRealm}, asRep.DecryptedEncPart.SName.NameString, "Service name string not as expected")
}
