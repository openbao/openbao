package messages

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/hashicorp/vault-plugin-auth-kerberos/internal/gokrb5/iana"
	"github.com/hashicorp/vault-plugin-auth-kerberos/internal/gokrb5/iana/msgtype"
	"github.com/hashicorp/vault-plugin-auth-kerberos/internal/gokrb5/test/testdata"
	"github.com/stretchr/testify/assert"
)

func TestUnmarshalAPRep(t *testing.T) {
	t.Parallel()
	var a APRep
	b, err := hex.DecodeString(testdata.MarshaledKRB5ap_rep)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	assert.Equal(t, iana.PVNO, a.PVNO, "PVNO not as expected")
	assert.Equal(t, msgtype.KRB_AP_REP, a.MsgType, "MsgType is not as expected")
	assert.Equal(t, testdata.TEST_ETYPE, a.EncPart.EType, "Ticket encPart etype not as expected")
	assert.Equal(t, iana.PVNO, a.EncPart.KVNO, "Ticket encPart KVNO not as expected")
	assert.Equal(t, []byte(testdata.TEST_CIPHERTEXT), a.EncPart.Cipher, "Ticket encPart cipher not as expected")
}

func TestUnmarshalEncAPRepPart(t *testing.T) {
	t.Parallel()
	var a EncAPRepPart
	b, err := hex.DecodeString(testdata.MarshaledKRB5ap_rep_enc_part)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	//Parse the test time value into a time.Time type
	tt, _ := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)

	assert.Equal(t, tt, a.CTime, "CTime not as expected")
	assert.Equal(t, 123456, a.Cusec, "Client microseconds not as expected")
	assert.Equal(t, int32(1), a.Subkey.KeyType, "Subkey type not as expected")
	assert.Equal(t, []byte("12345678"), a.Subkey.KeyValue, "Subkey value not as expected")
	assert.Equal(t, int64(17), a.SequenceNumber, "Sequence number not as expected")
}

func TestUnmarshalEncAPRepPart_optionalsNULL(t *testing.T) {
	t.Parallel()
	var a EncAPRepPart
	b, err := hex.DecodeString(testdata.MarshaledKRB5ap_rep_enc_partOptionalsNULL)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	//Parse the test time value into a time.Time type
	tt, _ := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)

	assert.Equal(t, tt, a.CTime, "CTime not as expected")
	assert.Equal(t, 123456, a.Cusec, "Client microseconds not as expected")
}
