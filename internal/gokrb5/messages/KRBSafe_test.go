package messages

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/hashicorp/vault-plugin-auth-kerberos/internal/gokrb5/iana"
	"github.com/hashicorp/vault-plugin-auth-kerberos/internal/gokrb5/iana/addrtype"
	"github.com/hashicorp/vault-plugin-auth-kerberos/internal/gokrb5/iana/msgtype"
	"github.com/hashicorp/vault-plugin-auth-kerberos/internal/gokrb5/test/testdata"
	"github.com/stretchr/testify/assert"
)

func TestUnmarshalKRBSafe(t *testing.T) {
	t.Parallel()
	var a KRBSafe
	b, err := hex.DecodeString(testdata.MarshaledKRB5safe)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	//Parse the test time value into a time.Time type
	tt, _ := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)

	assert.Equal(t, iana.PVNO, a.PVNO, "PVNO not as expected")
	assert.Equal(t, msgtype.KRB_SAFE, a.MsgType, "MsgType is not as expected")
	assert.Equal(t, []byte("krb5data"), a.SafeBody.UserData, "Safe body userdata not as expected")
	assert.Equal(t, tt, a.SafeBody.Timestamp, "Safe body timestamp not as expected")
	assert.Equal(t, 123456, a.SafeBody.Usec, "Safe body microseconds not as expected")
	assert.Equal(t, int64(17), a.SafeBody.SequenceNumber, "Safe body sequence number not as expected")
	assert.Equal(t, addrtype.IPv4, a.SafeBody.SAddress.AddrType, "SAddress type not as expected")
	assert.Equal(t, "12d00023", hex.EncodeToString(a.SafeBody.SAddress.Address), "SAddress not as expected")
	assert.Equal(t, addrtype.IPv4, a.SafeBody.RAddress.AddrType, "RAddress type not as expected")
	assert.Equal(t, "12d00023", hex.EncodeToString(a.SafeBody.RAddress.Address), "RAddress not as expected")
	assert.Equal(t, int32(1), a.Cksum.CksumType, "Checksum type not as expected")
	assert.Equal(t, []byte("1234"), a.Cksum.Checksum, "Checksum not as expected")
}

func TestUnmarshalKRBSafe_optionalsNULL(t *testing.T) {
	t.Parallel()
	var a KRBSafe
	b, err := hex.DecodeString(testdata.MarshaledKRB5safeOptionalsNULL)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	assert.Equal(t, iana.PVNO, a.PVNO, "PVNO not as expected")
	assert.Equal(t, msgtype.KRB_SAFE, a.MsgType, "MsgType is not as expected")
	assert.Equal(t, []byte("krb5data"), a.SafeBody.UserData, "Safe body userdata not as expected")
	assert.Equal(t, addrtype.IPv4, a.SafeBody.SAddress.AddrType, "SAddress type not as expected")
	assert.Equal(t, "12d00023", hex.EncodeToString(a.SafeBody.SAddress.Address), "SAddress not as expected")
	assert.Equal(t, int32(1), a.Cksum.CksumType, "Checksum type not as expected")
	assert.Equal(t, []byte("1234"), a.Cksum.Checksum, "Checksum not as expected")
}
