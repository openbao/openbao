package kadmin

import (
	"encoding/hex"
	"testing"

	"github.com/hashicorp/vault-plugin-auth-kerberos/internal/gokrb5/iana"
	"github.com/hashicorp/vault-plugin-auth-kerberos/internal/gokrb5/iana/msgtype"
	"github.com/hashicorp/vault-plugin-auth-kerberos/internal/gokrb5/test/testdata"
	"github.com/stretchr/testify/assert"
)

func TestUnmarshalReply(t *testing.T) {
	t.Parallel()
	var a Reply
	b, err := hex.DecodeString(testdata.MarshaledKpasswd_Rep)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	assert.Equal(t, 236, a.MessageLength, "message length not as expected")
	assert.Equal(t, 1, a.Version, "message version not as expected")
	assert.Equal(t, 140, a.APREPLength, "AP_REP length not as expected")
	assert.Equal(t, iana.PVNO, a.APREP.PVNO, "AP_REP within reply not as expected")
	assert.Equal(t, msgtype.KRB_AP_REP, a.APREP.MsgType, "AP_REP message type within reply not as expected")
	assert.Equal(t, int32(18), a.APREP.EncPart.EType, "AP_REQ etype not as expected")
	assert.Equal(t, iana.PVNO, a.KRBPriv.PVNO, "KRBPriv within reply not as expected")
	assert.Equal(t, msgtype.KRB_PRIV, a.KRBPriv.MsgType, "KRBPriv type within reply not as expected")
	assert.Equal(t, int32(18), a.KRBPriv.EncPart.EType, "KRBPriv etype not as expected")
}

// Request marshal is tested via integration test in the client package due to the dynamic keys and encryption.
