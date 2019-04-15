package kadmin

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/jcmturner/gokrb5.v5/iana/nametype"
	"gopkg.in/jcmturner/gokrb5.v5/testdata"
	"gopkg.in/jcmturner/gokrb5.v5/types"
)

func TestChangePasswdData_Marshal(t *testing.T) {
	t.Parallel()
	chgpasswd := ChangePasswdData{
		NewPasswd: []byte("newpassword"),
		TargName:  types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "testuser1"),
		TargRealm: "TEST.GOKRB5",
	}
	chpwdb, err := chgpasswd.Marshal()
	if err != nil {
		t.Fatalf("error marshaling change passwd data: %v\n", err)
	}
	v := "ChangePasswdData"
	b, err := hex.DecodeString(testdata.TestVectors[v])
	if err != nil {
		t.Fatalf("Test vector read error of %s: %v\n", v, err)
	}
	assert.Equal(t, b, chpwdb, "marshaled bytes of change passwd data not as expected")
}
