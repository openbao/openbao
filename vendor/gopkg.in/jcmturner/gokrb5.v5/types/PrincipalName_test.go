package types

import (
	"github.com/stretchr/testify/assert"
	"gopkg.in/jcmturner/gokrb5.v5/iana/nametype"

	"testing"
)

func TestPrincipalName_GetSalt(t *testing.T) {
	t.Parallel()
	pn := PrincipalName{
		NameType:   1,
		NameString: []string{"firststring", "secondstring"},
	}
	assert.Equal(t, "TEST.GOKRB5firststringsecondstring", pn.GetSalt("TEST.GOKRB5"), "Principal name default salt not as expected")
}

func TestParseSPNString(t *testing.T) {
	pn, realm := ParseSPNString("HTTP/www.example.com@REALM.COM")
	assert.Equal(t, "REALM.COM", realm, "realm value not as expected")
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, pn.NameType, "name type not as expected")
	assert.Equal(t, "HTTP", pn.NameString[0], "first element of name string not as expected")
	assert.Equal(t, "www.example.com", pn.NameString[1], "second element of name string not as expected")

	pn, realm = ParseSPNString("HTTP/www.example.com")
	assert.Equal(t, "", realm, "realm value not as expected")
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, pn.NameType, "name type not as expected")
	assert.Equal(t, "HTTP", pn.NameString[0], "first element of name string not as expected")
	assert.Equal(t, "www.example.com", pn.NameString[1], "second element of name string not as expected")

	pn, realm = ParseSPNString("www.example.com@REALM.COM")
	assert.Equal(t, "REALM.COM", realm, "realm value not as expected")
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, pn.NameType, "name type not as expected")
	assert.Equal(t, "www.example.com", pn.NameString[0], "second element of name string not as expected")

}
