package client

import (
	"bytes"
	"encoding/hex"
	"log"
	"testing"

	"github.com/hashicorp/vault-plugin-auth-kerberos/internal/gokrb5/config"
	"github.com/hashicorp/vault-plugin-auth-kerberos/internal/gokrb5/iana/etypeID"
	"github.com/hashicorp/vault-plugin-auth-kerberos/internal/gokrb5/iana/nametype"
	"github.com/hashicorp/vault-plugin-auth-kerberos/internal/gokrb5/keytab"
	"github.com/hashicorp/vault-plugin-auth-kerberos/internal/gokrb5/test"
	"github.com/hashicorp/vault-plugin-auth-kerberos/internal/gokrb5/test/testdata"
	"github.com/hashicorp/vault-plugin-auth-kerberos/internal/gokrb5/types"
	"github.com/stretchr/testify/assert"
)

func TestClient_SuccessfulLogin_AD(t *testing.T) {
	test.AD(t)

	b, _ := hex.DecodeString(testdata.TESTUSER1_KEYTAB)
	kt := keytab.New()
	kt.Unmarshal(b)
	c, _ := config.NewConfigFromString(testdata.TEST_KRB5CONF)
	c.Realms[0].KDC = []string{testdata.TEST_KDC_AD}
	cl := NewClientWithKeytab("testuser1", "TEST.GOKRB5", kt, c)

	err := cl.Login()
	if err != nil {
		t.Fatalf("Error on login: %v\n", err)
	}
}

func TestClient_GetServiceTicket_AD(t *testing.T) {
	test.AD(t)

	b, _ := hex.DecodeString(testdata.TESTUSER1_KEYTAB)
	kt := keytab.New()
	kt.Unmarshal(b)
	c, _ := config.NewConfigFromString(testdata.TEST_KRB5CONF)
	c.Realms[0].KDC = []string{testdata.TEST_KDC_AD}
	cl := NewClientWithKeytab("testuser1", "TEST.GOKRB5", kt, c)

	err := cl.Login()
	if err != nil {
		t.Fatalf("Error on login: %v\n", err)
	}
	spn := "HTTP/host.test.gokrb5"
	tkt, key, err := cl.GetServiceTicket(spn)
	if err != nil {
		t.Fatalf("Error getting service ticket: %v\n", err)
	}
	assert.Equal(t, spn, tkt.SName.PrincipalNameString())
	assert.Equal(t, int32(18), key.KeyType)

	b, _ = hex.DecodeString(testdata.SYSHTTP_KEYTAB)
	skt := keytab.New()
	skt.Unmarshal(b)
	sname := types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: []string{"sysHTTP"}}
	err = tkt.DecryptEncPart(skt, &sname)
	if err != nil {
		t.Errorf("could not decrypt service ticket: %v", err)
	}
	w := bytes.NewBufferString("")
	l := log.New(w, "", 0)
	isPAC, pac, err := tkt.GetPACType(skt, &sname, l)
	if err != nil {
		t.Log(w.String())
		t.Errorf("error getting PAC: %v", err)
	}
	assert.True(t, isPAC, "should have PAC")
	assert.Equal(t, "TEST", pac.KerbValidationInfo.LogonDomainName.String(), "domain name in PAC not correct")
}

func TestClient_SuccessfulLogin_AD_TRUST_USER_DOMAIN(t *testing.T) {
	test.AD(t)

	b, _ := hex.DecodeString(testdata.TESTUSER1_USERKRB5_AD_KEYTAB)
	kt := keytab.New()
	kt.Unmarshal(b)
	c, _ := config.NewConfigFromString(testdata.TEST_KRB5CONF)
	c.Realms[0].KDC = []string{testdata.TEST_KDC_AD_TRUST_USER_DOMAIN}
	c.LibDefaults.DefaultRealm = "USER.GOKRB5"
	cl := NewClientWithKeytab("testuser1", "USER.GOKRB5", kt, c, DisablePAFXFAST(true))

	err := cl.Login()
	if err != nil {
		t.Fatalf("Error on login: %v\n", err)
	}
}

func TestClient_GetServiceTicket_AD_TRUST_USER_DOMAIN(t *testing.T) {
	test.AD(t)

	b, _ := hex.DecodeString(testdata.TESTUSER1_USERKRB5_AD_KEYTAB)
	kt := keytab.New()
	kt.Unmarshal(b)
	c, _ := config.NewConfigFromString(testdata.TEST_KRB5CONF)
	c.Realms[0].KDC = []string{testdata.TEST_KDC_AD_TRUST_USER_DOMAIN}
	c.LibDefaults.DefaultRealm = "USER.GOKRB5"
	c.LibDefaults.Canonicalize = true
	c.LibDefaults.DefaultTktEnctypes = []string{"rc4-hmac"}
	c.LibDefaults.DefaultTktEnctypeIDs = []int32{etypeID.ETypesByName["rc4-hmac"]}
	c.LibDefaults.DefaultTGSEnctypes = []string{"rc4-hmac"}
	c.LibDefaults.DefaultTGSEnctypeIDs = []int32{etypeID.ETypesByName["rc4-hmac"]}
	cl := NewClientWithKeytab("testuser1", "USER.GOKRB5", kt, c, DisablePAFXFAST(true))

	err := cl.Login()

	if err != nil {
		t.Fatalf("Error on login: %v\n", err)
	}
	spn := "HTTP/host.res.gokrb5"
	tkt, key, err := cl.GetServiceTicket(spn)
	if err != nil {
		t.Fatalf("Error getting service ticket: %v\n", err)
	}
	assert.Equal(t, spn, tkt.SName.PrincipalNameString())
	assert.Equal(t, etypeID.ETypesByName["rc4-hmac"], key.KeyType)

	b, _ = hex.DecodeString(testdata.SYSHTTP_RESGOKRB5_AD_KEYTAB)
	skt := keytab.New()
	skt.Unmarshal(b)
	sname := types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: []string{"sysHTTP"}}
	err = tkt.DecryptEncPart(skt, &sname)
	if err != nil {
		t.Errorf("error decrypting ticket with service keytab: %v", err)
	}
	w := bytes.NewBufferString("")
	l := log.New(w, "", 0)
	isPAC, pac, err := tkt.GetPACType(skt, &sname, l)
	if err != nil {
		t.Log(w.String())
		t.Errorf("error getting PAC: %v", err)
	}
	assert.True(t, isPAC, "Did not find PAC in service ticket")
	assert.Equal(t, "testuser1", pac.KerbValidationInfo.EffectiveName.Value, "PAC value not parsed")

}

func TestClient_GetServiceTicket_AD_USER_DOMAIN(t *testing.T) {
	test.AD(t)

	b, _ := hex.DecodeString(testdata.TESTUSER1_USERKRB5_AD_KEYTAB)
	kt := keytab.New()
	kt.Unmarshal(b)
	c, _ := config.NewConfigFromString(testdata.TEST_KRB5CONF)
	c.Realms[0].KDC = []string{testdata.TEST_KDC_AD_TRUST_USER_DOMAIN}
	c.LibDefaults.DefaultRealm = "USER.GOKRB5"
	c.LibDefaults.Canonicalize = true
	c.LibDefaults.DefaultTktEnctypes = []string{"rc4-hmac"}
	c.LibDefaults.DefaultTktEnctypeIDs = []int32{etypeID.ETypesByName["rc4-hmac"]}
	c.LibDefaults.DefaultTGSEnctypes = []string{"rc4-hmac"}
	c.LibDefaults.DefaultTGSEnctypeIDs = []int32{etypeID.ETypesByName["rc4-hmac"]}
	cl := NewClientWithKeytab("testuser1", "USER.GOKRB5", kt, c, DisablePAFXFAST(true))

	err := cl.Login()

	if err != nil {
		t.Fatalf("Error on login: %v\n", err)
	}
	spn := "HTTP/user2.user.gokrb5"
	tkt, _, err := cl.GetServiceTicket(spn)
	if err != nil {
		t.Fatalf("Error getting service ticket: %v\n", err)
	}
	assert.Equal(t, spn, tkt.SName.PrincipalNameString())
	//assert.Equal(t, etypeID.ETypesByName["rc4-hmac"], key.KeyType)

	b, _ = hex.DecodeString(testdata.TESTUSER2_USERKRB5_AD_KEYTAB)
	skt := keytab.New()
	skt.Unmarshal(b)
	sname := types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: []string{"testuser2"}}
	err = tkt.DecryptEncPart(skt, &sname)
	if err != nil {
		t.Errorf("error decrypting ticket with service keytab: %v", err)
	}
	w := bytes.NewBufferString("")
	l := log.New(w, "", 0)
	isPAC, pac, err := tkt.GetPACType(skt, &sname, l)
	if err != nil {
		t.Log(w.String())
		t.Errorf("error getting PAC: %v", err)
	}
	assert.True(t, isPAC, "Did not find PAC in service ticket")
	assert.Equal(t, "testuser1", pac.KerbValidationInfo.EffectiveName.Value, "PAC value not parsed")

}
