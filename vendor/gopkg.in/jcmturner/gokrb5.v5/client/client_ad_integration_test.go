// +build adintegration
// To turn on this test use -tags=integration in go test command

package client

import (
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"gopkg.in/jcmturner/gokrb5.v5/config"
	"gopkg.in/jcmturner/gokrb5.v5/iana/etypeID"
	"gopkg.in/jcmturner/gokrb5.v5/keytab"
	"gopkg.in/jcmturner/gokrb5.v5/testdata"
	"testing"
)

func TestClient_SuccessfulLogin_AD(t *testing.T) {
	b, _ := hex.DecodeString(testdata.TESTUSER1_KEYTAB)
	kt, _ := keytab.Parse(b)
	c, _ := config.NewConfigFromString(testdata.TEST_KRB5CONF)
	c.Realms[0].KDC = []string{testdata.TEST_KDC_AD}
	cl := NewClientWithKeytab("testuser1", "TEST.GOKRB5", kt)
	cl.WithConfig(c)

	err := cl.Login()
	if err != nil {
		t.Fatalf("Error on login: %v\n", err)
	}
}

func TestClient_GetServiceTicket_AD(t *testing.T) {
	b, _ := hex.DecodeString(testdata.TESTUSER1_KEYTAB)
	kt, _ := keytab.Parse(b)
	c, _ := config.NewConfigFromString(testdata.TEST_KRB5CONF)
	c.Realms[0].KDC = []string{testdata.TEST_KDC_AD}
	cl := NewClientWithKeytab("testuser1", "TEST.GOKRB5", kt)
	cl.WithConfig(c)

	err := cl.Login()
	if err != nil {
		t.Fatalf("Error on login: %v\n", err)
	}
	spn := "HTTP/host.test.gokrb5"
	tkt, key, err := cl.GetServiceTicket(spn)
	if err != nil {
		t.Fatalf("Error getting service ticket: %v\n", err)
	}
	assert.Equal(t, spn, tkt.SName.GetPrincipalNameString())
	assert.Equal(t, int32(18), key.KeyType)
}

func TestClient_SuccessfulLogin_AD_TRUST_USER_DOMAIN(t *testing.T) {
	b, _ := hex.DecodeString(testdata.TESTUSER1_USERKRB5_AD_KEYTAB)
	kt, _ := keytab.Parse(b)
	c, _ := config.NewConfigFromString(testdata.TEST_KRB5CONF)
	c.Realms[0].KDC = []string{testdata.TEST_KDC_AD_TRUST_USER_DOMAIN}
	c.LibDefaults.DefaultRealm = "USER.GOKRB5"
	cl := NewClientWithKeytab("testuser1", "USER.GOKRB5", kt)
	cl.WithConfig(c)
	cl.GoKrb5Conf.DisablePAFXFast = true

	err := cl.Login()
	if err != nil {
		t.Fatalf("Error on login: %v\n", err)
	}
}

func TestClient_GetServiceTicket_AD_TRUST_USER_DOMAIN(t *testing.T) {
	b, _ := hex.DecodeString(testdata.TESTUSER1_USERKRB5_AD_KEYTAB)
	kt, _ := keytab.Parse(b)
	c, _ := config.NewConfigFromString(testdata.TEST_KRB5CONF)
	c.Realms[0].KDC = []string{testdata.TEST_KDC_AD_TRUST_USER_DOMAIN}
	c.LibDefaults.DefaultRealm = "USER.GOKRB5"
	c.LibDefaults.Canonicalize = true
	cl := NewClientWithKeytab("testuser1", "USER.GOKRB5", kt)
	c.LibDefaults.DefaultTktEnctypes = []string{"rc4-hmac"}
	c.LibDefaults.DefaultTktEnctypeIDs = []int32{etypeID.ETypesByName["rc4-hmac"]}
	c.LibDefaults.DefaultTGSEnctypes = []string{"rc4-hmac"}
	c.LibDefaults.DefaultTGSEnctypeIDs = []int32{etypeID.ETypesByName["rc4-hmac"]}
	cl.WithConfig(c)
	cl.GoKrb5Conf.DisablePAFXFast = true

	err := cl.Login()

	if err != nil {
		t.Fatalf("Error on login: %v\n", err)
	}
	spn := "HTTP/host.res.gokrb5"
	tkt, key, err := cl.GetServiceTicket(spn)
	if err != nil {
		t.Fatalf("Error getting service ticket: %v\n", err)
	}
	assert.Equal(t, spn, tkt.SName.GetPrincipalNameString())
	assert.Equal(t, etypeID.ETypesByName["rc4-hmac"], key.KeyType)

	b, _ = hex.DecodeString(testdata.SYSHTTP_RESGOKRB5_AD_KEYTAB)
	skt, _ := keytab.Parse(b)
	err = tkt.DecryptEncPart(skt, "sysHTTP")
	if err != nil {
		t.Errorf("error decrypting ticket with service keytab: %v", err)
	}
	isPAC, pac, err := tkt.GetPACType(skt, "sysHTTP")
	if err != nil {
		t.Errorf("error getting PAC: %v", err)
	}
	assert.True(t, isPAC, "Did not find PAC in service ticket")
	assert.Equal(t, "testuser1", pac.KerbValidationInfo.EffectiveName.Value, "PAC value not parsed")

}

func TestClient_GetServiceTicket_AD_USER_DOMAIN(t *testing.T) {
	b, _ := hex.DecodeString(testdata.TESTUSER1_USERKRB5_AD_KEYTAB)
	kt, _ := keytab.Parse(b)
	c, _ := config.NewConfigFromString(testdata.TEST_KRB5CONF)
	c.Realms[0].KDC = []string{testdata.TEST_KDC_AD_TRUST_USER_DOMAIN}
	c.LibDefaults.DefaultRealm = "USER.GOKRB5"
	c.LibDefaults.Canonicalize = true
	cl := NewClientWithKeytab("testuser1", "USER.GOKRB5", kt)
	c.LibDefaults.DefaultTktEnctypes = []string{"rc4-hmac"}
	c.LibDefaults.DefaultTktEnctypeIDs = []int32{etypeID.ETypesByName["rc4-hmac"]}
	c.LibDefaults.DefaultTGSEnctypes = []string{"rc4-hmac"}
	c.LibDefaults.DefaultTGSEnctypeIDs = []int32{etypeID.ETypesByName["rc4-hmac"]}
	cl.WithConfig(c)
	cl.GoKrb5Conf.DisablePAFXFast = true

	err := cl.Login()

	if err != nil {
		t.Fatalf("Error on login: %v\n", err)
	}
	spn := "HTTP/user2.user.gokrb5"
	tkt, _, err := cl.GetServiceTicket(spn)
	if err != nil {
		t.Fatalf("Error getting service ticket: %v\n", err)
	}
	assert.Equal(t, spn, tkt.SName.GetPrincipalNameString())
	//assert.Equal(t, etypeID.ETypesByName["rc4-hmac"], key.KeyType)

	b, _ = hex.DecodeString(testdata.TESTUSER2_USERKRB5_AD_KEYTAB)
	skt, _ := keytab.Parse(b)
	err = tkt.DecryptEncPart(skt, "testuser2")
	if err != nil {
		t.Errorf("error decrypting ticket with service keytab: %v", err)
	}
	isPAC, pac, err := tkt.GetPACType(skt, "testuser2")
	if err != nil {
		t.Errorf("error getting PAC: %v", err)
	}
	assert.True(t, isPAC, "Did not find PAC in service ticket")
	assert.Equal(t, "testuser1", pac.KerbValidationInfo.EffectiveName.Value, "PAC value not parsed")

}
