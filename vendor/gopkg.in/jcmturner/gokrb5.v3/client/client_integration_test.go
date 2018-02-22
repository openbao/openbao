// +build integration
// To turn on this test use -tags=integration in go test command

package client

import (
	"encoding/hex"
	"net/http"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/jcmturner/gokrb5.v3/config"
	"gopkg.in/jcmturner/gokrb5.v3/credentials"
	"gopkg.in/jcmturner/gokrb5.v3/iana/etypeID"
	"gopkg.in/jcmturner/gokrb5.v3/keytab"
	"gopkg.in/jcmturner/gokrb5.v3/testdata"
)

func TestClient_SuccessfulLogin_Keytab(t *testing.T) {
	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.TEST_KDC_ADDR
	}
	b, err := hex.DecodeString(testdata.TESTUSER1_KEYTAB)
	kt, _ := keytab.Parse(b)
	c, _ := config.NewConfigFromString(testdata.TEST_KRB5CONF)
	var tests = []string{
		testdata.TEST_KDC,
		testdata.TEST_KDC_OLD,
		testdata.TEST_KDC_LASTEST,
	}
	for _, test := range tests {
		c.Realms[0].KDC = []string{addr + ":" + test}
		cl := NewClientWithKeytab("testuser1", "TEST.GOKRB5", kt)
		cl.WithConfig(c)

		err = cl.Login()
		if err != nil {
			t.Errorf("Error on logging in with KDC %s: %v\n", test, err)
		}
	}
}

func TestClient_SuccessfulLogin_Password(t *testing.T) {
	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.TEST_KDC_ADDR
	}
	c, _ := config.NewConfigFromString(testdata.TEST_KRB5CONF)
	var tests = []string{
		testdata.TEST_KDC,
		testdata.TEST_KDC_OLD,
		testdata.TEST_KDC_LASTEST,
	}
	for _, test := range tests {
		c.Realms[0].KDC = []string{addr + ":" + test}
		cl := NewClientWithPassword("testuser1", "TEST.GOKRB5", "passwordvalue")
		cl.WithConfig(c)

		err := cl.Login()
		if err != nil {
			t.Errorf("Error on logging in with KDC %s: %v\n", test, err)
		}
	}
}

func TestClient_SuccessfulLogin_TCPOnly(t *testing.T) {
	b, err := hex.DecodeString(testdata.TESTUSER1_KEYTAB)
	kt, _ := keytab.Parse(b)
	c, _ := config.NewConfigFromString(testdata.TEST_KRB5CONF)
	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.TEST_KDC_ADDR
	}
	c.Realms[0].KDC = []string{addr + ":" + testdata.TEST_KDC}
	c.LibDefaults.UDPPreferenceLimit = 1
	cl := NewClientWithKeytab("testuser1", "TEST.GOKRB5", kt)
	cl.WithConfig(c)

	err = cl.Login()
	if err != nil {
		t.Fatalf("Error on login: %v\n", err)
	}
}

func TestClient_ASExchange_TGSExchange_EncTypes_Keytab(t *testing.T) {
	b, err := hex.DecodeString(testdata.TESTUSER1_KEYTAB)
	kt, _ := keytab.Parse(b)
	c, _ := config.NewConfigFromString(testdata.TEST_KRB5CONF)
	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.TEST_KDC_ADDR
	}
	c.Realms[0].KDC = []string{addr + ":" + testdata.TEST_KDC_LASTEST}
	var tests = []string{
		"des3-cbc-sha1-kd",
		"aes128-cts-hmac-sha1-96",
		"aes256-cts-hmac-sha1-96",
		"aes128-cts-hmac-sha256-128",
		"aes256-cts-hmac-sha384-192",
		"rc4-hmac",
	}
	for _, test := range tests {
		c.LibDefaults.DefaultTktEnctypes = []string{test}
		c.LibDefaults.DefaultTktEnctypeIDs = []int{etypeID.ETypesByName[test]}
		c.LibDefaults.DefaultTGSEnctypes = []string{test}
		c.LibDefaults.DefaultTGSEnctypeIDs = []int{etypeID.ETypesByName[test]}
		cl := NewClientWithKeytab("testuser1", "TEST.GOKRB5", kt)
		cl.WithConfig(c)

		err = cl.Login()
		if err != nil {
			t.Errorf("Error on login using enctype %s: %v\n", test, err)
		}
		tkt, key, err := cl.GetServiceTicket("HTTP/host.test.gokrb5")
		if err != nil {
			t.Errorf("Error in TGS exchange using enctype %s: %v", test, err)
		}
		assert.Equal(t, "TEST.GOKRB5", tkt.Realm, "Realm in ticket not as expected for %s test", test)
		assert.Equal(t, etypeID.ETypesByName[test], key.KeyType, "Key is not for enctype %s", test)
	}
}

func TestClient_ASExchange_TGSExchange_EncTypes_Password(t *testing.T) {
	c, _ := config.NewConfigFromString(testdata.TEST_KRB5CONF)
	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.TEST_KDC_ADDR
	}
	c.Realms[0].KDC = []string{addr + ":" + testdata.TEST_KDC_LASTEST}
	var tests = []string{
		"des3-cbc-sha1-kd",
		"aes128-cts-hmac-sha1-96",
		"aes256-cts-hmac-sha1-96",
		"aes128-cts-hmac-sha256-128",
		"aes256-cts-hmac-sha384-192",
		"rc4-hmac",
	}
	for _, test := range tests {
		c.LibDefaults.DefaultTktEnctypes = []string{test}
		c.LibDefaults.DefaultTktEnctypeIDs = []int{etypeID.ETypesByName[test]}
		c.LibDefaults.DefaultTGSEnctypes = []string{test}
		c.LibDefaults.DefaultTGSEnctypeIDs = []int{etypeID.ETypesByName[test]}
		cl := NewClientWithPassword("testuser1", "TEST.GOKRB5", "passwordvalue")
		cl.WithConfig(c)

		err := cl.Login()
		if err != nil {
			t.Errorf("Error on login using enctype %s: %v\n", test, err)
		}
		tkt, key, err := cl.GetServiceTicket("HTTP/host.test.gokrb5")
		if err != nil {
			t.Errorf("Error in TGS exchange using enctype %s: %v", test, err)
		}
		assert.Equal(t, "TEST.GOKRB5", tkt.Realm, "Realm in ticket not as expected for %s test", test)
		assert.Equal(t, etypeID.ETypesByName[test], key.KeyType, "Key is not for enctype %s", test)
	}
}

func TestClient_FailedLogin(t *testing.T) {
	b, err := hex.DecodeString(testdata.TESTUSER1_WRONGPASSWD)
	kt, _ := keytab.Parse(b)
	c, _ := config.NewConfigFromString(testdata.TEST_KRB5CONF)
	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.TEST_KDC_ADDR
	}
	c.Realms[0].KDC = []string{addr + ":" + testdata.TEST_KDC}
	cl := NewClientWithKeytab("testuser1", "TEST.GOKRB5", kt)
	cl.WithConfig(c)

	err = cl.Login()
	if err == nil {
		t.Fatal("Login with incorrect password did not error")
	}
}

func TestClient_SuccessfulLogin_UserRequiringPreAuth(t *testing.T) {
	b, err := hex.DecodeString(testdata.TESTUSER2_KEYTAB)
	kt, _ := keytab.Parse(b)
	c, _ := config.NewConfigFromString(testdata.TEST_KRB5CONF)
	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.TEST_KDC_ADDR
	}
	c.Realms[0].KDC = []string{addr + ":" + testdata.TEST_KDC}
	cl := NewClientWithKeytab("testuser2", "TEST.GOKRB5", kt)
	cl.WithConfig(c)

	err = cl.Login()
	if err != nil {
		t.Fatalf("Error on login: %v\n", err)
	}
}

func TestClient_SuccessfulLogin_UserRequiringPreAuth_TCPOnly(t *testing.T) {
	b, err := hex.DecodeString(testdata.TESTUSER2_KEYTAB)
	kt, _ := keytab.Parse(b)
	c, _ := config.NewConfigFromString(testdata.TEST_KRB5CONF)
	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.TEST_KDC_ADDR
	}
	c.Realms[0].KDC = []string{addr + ":" + testdata.TEST_KDC}
	c.LibDefaults.UDPPreferenceLimit = 1
	cl := NewClientWithKeytab("testuser2", "TEST.GOKRB5", kt)
	cl.WithConfig(c)

	err = cl.Login()
	if err != nil {
		t.Fatalf("Error on login: %v\n", err)
	}
}

func TestClient_NetworkTimeout(t *testing.T) {
	b, err := hex.DecodeString(testdata.TESTUSER1_KEYTAB)
	kt, _ := keytab.Parse(b)
	c, _ := config.NewConfigFromString(testdata.TEST_KRB5CONF)
	c.Realms[0].KDC = []string{testdata.TEST_KDC_BADADDR + ":88"}
	cl := NewClientWithKeytab("testuser1", "TEST.GOKRB5", kt)
	cl.WithConfig(c)

	err = cl.Login()
	if err == nil {
		t.Fatal("Login with incorrect KDC address did not error")
	}
}

func TestClient_GetServiceTicket(t *testing.T) {
	b, err := hex.DecodeString(testdata.TESTUSER1_KEYTAB)
	kt, _ := keytab.Parse(b)
	c, _ := config.NewConfigFromString(testdata.TEST_KRB5CONF)
	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.TEST_KDC_ADDR
	}
	c.Realms[0].KDC = []string{addr + ":" + testdata.TEST_KDC}
	cl := NewClientWithKeytab("testuser1", "TEST.GOKRB5", kt)
	cl.WithConfig(c)

	err = cl.Login()
	if err != nil {
		t.Fatalf("Error on login: %v\n", err)
	}
	spn := "HTTP/host.test.gokrb5"
	tkt, key, err := cl.GetServiceTicket(spn)
	if err != nil {
		t.Fatalf("Error getting service ticket: %v\n", err)
	}
	assert.Equal(t, spn, tkt.SName.GetPrincipalNameString())
	assert.Equal(t, 18, key.KeyType)

	//Check cache use - should get the same values back again
	tkt2, key2, err := cl.GetServiceTicket(spn)
	if err != nil {
		t.Fatalf("Error getting service ticket: %v\n", err)
	}
	assert.Equal(t, tkt.EncPart.Cipher, tkt2.EncPart.Cipher)
	assert.Equal(t, key.KeyValue, key2.KeyValue)
}

func TestClient_GetServiceTicket_OlderKDC(t *testing.T) {
	b, err := hex.DecodeString(testdata.TESTUSER1_KEYTAB)
	kt, _ := keytab.Parse(b)
	c, _ := config.NewConfigFromString(testdata.TEST_KRB5CONF)
	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.TEST_KDC_ADDR
	}
	c.Realms[0].KDC = []string{addr + ":" + testdata.TEST_KDC_OLD}
	cl := NewClientWithKeytab("testuser1", "TEST.GOKRB5", kt)
	cl.WithConfig(c)

	err = cl.Login()
	if err != nil {
		t.Fatalf("Error on login: %v\n", err)
	}
	spn := "HTTP/host.test.gokrb5"
	tkt, key, err := cl.GetServiceTicket(spn)
	if err != nil {
		t.Fatalf("Error getting service ticket: %v\n", err)
	}
	assert.Equal(t, spn, tkt.SName.GetPrincipalNameString())
	assert.Equal(t, 18, key.KeyType)
}

func TestClient_SetSPNEGOHeader(t *testing.T) {
	b, _ := hex.DecodeString(testdata.TESTUSER1_KEYTAB)
	kt, _ := keytab.Parse(b)
	c, _ := config.NewConfigFromString(testdata.TEST_KRB5CONF)
	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.TEST_KDC_ADDR
	}
	c.Realms[0].KDC = []string{addr + ":" + testdata.TEST_KDC}
	cl := NewClientWithKeytab("testuser1", "TEST.GOKRB5", kt)
	cl.WithConfig(c)

	err := cl.Login()
	if err != nil {
		t.Fatalf("Error on AS_REQ: %v\n", err)
	}
	url := os.Getenv("TEST_HTTP_URL")
	if url == "" {
		url = testdata.TEST_HTTP_URL
	}
	r, _ := http.NewRequest("GET", url, nil)
	httpResp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatalf("Request error: %v\n", err)
	}
	assert.Equal(t, http.StatusUnauthorized, httpResp.StatusCode, "Status code in response to client with no SPNEGO not as expected")
	err = cl.SetSPNEGOHeader(r, "HTTP/host.test.gokrb5")
	if err != nil {
		t.Fatalf("Error setting client SPNEGO header: %v", err)
	}
	httpResp, err = http.DefaultClient.Do(r)
	if err != nil {
		t.Fatalf("Request error: %v\n", err)
	}
	assert.Equal(t, http.StatusOK, httpResp.StatusCode, "Status code in response to client SPNEGO request not as expected")
}

func TestMultiThreadedClientUse(t *testing.T) {
	b, _ := hex.DecodeString(testdata.TESTUSER1_KEYTAB)
	kt, _ := keytab.Parse(b)
	c, _ := config.NewConfigFromString(testdata.TEST_KRB5CONF)
	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.TEST_KDC_ADDR
	}
	c.Realms[0].KDC = []string{addr + ":" + testdata.TEST_KDC}
	cl := NewClientWithKeytab("testuser1", "TEST.GOKRB5", kt)
	cl.WithConfig(c)

	for i := 0; i < 5; i++ {
		go login(t, &cl)
	}

	for i := 0; i < 5; i++ {
		go spnegoGet(t, &cl)
	}
}

func login(t *testing.T, cl *Client) {
	err := cl.Login()
	if err != nil {
		t.Fatalf("Error on AS_REQ: %v\n", err)
	}
}

func spnegoGet(t *testing.T, cl *Client) {
	url := os.Getenv("TEST_HTTP_URL")
	if url == "" {
		url = testdata.TEST_HTTP_URL
	}
	r, _ := http.NewRequest("GET", url, nil)
	httpResp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatalf("Request error: %v\n", err)
	}
	assert.Equal(t, http.StatusUnauthorized, httpResp.StatusCode, "Status code in response to client with no SPNEGO not as expected")
	err = cl.SetSPNEGOHeader(r, "HTTP/host.test.gokrb5")
	if err != nil {
		t.Fatalf("Error setting client SPNEGO header: %v", err)
	}
	httpResp, err = http.DefaultClient.Do(r)
	if err != nil {
		t.Fatalf("Request error: %v\n", err)
	}
	assert.Equal(t, http.StatusOK, httpResp.StatusCode, "Status code in response to client SPNEGO request not as expected")
}

func TestNewClientFromCCache(t *testing.T) {
	b, err := hex.DecodeString(testdata.CCACHE_TEST)
	if err != nil {
		t.Fatalf("Error decoding test data")
	}
	cc, err := credentials.ParseCCache(b)
	if err != nil {
		t.Fatal("Error getting test CCache")
	}
	cl, err := NewClientFromCCache(cc)
	if err != nil {
		t.Fatalf("Error creating client from CCache: %v", err)
	}
	c, _ := config.NewConfigFromString(testdata.TEST_KRB5CONF)
	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.TEST_KDC_ADDR
	}
	c.Realms[0].KDC = []string{addr + ":" + testdata.TEST_KDC}
	cl.WithConfig(c)
	if ok, err := cl.IsConfigured(); !ok {
		t.Fatalf("Client was not configured from CCache: %v", err)
	}
}

func TestResolveKDC(t *testing.T) {
	//ns := os.Getenv("DNSUTILS_OVERRIDE_NS")
	//if ns == "" {
	//	os.Setenv("DNSUTILS_OVERRIDE_NS", testdata.TEST_NS)
	//}
	c, _ := config.NewConfigFromString(testdata.TEST_KRB5CONF)
	c.LibDefaults.DNSLookupKDC = true
	var cl Client
	cl.WithConfig(c)
	count, res, err := cl.resolveKDC(c.LibDefaults.DefaultRealm, true)
	if err != nil {
		t.Errorf("error resolving KDC via DNS TCP: %v", err)
	}
	assert.Equal(t, 5, count, "Number of SRV records not as expected: %v", res)
	assert.Equal(t, count, len(res), "Map size does not match: %v", res)
	t.Logf("res: %v", res)
	expected := []string{
		"kdc.test.gokrb5:88",
		"kdc1a.test.gokrb5:88",
		"kdc2a.test.gokrb5:88",
		"kdc1b.test.gokrb5:88",
		"kdc2b.test.gokrb5:88",
	}
	for _, s := range expected {
		var found bool
		for _, v := range res {
			if s == v {
				found = true
				break
			}
		}
		assert.True(t, found, "Record %s not found in results", s)
	}
	c.LibDefaults.DNSLookupKDC = false
	_, res, err = cl.resolveKDC(c.LibDefaults.DefaultRealm, true)
	if err != nil {
		t.Errorf("error resolving KDCs from config: %v", err)
	}
	assert.Equal(t, "10.80.88.88:88", res[1], "KDC not read from config as expected")
}

func TestClient_Login_DNSKDCs(t *testing.T) {
	//ns := os.Getenv("DNSUTILS_OVERRIDE_NS")
	//if ns == "" {
	//	os.Setenv("DNSUTILS_OVERRIDE_NS", testdata.TEST_NS)
	//}
	c, _ := config.NewConfigFromString(testdata.TEST_KRB5CONF)
	// Set to lookup KDCs in DNS
	c.LibDefaults.DNSLookupKDC = true
	//Blank out the KDCs to ensure they are not being used
	c.Realms = []config.Realm{}

	b, err := hex.DecodeString(testdata.TESTUSER1_KEYTAB)
	kt, _ := keytab.Parse(b)
	cl := NewClientWithKeytab("testuser1", "TEST.GOKRB5", kt)
	cl.WithConfig(c)

	err = cl.Login()
	if err != nil {
		t.Errorf("Error on logging in using DNS lookup of KDCs: %v\n", err)
	}
}

// Login to the TEST.GOKRB5 domain and request service ticket for resource in the RESDOM.GOKRB5 domain.
// There is a trust between the two domains.
func TestClient_GetServiceTicket_Trusted_Resource_Domain(t *testing.T) {
	b, _ := hex.DecodeString(testdata.TESTUSER1_KEYTAB)
	kt, _ := keytab.Parse(b)
	c, _ := config.NewConfigFromString(testdata.TEST_KRB5CONF)

	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.TEST_KDC_ADDR
	}
	for i, r := range c.Realms {
		if r.Realm == "TEST.GOKRB5" {
			c.Realms[i].KDC = []string{addr + ":" + testdata.TEST_KDC}
		}
		if r.Realm == "RESDOM.GOKRB5" {
			c.Realms[i].KDC = []string{addr + ":" + testdata.TEST_KDC_RESDOM}
		}
	}

	c.LibDefaults.DefaultRealm = "TEST.GOKRB5"
	cl := NewClientWithKeytab("testuser1", "TEST.GOKRB5", kt)
	c.LibDefaults.DefaultTktEnctypes = []string{"aes256-cts-hmac-sha1-96"}
	c.LibDefaults.DefaultTktEnctypeIDs = []int{etypeID.ETypesByName["aes256-cts-hmac-sha1-96"]}
	c.LibDefaults.DefaultTGSEnctypes = []string{"aes256-cts-hmac-sha1-96"}
	c.LibDefaults.DefaultTGSEnctypeIDs = []int{etypeID.ETypesByName["aes256-cts-hmac-sha1-96"]}
	cl.WithConfig(c)

	err := cl.Login()

	if err != nil {
		t.Fatalf("Error on login: %v\n", err)
	}
	spn := "HTTP/host.resdom.gokrb5"
	tkt, key, err := cl.GetServiceTicket(spn)
	if err != nil {
		t.Fatalf("Error getting service ticket: %v\n", err)
	}
	assert.Equal(t, spn, tkt.SName.GetPrincipalNameString())
	assert.Equal(t, etypeID.ETypesByName["aes256-cts-hmac-sha1-96"], key.KeyType)

	b, _ = hex.DecodeString(testdata.SYSHTTP_RESDOM_KEYTAB)
	skt, _ := keytab.Parse(b)
	err = tkt.DecryptEncPart(skt, "")
	if err != nil {
		t.Errorf("Error decrypting ticket with service keytab: %v", err)
	}
}
