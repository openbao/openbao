// +build integration
// To turn on this test use -tags=integration in go test command

package client

import (
	"bytes"
	"encoding/hex"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"testing"
	"time"

	"errors"
	"fmt"
	"github.com/stretchr/testify/assert"
	"gopkg.in/jcmturner/gokrb5.v5/config"
	"gopkg.in/jcmturner/gokrb5.v5/credentials"
	"gopkg.in/jcmturner/gokrb5.v5/iana/etypeID"
	"gopkg.in/jcmturner/gokrb5.v5/keytab"
	"gopkg.in/jcmturner/gokrb5.v5/testdata"
	"strings"
	"sync"
)

func TestClient_SuccessfulLogin_Keytab(t *testing.T) {
	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.TEST_KDC_ADDR
	}
	b, _ := hex.DecodeString(testdata.TESTUSER1_KEYTAB)
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

		err := cl.Login()
		if err != nil {
			t.Errorf("error on logging in with KDC %s: %v\n", test, err)
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
			t.Errorf("error on logging in with KDC %s: %v\n", test, err)
		}
	}
}

func TestClient_SuccessfulLogin_TCPOnly(t *testing.T) {
	b, _ := hex.DecodeString(testdata.TESTUSER1_KEYTAB)
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

	err := cl.Login()
	if err != nil {
		t.Fatalf("error on login: %v\n", err)
	}
}

func TestClient_ASExchange_TGSExchange_EncTypes_Keytab(t *testing.T) {
	b, _ := hex.DecodeString(testdata.TESTUSER1_KEYTAB)
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
		c.LibDefaults.DefaultTktEnctypeIDs = []int32{etypeID.ETypesByName[test]}
		c.LibDefaults.DefaultTGSEnctypes = []string{test}
		c.LibDefaults.DefaultTGSEnctypeIDs = []int32{etypeID.ETypesByName[test]}
		cl := NewClientWithKeytab("testuser1", "TEST.GOKRB5", kt)
		cl.WithConfig(c)

		err := cl.Login()
		if err != nil {
			t.Errorf("error on login using enctype %s: %v\n", test, err)
		}
		tkt, key, err := cl.GetServiceTicket("HTTP/host.test.gokrb5")
		if err != nil {
			t.Errorf("error in TGS exchange using enctype %s: %v", test, err)
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
		c.LibDefaults.DefaultTktEnctypeIDs = []int32{etypeID.ETypesByName[test]}
		c.LibDefaults.DefaultTGSEnctypes = []string{test}
		c.LibDefaults.DefaultTGSEnctypeIDs = []int32{etypeID.ETypesByName[test]}
		cl := NewClientWithPassword("testuser1", "TEST.GOKRB5", "passwordvalue")
		cl.WithConfig(c)

		err := cl.Login()
		if err != nil {
			t.Errorf("error on login using enctype %s: %v\n", test, err)
		}
		tkt, key, err := cl.GetServiceTicket("HTTP/host.test.gokrb5")
		if err != nil {
			t.Errorf("error in TGS exchange using enctype %s: %v", test, err)
		}
		assert.Equal(t, "TEST.GOKRB5", tkt.Realm, "Realm in ticket not as expected for %s test", test)
		assert.Equal(t, etypeID.ETypesByName[test], key.KeyType, "Key is not for enctype %s", test)
	}
}

func TestClient_FailedLogin(t *testing.T) {
	b, _ := hex.DecodeString(testdata.TESTUSER1_WRONGPASSWD)
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
	if err == nil {
		t.Fatal("login with incorrect password did not error")
	}
}

func TestClient_SuccessfulLogin_UserRequiringPreAuth(t *testing.T) {
	b, _ := hex.DecodeString(testdata.TESTUSER2_KEYTAB)
	kt, _ := keytab.Parse(b)
	c, _ := config.NewConfigFromString(testdata.TEST_KRB5CONF)
	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.TEST_KDC_ADDR
	}
	c.Realms[0].KDC = []string{addr + ":" + testdata.TEST_KDC}
	cl := NewClientWithKeytab("testuser2", "TEST.GOKRB5", kt)
	cl.WithConfig(c)

	err := cl.Login()
	if err != nil {
		t.Fatalf("error on login: %v\n", err)
	}
}

func TestClient_SuccessfulLogin_UserRequiringPreAuth_TCPOnly(t *testing.T) {
	b, _ := hex.DecodeString(testdata.TESTUSER2_KEYTAB)
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

	err := cl.Login()
	if err != nil {
		t.Fatalf("error on login: %v\n", err)
	}
}

func TestClient_NetworkTimeout(t *testing.T) {
	b, _ := hex.DecodeString(testdata.TESTUSER1_KEYTAB)
	kt, _ := keytab.Parse(b)
	c, _ := config.NewConfigFromString(testdata.TEST_KRB5CONF)
	c.Realms[0].KDC = []string{testdata.TEST_KDC_BADADDR + ":88"}
	cl := NewClientWithKeytab("testuser1", "TEST.GOKRB5", kt)
	cl.WithConfig(c)

	err := cl.Login()
	if err == nil {
		t.Fatal("login with incorrect KDC address did not error")
	}
}

func TestClient_GetServiceTicket(t *testing.T) {
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
		t.Fatalf("error on login: %v\n", err)
	}
	spn := "HTTP/host.test.gokrb5"
	tkt, key, err := cl.GetServiceTicket(spn)
	if err != nil {
		t.Fatalf("error getting service ticket: %v\n", err)
	}
	assert.Equal(t, spn, tkt.SName.GetPrincipalNameString())
	assert.Equal(t, int32(18), key.KeyType)

	//Check cache use - should get the same values back again
	tkt2, key2, err := cl.GetServiceTicket(spn)
	if err != nil {
		t.Fatalf("error getting service ticket: %v\n", err)
	}
	assert.Equal(t, tkt.EncPart.Cipher, tkt2.EncPart.Cipher)
	assert.Equal(t, key.KeyValue, key2.KeyValue)
}

func TestClient_GetServiceTicket_InvalidSPN(t *testing.T) {
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
		t.Fatalf("error on login: %v\n", err)
	}
	spn := "host.test.gokrb5"
	_, _, err = cl.GetServiceTicket(spn)
	assert.NotNil(t, err, "Expected unknown principal error")
	assert.True(t, strings.Contains(err.Error(), "KDC_ERR_S_PRINCIPAL_UNKNOWN"), "Error text not as expected")
}

func TestClient_GetServiceTicket_OlderKDC(t *testing.T) {
	b, _ := hex.DecodeString(testdata.TESTUSER1_KEYTAB)
	kt, _ := keytab.Parse(b)
	c, _ := config.NewConfigFromString(testdata.TEST_KRB5CONF)
	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.TEST_KDC_ADDR
	}
	c.Realms[0].KDC = []string{addr + ":" + testdata.TEST_KDC_OLD}
	cl := NewClientWithKeytab("testuser1", "TEST.GOKRB5", kt)
	cl.WithConfig(c)

	err := cl.Login()
	if err != nil {
		t.Fatalf("error on login: %v\n", err)
	}
	spn := "HTTP/host.test.gokrb5"
	tkt, key, err := cl.GetServiceTicket(spn)
	if err != nil {
		t.Fatalf("error getting service ticket: %v\n", err)
	}
	assert.Equal(t, spn, tkt.SName.GetPrincipalNameString())
	assert.Equal(t, int32(18), key.KeyType)
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
		t.Fatalf("error on AS_REQ: %v\n", err)
	}
	url := os.Getenv("TEST_HTTP_URL")
	if url == "" {
		url = testdata.TEST_HTTP_URL
	}
	r, _ := http.NewRequest("GET", url, nil)
	httpResp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatalf("request error: %v\n", err)
	}
	assert.Equal(t, http.StatusUnauthorized, httpResp.StatusCode, "Status code in response to client with no SPNEGO not as expected")
	err = cl.SetSPNEGOHeader(r, "HTTP/host.test.gokrb5")
	if err != nil {
		t.Fatalf("error setting client SPNEGO header: %v", err)
	}
	httpResp, err = http.DefaultClient.Do(r)
	if err != nil {
		t.Fatalf("request error: %v\n", err)
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

	var wg sync.WaitGroup
	wg.Add(5)
	for i := 0; i < 5; i++ {
		go func() {
			defer wg.Done()
			err := cl.Login()
			if err != nil {
				panic(err)
			}
		}()
	}
	wg.Wait()

	var wg2 sync.WaitGroup
	wg2.Add(5)
	for i := 0; i < 5; i++ {
		go func() {
			defer wg2.Done()
			err := spnegoGet(&cl)
			if err != nil {
				panic(err)
			}
		}()
	}
	wg2.Wait()
}

func TestMultiThreadedClientSession(t *testing.T) {
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
		t.Fatalf("failed to log in: %v", err)
	}

	s, err := cl.GetSessionFromRealm("TEST.GOKRB5")
	if err != nil {
		t.Fatalf("error initially getting session: %v", err)
	}
	go func() {
		for {
			err := cl.renewTGT(s)
			if err != nil {
				t.Logf("error renewing TGT: %v", err)
			}
			time.Sleep(time.Millisecond * 100)
		}
	}()

	var wg sync.WaitGroup
	wg.Add(10)
	for i := 0; i < 10; i++ {
		go func() {
			defer wg.Done()
			s, err := cl.GetSessionFromRealm("TEST.GOKRB5")
			if err != nil {
				t.Logf("error getting session: %v", err)
			}
			fmt.Fprintf(ioutil.Discard, "%v", s.RenewTill)
		}()
		time.Sleep(time.Second)
	}
	wg.Wait()
}

func spnegoGet(cl *Client) error {
	url := os.Getenv("TEST_HTTP_URL")
	if url == "" {
		url = testdata.TEST_HTTP_URL
	}
	r, _ := http.NewRequest("GET", url, nil)
	httpResp, err := http.DefaultClient.Do(r)
	if err != nil {
		return fmt.Errorf("request error: %v\n", err)
	}
	if httpResp.StatusCode != http.StatusUnauthorized {
		return errors.New("did not get unauthorized code when no SPNEGO header set")
	}
	err = cl.SetSPNEGOHeader(r, "HTTP/host.test.gokrb5")
	if err != nil {
		return fmt.Errorf("error setting client SPNEGO header: %v", err)
	}
	httpResp, err = http.DefaultClient.Do(r)
	if err != nil {
		return fmt.Errorf("request error: %v\n", err)
	}
	if httpResp.StatusCode != http.StatusOK {
		return errors.New("did not get OK code when SPNEGO header set")
	}
	return nil
}

func TestNewClientFromCCache(t *testing.T) {
	b, err := hex.DecodeString(testdata.CCACHE_TEST)
	if err != nil {
		t.Fatalf("error decoding test data")
	}
	cc, err := credentials.ParseCCache(b)
	if err != nil {
		t.Fatal("error getting test CCache")
	}
	cl, err := NewClientFromCCache(cc)
	if err != nil {
		t.Fatalf("error creating client from CCache: %v", err)
	}
	c, _ := config.NewConfigFromString(testdata.TEST_KRB5CONF)
	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.TEST_KDC_ADDR
	}
	c.Realms[0].KDC = []string{addr + ":" + testdata.TEST_KDC}
	cl.WithConfig(c)
	if ok, err := cl.IsConfigured(); !ok {
		t.Fatalf("client was not configured from CCache: %v", err)
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
	c.LibDefaults.DefaultTktEnctypeIDs = []int32{etypeID.ETypesByName["aes256-cts-hmac-sha1-96"]}
	c.LibDefaults.DefaultTGSEnctypes = []string{"aes256-cts-hmac-sha1-96"}
	c.LibDefaults.DefaultTGSEnctypeIDs = []int32{etypeID.ETypesByName["aes256-cts-hmac-sha1-96"]}
	cl.WithConfig(c)

	err := cl.Login()

	if err != nil {
		t.Fatalf("error on login: %v\n", err)
	}
	spn := "HTTP/host.resdom.gokrb5"
	tkt, key, err := cl.GetServiceTicket(spn)
	if err != nil {
		t.Fatalf("error getting service ticket: %v\n", err)
	}
	assert.Equal(t, spn, tkt.SName.GetPrincipalNameString())
	assert.Equal(t, etypeID.ETypesByName["aes256-cts-hmac-sha1-96"], key.KeyType)

	b, _ = hex.DecodeString(testdata.SYSHTTP_RESDOM_KEYTAB)
	skt, _ := keytab.Parse(b)
	err = tkt.DecryptEncPart(skt, "")
	if err != nil {
		t.Errorf("error decrypting ticket with service keytab: %v", err)
	}
}

const (
	kinitCmd = "kinit"
	kvnoCmd  = "kvno"
	spn      = "HTTP/host.test.gokrb5"
)

func login() error {
	file, err := os.Create("/etc/krb5.conf")
	if err != nil {
		return fmt.Errorf("cannot open krb5.conf: %v", err)
	}
	defer file.Close()
	fmt.Fprintf(file, testdata.TEST_KRB5CONF)

	cmd := exec.Command(kinitCmd, "testuser1@TEST.GOKRB5")

	stdinR, stdinW := io.Pipe()
	stderrR, stderrW := io.Pipe()
	cmd.Stdin = stdinR
	cmd.Stderr = stderrW

	err = cmd.Start()
	if err != nil {
		return fmt.Errorf("could not start %s command: %v", kinitCmd, err)
	}

	go func() {
		io.WriteString(stdinW, "passwordvalue")
		stdinW.Close()
	}()
	errBuf := new(bytes.Buffer)
	go func() {
		io.Copy(errBuf, stderrR)
		stderrR.Close()
	}()

	err = cmd.Wait()
	if err != nil {
		return fmt.Errorf("%s did not run successfully: %v stderr: %s", kinitCmd, err, string(errBuf.Bytes()))
	}
	return nil
}

func getServiceTkt() error {
	cmd := exec.Command(kvnoCmd, spn)
	err := cmd.Start()
	if err != nil {
		return fmt.Errorf("could not start %s command: %v", kvnoCmd, err)
	}
	err = cmd.Wait()
	if err != nil {
		return fmt.Errorf("%s did not run successfully: %v", kvnoCmd, err)
	}
	return nil
}

func loadCCache() (credentials.CCache, error) {
	usr, _ := user.Current()
	cpath := "/tmp/krb5cc_" + usr.Uid
	return credentials.LoadCCache(cpath)
}

func TestGetServiceTicketFromCCacheTGT(t *testing.T) {
	err := login()
	if err != nil {
		t.Fatalf("error logging in with kinit: %v", err)
	}
	c, err := loadCCache()
	if err != nil {
		t.Errorf("error loading CCache: %v", err)
	}
	cfg, _ := config.NewConfigFromString(testdata.TEST_KRB5CONF)
	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.TEST_KDC_ADDR
	}
	cfg.Realms[0].KDC = []string{addr + ":" + testdata.TEST_KDC}
	cl, err := NewClientFromCCache(c)
	if err != nil {
		t.Fatalf("error generating client from ccache: %v", err)
	}
	cl.WithConfig(cfg)
	url := os.Getenv("TEST_HTTP_URL")
	if url == "" {
		url = testdata.TEST_HTTP_URL
	}
	r, _ := http.NewRequest("GET", url, nil)
	err = cl.SetSPNEGOHeader(r, "HTTP/host.test.gokrb5")
	if err != nil {
		t.Fatalf("error setting client SPNEGO header: %v", err)
	}
	httpResp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatalf("request error: %v\n", err)
	}
	assert.Equal(t, http.StatusOK, httpResp.StatusCode, "status code in response to client SPNEGO request not as expected")
}

func TestGetServiceTicketFromCCacheWithoutKDC(t *testing.T) {
	err := login()
	if err != nil {
		t.Fatalf("error logging in with kinit: %v", err)
	}
	err = getServiceTkt()
	if err != nil {
		t.Fatalf("error getting service ticket: %v", err)
	}
	c, err := loadCCache()
	if err != nil {
		t.Errorf("error loading CCache: %v", err)
	}
	cfg, _ := config.NewConfigFromString("...")
	cl, err := NewClientFromCCache(c)
	if err != nil {
		t.Fatalf("error generating client from ccache: %v", err)
	}
	cl.WithConfig(cfg)
	url := os.Getenv("TEST_HTTP_URL")
	if url == "" {
		url = testdata.TEST_HTTP_URL
	}
	r, _ := http.NewRequest("GET", url, nil)
	err = cl.SetSPNEGOHeader(r, "HTTP/host.test.gokrb5")
	if err != nil {
		t.Fatalf("error setting client SPNEGO header: %v", err)
	}
	httpResp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatalf("request error: %v\n", err)
	}
	assert.Equal(t, http.StatusOK, httpResp.StatusCode, "status code in response to client SPNEGO request not as expected")
}

func TestClient_ChangePasswd(t *testing.T) {
	b, _ := hex.DecodeString(testdata.TESTUSER1_KEYTAB)
	kt, _ := keytab.Parse(b)
	c, _ := config.NewConfigFromString(testdata.TEST_KRB5CONF)
	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.TEST_KDC_ADDR
	}
	c.Realms[0].KDC = []string{addr + ":" + testdata.TEST_KDC}
	c.Realms[0].KPasswdServer = []string{addr + ":464"}
	cl := NewClientWithKeytab("testuser1", "TEST.GOKRB5", kt)
	cl.WithConfig(c)

	ok, err := cl.ChangePasswd("newpassword")
	if err != nil {
		t.Fatalf("error changing password: %v", err)
	}
	assert.True(t, ok, "password was not changed")

	cl = NewClientWithPassword("testuser1", "TEST.GOKRB5", "newpassword")
	cl.WithConfig(c)
	ok, err = cl.ChangePasswd(testdata.TESTUSER1_PASSWORD)
	if err != nil {
		t.Fatalf("error changing password: %v", err)
	}
	assert.True(t, ok, "password was not changed back")
}

func TestClient_AutoRenew_Goroutine_Count(t *testing.T) {
	// Tests that the auto renew of client credentials is not spawning goroutines out of control.
	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.TEST_KDC_ADDR
	}
	b, _ := hex.DecodeString(testdata.TESTUSER1_KEYTAB)
	kt, _ := keytab.Parse(b)
	c, _ := config.NewConfigFromString(testdata.TEST_KRB5CONF)
	c.Realms[0].KDC = []string{addr + ":" + testdata.TEST_KDC_SHORTTICKETS}
	cl := NewClientWithKeytab("testuser1", "TEST.GOKRB5", kt)
	cl.WithConfig(c)

	err := cl.Login()
	if err != nil {
		t.Errorf("error on logging in: %v\n", err)
	}
	n := runtime.NumGoroutine()
	for i := 0; i < 6; i++ {
		time.Sleep(time.Second * 20)
		if runtime.NumGoroutine() > n {
			t.Fatalf("number of goroutines is increasing: should not be more than %d, is %d", n, runtime.NumGoroutine())
		}
	}
}

func TestClient_Destroy(t *testing.T) {
	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.TEST_KDC_ADDR
	}
	b, _ := hex.DecodeString(testdata.TESTUSER1_KEYTAB)
	kt, _ := keytab.Parse(b)
	c, _ := config.NewConfigFromString(testdata.TEST_KRB5CONF)
	c.Realms[0].KDC = []string{addr + ":" + testdata.TEST_KDC_SHORTTICKETS}
	cl := NewClientWithKeytab("testuser1", "TEST.GOKRB5", kt)
	cl.WithConfig(c)

	err := cl.Login()
	if err != nil {
		t.Fatalf("error on login: %v\n", err)
	}
	spn := "HTTP/host.test.gokrb5"
	_, _, err = cl.GetServiceTicket(spn)
	if err != nil {
		t.Fatalf("error getting service ticket: %v\n", err)
	}
	n := runtime.NumGoroutine()
	time.Sleep(time.Second * 60)
	cl.Destroy()
	time.Sleep(time.Second * 5)
	assert.True(t, runtime.NumGoroutine() < n, "auto-renewal goroutine was not stopped when client destroyed")
	is, _ := cl.IsConfigured()
	assert.False(t, is, "client is still configured after it was destroyed")
}
