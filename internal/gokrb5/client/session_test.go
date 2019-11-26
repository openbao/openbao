package client

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/vault-plugin-auth-kerberos/internal/gokrb5/config"
	"github.com/hashicorp/vault-plugin-auth-kerberos/internal/gokrb5/iana/etypeID"
	"github.com/hashicorp/vault-plugin-auth-kerberos/internal/gokrb5/keytab"
	"github.com/hashicorp/vault-plugin-auth-kerberos/internal/gokrb5/test"
	"github.com/hashicorp/vault-plugin-auth-kerberos/internal/gokrb5/test/testdata"
	"github.com/stretchr/testify/assert"
)

func TestMultiThreadedClientSession(t *testing.T) {
	test.Integration(t)

	b, _ := hex.DecodeString(testdata.TESTUSER1_KEYTAB)
	kt := keytab.New()
	kt.Unmarshal(b)
	c, _ := config.NewConfigFromString(testdata.TEST_KRB5CONF)
	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.TEST_KDC_ADDR
	}
	c.Realms[0].KDC = []string{addr + ":" + testdata.TEST_KDC}
	cl := NewClientWithKeytab("testuser1", "TEST.GOKRB5", kt, c)
	err := cl.Login()
	if err != nil {
		t.Fatalf("failed to log in: %v", err)
	}

	s, ok := cl.sessions.get("TEST.GOKRB5")
	if !ok {
		t.Fatal("error initially getting session")
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
			tgt, _, err := cl.sessionTGT("TEST.GOKRB5")
			if err != nil || tgt.Realm != "TEST.GOKRB5" {
				t.Logf("error getting session: %v", err)
			}
			_, _, _, r, _ := cl.sessionTimes("TEST.GOKRB5")
			fmt.Fprintf(ioutil.Discard, "%v", r)
		}()
		time.Sleep(time.Second)
	}
	wg.Wait()
}

func TestClient_AutoRenew_Goroutine(t *testing.T) {
	test.Integration(t)

	// Tests that the auto renew of client credentials is not spawning goroutines out of control.
	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.TEST_KDC_ADDR
	}
	b, _ := hex.DecodeString(testdata.TESTUSER2_KEYTAB)
	kt := keytab.New()
	kt.Unmarshal(b)
	c, _ := config.NewConfigFromString(testdata.TEST_KRB5CONF)
	c.Realms[0].KDC = []string{addr + ":" + testdata.TEST_KDC_SHORTTICKETS}
	c.LibDefaults.PreferredPreauthTypes = []int{int(etypeID.DES3_CBC_SHA1_KD)} // a preauth etype the KDC does not support. Test this does not cause renewal to fail.
	cl := NewClientWithKeytab("testuser2", "TEST.GOKRB5", kt, c)

	err := cl.Login()
	if err != nil {
		t.Errorf("error on logging in: %v\n", err)
	}
	n := runtime.NumGoroutine()
	for i := 0; i < 24; i++ {
		time.Sleep(time.Second * 5)
		_, endTime, _, _, err := cl.sessionTimes("TEST.GOKRB5")
		if err != nil {
			t.Errorf("could not get client's session: %v", err)
		}
		if time.Now().UTC().After(endTime) {
			t.Fatalf("session auto update failed")
		}
		spn := "HTTP/host.test.gokrb5"
		tkt, key, err := cl.GetServiceTicket(spn)
		if err != nil {
			t.Fatalf("error getting service ticket: %v\n", err)
		}
		b, _ := hex.DecodeString(testdata.HTTP_KEYTAB)
		skt := keytab.New()
		skt.Unmarshal(b)
		tkt.DecryptEncPart(skt, nil)
		assert.Equal(t, spn, tkt.SName.PrincipalNameString())
		assert.Equal(t, int32(18), key.KeyType)
		if runtime.NumGoroutine() > n {
			t.Fatalf("number of goroutines is increasing: should not be more than %d, is %d", n, runtime.NumGoroutine())
		}
	}
}
