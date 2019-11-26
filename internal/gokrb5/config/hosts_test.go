package config

import (
	"io/ioutil"
	"os"
	"testing"
)

func TestConfig_GetKDCsUsesConfiguredKDC(t *testing.T) {
	t.Parallel()

	// This test is meant to cover the fix for
	// https://github.com/jcmturner/gokrb5/issues/332
	krb5ConfWithKDCAndDNSLookupKDC := `
[libdefaults]
 dns_lookup_kdc = true
[realms]
 TEST.GOKRB5 = {
  kdc = 10.1.2.3.4:88
 }
`

	cf, _ := ioutil.TempFile(os.TempDir(), "TEST-gokrb5-krb5.conf")
	defer os.Remove(cf.Name())
	cf.WriteString(krb5ConfWithKDCAndDNSLookupKDC)

	c, err := Load(cf.Name())
	if err != nil {
		t.Fatalf("Error loading config: %v", err)
	}

	count, kdcs, err := c.GetKDCs("TEST.GOKRB5", false)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("expected 1 but received %d", count)
	}
	if kdcs[1] != "10.1.2.3.4:88" {
		t.Fatalf("expected 10.1.2.3.4:88 but received %s", kdcs[1])
	}
}
