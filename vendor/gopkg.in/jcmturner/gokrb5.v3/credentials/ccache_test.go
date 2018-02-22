package credentials

import (
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"gopkg.in/jcmturner/gokrb5.v3/iana/nametype"
	"gopkg.in/jcmturner/gokrb5.v3/testdata"
	"gopkg.in/jcmturner/gokrb5.v3/types"
	"testing"
)

func TestParse(t *testing.T) {
	b, err := hex.DecodeString(testdata.CCACHE_TEST)
	if err != nil {
		t.Fatal("Error decoding test data")
	}
	c, err := ParseCCache(b)
	if err != nil {
		t.Fatalf("Error parsing cache: %v", err)
	}
	assert.Equal(t, uint8(4), c.Version, "Version not as expected")
	assert.Equal(t, 1, len(c.Header.fields), "Number of header fields not as expected")
	assert.Equal(t, uint16(1), c.Header.fields[0].tag, "Header tag not as expected")
	assert.Equal(t, uint16(8), c.Header.fields[0].length, "Length of header not as expected")
	assert.Equal(t, "TEST.GOKRB5", c.DefaultPrincipal.Realm, "Default client principal realm not as expected")
	assert.Equal(t, "testuser1", c.DefaultPrincipal.PrincipalName.GetPrincipalNameString(), "Default client principaal name not as expected")
	assert.Equal(t, 3, len(c.Credentials), "Number of credentials not as expected")
	tgtpn := types.PrincipalName{
		NameType:   nametype.KRB_NT_SRV_INST,
		NameString: []string{"krbtgt", "TEST.GOKRB5"},
	}
	assert.True(t, c.Contains(tgtpn), "Cache does not contain TGT credential")
	httppn := types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{"HTTP", "host.test.gokrb5"},
	}
	assert.True(t, c.Contains(httppn), "Cache does not contain HTTP SPN credential")
}

func TestCCache_GetClientPrincipalName(t *testing.T) {
	b, err := hex.DecodeString(testdata.CCACHE_TEST)
	if err != nil {
		t.Fatal("Error decoding test data")
	}
	c, err := ParseCCache(b)
	if err != nil {
		t.Fatalf("Error parsing cache: %v", err)
	}
	pn := types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{"testuser1"},
	}
	assert.Equal(t, pn, c.GetClientPrincipalName(), "Client PrincipalName not as expected")
}

func TestCCache_GetClientCredentials(t *testing.T) {
	b, err := hex.DecodeString(testdata.CCACHE_TEST)
	if err != nil {
		t.Fatal("Error decoding test data")
	}
	c, err := ParseCCache(b)
	if err != nil {
		t.Fatalf("Error parsing cache: %v", err)
	}
	pn := types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{"testuser1"},
	}
	cred := c.GetClientCredentials()
	assert.Equal(t, "TEST.GOKRB5", cred.Realm, "Client realm in credential not as expected")
	assert.Equal(t, pn, cred.CName, "Client Principal Name not as expected")
	assert.Equal(t, "testuser1", cred.Username, "Username not as expected")
}

func TestCCache_GetClientRealm(t *testing.T) {
	b, err := hex.DecodeString(testdata.CCACHE_TEST)
	if err != nil {
		t.Fatal("Error decoding test data")
	}
	c, err := ParseCCache(b)
	if err != nil {
		t.Fatalf("Error parsing cache: %v", err)
	}
	assert.Equal(t, "TEST.GOKRB5", c.GetClientRealm(), "Client realm not as expected")
}

func TestCCache_GetEntry(t *testing.T) {
	b, err := hex.DecodeString(testdata.CCACHE_TEST)
	if err != nil {
		t.Fatal("Error decoding test data")
	}
	c, err := ParseCCache(b)
	if err != nil {
		t.Fatalf("Error parsing cache: %v", err)
	}
	httppn := types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{"HTTP", "host.test.gokrb5"},
	}
	cred, ok := c.GetEntry(httppn)
	if !ok {
		t.Fatal("Could not get entry from CCache as not found")
	}
	assert.Equal(t, httppn, cred.Server.PrincipalName, "Credential does not have the right server principal name")
}

func TestCCache_GetEntries(t *testing.T) {
	b, err := hex.DecodeString(testdata.CCACHE_TEST)
	if err != nil {
		t.Fatal("Error decoding test data")
	}
	c, err := ParseCCache(b)
	if err != nil {
		t.Fatalf("Error parsing cache: %v", err)
	}
	creds := c.GetEntries()
	assert.Equal(t, 2, len(creds), "Number of credentials entries not as expected")
}
