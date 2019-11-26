package types

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/hashicorp/vault-plugin-auth-kerberos/internal/gokrb5/iana/adtype"
	"github.com/hashicorp/vault-plugin-auth-kerberos/internal/gokrb5/iana/nametype"
	"github.com/hashicorp/vault-plugin-auth-kerberos/internal/gokrb5/test/testdata"
	"github.com/stretchr/testify/assert"
)

func TestUnmarshalAuthorizationData(t *testing.T) {
	t.Parallel()
	var a AuthorizationData
	b, err := hex.DecodeString(testdata.MarshaledKRB5authorization_data)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	assert.Equal(t, 2, len(a), "Number of authorization data entries not as expected")
	for i, entry := range a {
		assert.Equal(t, adtype.ADIfRelevant, entry.ADType, fmt.Sprintf("Authorization data type of entry %d not as expected", i+1))
		assert.Equal(t, []byte("foobar"), entry.ADData, fmt.Sprintf("Authorization data of entry %d not as expected", i+1))
	}
}

func TestUnmarshalAuthorizationData_kdcissued(t *testing.T) {
	t.Parallel()
	var a ADKDCIssued
	b, err := hex.DecodeString(testdata.MarshaledKRB5ad_kdcissued)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	assert.Equal(t, int32(1), a.ADChecksum.CksumType, "Checksum type not as expected")
	assert.Equal(t, []byte("1234"), a.ADChecksum.Checksum, "Checksum not as expected")
	assert.Equal(t, testdata.TEST_REALM, a.IRealm, "Issuing realm not as expected")
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, a.Isname.NameType, "Issuing name type not as expected")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.Isname.NameString, "Issuing name string entries not as expected")
	assert.Equal(t, 2, len(a.Elements), "Number of authorization data elements not as expected")
	for i, ele := range a.Elements {
		assert.Equal(t, adtype.ADIfRelevant, ele.ADType, fmt.Sprintf("Authorization data type of element %d not as expected", i+1))
		assert.Equal(t, []byte(testdata.TEST_AUTHORIZATION_DATA_VALUE), ele.ADData, fmt.Sprintf("Authorization data of element %d not as expected", i+1))
	}
}
