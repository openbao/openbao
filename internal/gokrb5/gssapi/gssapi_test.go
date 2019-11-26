package gssapi

import (
	"testing"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/stretchr/testify/assert"
)

func TestOID(t *testing.T) {
	var tests = []struct {
		name OIDName
		oid  []int
	}{
		{OIDMSLegacyKRB5, []int{1, 2, 840, 48018, 1, 2, 2}},
		{OIDKRB5, []int{1, 2, 840, 113554, 1, 2, 2}},
		{OIDSPNEGO, []int{1, 3, 6, 1, 5, 5, 2}},
	}

	for _, tst := range tests {
		oid := asn1.ObjectIdentifier(tst.oid)
		assert.True(t, oid.Equal(OID(tst.name)), "OID value not as expected for %s", tst.name)
	}
}
