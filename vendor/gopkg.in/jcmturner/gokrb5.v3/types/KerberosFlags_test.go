package types

import (
	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/stretchr/testify/assert"
	"gopkg.in/jcmturner/gokrb5.v3/iana/flags"
	"testing"
)

func TestKerberosFlags_SetFlag(t *testing.T) {
	b := []byte{byte(64), byte(0), byte(0), byte(16)}
	var f asn1.BitString
	SetFlag(&f, flags.Forwardable)
	SetFlag(&f, flags.RenewableOK)
	assert.Equal(t, b, f.Bytes, "Flag bytes not as expected")
}

func TestKerberosFlags_UnsetFlag(t *testing.T) {
	b := []byte{byte(64), byte(0), byte(0), byte(0)}
	var f asn1.BitString
	SetFlag(&f, flags.Forwardable)
	SetFlag(&f, flags.RenewableOK)
	UnsetFlag(&f, flags.RenewableOK)
	assert.Equal(t, b, f.Bytes, "Flag bytes not as expected")
}

func TestKerberosFlags_IsFlagSet(t *testing.T) {
	var f asn1.BitString
	SetFlag(&f, flags.Forwardable)
	SetFlag(&f, flags.RenewableOK)
	UnsetFlag(&f, flags.Proxiable)
	assert.True(t, IsFlagSet(&f, flags.Forwardable))
	assert.True(t, IsFlagSet(&f, flags.RenewableOK))
	assert.False(t, IsFlagSet(&f, flags.Proxiable))
}
