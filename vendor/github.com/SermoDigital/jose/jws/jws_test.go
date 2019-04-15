package jws

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/rand"
	"testing"

	"github.com/SermoDigital/jose/crypto"
)

type easy []byte

func (e *easy) UnmarshalJSON(b []byte) error {
	if len(b) > 1 && b[0] == '"' && b[len(b)-1] == '"' {
		b = b[1 : len(b)-1]
	}
	// json.Marshal encodes easy as it would a []byte, so in
	// `"base64"` format.
	dst := make([]byte, base64.StdEncoding.DecodedLen(len(b)))
	n, err := base64.StdEncoding.Decode(dst, b)
	if err != nil {
		return err
	}
	*e = easy(dst[:n])
	return nil
}

var _ json.Unmarshaler = (*easy)(nil)

var easyData = easy("easy data!")

func TestParseWithUnmarshaler(t *testing.T) {
	j := New(easyData, crypto.SigningMethodRS512)
	b, err := j.Flat(rsaPriv)
	if err != nil {
		t.Error(err)
	}

	var e easy
	j2, err := Parse(b, &e)
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(easyData, *j2.Payload().(*easy)) {
		Error(t, easyData, *j2.Payload().(*easy))
	}
}

func TestParseCompact(t *testing.T) {
	j := New(easyData, crypto.SigningMethodRS512)
	b, err := j.Compact(rsaPriv)
	if err != nil {
		t.Error(err)
	}

	j2, err := ParseCompact(b)
	if err != nil {
		t.Error(err)
	}

	var k easy
	if err := k.UnmarshalJSON([]byte(j2.Payload().(string))); err != nil {
		t.Error(err)
	}

	if !bytes.Equal(k, easyData) {
		Error(t, easyData, k)
	}
}

func TestParseCompactWithUnmarshaler(t *testing.T) {
	j := New(easyData, crypto.SigningMethodRS512)
	b, err := j.Compact(rsaPriv)
	if err != nil {
		t.Error(err)
	}
	var e easy
	j2, err := ParseCompact(b, &e)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(easyData, *j2.Payload().(*easy)) {
		Error(t, easyData, *j2.Payload().(*easy))
	}
}

func TestParseGeneral(t *testing.T) {
	sm := []crypto.SigningMethod{
		crypto.SigningMethodRS256,
		crypto.SigningMethodPS384,
		crypto.SigningMethodPS512,
	}

	j := New(easyData, sm...)
	b, err := j.General(rsaPriv)
	if err != nil {
		t.Error(err)
	}

	j2, err := ParseGeneral(b)
	if err != nil {
		t.Error(err)
	}

	for i, v := range j2.(*jws).sb {
		k := v.protected.Get("alg").(string)
		if k != sm[i].Alg() {
			Error(t, sm[i].Alg(), k)
		}
	}
}

func TestVerifyMulti(t *testing.T) {
	sm := []crypto.SigningMethod{
		crypto.SigningMethodRS256,
		crypto.SigningMethodPS384,
		crypto.SigningMethodPS512,
	}

	j := New(easyData, sm...)
	b, err := j.General(rsaPriv)
	if err != nil {
		t.Error(err)
	}

	j2, err := ParseGeneral(b)
	if err != nil {
		t.Error(err)
	}

	keys := []interface{}{rsaPub, rsaPub, rsaPub}
	if err := j2.VerifyMulti(keys, sm, nil); err != nil {
		t.Error(err)
	}
}

func TestVerifyMultiOneKey(t *testing.T) {
	sm := []crypto.SigningMethod{
		crypto.SigningMethodRS256,
		crypto.SigningMethodPS384,
		crypto.SigningMethodPS512,
	}

	j := New(easyData, sm...)
	b, err := j.General(rsaPriv)
	if err != nil {
		t.Error(err)
	}

	j2, err := ParseGeneral(b)
	if err != nil {
		t.Error(err)
	}

	keys := []interface{}{rsaPub}
	if err := j2.VerifyMulti(keys, sm, nil); err != nil {
		t.Error(err)
	}
}

func TestVerifyMultiMismatchedAlgs(t *testing.T) {
	sm := []crypto.SigningMethod{
		crypto.SigningMethodRS256,
		crypto.SigningMethodPS384,
		crypto.SigningMethodPS512,
	}

	j := New(easyData, sm...)
	b, err := j.General(rsaPriv)
	if err != nil {
		t.Error(err)
	}

	j2, err := ParseGeneral(b)
	if err != nil {
		t.Error(err)
	}

	shuffle := func(a []crypto.SigningMethod) {
		N := len(a)
		for i := 0; i < N; i++ {
			r := i + rand.Intn(N-i)
			a[r], a[i] = a[i], a[r]
		}
	}

	shuffle(sm)

	keys := []interface{}{rsaPub, rsaPub, rsaPub}
	if err := j2.VerifyMulti(keys, sm, nil); err == nil {
		t.Error("Should NOT be nil")
	}
}

func TestVerifyMultiNotEnoughMethods(t *testing.T) {
	sm := []crypto.SigningMethod{
		crypto.SigningMethodRS256,
		crypto.SigningMethodPS384,
		crypto.SigningMethodPS512,
	}

	j := New(easyData, sm...)
	b, err := j.General(rsaPriv)
	if err != nil {
		t.Error(err)
	}

	j2, err := ParseGeneral(b)
	if err != nil {
		t.Error(err)
	}

	sm = sm[0 : len(sm)-1]

	keys := []interface{}{rsaPub, rsaPub, rsaPub}
	if err := j2.VerifyMulti(keys, sm, nil); err == nil {
		t.Error("Should NOT be nil")
	}
}

func TestVerifyMultiNotEnoughKeys(t *testing.T) {
	sm := []crypto.SigningMethod{
		crypto.SigningMethodRS256,
		crypto.SigningMethodPS384,
		crypto.SigningMethodPS512,
	}

	j := New(easyData, sm...)
	b, err := j.General(rsaPriv)
	if err != nil {
		t.Error(err)
	}

	j2, err := ParseGeneral(b)
	if err != nil {
		t.Error(err)
	}

	keys := []interface{}{rsaPub, rsaPub}
	if err := j2.VerifyMulti(keys, sm, nil); err == nil {
		t.Error("Should NOT be nil")
	}
}

func TestVerifyMultiSigningOpts(t *testing.T) {
	sm := []crypto.SigningMethod{
		crypto.SigningMethodRS256,
		crypto.SigningMethodPS384,
		crypto.SigningMethodPS512,
	}

	j := New(easyData, sm...)
	b, err := j.General(rsaPriv)
	if err != nil {
		t.Error(err)
	}

	j2, err := ParseGeneral(b)
	if err != nil {
		t.Error(err)
	}

	o := SigningOpts{
		Number:  3,
		Indices: []int{0, 1, 2},
	}

	keys := []interface{}{rsaPub, rsaPub, rsaPub}
	if err := j2.VerifyMulti(keys, sm, &o); err != nil {
		t.Error(err)
	}
}

func TestVerifyMultiSigningOptsErr(t *testing.T) {
	sm := []crypto.SigningMethod{
		crypto.SigningMethodRS256,
		crypto.SigningMethodPS384,
		crypto.SigningMethodPS512,
	}

	j := New(easyData, sm...)
	b, err := j.General(rsaPriv)
	if err != nil {
		t.Error(err)
	}

	j2, err := ParseGeneral(b)
	if err != nil {
		t.Error(err)
	}

	o := SigningOpts{
		Number:  4,
		Indices: []int{0, 1, 2, 3},
	}

	keys := []interface{}{rsaPub, rsaPub, rsaPub}
	if err := j2.VerifyMulti(keys, sm, &o); err == nil {
		t.Error("Should not be nil!")
	}
}

func TestVerify(t *testing.T) {
	j := New(easyData, crypto.SigningMethodPS512)
	b, err := j.Flat(rsaPriv)
	if err != nil {
		t.Error(err)
	}

	j2, err := ParseFlat(b)
	if err != nil {
		t.Error(err)
	}

	if err := j2.Verify(rsaPub, crypto.SigningMethodPS512); err != nil {
		t.Error(err)
	}
}

func TestVerifyCallback(t *testing.T) {
	j := New(easyData, crypto.SigningMethodPS512)
	b, err := j.Flat(rsaPriv)
	if err != nil {
		t.Error(err)
	}

	j2, err := ParseFlat(b)
	if err != nil {
		t.Error(err)
	}

	cb := func(j JWS) ([]interface{}, error) {
		return []interface{}{rsaPub}, nil
	}

	if err := j2.VerifyCallback(cb, []crypto.SigningMethod{crypto.SigningMethodPS512}, nil); err != nil {
		t.Error(err)
	}
}

func TestVerifyCallbackErr(t *testing.T) {
	j := New(easyData, crypto.SigningMethodPS512)
	b, err := j.Flat(rsaPriv)
	if err != nil {
		t.Error(err)
	}

	j2, err := ParseFlat(b)
	if err != nil {
		t.Error(err)
	}

	cb := func(j JWS) ([]interface{}, error) {
		return nil, errors.New("k")
	}

	if err := j2.VerifyCallback(cb, []crypto.SigningMethod{crypto.SigningMethodPS512}, nil); err == nil {
		t.Error("Should not be nil!")
	}
}

func TestVerifyNoSBs(t *testing.T) {
	j := New(easyData, crypto.SigningMethodPS512)
	b, err := j.Flat(rsaPriv)
	if err != nil {
		t.Error(err)
	}

	j2, err := ParseFlat(b)
	if err != nil {
		t.Error(err)
	}
	j2.(*jws).sb = nil
	if err := j2.Verify(rsaPub, crypto.SigningMethodPS512); err != ErrCannotValidate {
		Error(t, ErrCannotValidate, err)
	}
}
