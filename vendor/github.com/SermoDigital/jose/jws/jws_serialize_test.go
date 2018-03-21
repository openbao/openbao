package jws

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/SermoDigital/jose"
	"github.com/SermoDigital/jose/crypto"
)

var dataRaw = struct {
	H      jose.Protected
	Name   string
	Scopes []string
	Admin  bool
	Data   struct{ Foo, Bar int }
}{
	H: jose.Protected{
		"1234": "5678",
	},
	Name: "Eric",
	Scopes: []string{
		"user.account.info",
		"user.account.update",
		"user.account.delete",
	},
	Admin: true,
	Data: struct {
		Foo, Bar int
	}{
		Foo: 12,
		Bar: int(^uint(0) >> 1),
	},
}

var dataSerialized []byte

func init() {
	var err error
	dataSerialized, err = json.Marshal(dataRaw)
	if err != nil {
		panic(err)
	}
}

func TestGeneralIntegrity(t *testing.T) {
	j := New(dataRaw, crypto.SigningMethodRS512)
	b, err := j.General(rsaPriv)
	if err != nil {
		t.Error(err)
	}

	var jj struct {
		Payload    json.RawMessage `json:"payload"`
		Signatures []sigHead       `json:"signatures"`
	}

	if err := json.Unmarshal(b, &jj); err != nil {
		t.Error(err)
	}

	got, err := jose.DecodeEscaped(jj.Payload)
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(got, dataSerialized) {
		Error(t, dataSerialized, got)
	}
}

func TestFlatIntegrity(t *testing.T) {
	j := New(dataRaw, crypto.SigningMethodRS512)
	b, err := j.Flat(rsaPriv)
	if err != nil {
		t.Error(err)
	}

	var jj struct {
		Payload json.RawMessage `json:"payload"`
		sigHead
	}

	if err := json.Unmarshal(b, &jj); err != nil {
		t.Error(err)
	}

	got, err := jose.DecodeEscaped(jj.Payload)
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(got, dataSerialized) {
		Error(t, dataSerialized, got)
	}
}

func TestCompactIntegrity(t *testing.T) {
	j := New(dataRaw, crypto.SigningMethodRS512)
	b, err := j.Compact(rsaPriv)
	if err != nil {
		t.Error(err)
	}

	parts := bytes.Split(b, []byte{'.'})

	dec, err := jose.Base64Decode(parts[1])
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(dec, dataSerialized) {
		Error(t, dec, dataSerialized)
	}
}
