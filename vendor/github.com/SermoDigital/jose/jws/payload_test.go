package jws

import (
	"encoding/json"
	"testing"

	"github.com/SermoDigital/jose"
)

func TestPayloadMarshal(t *testing.T) {
	p := &payload{v: "Test string!"}

	enc, err := json.Marshal(p)
	if err != nil {
		t.Error(err)
	}

	var pp payload
	if err = json.Unmarshal(enc, &pp); err != nil {
		t.Error(err)
	}

	if pp.v != "Test string!" {
		Error(t, "Test string!", pp.v)
	}
}

func TestComplexPayloadMarshal(t *testing.T) {
	p := payload{
		v: map[string]interface{}{
			"alg": "HM256",
			"typ": "JWT",
		},
	}

	enc, err := json.Marshal(&p)
	if err != nil {
		t.Error(err)
	}

	var pp payload
	if err = json.Unmarshal(enc, &pp); err != nil {
		t.Error(err)
	}

	h, ok := pp.v.(map[string]interface{})
	if !ok {
		ErrorTypes(t, map[string]interface{}{}, pp.v)
	}

	ph := jose.Protected(h)

	if alg := ph.Get("alg"); alg != "HM256" {
		Error(t, "HM256", alg)
	}

	if typ := ph.Get("typ"); typ != "JWT" {
		Error(t, "JWT", typ)
	}
}
