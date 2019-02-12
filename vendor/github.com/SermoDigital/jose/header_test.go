package jose

import (
	"encoding/json"
	"testing"
)

func TestMarshalProtectedHeader(t *testing.T) {
	p := Protected{
		"alg": "HM256",
	}

	b, err := json.Marshal(p)
	if err != nil {
		t.Error(err)
	}

	var p2 Protected

	if json.Unmarshal(b, &p2); err != nil {
		t.Error(err)
	}

	if p2["alg"] != p["alg"] {
		Error(t, p["alg"], p2["alg"])
	}
}

func TestMarshalHeader(t *testing.T) {
	h := Header{
		"alg": "HM256",
	}

	b, err := json.Marshal(h)
	if err != nil {
		t.Error(err)
	}

	var p2 Protected

	if json.Unmarshal(b, &p2); err != nil {
		t.Error(err)
	}

	if p2["alg"] != h["alg"] {
		Error(t, h["alg"], p2["alg"])
	}
}

func TestBasicHeaderFunctions(t *testing.T) {
	var h Header

	if v := h.Get("b"); v != nil {
		Error(t, nil, v)
	}

	h = Header{}

	h.Set("a", "b")

	if v := h.Get("a"); v != "b" {
		Error(t, "a", v)
	}

	if !h.Has("a") {
		t.Error("h should have `a`")
	}

	if v := h.Get("b"); v != nil {
		Error(t, nil, v)
	}

	h.Del("a")

	if v := h.Get("a"); v != nil {
		Error(t, nil, v)
	}
}
