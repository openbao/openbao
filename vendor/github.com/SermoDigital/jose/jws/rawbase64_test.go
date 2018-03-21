package jws

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestMarshalRawBase64(t *testing.T) {
	s := rawBase64("Test string!")

	enc, err := json.Marshal(s)
	if err != nil {
		t.Error(err)
	}

	var ss rawBase64
	if err = json.Unmarshal(enc, &ss); err != nil {
		t.Error(err)
	}

	if !bytes.Equal(ss, s) {
		Error(t, s, ss)
	}
}
