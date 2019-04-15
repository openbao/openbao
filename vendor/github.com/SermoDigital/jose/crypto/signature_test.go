package crypto

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestMarshalSignature(t *testing.T) {
	s := Signature("Test string!")

	enc, err := json.Marshal(s)
	if err != nil {
		t.Error(err)
	}

	var ss Signature
	if err = json.Unmarshal(enc, &ss); err != nil {
		t.Error(err)
	}

	if !bytes.Equal(ss, s) {
		Error(t, s, ss)
	}
}
