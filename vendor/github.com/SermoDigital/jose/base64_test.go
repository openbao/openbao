package jose

import (
	"bytes"
	"testing"
)

func TestBase64(t *testing.T) {
	encoded := []byte("SGVsbG8sIHBsYXlncm91bmQ")
	raw := []byte("Hello, playground")

	testEnc := Base64Encode(raw)
	if !bytes.Equal(testEnc, encoded) {
		Error(t, encoded, testEnc)
	}

	testDec, err := Base64Decode(testEnc)
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(testDec, raw) {
		Error(t, raw, testDec)
	}
}
