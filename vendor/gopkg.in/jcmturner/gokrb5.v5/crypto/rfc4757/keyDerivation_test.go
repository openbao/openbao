package rfc4757

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	testPassword = "foo"
	testKey      = "ac8e657f83df82beea5d43bdaf7800cc"
)

func TestStringToKey(t *testing.T) {
	t.Parallel()
	kb, err := StringToKey(testPassword)
	if err != nil {
		t.Fatalf("Error deriving key from string: %v", err)
	}
	k := hex.EncodeToString(kb)
	assert.Equal(t, testKey, k, "Key not as expected")
}
