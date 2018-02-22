package types

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestPrincipalName_GetSalt(t *testing.T) {
	pn := PrincipalName{
		NameType:   1,
		NameString: []string{"firststring", "secondstring"},
	}
	assert.Equal(t, "TEST.GOKRB5firststringsecondstring", pn.GetSalt("TEST.GOKRB5"), "Principal name default salt not as expected")
}
