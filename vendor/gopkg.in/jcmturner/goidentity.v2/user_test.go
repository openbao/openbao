package goidentity

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestUserImplementsInterface(t *testing.T) {
	u := new(User)
	i := new(Identity)
	assert.Implements(t, i, u, "User type does not implement the Identity interface")
}
