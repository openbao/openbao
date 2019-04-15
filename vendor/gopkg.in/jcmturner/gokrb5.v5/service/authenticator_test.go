package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/jcmturner/goidentity.v2"
)

func TestImplementsInterface(t *testing.T) {
	t.Parallel()
	//s := new(SPNEGOAuthenticator)
	var s SPNEGOAuthenticator
	a := new(goidentity.Authenticator)
	assert.Implements(t, a, s, "SPNEGOAuthenticator type does not implement the goidentity.Authenticator interface")
}
