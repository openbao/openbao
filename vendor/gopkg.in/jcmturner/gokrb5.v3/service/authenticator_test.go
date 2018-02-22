package service

import (
	"github.com/stretchr/testify/assert"
	goidentity "gopkg.in/jcmturner/goidentity.v1"
	"testing"
)

func TestImplementsInterface(t *testing.T) {
	//s := new(SPNEGOAuthenticator)
	var s SPNEGOAuthenticator
	a := new(goidentity.Authenticator)
	assert.Implements(t, a, s, "SPNEGOAuthenticator type does not implement the goidentity.Authenticator interface")
}
