package credentials

import (
	"github.com/stretchr/testify/assert"
	goidentity "gopkg.in/jcmturner/goidentity.v1"
	"testing"
)

func TestImplementsInterface(t *testing.T) {
	u := new(Credentials)
	i := new(goidentity.Identity)
	assert.Implements(t, i, u, "Credentials type does not implement the Identity interface")
}
