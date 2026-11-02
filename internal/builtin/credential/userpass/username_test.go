package userpass

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUsername_Regex(t *testing.T) {
	require.True(t, validUsername.MatchString("ex@example.com"))
	require.True(t, validUsername.MatchString("example"))

	require.False(t, validUsername.MatchString("ex @example.com"))
	require.False(t, validUsername.MatchString("ex ample"))
}