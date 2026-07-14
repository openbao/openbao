package homedir

import (
	"os/user"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDir(t *testing.T) {
	u, err := user.Current()
	require.NoError(t, err)

	t.Logf("user home is: %s", u.HomeDir)

	dir, err := Dir()
	require.NoError(t, err)
	require.Equal(t, u.HomeDir, dir)

	cache = ""
	t.Setenv("HOME", "")

	dir, err = Dir()
	require.NoError(t, err)
	require.Equal(t, u.HomeDir, dir)
}

func TestExpand(t *testing.T) {
	u, err := user.Current()
	require.NoError(t, err)

	cases := []struct {
		input string
		want  string
		err   bool
	}{
		{"/foo", "/foo", false},
		{"~/foo", filepath.Join(u.HomeDir, "foo"), false},
		{"", "", false},
		{"~", u.HomeDir, false},
		{"~foo/foo", "", true},
	}

	for _, tc := range cases {
		have, err := Expand(tc.input)
		switch {
		case tc.err:
			require.Error(t, err)
		default:
			require.NoError(t, err)
			require.Equal(t, tc.want, have)
		}
	}
}
