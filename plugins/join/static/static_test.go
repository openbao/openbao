package static

import (
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/require"
)

func TestStatic(t *testing.T) {
	static := Static{logger: hclog.NewNullLogger()}
	cfg := map[string]any{"addresses": []any{"https://127.0.0.1:8200", "https://127.0.0.2:8201"}}
	addrs, err := static.Candidates(t.Context(), cfg)
	require.NoError(t, err)
	require.Equal(t, 2, len(addrs))
}
