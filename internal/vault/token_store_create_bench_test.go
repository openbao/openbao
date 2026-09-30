package vault

import (
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/v2/internal/helper/benchhelpers"
	"github.com/openbao/openbao/v2/internal/helper/namespace"
	"github.com/stretchr/testify/require"
)

func BenchmarkTokenStore_HandleCreateCommon(b *testing.B) {
	c, _, root := TestCoreUnsealed(benchhelpers.TBtoT(b))
	ts := c.tokenStore

	ctx := namespace.RootContext(b.Context())

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		req := logical.TestRequest(benchhelpers.TBtoT(b), logical.UpdateOperation, "create")
		req.ClientToken = root
		req.Data = map[string]any{
			"policies": []string{"default"},
			"ttl":      "1h",
		}

		resp, err := ts.HandleRequest(ctx, req)
		require.NoErrorf(b, err, "err: %v", err)
		if resp != nil && resp.IsError() {
			b.Fatalf("resp err: %v", resp.Error())
		}
	}
}
