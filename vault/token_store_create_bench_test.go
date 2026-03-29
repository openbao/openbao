package vault

import (
	"context"
	"testing"

	"github.com/openbao/openbao/helper/benchhelpers"
	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func BenchmarkTokenStore_HandleCreateCommon(b *testing.B) {
	c, _, root := TestCoreUnsealed(benchhelpers.TBtoT(b))
	ts := c.tokenStore

	ctx := namespace.RootContext(context.Background())

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		req := logical.TestRequest(benchhelpers.TBtoT(b), logical.UpdateOperation, "create")
		req.ClientToken = root
		req.Data = map[string]interface{}{
			"policies": []string{"default"},
			"ttl":      "1h",
		}

		resp, err := ts.HandleRequest(ctx, req)
		if err != nil {
			b.Fatalf("err: %v", err)
		}
		if resp != nil && resp.IsError() {
			b.Fatalf("resp err: %v", resp.Error())
		}
	}
}
