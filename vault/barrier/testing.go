package barrier

import (
	"crypto/rand"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/sdk/v2/physical"
	"github.com/openbao/openbao/sdk/v2/physical/inmem"
)

// MockBarrier returns a physical backend, security barrier, and root key
func MockBarrier(t testing.TB, logger hclog.Logger) (physical.Backend, SecurityBarrier, []byte) {
	inm, err := inmem.NewInmem(nil, logger)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	b := NewAESGCMBarrier(inm, "")

	// Initialize and unseal
	key, _ := b.GenerateKey(rand.Reader)
	err = b.Initialize(t.Context(), key, nil, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	err = b.Unseal(t.Context(), key)
	if err != nil {
		t.Fatal(err)
	}
	return inm, b, key
}
