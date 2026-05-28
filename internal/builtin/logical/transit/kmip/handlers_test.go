package kmip

import (
	"testing"

	kmiplib "github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/ttlv"
)

func TestRoutesMatchSupportedOps(t *testing.T) {
	routes := map[kmiplib.Operation]bool{}
	for op := range coreRoutes(nil) {
		routes[op] = true
	}
	for op := range cryptoRoutes(nil) {
		routes[op] = true
	}

	if len(routes) != len(SupportedOperations) {
		t.Fatalf("count mismatch: supported=%d registered routes=%d", len(SupportedOperations), len(routes))
	}

	for _, op := range SupportedOperations {
		if !routes[op] {
			t.Errorf("%s is in SupportedOperations but has no route", ttlv.EnumStr(op))
		}
	}
}
