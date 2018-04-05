package kv

import (
	"context"
	"fmt"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/helper/logging"
	"github.com/hashicorp/vault/logical"
)

func TestVersionedKV_Upgrade(t *testing.T) {
	b, storage := testPassthroughBackendWithStorage()

	for i := 0; i < 1024*1024; i++ {
		data := map[string]interface{}{
			"bar": i,
		}

		req := &logical.Request{
			Operation: logical.CreateOperation,
			Path:      fmt.Sprintf("%d/foo", i),
			Storage:   storage,
			Data:      data,
		}

		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%s resp:%#v\n", err, resp)
		}
	}

	config := &logical.BackendConfig{
		Logger:      logging.NewVaultLogger(log.Trace),
		System:      &logical.StaticSystemView{},
		StorageView: storage,
		BackendUUID: "test",
		Config: map[string]string{
			"versioned": "true",
			"upgrade":   "true",
		},
	}

	var err error
	b, err = Factory(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}

	// verify requests are rejected during upgrade
	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      fmt.Sprintf("data/%d/foo", 1),
		Storage:   storage,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if resp == nil || resp.Error().Error() != "Uprading from non-versioned to versioned data. This backend will be unavailable for a brief period and will resume service shortly." {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	// wait for upgrade to finish
	for {
		if atomic.LoadUint32(b.(*versionedKVBackend).upgrading) == 0 {
			break
		}

		time.Sleep(time.Second)
	}

	for i := 0; i < 1024*1024; i++ {
		data := map[string]interface{}{
			"bar": float64(i),
		}

		req := &logical.Request{
			Operation: logical.ReadOperation,
			Path:      fmt.Sprintf("data/%d/foo", i),
			Storage:   storage,
		}

		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("err:%s resp:%#v\n", err, resp)
		}

		if !reflect.DeepEqual(resp.Data["data"].(map[string]interface{}), data) {
			t.Fatalf("bad response %#v", resp)
		}
	}
}
