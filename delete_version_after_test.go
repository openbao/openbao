package kv

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

func TestDeletionTimeCalc(t *testing.T) {
	zeroTime := time.Time{}
	ct := time.Date(2019, time.March, 25, 1, 0, 0, 0, time.UTC)
	dm, ds := 6*time.Hour, 3*time.Hour
	var tests = []struct {
		mount, meta time.Duration
		want        time.Time
		wantOk      bool
	}{
		{0, 0, zeroTime, false},
		{0, ds, ct.Add(ds), true},
		{ds, 0, ct.Add(ds), true},
		{dm, ds, ct.Add(ds), true},
		{ds, dm, ct.Add(ds), true},
		{ds, ds, ct.Add(ds), true},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(fmt.Sprintf("mount=%v,meta=%v", tt.mount, tt.meta), func(t *testing.T) {
			t.Parallel()
			got, gotOk := deletionTime(ct, tt.mount, tt.meta)
			if tt.wantOk != gotOk {
				t.Errorf("gotOk %t, wantOk %t", gotOk, tt.wantOk)
			}
			if tt.want != got {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func getTime(t *testing.T, k string, d map[string]interface{}) time.Time {
	t.Helper()
	ts, ok := d[k].(string)
	if !ok {
		t.Fatalf("%s value was %T, expected string", k, d[k])
		return time.Time{}
	}
	tm, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		t.Errorf("want a valid %s, got %s", k, ts)
		return time.Time{}
	}
	return tm
}

func wantNoResponse(t *testing.T, resp *logical.Response, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("want no error, got err: %s", err)
	}
	if resp != nil {
		t.Fatalf("want no response, got response: %#v", resp)
	}
}

func wantResponse(t *testing.T, resp *logical.Response, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("want no error, got err: %#v", err)
	}
	if resp == nil {
		t.Fatal("want response, got no response")
	}
	if resp.IsError() {
		t.Fatalf("want response that is not an error, got response: %#v", resp)
	}
}

func untilDeletion(t *testing.T, ut time.Time, d map[string]interface{}) time.Duration {
	t.Helper()
	return getTime(t, "deletion_time", d).Sub(ut)
}

func lifetime(t *testing.T, d map[string]interface{}) time.Duration {
	t.Helper()
	ct := getTime(t, "created_time", d)
	return untilDeletion(t, ct, d)
}

func TestDeleteVersionAfter(t *testing.T) {
	nd := -1 * time.Second
	dm, ds := 6*time.Hour, 3*time.Hour
	var tests = []struct {
		mount, meta      time.Duration
		want             time.Duration
		wantDeletionTime bool
	}{
		{0, 0, 0, false},
		{0, ds, ds, true},
		{ds, 0, ds, true},
		{dm, ds, ds, true},
		{ds, dm, ds, true},
		{nd, 0, 0, false},
		{nd, ds, 0, false},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(fmt.Sprintf("mount=%v,meta=%v", tt.mount, tt.meta), func(t *testing.T) {
			t.Parallel()

			b, storage := getBackend(t)

			data := map[string]interface{}{
				"delete_version_after": tt.mount.String(),
			}
			req := &logical.Request{
				Operation: logical.CreateOperation,
				Path:      "config",
				Storage:   storage,
				Data:      data,
			}
			resp, err := b.HandleRequest(context.Background(), req)
			wantNoResponse(t, resp, err)

			req = &logical.Request{
				Operation: logical.ReadOperation,
				Path:      "config",
				Storage:   storage,
			}
			resp, err = b.HandleRequest(context.Background(), req)
			wantResponse(t, resp, err)
			want, got := tt.mount.String(), resp.Data["delete_version_after"]
			if want != got {
				t.Fatalf("want delete_version_after: %v, got %v", want, got)
			}

			data = map[string]interface{}{
				"max_versions":         2,
				"delete_version_after": tt.meta.String(),
			}
			req = &logical.Request{
				Operation: logical.CreateOperation,
				Path:      "metadata/foo",
				Storage:   storage,
				Data:      data,
			}
			resp, err = b.HandleRequest(context.Background(), req)
			wantNoResponse(t, resp, err)

			req = &logical.Request{
				Operation: logical.ReadOperation,
				Path:      "metadata/foo",
				Storage:   storage,
			}
			resp, err = b.HandleRequest(context.Background(), req)
			wantResponse(t, resp, err)
			want, got = tt.meta.String(), resp.Data["delete_version_after"]
			if want != got {
				t.Fatalf("want delete_version_after: %v, got %v", want, got)
			}

			data = map[string]interface{}{
				"data": map[string]interface{}{
					"bar": "baz1",
				},
			}
			req = &logical.Request{
				Operation: logical.CreateOperation,
				Path:      "data/foo",
				Storage:   storage,
				Data:      data,
			}
			resp, err = b.HandleRequest(context.Background(), req)
			wantResponse(t, resp, err)
			if !tt.wantDeletionTime {
				if dtv := resp.Data["deletion_time"].(string); dtv != "" {
					t.Logf("resp: %#v", resp)
					t.Fatalf("deletion_time %#v, want no deletion_time", dtv)
				}
			} else {
				want, got := tt.want, lifetime(t, resp.Data)
				if want != got {
					t.Fatalf("diff between deletion_time and created_time %v, want %v", got, want)
				}
			}

			req = &logical.Request{
				Operation: logical.ReadOperation,
				Path:      "data/foo",
				Storage:   storage,
			}
			resp, err = b.HandleRequest(context.Background(), req)
			wantResponse(t, resp, err)
			meta := resp.Data["metadata"].(map[string]interface{})
			if !tt.wantDeletionTime {
				if dtv := meta["deletion_time"].(string); dtv != "" {
					t.Logf("meta: %#v", meta)
					t.Fatalf("deletion_time %#v, want no deletion_time", dtv)
				}
			} else {
				want, got := tt.want, lifetime(t, meta)
				if want != got {
					t.Fatalf("diff between deletion_time and created_time %v, want %v", got, want)
				}
			}

			data = map[string]interface{}{
				"versions": "1",
			}
			req = &logical.Request{
				Operation: logical.CreateOperation,
				Path:      "delete/foo",
				Storage:   storage,
				Data:      data,
			}
			resp, err = b.HandleRequest(context.Background(), req)
			wantNoResponse(t, resp, err)

			data = map[string]interface{}{
				"versions": "1",
			}
			req = &logical.Request{
				Operation: logical.CreateOperation,
				Path:      "undelete/foo",
				Storage:   storage,
				Data:      data,
			}
			undeleteTime := time.Now() // the deletion timer is reset after an undelete
			resp, err = b.HandleRequest(context.Background(), req)
			wantNoResponse(t, resp, err)

			req = &logical.Request{
				Operation: logical.ReadOperation,
				Path:      "metadata/foo",
				Storage:   storage,
				Data:      data,
			}
			resp, err = b.HandleRequest(context.Background(), req)
			if err != nil || resp == nil || resp.IsError() {
				t.Fatalf("err:%s resp:%#v\n", err, resp)
			}
			if !tt.wantDeletionTime {
				if dtv := resp.Data["versions"].(map[string]interface{})["1"].(map[string]interface{})["deletion_time"].(string); dtv != "" {
					t.Logf("resp: %#v", resp)
					t.Fatalf("after undelete, deletion_time %#v, want no deletion_time", dtv)
				}
			} else {
				got := untilDeletion(t, undeleteTime, resp.Data["versions"].(map[string]interface{})["1"].(map[string]interface{}))
				want := tt.want + 5*time.Second
				if got > want {
					t.Fatalf("diff between deletion_time and undelete time %v, want %v < 5 sec", got, want)
				}
			}
		})
	}
}
