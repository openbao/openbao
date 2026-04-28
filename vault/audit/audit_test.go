// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package audit

import (
	"context"
	"encoding/json"
	"errors"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/go-test/deep"
	"github.com/openbao/openbao/helper/testhelpers/corehelpers"
	"github.com/stretchr/testify/require"

	"github.com/hashicorp/errwrap"
	log "github.com/hashicorp/go-hclog"
	uuid "github.com/hashicorp/go-uuid"
	"github.com/mitchellh/copystructure"
	au "github.com/openbao/openbao/audit"
	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/sdk/v2/helper/compressutil"
	"github.com/openbao/openbao/sdk/v2/helper/jsonutil"
	"github.com/openbao/openbao/sdk/v2/helper/logging"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/vault/barrier"
	"github.com/openbao/openbao/vault/routing"
)

func TestDefaultAuditTable(t *testing.T) {
	table := defaultAuditTable()
	require.Len(t, table.Entries, 0)
	require.Equal(t, table.Type, TableType)
}

func TestAuditBroker_LogRequest(t *testing.T) {
	l := logging.NewVaultLogger(log.Trace)
	_, barr, _ := barrier.MockBarrier(t, l)
	b, err := NewAuditBroker(t.Context(), barrier.NewView(barr, barrier.SystemBarrierPrefix), l)
	require.NoError(t, err)
	a1 := corehelpers.TestNoopAudit(t, nil)
	a2 := corehelpers.TestNoopAudit(t, nil)
	b.Register("foo", a1, nil, false)
	b.Register("bar", a2, nil, false)

	auth := &logical.Auth{
		ClientToken: "foo",
		Policies:    []string{"dev", "ops"},
		Metadata: map[string]string{
			"user":   "armon",
			"source": "github",
		},
	}
	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "sys/mounts",
	}

	// Copy so we can verify nothing changed
	authCopyRaw, err := copystructure.Copy(auth)
	require.NoError(t, err)
	authCopy := authCopyRaw.(*logical.Auth)

	reqCopyRaw, err := copystructure.Copy(req)
	require.NoError(t, err)
	reqCopy := reqCopyRaw.(*logical.Request)

	// Create an identifier for the request to verify against
	req.ID, err = uuid.GenerateUUID()
	require.NoError(t, err)
	reqCopy.ID = req.ID

	reqErrs := errors.New("errs")
	logInput := &logical.LogInput{
		Auth:     authCopy,
		Request:  reqCopy,
		OuterErr: reqErrs,
	}
	ctx := namespace.RootContext(t.Context())
	err = b.LogRequest(ctx, logInput)
	require.NoError(t, err)

	for _, a := range []*corehelpers.NoopAudit{a1, a2} {
		require.Equal(t, a.ReqAuth[0], auth)
		require.Equal(t, a.Req[0], req)
		require.EqualError(t, a.ReqErrs[0], reqErrs.Error())
	}

	// Should still work with one failing backend
	a1.ReqErr = errors.New("failed")
	logInput = &logical.LogInput{
		Auth:    auth,
		Request: req,
	}
	require.NoError(t, b.LogRequest(ctx, logInput))

	// Should FAIL work with both failing backends
	a2.ReqErr = errors.New("failed")
	require.True(t, errwrap.Contains(b.LogRequest(ctx, logInput), "no audit backend succeeded in logging the request"))
}

func TestAuditBroker_LogResponse(t *testing.T) {
	l := logging.NewVaultLogger(log.Trace)
	_, barr, _ := barrier.MockBarrier(t, l)
	b, err := NewAuditBroker(t.Context(), barrier.NewView(barr, barrier.SystemBarrierPrefix), l)
	require.NoError(t, err)

	a1 := corehelpers.TestNoopAudit(t, nil)
	a2 := corehelpers.TestNoopAudit(t, nil)
	b.Register("foo", a1, nil, false)
	b.Register("bar", a2, nil, false)

	auth := &logical.Auth{
		NumUses:     10,
		ClientToken: "foo",
		Policies:    []string{"dev", "ops"},
		Metadata: map[string]string{
			"user":   "armon",
			"source": "github",
		},
	}
	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "sys/mounts",
	}
	resp := &logical.Response{
		Secret: &logical.Secret{
			LeaseOptions: logical.LeaseOptions{
				TTL: 1 * time.Hour,
			},
		},
		Data: map[string]interface{}{
			"user":     "root",
			"password": "password",
		},
	}
	respErr := errors.New("permission denied")

	// Copy so we can verify nothing changed
	authCopyRaw, err := copystructure.Copy(auth)
	require.NoError(t, err)
	authCopy := authCopyRaw.(*logical.Auth)

	reqCopyRaw, err := copystructure.Copy(req)
	require.NoError(t, err)
	reqCopy := reqCopyRaw.(*logical.Request)

	respCopyRaw, err := copystructure.Copy(resp)
	require.NoError(t, err)

	respCopy := respCopyRaw.(*logical.Response)
	logInput := &logical.LogInput{
		Auth:     authCopy,
		Request:  reqCopy,
		Response: respCopy,
		OuterErr: respErr,
	}
	ctx := namespace.RootContext(t.Context())
	require.NoError(t, b.LogResponse(ctx, logInput))

	for _, a := range []*corehelpers.NoopAudit{a1, a2} {
		require.Equal(t, a.RespAuth[0], auth)
		require.Equal(t, a.RespReq[0], req)
		require.Equal(t, a.Resp[0], resp)
		require.EqualError(t, a.RespErrs[0], respErr.Error())
	}

	// Should still work with one failing backend
	a1.RespErr = errors.New("failed")
	logInput = &logical.LogInput{
		Auth:     auth,
		Request:  req,
		Response: resp,
		OuterErr: respErr,
	}
	require.NoError(t, b.LogResponse(ctx, logInput))

	// Should FAIL work with both failing backends
	a2.RespErr = errors.New("failed")
	require.True(t, strings.Contains(b.LogResponse(ctx, logInput).Error(), "no audit backend succeeded in logging the response"))
}

func TestAuditBroker_AuditHeaders(t *testing.T) {
	logger := logging.NewVaultLogger(log.Trace)
	_, barr, _ := barrier.MockBarrier(t, logger)
	b, err := NewAuditBroker(t.Context(), barrier.NewView(barr, barrier.SystemBarrierPrefix), logger)
	require.NoError(t, err)
	a1 := corehelpers.TestNoopAudit(t, nil)
	a2 := corehelpers.TestNoopAudit(t, nil)
	b.Register("foo", a1, nil, false)
	b.Register("bar", a2, nil, false)

	auth := &logical.Auth{
		ClientToken: "foo",
		Policies:    []string{"dev", "ops"},
		Metadata: map[string]string{
			"user":   "armon",
			"source": "github",
		},
	}
	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "sys/mounts",
		Headers: map[string][]string{
			"X-Test-Header":  {"foo"},
			"X-Vault-Header": {"bar"},
			"Content-Type":   {"baz"},
		},
	}
	respErr := errors.New("permission denied")

	// Copy so we can verify nothing changed
	reqCopyRaw, err := copystructure.Copy(req)
	require.NoError(t, err)
	reqCopy := reqCopyRaw.(*logical.Request)

	require.NoError(t, b.AuditedHeaderConfig().Add(t.Context(), "X-Test-Header", false))
	require.NoError(t, b.AuditedHeaderConfig().Add(t.Context(), "X-Vault-Header", false))

	logInput := &logical.LogInput{
		Auth:     auth,
		Request:  reqCopy,
		OuterErr: respErr,
	}
	ctx := namespace.RootContext(t.Context())
	require.NoError(t, b.LogRequest(ctx, logInput))

	expected := map[string][]string{
		"x-test-header":  {"foo"},
		"x-vault-header": {"bar"},
	}

	for _, a := range []*corehelpers.NoopAudit{a1, a2} {
		require.Equal(t, a.ReqHeaders[0], expected)
	}

	// Should still work with one failing backend
	a1.ReqErr = errors.New("failed")
	logInput = &logical.LogInput{
		Auth:     auth,
		Request:  req,
		OuterErr: respErr,
	}
	require.NoError(t, b.LogRequest(ctx, logInput))

	// Should FAIL work with both failing backends
	a2.ReqErr = errors.New("failed")
	require.True(t, errwrap.Contains(b.LogRequest(ctx, logInput), "no audit backend succeeded in logging the request"))
}

type mockCore struct {
	b      barrier.View
	router *routing.Router
}

func (mc mockCore) MountEntryView(me *routing.MountEntry) (barrier.View, error) {
	return barrier.NewView(mc.b, "").SubView(path.Join(BarrierPrefix, me.UUID) + "/"), nil
}

func (mc mockCore) NamespaceView(ns *namespace.Namespace) barrier.View {
	return mc.b
}

func (mockCore) NewAuditBackend(ctx context.Context, entry *routing.MountEntry, view logical.Storage, conf map[string]string) (au.Backend, error) {
	switch entry.Type {
	case "noop":
		f := corehelpers.NoopAuditFactory(nil)
		return f(ctx, &au.BackendConfig{})
	case "fail":
		return nil, errors.New("failing enabling")
	default:
		return &corehelpers.NoopAudit{}, nil
	}
}

func (mockCore) NamespaceByID(ctx context.Context, nsID string) (*namespace.Namespace, error) {
	return namespace.RootNamespace, nil
}
func (mockCore) RemoveAuditReloadFunc(entry *routing.MountEntry) {}

func newMockAuditTable(t *testing.T) (*Table, barrier.View) {
	t.Helper()
	logger := logging.NewVaultLogger(log.Trace)
	_, barr, _ := barrier.MockBarrier(t, logger)
	view := barrier.NewView(barr, "")
	c := mockCore{
		b:      view,
		router: routing.NewRouter(logger),
	}
	audit, _, err := NewAuditTable(t.Context(), c, c.router, view, logger)
	require.NoError(t, err)
	return audit, view
}

func Test_AuditTable_UpgradeToTyped(t *testing.T) {
	audit, view := newMockAuditTable(t)
	me := &routing.MountEntry{
		Table: TableType,
		Path:  "foo",
		Type:  "noop",
	}
	require.NoError(t, audit.EnableAudit(namespace.RootContext(t.Context()), me, true))

	// Save the expected table
	goodJson, err := json.Marshal(audit.Mt)
	require.NoError(t, err)

	// Create a pre-typed version
	audit.Mt.Type = ""
	for _, entry := range audit.Mt.Entries {
		entry.Table = ""
	}

	raw, err := json.Marshal(audit.Mt)
	require.NoError(t, err)
	require.NotEqual(t, goodJson, raw)

	// Write the pre-typed version
	entry := &logical.StorageEntry{
		Key:   ConfigPath,
		Value: raw,
	}
	require.NoError(t, view.Put(t.Context(), entry))

	require.NoError(t, audit.loadAudits(t.Context(), view, false))
	mt := audit.Mt

	entry, err = view.Get(t.Context(), ConfigPath)
	require.NoError(t, err)
	require.NotNil(t, entry)

	decompressedBytes, uncompressed, err := compressutil.Decompress(entry.Value)
	require.NoError(t, err)

	actual := decompressedBytes
	if uncompressed {
		actual = entry.Value
	}

	// Decode actual and expected and compare.
	var expectedDecoded map[string]interface{}
	var actualDecoded map[string]interface{}

	require.NoError(t, json.Unmarshal(goodJson, &expectedDecoded))
	require.NoError(t, json.Unmarshal(actual, &actualDecoded))
	require.Lenf(t, deep.Equal(actualDecoded, expectedDecoded), 0, "bad: expected\n%s\nactual\n%s\n", string(goodJson), string(actual))

	// Now try saving invalid versions
	origTableType := mt.Type
	mt.Type = "foo"
	require.Error(t, audit.persistAudit(t.Context(), view, mt, false))

	if len(mt.Entries) > 0 {
		mt.Type = origTableType
		mt.Entries[0].Table = "bar"
		require.Error(t, audit.persistAudit(t.Context(), view, mt, false))

		mt.Entries[0].Table = mt.Type
		require.NoError(t, audit.persistAudit(t.Context(), view, mt, false))
	}
}

func TestAuditTable_EnableAudit_MixedFailures(t *testing.T) {
	logger := logging.NewVaultLogger(log.Trace)
	_, barr, _ := barrier.MockBarrier(t, logger)
	view := barrier.NewView(barr, "")
	c := mockCore{
		b:      view,
		router: routing.NewRouter(logger),
	}
	audit, _, err := NewAuditTable(t.Context(), c, c.router, view, logger)
	require.NoError(t, err)

	ctx := namespace.ContextWithNamespace(t.Context(), namespace.RootNamespace)
	require.NoError(t, audit.persistAudit(ctx, view, &routing.MountTable{
		Type: TableType,
		Entries: []*routing.MountEntry{
			{
				Table: TableType,
				Path:  "noop/",
				Type:  "noop",
				UUID:  "abcd",
			},
			{
				Table: TableType,
				Path:  "noop2/",
				Type:  "noop",
				UUID:  "bcde",
			},
		},
	}, false))

	// Both should set up successfully
	audit, _, err = NewAuditTable(ctx, c, c.router, view, logger)
	require.NoError(t, err)

	// We expect this to work because the other entry is still valid
	audit.Mt.Entries[0].Type = "fail"
	require.NoError(t, audit.persistAudit(t.Context(), view, audit.Mt, false))

	audit, _, err = NewAuditTable(ctx, c, c.router, view, logger)
	require.NoError(t, err)

	audit.Mt.Entries[1].Type = "fail"
	require.NoError(t, audit.persistAudit(t.Context(), view, audit.Mt, false))

	// No audit backend set up successfully, so expect error
	_, _, err = NewAuditTable(ctx, c, c.router, view, logger)
	require.Error(t, err)
}

// Test that the local table actually gets populated as expected with local
// entries, and that upon reading the entries from both are recombined
// correctly
func TestAuditTable_EnableAudit_Local(t *testing.T) {
	logger := logging.NewVaultLogger(log.Trace)
	_, barr, _ := barrier.MockBarrier(t, logger)
	view := barrier.NewView(barr, "")
	c := mockCore{
		b:      view,
		router: routing.NewRouter(logger),
	}
	ctx := namespace.ContextWithNamespace(t.Context(), namespace.RootNamespace)
	audit, _, err := NewAuditTable(ctx, c, c.router, view, logger)
	require.NoError(t, err)

	require.NoError(t, audit.persistAudit(ctx, view, &routing.MountTable{
		Type: TableType,
		Entries: []*routing.MountEntry{
			{
				Table:       TableType,
				Path:        "noop/",
				Type:        "noop",
				UUID:        "abcd",
				Accessor:    "noop-abcd",
				NamespaceID: namespace.RootNamespaceID,
				Namespace:   namespace.RootNamespace,
			},
			{
				Table:       TableType,
				Path:        "noop2/",
				Type:        "noop",
				UUID:        "bcde",
				Accessor:    "noop-bcde",
				NamespaceID: namespace.RootNamespaceID,
				Namespace:   namespace.RootNamespace,
			},
		},
	}, false))

	audit, _, err = NewAuditTable(ctx, c, c.router, view, logger)
	require.NoError(t, err)

	rawLocal, err := view.Get(ctx, LocalConfigPath)
	require.NoError(t, err)
	require.NotNil(t, rawLocal)

	localAuditTable := &routing.MountTable{}
	require.NoError(t, jsonutil.DecodeJSON(rawLocal.Value, localAuditTable))

	require.Len(t, localAuditTable.Entries, 0)

	audit.Mt.Entries[1].Local = true
	require.NoError(t, audit.persistAudit(ctx, view, audit.Mt, false))

	rawLocal, err = view.Get(ctx, LocalConfigPath)
	require.NoError(t, err)
	require.NotNil(t, rawLocal)

	localAuditTable = &routing.MountTable{}
	require.NoError(t, jsonutil.DecodeJSON(rawLocal.Value, localAuditTable))

	require.Len(t, localAuditTable.Entries, 1)

	oldAudit := audit
	require.NoError(t, audit.loadAudits(ctx, view, false))

	require.Equal(t, oldAudit, audit)
	require.Len(t, audit.Mt.Entries, 2)
}
