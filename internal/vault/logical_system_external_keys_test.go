// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/v2/internal/helper/namespace"
	"github.com/stretchr/testify/require"
)

func TestExternalKeysBackend(t *testing.T) {
	b := testSystemBackend(t)
	ctx := namespace.RootContext(t.Context())

	type test struct {
		path   string
		op     logical.Operation
		input  map[string]any // The request data that is sent.
		output map[string]any // The response data that is expected in return.
		err    bool           // Should this request fail?
	}

	empty := map[string]any{}

	runTests := func(t *testing.T, tt []test) {
		t.Helper()
		storage := &logical.InmemStorage{}

		for _, tc := range tt {
			resp, err := b.HandleRequest(ctx, &logical.Request{
				Path:      "external-keys/" + tc.path,
				Operation: tc.op,
				Data:      tc.input,
				Storage:   storage,
			})

			if tc.err {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			if tc.output != nil {
				require.Equal(t, tc.output, resp.Data)
			}
		}
	}

	t.Run("update config", func(t *testing.T) {
		t.Run("verify=true", func(t *testing.T) {
			runTests(t, []test{
				{path: "configs", op: logical.ListOperation, output: empty},
				{path: "configs/foo", op: logical.ReadOperation, err: true},
				{path: "configs/foo", op: logical.UpdateOperation, input: empty, err: true},
				{path: "configs/foo", op: logical.UpdateOperation, input: map[string]any{"plugin": "transit"}, err: true},
				{path: "configs/foo", op: logical.UpdateOperation, input: map[string]any{"plugin": "transit", "token": "dummy"}},
				{path: "configs/foo", op: logical.ReadOperation, output: map[string]any{"plugin": "transit", "token": "***"}},
				{path: "configs/foo", op: logical.UpdateOperation, input: map[string]any{"plugin": "transit", "token": "dummy", "namespace": "empire/"}},
				{path: "configs/foo", op: logical.ReadOperation, output: map[string]any{"plugin": "transit", "token": "***", "namespace": "empire/"}},
				{path: "configs", op: logical.ListOperation, output: map[string]any{"keys": []string{"foo"}}},
			})
		})

		t.Run("verify=false", func(t *testing.T) {
			runTests(t, []test{
				{path: "configs", op: logical.ListOperation, output: empty},
				{path: "configs/foo", op: logical.ReadOperation, err: true},
				{path: "configs/foo", op: logical.UpdateOperation, input: map[string]any{"verify": false}, err: true},
				{path: "configs/foo", op: logical.UpdateOperation, input: map[string]any{"plugin": "transit", "verify": false}},
				{path: "configs/foo", op: logical.ReadOperation, output: map[string]any{"plugin": "transit"}},
				{path: "configs", op: logical.ListOperation, output: map[string]any{"keys": []string{"foo"}}},
			})
		})
	})

	t.Run("patch config", func(t *testing.T) {
		t.Run("verify=true", func(t *testing.T) {
			runTests(t, []test{
				{path: "configs/foo", op: logical.PatchOperation, input: map[string]any{"plugin": "transit", "token": "dummy"}, err: true},
				{path: "configs/foo", op: logical.UpdateOperation, input: map[string]any{"plugin": "transit", "token": "dummy"}},
				{path: "configs/foo", op: logical.PatchOperation, input: map[string]any{"token": nil}, err: true},
				{path: "configs/foo", op: logical.PatchOperation, input: map[string]any{"mount_path": "somewhere/"}},
				{path: "configs/foo", op: logical.ReadOperation, output: map[string]any{"plugin": "transit", "token": "***", "mount_path": "somewhere/"}},
				{path: "configs/foo", op: logical.PatchOperation, input: map[string]any{"mount_path": nil}},
				{path: "configs/foo", op: logical.ReadOperation, output: map[string]any{"plugin": "transit", "token": "***"}},
			})
		})

		t.Run("verify=false", func(t *testing.T) {
			runTests(t, []test{
				{path: "configs/foo", op: logical.PatchOperation, input: map[string]any{"plugin": "transit", "verify": false}, err: true},
				{path: "configs/foo", op: logical.UpdateOperation, input: map[string]any{"plugin": "transit", "verify": false}},
				{path: "configs/foo", op: logical.PatchOperation, input: map[string]any{"foo": "bar", "verify": false}},
				{path: "configs/foo", op: logical.ReadOperation, output: map[string]any{"plugin": "transit", "foo": "bar"}},
			})
		})
	})

	t.Run("delete config", func(t *testing.T) {
		runTests(t, []test{
			{path: "configs/foo", op: logical.DeleteOperation},
			{path: "configs/foo", op: logical.UpdateOperation, input: map[string]any{"plugin": "transit", "token": "dummy"}},
			{path: "configs/foo/keys/bar", op: logical.UpdateOperation, input: map[string]any{"name": "bar"}},
			{path: "configs/foo", op: logical.DeleteOperation},
			{path: "configs", op: logical.ListOperation, output: empty},
			{path: "configs/foo", op: logical.ReadOperation, err: true},
			{path: "configs/foo/keys", op: logical.ListOperation, output: empty},
			{path: "configs/foo/keys/bar", op: logical.ReadOperation, err: true},
			{path: "configs/foo", op: logical.DeleteOperation},
		})
	})

	t.Run("update key", func(t *testing.T) {
		t.Run("verify=true", func(t *testing.T) {
			runTests(t, []test{
				{path: "configs/foo", op: logical.UpdateOperation, input: map[string]any{"plugin": "transit", "token": "dummy"}},
				{path: "configs/foo/keys", op: logical.ListOperation, output: empty},
				{path: "configs/foo/keys/bar", op: logical.ReadOperation, err: true},
				{path: "configs/foo/keys/bar", op: logical.UpdateOperation, input: empty, err: true},
				{path: "configs/foo/keys/bar", op: logical.UpdateOperation, input: map[string]any{"name": "bar"}},
				{path: "configs/foo/keys/bar", op: logical.ReadOperation, output: map[string]any{"name": "bar"}},
				{path: "configs/foo/keys/bar", op: logical.UpdateOperation, input: map[string]any{"name": "bar", "disable_prehashing": true}},
				{path: "configs/foo/keys/bar", op: logical.ReadOperation, output: map[string]any{"name": "bar", "disable_prehashing": true}},
			})
		})

		t.Run("verify=false", func(t *testing.T) {
			runTests(t, []test{
				{path: "configs/foo", op: logical.UpdateOperation, input: map[string]any{"plugin": "transit", "token": "dummy"}},
				{path: "configs/foo/keys", op: logical.ListOperation, output: empty},
				{path: "configs/foo/keys/bar", op: logical.ReadOperation, err: true},
				{path: "configs/foo/keys/bar", op: logical.UpdateOperation, input: map[string]any{"verify": false}},
				{path: "configs/foo/keys/bar", op: logical.ReadOperation, output: empty},
				{path: "configs/foo/keys/bar", op: logical.UpdateOperation, input: map[string]any{"abc": "def", "verify": false}},
				{path: "configs/foo/keys/bar", op: logical.ReadOperation, output: map[string]any{"abc": "def"}},
			})
		})
	})

	t.Run("patch key", func(t *testing.T) {
		t.Run("verify=true", func(t *testing.T) {
			runTests(t, []test{
				{path: "configs/foo", op: logical.UpdateOperation, input: map[string]any{"plugin": "transit", "token": "dummy"}},
				{path: "configs/foo/keys/bar", op: logical.PatchOperation, input: map[string]any{"name": "bar"}, err: true},
				{path: "configs/foo/keys/bar", op: logical.UpdateOperation, input: map[string]any{"name": "bar"}},
				{path: "configs/foo/keys/bar", op: logical.PatchOperation, input: map[string]any{"name": nil}, err: true},
				{path: "configs/foo/keys/bar", op: logical.PatchOperation, input: map[string]any{"disable_prehashing": true}},
				{path: "configs/foo/keys/bar", op: logical.ReadOperation, output: map[string]any{"name": "bar", "disable_prehashing": true}},
				{path: "configs/foo/keys/bar", op: logical.PatchOperation, input: map[string]any{"disable_prehashing": nil}},
				{path: "configs/foo/keys/bar", op: logical.ReadOperation, output: map[string]any{"name": "bar"}},
			})
		})

		t.Run("verify=false", func(t *testing.T) {
			runTests(t, []test{
				{path: "configs/foo", op: logical.UpdateOperation, input: map[string]any{"plugin": "transit", "token": "dummy"}},
				{path: "configs/foo/keys/bar", op: logical.PatchOperation, input: map[string]any{"abc": "def", "verify": false}, err: true},
				{path: "configs/foo/keys/bar", op: logical.UpdateOperation, input: map[string]any{"abc": "def", "verify": false}},
				{path: "configs/foo/keys/bar", op: logical.PatchOperation, input: map[string]any{"abc": nil, "def": "abc", "verify": false}},
				{path: "configs/foo/keys/bar", op: logical.ReadOperation, output: map[string]any{"def": "abc"}},
			})
		})
	})

	t.Run("delete key", func(t *testing.T) {
		runTests(t, []test{
			{path: "configs/foo", op: logical.UpdateOperation, input: map[string]any{"plugin": "transit", "token": "dummy"}},
			{path: "configs/foo/keys/bar", op: logical.DeleteOperation},
			{path: "configs/foo/keys/bar", op: logical.UpdateOperation, input: map[string]any{"name": "bar"}},
			{path: "configs/foo/keys/bar", op: logical.DeleteOperation},
			{path: "configs/foo/keys/bar", op: logical.ReadOperation, err: true},
			{path: "configs/foo/keys/bar", op: logical.DeleteOperation},
		})
	})

	t.Run("update grants", func(t *testing.T) {
		runTests(t, []test{
			{path: "configs/foo", op: logical.UpdateOperation, input: map[string]any{"plugin": "transit", "token": "dummy"}},
			{path: "configs/foo/keys/bar", op: logical.UpdateOperation, input: map[string]any{"name": "bar"}},
			{path: "configs/foo/keys/bar/grants/pki/", op: logical.UpdateOperation},
			{path: "configs/foo/keys/bar/grants", op: logical.ListOperation, output: map[string]any{"keys": []string{"pki/"}}},
			{path: "configs/foo/keys/bar/grants/transit", op: logical.UpdateOperation},
			{path: "configs/foo/keys/bar/grants", op: logical.ListOperation, output: map[string]any{"keys": []string{"pki/", "transit/"}}},
			{path: "configs/foo/keys/bar/grants/pki", op: logical.DeleteOperation},
			{path: "configs/foo/keys/bar/grants", op: logical.ListOperation, output: map[string]any{"keys": []string{"transit/"}}},
			{path: "configs/foo/keys/bar/grants/pki", op: logical.DeleteOperation},
			{path: "configs/foo/keys/bar/grants/transit/", op: logical.DeleteOperation},
			{path: "configs/foo/keys/bar/grants", op: logical.ListOperation, output: empty},
			{path: "configs/foo/keys/bar/grants/transit/", op: logical.DeleteOperation},
		})
	})
}
