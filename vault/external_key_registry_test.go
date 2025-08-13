// Copyright The OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"testing"

	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
)

func TestExternalKeysBackend(t *testing.T) {
	sys := testSystemBackend(t)
	ctx := namespace.RootContext(context.Background())

	type request struct {
		path string            // /sys/external-keys/:path
		op   logical.Operation // The operation

		input  map[string]any // The request data we send
		output map[string]any // The response data we expect back

		noverify bool // Disable automatically verifying an UpdateOperation via a ReadOperation
		err      bool // Should this request fail?
	}

	tests := []struct {
		name     string
		requests []request
	}{
		{
			name: "create empty config",
			requests: []request{
				{
					path:  "configs/my-config",
					op:    logical.UpdateOperation,
					input: map[string]any{},
					err:   true,
				},
			},
		},
		{
			name: "create untyped and uninherited config",
			requests: []request{
				{
					path:  "configs/my-config",
					op:    logical.UpdateOperation,
					input: map[string]any{"foo": "bar", "bar": "baz"},
					err:   true,
				},
			},
		},
		{
			name: "create ambiguous config",
			requests: []request{
				{
					path:  "configs/my-config",
					op:    logical.UpdateOperation,
					input: map[string]any{"type": "red", "inherits": "their-config"},
					err:   true,
				},
			},
		},
		{
			name: "create typed config",
			requests: []request{
				{
					path:  "configs/my-config",
					op:    logical.UpdateOperation,
					input: map[string]any{"type": "red"},
				},
			},
		},
		{
			name: "list configs",
			requests: []request{
				{
					path:   "configs",
					op:     logical.ListOperation,
					output: map[string]any{},
				},
				{
					path:  "configs/my-config",
					op:    logical.UpdateOperation,
					input: map[string]any{"type": "red"},
				},
				{
					path:  "configs/my-other-config",
					op:    logical.UpdateOperation,
					input: map[string]any{"type": "blue"},
				},
				{
					path:   "configs",
					op:     logical.ListOperation,
					output: map[string]any{"keys": []string{"my-config", "my-other-config"}},
				},
			},
		},
		{
			name: "create typed config with additional values",
			requests: []request{
				{
					path: "configs/my-config",
					op:   logical.UpdateOperation,
					input: map[string]any{
						"type": "red", "endpoint": "https://eu.red.kms", "project": "openbao",
					},
				},
			},
		},
		{
			name: "create typed config with non-string additional values",
			requests: []request{
				{
					path:  "configs/my-config",
					op:    logical.UpdateOperation,
					input: map[string]any{"type": "red", "timeout": 100},
					err:   true,
				},
			},
		},
		{
			name: "update typed config to add additional values",
			requests: []request{
				{
					path:  "configs/my-config",
					op:    logical.UpdateOperation,
					input: map[string]any{"type": "red"},
				},
				{
					path: "configs/my-config",
					op:   logical.UpdateOperation,
					input: map[string]any{
						"type": "red", "endpoint": "https://eu.red.kms", "project": "openbao",
					},
				},
			},
		},
		{
			name: "update typed config to remove additional values",
			requests: []request{
				{
					path: "configs/my-config",
					op:   logical.UpdateOperation,
					input: map[string]any{
						"type": "red", "endpoint": "https://eu.red.kms", "project": "openbao",
					},
				},
				{
					path:  "configs/my-config",
					op:    logical.UpdateOperation,
					input: map[string]any{"type": "red"},
				},
			},
		},
		{
			name: "patch typed config to remove additional values",
			requests: []request{
				{
					path: "configs/my-config",
					op:   logical.UpdateOperation,
					input: map[string]any{
						"type": "red", "endpoint": "https://eu.red.kms", "project": "openbao",
					},
				},
				{
					path:  "configs/my-config",
					op:    logical.PatchOperation,
					input: map[string]any{"endpoint": nil, "project": nil, "foo": nil},
				},
				{
					path:   "configs/my-config",
					op:     logical.ReadOperation,
					output: map[string]any{"type": "red"},
				},
			},
		},
		{
			name: "update typed config to modify additional values",
			requests: []request{
				{
					path: "configs/my-config",
					op:   logical.UpdateOperation,
					input: map[string]any{
						"type": "red", "endpoint": "https://eu.red.kms", "project": "openbao-eu",
					},
				},
				{
					path: "configs/my-config",
					op:   logical.UpdateOperation,
					input: map[string]any{
						"type": "red", "endpoint": "https://us.red.kms", "project": "openbao-us",
					},
				},
			},
		},
		{
			name: "update typed config to change type",
			requests: []request{
				{
					path: "configs/my-config",
					op:   logical.UpdateOperation,
					input: map[string]any{
						"type": "red", "endpoint": "https://eu.red.kms", "project": "openbao",
					},
				},
				{
					path: "configs/my-config",
					op:   logical.UpdateOperation,
					input: map[string]any{
						"type": "blue", "endpoint": "https://eu.blue.kms", "project": "openbao",
					},
				},
			},
		},
		{
			name: "update typed config to remove type",
			requests: []request{
				{
					path: "configs/my-config",
					op:   logical.UpdateOperation,
					input: map[string]any{
						"type": "red", "endpoint": "https://eu.red.kms", "project": "openbao",
					},
				},
				{
					path:  "configs/my-config",
					op:    logical.UpdateOperation,
					input: map[string]any{"endpoint": "https://eu.red.kms", "project": "openbao"},
					err:   true,
				},
			},
		},
		{
			name: "update typed config to be an inherited config",
			requests: []request{
				{
					path: "configs/my-config",
					op:   logical.UpdateOperation,
					input: map[string]any{
						"type": "red", "endpoint": "https://eu.red.kms", "project": "openbao",
					},
				},
				{
					path:  "configs/my-config",
					op:    logical.UpdateOperation,
					input: map[string]any{"inherits": "their-config"},
					err:   true,
				},
			},
		},
		{
			name: "update typed config to be an ambigous config",
			requests: []request{
				{
					path:  "configs/my-config",
					op:    logical.UpdateOperation,
					input: map[string]any{"type": "red"},
				},
				{
					path:  "configs/my-config",
					op:    logical.UpdateOperation,
					input: map[string]any{"type": "red", "inherits": "their-config"},
					err:   true,
				},
			},
		},
		{
			name: "create inherited config",
			requests: []request{
				{
					path:  "configs/my-config",
					op:    logical.UpdateOperation,
					input: map[string]any{"inherits": "their-config"},
				},
			},
		},
		{
			name: "create inherited config with additional values",
			requests: []request{
				{
					path:  "configs/my-config",
					op:    logical.UpdateOperation,
					input: map[string]any{"inherits": "their-config", "project": "openbao"},
					err:   true,
				},
			},
		},
		{
			name: "update inherited config",
			requests: []request{
				{
					path:  "configs/my-config",
					op:    logical.UpdateOperation,
					input: map[string]any{"inherits": "their-config"},
				},
				{
					path:  "configs/my-config",
					op:    logical.UpdateOperation,
					input: map[string]any{"inherits": "their-other-red-config"},
				},
			},
		},
		{
			name: "patch inherited config",
			requests: []request{
				{
					path:  "configs/my-config",
					op:    logical.UpdateOperation,
					input: map[string]any{"inherits": "their-config"},
				},
				{
					path:  "configs/my-config",
					op:    logical.PatchOperation,
					input: map[string]any{"inherits": "their-other-config"},
				},
				{
					path:   "configs/my-config",
					op:     logical.ReadOperation,
					output: map[string]any{"inherits": "their-other-config"},
				},
			},
		},
		{
			name: "update inherited config to add additional values",
			requests: []request{
				{
					path:  "configs/my-config",
					op:    logical.UpdateOperation,
					input: map[string]any{"inherits": "their-config"},
				},
				{
					path:  "configs/my-config",
					op:    logical.UpdateOperation,
					input: map[string]any{"inherits": "their-config", "project": "openbao"},
					err:   true,
				},
			},
		},
		{
			name: "update inherited config to remove inherits field",
			requests: []request{
				{
					path:  "configs/my-config",
					op:    logical.UpdateOperation,
					input: map[string]any{"inherits": "their-config"},
				},
				{
					path:  "configs/my-config",
					op:    logical.UpdateOperation,
					input: map[string]any{},
					err:   true,
				},
			},
		},
		{
			name: "update inherited config into ambiguous config",
			requests: []request{
				{
					path:  "configs/my-config",
					op:    logical.UpdateOperation,
					input: map[string]any{"inherits": "their-config"},
				},
				{
					path:  "configs/my-config",
					op:    logical.UpdateOperation,
					input: map[string]any{"inherits": "their-config", "type": "red"},
					err:   true,
				},
			},
		},
		{
			name: "update inherited config into typed config",
			requests: []request{
				{
					path:  "configs/my-config",
					op:    logical.UpdateOperation,
					input: map[string]any{"inherits": "their-config"},
				},
				{
					path: "configs/my-config",
					op:   logical.UpdateOperation,
					input: map[string]any{
						"type": "red", "endpoint": "https://eu.red.kms", "project": "openbao",
					},
				},
			},
		},
		{
			name: "patch inherited config into typed config",
			requests: []request{
				{
					path:  "configs/my-config",
					op:    logical.UpdateOperation,
					input: map[string]any{"inherits": "their-config"},
				},
				{
					path: "configs/my-config",
					op:   logical.PatchOperation,
					input: map[string]any{
						"inherits": nil, "type": "red", "endpoint": "https://eu.red.kms",
					},
				},
				{
					path:   "configs/my-config",
					op:     logical.ReadOperation,
					output: map[string]any{"type": "red", "endpoint": "https://eu.red.kms"},
				},
			},
		},
		{
			name: "patch non-existing config",
			requests: []request{
				{
					path:  "configs/my-config",
					op:    logical.PatchOperation,
					input: map[string]any{"type": "red"},
					err:   true,
				},
			},
		},
		{
			name: "create key for non-existing config",
			requests: []request{
				{
					path:  "configs/my-config/keys/my-key",
					op:    logical.UpdateOperation,
					input: map[string]any{"label": "my-key"},
					err:   true,
				},
			},
		},
		{
			name: "create key for inherited config",
			requests: []request{
				{
					path:  "configs/my-config",
					op:    logical.UpdateOperation,
					input: map[string]any{"inherits": "their-config"},
				},
				{
					path:  "configs/my-config/keys/my-key",
					op:    logical.UpdateOperation,
					input: map[string]any{"label": "my-key"},
					err:   true,
				},
			},
		},
		{
			name: "create key",
			requests: []request{
				{
					path:  "configs/my-config",
					op:    logical.UpdateOperation,
					input: map[string]any{"type": "red"},
				},
				{
					path:  "configs/my-config/keys/my-key",
					op:    logical.UpdateOperation,
					input: map[string]any{"label": "my-key"},
				},
				{
					path:  "configs/my-config/keys/my-other-key",
					op:    logical.UpdateOperation,
					input: map[string]any{},
				},
			},
		},
		{
			name: "update key",
			requests: []request{
				{
					path:  "configs/my-config",
					op:    logical.UpdateOperation,
					input: map[string]any{"type": "red"},
				},
				{
					path:  "configs/my-config/keys/my-key",
					op:    logical.UpdateOperation,
					input: map[string]any{"label": "my-key"},
				},
				{
					path:  "configs/my-config/keys/my-key",
					op:    logical.UpdateOperation,
					input: map[string]any{"label": "my-other-key", "capabilities": "sign"},
				},
			},
		},
		{
			name: "patch key",
			requests: []request{
				{
					path:  "configs/my-config",
					op:    logical.UpdateOperation,
					input: map[string]any{"type": "red"},
				},
				{
					path:  "configs/my-config/keys/my-key",
					op:    logical.UpdateOperation,
					input: map[string]any{"label": "my-key"},
				},
				{
					path:  "configs/my-config/keys/my-key",
					op:    logical.PatchOperation,
					input: map[string]any{"label": nil, "capabilities": "sign"},
				},
				{
					path:   "configs/my-config/keys/my-key",
					op:     logical.ReadOperation,
					output: map[string]any{"capabilities": "sign"},
				},
			},
		},
		{
			name: "patch non-existing key",
			requests: []request{
				{
					path:  "configs/my-config",
					op:    logical.UpdateOperation,
					input: map[string]any{"type": "red"},
				},
				{
					path:  "configs/my-config/keys/my-key",
					op:    logical.PatchOperation,
					input: map[string]any{"label": nil, "capabilities": "sign"},
					err:   true,
				},
			},
		},
		{
			name: "list keys",
			requests: []request{
				{
					path:  "configs/my-config",
					op:    logical.UpdateOperation,
					input: map[string]any{"type": "red"},
				},
				{
					path:  "configs/my-other-config",
					op:    logical.UpdateOperation,
					input: map[string]any{"type": "blue"},
				},
				{
					path:   "configs/my-config/keys",
					op:     logical.ListOperation,
					output: map[string]any{},
				},
				{
					path:  "configs/my-config/keys/my-key",
					op:    logical.UpdateOperation,
					input: map[string]any{"label": "my-key"},
				},
				{
					path:   "configs/my-other-config/keys",
					op:     logical.ListOperation,
					output: map[string]any{},
				},
				{
					path:  "configs/my-other-config/keys/my-other-key",
					op:    logical.UpdateOperation,
					input: map[string]any{"label": "my-key"},
				},
				{
					path:   "configs/my-config/keys",
					op:     logical.ListOperation,
					output: map[string]any{"keys": []string{"my-key"}},
				},
				{
					path:   "configs/my-other-config/keys",
					op:     logical.ListOperation,
					output: map[string]any{"keys": []string{"my-other-key"}},
				},
			},
		},
		{
			name: "delete key",
			requests: []request{
				{
					path:  "configs/my-config",
					op:    logical.UpdateOperation,
					input: map[string]any{"type": "red"},
				},
				{
					path: "configs/my-config/keys/my-key",
					op:   logical.DeleteOperation,
				},
				{
					path: "configs/my-config/keys/my-key",
					op:   logical.ReadOperation,
					err:  true,
				},
				{
					path:  "configs/my-config/keys/my-key",
					op:    logical.DeleteOperation,
					input: map[string]any{"label": "my-key"},
				},
			},
		},
		{
			name: "delete config and keys",
			requests: []request{
				{
					path:  "configs/my-config",
					op:    logical.UpdateOperation,
					input: map[string]any{"type": "red"},
				},
				{
					path:  "configs/my-config/keys/my-key",
					op:    logical.UpdateOperation,
					input: map[string]any{"label": "my-key"},
				},
				{
					path:  "configs/my-config/keys/my-other-key",
					op:    logical.UpdateOperation,
					input: map[string]any{"label": "my-other-key"},
				},
				{
					path: "configs/my-config",
					op:   logical.DeleteOperation,
				},
				{
					path: "configs/my-config",
					op:   logical.ReadOperation,
					err:  true,
				},
				{
					path:   "configs/my-config/keys",
					op:     logical.ListOperation,
					output: map[string]any{},
				},
			},
		},
		{
			name: "update key without affecting grants",
			requests: []request{
				{
					path:  "configs/my-config",
					op:    logical.UpdateOperation,
					input: map[string]any{"type": "red"},
				},
				{
					path:  "configs/my-config/keys/my-key",
					op:    logical.UpdateOperation,
					input: map[string]any{"label": "my-key"},
				},
				{
					path:     "configs/my-config/keys/my-key/grants/my-mount",
					op:       logical.UpdateOperation,
					noverify: true,
				},
				{
					path:  "configs/my-config/keys/my-key",
					op:    logical.PatchOperation,
					input: map[string]any{"capabilities": "sign"},
				},
				{
					path:   "configs/my-config/keys/my-key/grants",
					op:     logical.ListOperation,
					output: map[string]any{"keys": []string{"my-mount/"}},
				},
				{
					path:  "configs/my-config/keys/my-key",
					op:    logical.UpdateOperation,
					input: map[string]any{"label": "my-other-key"},
				},
				{
					path:   "configs/my-config/keys/my-key/grants",
					op:     logical.ListOperation,
					output: map[string]any{"keys": []string{"my-mount/"}},
				},
			},
		},

		{
			name: "add grants",
			requests: []request{
				{
					path:  "configs/my-config",
					op:    logical.UpdateOperation,
					input: map[string]any{"type": "red"},
				},
				{
					path:  "configs/my-config/keys/my-key",
					op:    logical.UpdateOperation,
					input: map[string]any{"label": "my-key"},
				},
				{
					path:     "configs/my-config/keys/my-key/grants/my-mount",
					op:       logical.UpdateOperation,
					noverify: true,
				},
				{
					path:     "configs/my-config/keys/my-key/grants/another-mount",
					op:       logical.UpdateOperation,
					noverify: true,
				},
				{
					path:     "configs/my-config/keys/my-key/grants/my-mount",
					op:       logical.UpdateOperation,
					noverify: true,
				},
				{
					path:   "configs/my-config/keys/my-key/grants",
					op:     logical.ListOperation,
					output: map[string]any{"keys": []string{"my-mount/", "another-mount/"}},
				},
			},
		},
		{
			name: "remove grants",
			requests: []request{
				{
					path:  "configs/my-config",
					op:    logical.UpdateOperation,
					input: map[string]any{"type": "red"},
				},
				{
					path:  "configs/my-config/keys/my-key",
					op:    logical.UpdateOperation,
					input: map[string]any{"label": "my-key"},
				},
				{
					path:     "configs/my-config/keys/my-key/grants/my-mount",
					op:       logical.UpdateOperation,
					noverify: true,
				},
				{
					path:     "configs/my-config/keys/my-key/grants/another-mount",
					op:       logical.UpdateOperation,
					noverify: true,
				},
				{
					path: "configs/my-config/keys/my-key/grants/my-mount",
					op:   logical.DeleteOperation,
				},
				{
					path:   "configs/my-config/keys/my-key/grants",
					op:     logical.ListOperation,
					output: map[string]any{"keys": []string{"another-mount/"}},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			// We keep storage across requests per test, but not across tests.
			storage := &logical.InmemStorage{}

			for _, req := range test.requests {
				r := logical.TestRequest(t, req.op, "external-keys/"+req.path)
				r.Storage = storage
				r.Data = req.input

				resp, err := sys.HandleRequest(ctx, r)

				if req.err {
					require.Error(t, err)
					continue
				}

				require.NoError(t, err, resp)

				if req.output == nil {
					require.Nil(t, resp)
				} else {
					require.Equal(t, req.output, resp.Data)
				}

				// Automatically verify that a ReadOperation following a
				// successful UpdateOperation results in the same data.
				if req.noverify || req.op != logical.UpdateOperation {
					continue
				}

				r = logical.TestRequest(t, logical.ReadOperation, "external-keys/"+req.path)
				r.Storage = storage

				resp, err = sys.HandleRequest(ctx, r)
				require.NoError(t, err)

				require.Equal(t, req.input, resp.Data)
			}
		})
	}
}
