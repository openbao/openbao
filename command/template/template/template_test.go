// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package template

import (
	"bytes"
	"fmt"
	"os"
	"os/user"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	dep "github.com/hashicorp/consul-template/dependency"
	"github.com/hashicorp/consul/api"
	"github.com/stretchr/testify/require"
)

func TestNewTemplate(t *testing.T) {
	f, err := os.CreateTemp("", "")
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("test")
	defer os.Remove(f.Name())

	cases := []struct {
		name string
		i    *NewTemplateInput
		e    *Template
		err  bool
	}{
		{
			"nil",
			nil,
			nil,
			true,
		},
		{
			"source_and_contents",
			&NewTemplateInput{
				Source:   "source",
				Contents: "contents",
			},
			nil,
			true,
		},
		{
			"no_source_and_no_contents",
			&NewTemplateInput{},
			nil,
			true,
		},
		{
			"non_existent",
			&NewTemplateInput{
				Source: "/path/to/nope/not/once/not/never",
			},
			nil,
			true,
		},
		{
			"sets_contents_from_source",
			&NewTemplateInput{
				Source: f.Name(),
			},
			&Template{
				contents: "test",
				source:   f.Name(),
				hexMD5:   "098f6bcd4621d373cade4e832627b4f6",
			},
			false,
		},
		{
			"contents",
			&NewTemplateInput{
				Contents: "test",
			},
			&Template{
				contents: "test",
				hexMD5:   "098f6bcd4621d373cade4e832627b4f6",
			},
			false,
		},
		{
			"custom_delims",
			&NewTemplateInput{
				Contents:   "test",
				LeftDelim:  "<<",
				RightDelim: ">>",
			},
			&Template{
				contents:   "test",
				hexMD5:     "098f6bcd4621d373cade4e832627b4f6",
				leftDelim:  "<<",
				rightDelim: ">>",
			},
			false,
		},
		{
			"err_missing_key",
			&NewTemplateInput{
				Contents:      "test",
				ErrMissingKey: true,
			},
			&Template{
				contents:      "test",
				hexMD5:        "098f6bcd4621d373cade4e832627b4f6",
				errMissingKey: true,
			},
			false,
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			a, err := NewTemplate(tc.i)
			if (err != nil) != tc.err {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(tc.e, a) {
				t.Errorf("\nexp: %#v\nact: %#v", tc.e, a)
			}
		})
	}
}

func TestTemplate_Execute(t *testing.T) {
	now = func() time.Time { return time.Unix(0, 0).UTC() }

	f, err := os.CreateTemp("", "")
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("test")
	defer os.Remove(f.Name())

	cases := []struct {
		name string
		ti   *NewTemplateInput
		i    *ExecuteInput
		e    string
		err  bool
	}{
		{
			"nil",
			&NewTemplateInput{
				Contents: `test`,
			},
			nil,
			"test",
			false,
		},
		{
			"bad_func",
			&NewTemplateInput{
				Contents: `{{ bad_func }}`,
			},
			nil,
			"",
			true,
		},
		{
			"missing_deps",
			&NewTemplateInput{
				Contents: `{{ key "foo" }}`,
			},
			&ExecuteInput{
				Brain: NewBrain(),
			},
			"",
			false,
		},

		// missing keys
		{
			"err_missing_keys__true",
			&NewTemplateInput{
				Contents:      `{{ .Data.Foo }}`,
				ErrMissingKey: true,
			},
			nil,
			"",
			true,
		},
		{
			"err_missing_keys__false",
			&NewTemplateInput{
				Contents:      `{{ .Data.Foo }}`,
				ErrMissingKey: false,
			},
			nil,
			"<no value>",
			false,
		},

		// funcs
		{
			"func_base64Decode",
			&NewTemplateInput{
				Contents: `{{ base64Decode "aGVsbG8=" }}`,
			},
			nil,
			"hello",
			false,
		},
		{
			"func_base64Decode_bad",
			&NewTemplateInput{
				Contents: `{{ base64Decode "aGVsxxbG8=" }}`,
			},
			nil,
			"",
			true,
		},
		{
			"func_base64Encode",
			&NewTemplateInput{
				Contents: `{{ base64Encode "hello" }}`,
			},
			nil,
			"aGVsbG8=",
			false,
		},
		{
			"func_base64URLDecode",
			&NewTemplateInput{
				Contents: `{{ base64URLDecode "dGVzdGluZzEyMw==" }}`,
			},
			nil,
			"testing123",
			false,
		},
		{
			"func_base64URLDecode_bad",
			&NewTemplateInput{
				Contents: `{{ base64URLDecode "aGVsxxbG8=" }}`,
			},
			nil,
			"",
			true,
		},
		{
			"func_base64URLEncode",
			&NewTemplateInput{
				Contents: `{{ base64URLEncode "testing123" }}`,
			},
			nil,
			"dGVzdGluZzEyMw==",
			false,
		},
		{
			"func_hmacSHA256Hex",
			&NewTemplateInput{
				Contents: `{{ hmacSHA256Hex "somemessage" "somekey" }}`,
			},
			nil,
			"6116e95f2827172aa6ef8b22b883f6a77e966aefc129c6b8228ebd0aac74e98d",
			false,
		},
		{
			"func_datacenters",
			&NewTemplateInput{
				Contents: `{{ datacenters }}`,
			},
			&ExecuteInput{
				Brain: func() *Brain {
					b := NewBrain()
					d, err := dep.NewCatalogDatacentersQuery(false)
					if err != nil {
						t.Fatal(err)
					}
					b.Remember(d, []string{"dc1", "dc2"})
					return b
				}(),
			},
			"[dc1 dc2]",
			false,
		},
		{
			"func_datacenters_ignore",
			&NewTemplateInput{
				Contents: `{{ datacenters true }}`,
			},
			&ExecuteInput{
				Brain: func() *Brain {
					b := NewBrain()
					d, err := dep.NewCatalogDatacentersQuery(true)
					if err != nil {
						t.Fatal(err)
					}
					b.Remember(d, []string{"dc1", "dc2"})
					return b
				}(),
			},
			"[dc1 dc2]",
			false,
		},
		{
			"func_envOrDefault",
			&NewTemplateInput{
				Contents: `{{ envOrDefault "SET_VAR" "100" }} {{ envOrDefault "EMPTY_VAR" "200" }} {{ envOrDefault "UNSET_VAR" "300" }}`,
			},
			&ExecuteInput{
				Env: func() []string {
					return []string{"SET_VAR=400", "EMPTY_VAR="}
				}(),
				Brain: func() *Brain {
					b := NewBrain()
					return b
				}(),
			},
			"400  300",
			false,
		},
		{
			"func_file",
			&NewTemplateInput{
				Contents: `{{ file "/path/to/file" }}`,
			},
			&ExecuteInput{
				Brain: func() *Brain {
					b := NewBrain()
					d, err := dep.NewFileQuery("/path/to/file")
					if err != nil {
						t.Fatal(err)
					}
					b.Remember(d, "content")
					return b
				}(),
			},
			"content",
			false,
		},
		{
			"func_key",
			&NewTemplateInput{
				Contents: `{{ key "key" }}`,
			},
			&ExecuteInput{
				Brain: func() *Brain {
					b := NewBrain()
					d, err := dep.NewKVGetQuery("key")
					if err != nil {
						t.Fatal(err)
					}
					d.EnableBlocking()
					b.Remember(d, "5")
					return b
				}(),
			},
			"5",
			false,
		},
		{
			"func_keyExists",
			&NewTemplateInput{
				Contents: `{{ keyExists "key" }} {{ keyExists "no_key" }}`,
			},
			&ExecuteInput{
				Brain: func() *Brain {
					b := NewBrain()
					d, err := dep.NewKVGetQuery("key")
					if err != nil {
						t.Fatal(err)
					}
					b.Remember(d, true)
					return b
				}(),
			},
			"true false",
			false,
		},
		{
			"func_keyOrDefault",
			&NewTemplateInput{
				Contents: `{{ keyOrDefault "key" "100" }} {{ keyOrDefault "no_key" "200" }}`,
			},
			&ExecuteInput{
				Brain: func() *Brain {
					b := NewBrain()
					d, err := dep.NewKVGetQuery("key")
					if err != nil {
						t.Fatal(err)
					}
					b.Remember(d, "150")
					return b
				}(),
			},
			"150 200",
			false,
		},
		{
			"func_ls",
			&NewTemplateInput{
				Contents: `{{ range ls "list" }}{{ .Key }}={{ .Value }}{{ end }}`,
			},
			&ExecuteInput{
				Brain: func() *Brain {
					b := NewBrain()
					d, err := dep.NewKVListQuery("list")
					if err != nil {
						t.Fatal(err)
					}
					b.Remember(d, []*dep.KeyPair{
						{Key: "", Value: ""},
						{Key: "foo", Value: "bar"},
						{Key: "foo/zip", Value: "zap"},
					})
					return b
				}(),
			},
			"foo=bar",
			false,
		},
		{
			"func_node",
			&NewTemplateInput{
				Contents: `{{ with node }}{{ .Node.Node }}{{ range .Services }}{{ .Service }}{{ end }}{{ end }}`,
			},
			&ExecuteInput{
				Brain: func() *Brain {
					b := NewBrain()
					d, err := dep.NewCatalogNodeQuery("")
					if err != nil {
						t.Fatal(err)
					}
					b.Remember(d, &dep.CatalogNode{
						Node: &dep.Node{Node: "node1"},
						Services: []*dep.CatalogNodeService{
							{
								Service: "service1",
							},
						},
					})
					return b
				}(),
			},
			"node1service1",
			false,
		},
		{
			"func_node_nil_pointer_evaluation",
			&NewTemplateInput{
				Contents: `{{ $v := node }}{{ $v.Node }}`,
			},
			&ExecuteInput{
				Brain: NewBrain(),
			},
			"<no value>",
			false,
		},
		{
			"func_nodes",
			&NewTemplateInput{
				Contents: `{{ range nodes }}{{ .Node }}{{ end }}`,
			},
			&ExecuteInput{
				Brain: func() *Brain {
					b := NewBrain()
					d, err := dep.NewCatalogNodesQuery("")
					if err != nil {
						t.Fatal(err)
					}
					b.Remember(d, []*dep.Node{
						{Node: "node1"},
						{Node: "node2"},
					})
					return b
				}(),
			},
			"node1node2",
			false,
		},
		{
			"func_secret_read",
			&NewTemplateInput{
				Contents: `{{ with secret "secret/foo" }}{{ .Data.zip }}{{ end }}`,
			},
			&ExecuteInput{
				Brain: func() *Brain {
					b := NewBrain()
					d, err := dep.NewVaultReadQuery("secret/foo")
					if err != nil {
						t.Fatal(err)
					}
					b.Remember(d, &dep.Secret{
						LeaseID:       "abcd1234",
						LeaseDuration: 120,
						Renewable:     true,
						Data:          map[string]interface{}{"zip": "zap"},
					})
					return b
				}(),
			},
			"zap",
			false,
		},
		{
			"func_secret_nil_pointer_evaluation",
			&NewTemplateInput{
				Contents: `{{ $v := secret "secret/foo" }}{{ $v.Data.zip }}`,
			},
			&ExecuteInput{
				Brain: NewBrain(),
			},
			"<no value>",
			false,
		},
		{
			"func_secret_read_versions",
			&NewTemplateInput{
				Contents: `{{with secret "secret/foo"}}{{.Data.zip}}{{end}}:{{with secret "secret/foo?version=1"}}{{.Data.zip}}{{end}}`,
			},
			&ExecuteInput{
				Brain: func() *Brain {
					b := NewBrain()
					d, err := dep.NewVaultReadQuery("secret/foo")
					if err != nil {
						t.Fatal(err)
					}
					b.Remember(d, &dep.Secret{
						Data: map[string]interface{}{"zip": "zap"},
					})
					d1, err := dep.NewVaultReadQuery("secret/foo?version=1")
					if err != nil {
						t.Fatal(err)
					}
					b.Remember(d1, &dep.Secret{
						Data: map[string]interface{}{"zip": "zed"},
					})
					return b
				}(),
			},
			"zap:zed",
			false,
		},
		{
			"func_secret_read_no_exist",
			&NewTemplateInput{
				Contents: `{{ with secret "secret/nope" }}{{ .Data.zip }}{{ end }}`,
			},
			&ExecuteInput{
				Brain: func() *Brain {
					return NewBrain()
				}(),
			},
			"",
			false,
		},
		{
			"func_secret_read_no_exist_falsey",
			&NewTemplateInput{
				Contents: `{{ if secret "secret/nope" }}yes{{ else }}no{{ end }}`,
			},
			&ExecuteInput{
				Brain: func() *Brain {
					return NewBrain()
				}(),
			},
			"no",
			false,
		},
		{
			"func_secret_write",
			&NewTemplateInput{
				Contents: `{{ with secret "transit/encrypt/foo" "plaintext=a" }}{{ .Data.ciphertext }}{{ end }}`,
			},
			&ExecuteInput{
				Brain: func() *Brain {
					b := NewBrain()
					d, err := dep.NewVaultWriteQuery("transit/encrypt/foo", map[string]interface{}{
						"plaintext": "a",
					})
					if err != nil {
						t.Fatal(err)
					}
					b.Remember(d, &dep.Secret{
						LeaseID:       "abcd1234",
						LeaseDuration: 120,
						Renewable:     true,
						Data:          map[string]interface{}{"ciphertext": "encrypted"},
					})
					return b
				}(),
			},
			"encrypted",
			false,
		},
		{
			"func_secret_write_empty",
			&NewTemplateInput{
				Contents: `{{ with secret "transit/encrypt/foo" "" }}{{ .Data.ciphertext }}{{ end }}`,
			},
			&ExecuteInput{
				Brain: func() *Brain {
					b := NewBrain()
					d, err := dep.NewVaultWriteQuery("transit/encrypt/foo", nil)
					if err != nil {
						t.Fatal(err)
					}
					b.Remember(d, &dep.Secret{
						Data: map[string]interface{}{"ciphertext": "encrypted"},
					})
					return b
				}(),
			},
			"encrypted",
			false,
		},
		{
			"func_secret_write_no_exist",
			&NewTemplateInput{
				Contents: `{{ with secret "secret/nope" "a=b" }}{{ .Data.zip }}{{ end }}`,
			},
			&ExecuteInput{
				Brain: func() *Brain {
					return NewBrain()
				}(),
			},
			"",
			false,
		},
		{
			"func_secret_write_no_exist_falsey",
			&NewTemplateInput{
				Contents: `{{ if secret "secret/nope" "a=b" }}yes{{ else }}no{{ end }}`,
			},
			&ExecuteInput{
				Brain: func() *Brain {
					return NewBrain()
				}(),
			},
			"no",
			false,
		},
		{
			"func_secret_no_exist_falsey_with",
			&NewTemplateInput{
				Contents: `{{ with secret "secret/nope" }}{{ .Data.foo.bar }}{{ end }}`,
			},
			&ExecuteInput{
				Brain: func() *Brain {
					return NewBrain()
				}(),
			},
			"",
			false,
		},
		{
			"func_secrets",
			&NewTemplateInput{
				Contents: `{{ secrets "secret/" }}`,
			},
			&ExecuteInput{
				Brain: func() *Brain {
					b := NewBrain()
					d, err := dep.NewVaultListQuery("secret/")
					if err != nil {
						t.Fatal(err)
					}
					b.Remember(d, []string{"bar", "foo"})
					return b
				}(),
			},
			"[bar foo]",
			false,
		},
		{
			"func_secrets_no_exist",
			&NewTemplateInput{
				Contents: `{{ secrets "secret/" }}`,
			},
			&ExecuteInput{
				Brain: func() *Brain {
					return NewBrain()
				}(),
			},
			"[]",
			false,
		},
		{
			"func_secrets_no_exist_falsey",
			&NewTemplateInput{
				Contents: `{{ if secrets "secret/" }}yes{{ else }}no{{ end }}`,
			},
			&ExecuteInput{
				Brain: func() *Brain {
					return NewBrain()
				}(),
			},
			"no",
			false,
		},
		{
			"func_secrets_no_exist_falsey_with",
			&NewTemplateInput{
				Contents: `{{ with secrets "secret/" }}{{ . }}{{ end }}`,
			},
			&ExecuteInput{
				Brain: func() *Brain {
					return NewBrain()
				}(),
			},
			"",
			false,
		},
		{
			"func_service",
			&NewTemplateInput{
				Contents: `{{ range service "webapp" }}{{ .Address }}{{ end }}`,
			},
			&ExecuteInput{
				Brain: func() *Brain {
					b := NewBrain()
					d, err := dep.NewHealthServiceQuery("webapp")
					if err != nil {
						t.Fatal(err)
					}
					b.Remember(d, []*dep.HealthService{
						{
							Node:    "node1",
							Address: "1.2.3.4",
						},
						{
							Node:    "node2",
							Address: "5.6.7.8",
						},
					})
					return b
				}(),
			},
			"1.2.3.45.6.7.8",
			false,
		},
		{
			"func_service_filter",
			&NewTemplateInput{
				Contents: `{{ range service "webapp" "passing,any" }}{{ .Address }}{{ end }}`,
			},
			&ExecuteInput{
				Brain: func() *Brain {
					b := NewBrain()
					d, err := dep.NewHealthServiceQuery("webapp|passing,any")
					if err != nil {
						t.Fatal(err)
					}
					b.Remember(d, []*dep.HealthService{
						{
							Node:    "node1",
							Address: "1.2.3.4",
						},
						{
							Node:    "node2",
							Address: "5.6.7.8",
						},
					})
					return b
				}(),
			},
			"1.2.3.45.6.7.8",
			false,
		},
		{
			"func_services",
			&NewTemplateInput{
				Contents: `{{ range services }}{{ .Name }}{{ end }}`,
			},
			&ExecuteInput{
				Brain: func() *Brain {
					b := NewBrain()
					d, err := dep.NewCatalogServicesQuery("")
					if err != nil {
						t.Fatal(err)
					}
					b.Remember(d, []*dep.CatalogSnippet{
						{
							Name: "service1",
						},
						{
							Name: "service2",
						},
					})
					return b
				}(),
			},
			"service1service2",
			false,
		},
		{
			"func_tree",
			&NewTemplateInput{
				Contents: `{{ range tree "key" }}{{ .Key }}={{ .Value }}{{ end }}`,
			},
			&ExecuteInput{
				Brain: func() *Brain {
					b := NewBrain()
					d, err := dep.NewKVListQuery("key")
					if err != nil {
						t.Fatal(err)
					}
					b.Remember(d, []*dep.KeyPair{
						{Key: "", Value: ""},
						{Key: "admin/port", Value: "1134"},
						{Key: "maxconns", Value: "5"},
						{Key: "minconns", Value: "2"},
					})
					return b
				}(),
			},
			"admin/port=1134maxconns=5minconns=2",
			false,
		},

		// scratch
		{
			"scratch.Key",
			&NewTemplateInput{
				Contents: `{{ scratch.Set "a" "2" }}{{ scratch.Key "a" }}`,
			},
			&ExecuteInput{
				Brain: NewBrain(),
			},
			"true",
			false,
		},
		{
			"scratch.Get",
			&NewTemplateInput{
				Contents: `{{ scratch.Set "a" "2" }}{{ scratch.Get "a" }}`,
			},
			&ExecuteInput{
				Brain: NewBrain(),
			},
			"2",
			false,
		},
		{
			"scratch.SetX",
			&NewTemplateInput{
				Contents: `{{ scratch.SetX "a" "2" }}{{ scratch.SetX "a" "1" }}{{ scratch.Get "a" }}`,
			},
			&ExecuteInput{
				Brain: NewBrain(),
			},
			"2",
			false,
		},
		{
			"scratch.MapSet",
			&NewTemplateInput{
				Contents: `{{ scratch.MapSet "a" "foo" "bar" }}{{ scratch.MapValues "a" }}`,
			},
			&ExecuteInput{
				Brain: NewBrain(),
			},
			"[bar]",
			false,
		},
		{
			"scratch.MapSetX",
			&NewTemplateInput{
				Contents: `{{ scratch.MapSetX "a" "foo" "bar" }}{{ scratch.MapSetX "a" "foo" "baz" }}{{ scratch.MapValues "a" }}`,
			},
			&ExecuteInput{
				Brain: NewBrain(),
			},
			"[bar]",
			false,
		},

		// helpers
		{
			"helper_by_key",
			&NewTemplateInput{
				Contents: `{{ range $key, $pairs := tree "list" | byKey }}{{ $key }}:{{ range $pairs }}{{ .Key }}={{ .Value }}{{ end }}{{ end }}`,
			},
			&ExecuteInput{
				Brain: func() *Brain {
					b := NewBrain()
					d, err := dep.NewKVListQuery("list")
					if err != nil {
						t.Fatal(err)
					}
					b.Remember(d, []*dep.KeyPair{
						{Key: "", Value: ""},
						{Key: "foo/bar", Value: "a"},
						{Key: "zip/zap", Value: "b"},
					})
					return b
				}(),
			},
			"foo:bar=azip:zap=b",
			false,
		},
		{
			"helper_by_tag",
			&NewTemplateInput{
				Contents: `{{ range $tag, $services := service "webapp" | byTag }}{{ $tag }}:{{ range $services }}{{ .Address }}{{ end }}{{ end }}`,
			},
			&ExecuteInput{
				Brain: func() *Brain {
					b := NewBrain()
					d, err := dep.NewHealthServiceQuery("webapp")
					if err != nil {
						t.Fatal(err)
					}
					b.Remember(d, []*dep.HealthService{
						{
							Address: "1.2.3.4",
							Tags:    []string{"prod", "staging"},
						},
						{
							Address: "5.6.7.8",
							Tags:    []string{"staging"},
						},
					})
					return b
				}(),
			},
			"prod:1.2.3.4staging:1.2.3.45.6.7.8",
			false,
		},
		{
			"helper_contains",
			&NewTemplateInput{
				Contents: `{{ range service "webapp" }}{{ if .Tags | contains "prod" }}{{ .Address }}{{ end }}{{ end }}`,
			},
			&ExecuteInput{
				Brain: func() *Brain {
					b := NewBrain()
					d, err := dep.NewHealthServiceQuery("webapp")
					if err != nil {
						t.Fatal(err)
					}
					b.Remember(d, []*dep.HealthService{
						{
							Address: "1.2.3.4",
							Tags:    []string{"prod", "staging"},
						},
						{
							Address: "5.6.7.8",
							Tags:    []string{"staging"},
						},
					})
					return b
				}(),
			},
			"1.2.3.4",
			false,
		},
		{
			"helper_containsAll",
			&NewTemplateInput{
				Contents: `{{ $requiredTags := parseJSON "[\"prod\",\"us-realm\"]" }}{{ range service "webapp" }}{{ if .Tags | containsAll $requiredTags }}{{ .Address }}{{ end }}{{ end }}`,
			},
			&ExecuteInput{
				Brain: func() *Brain {
					b := NewBrain()
					d, err := dep.NewHealthServiceQuery("webapp")
					if err != nil {
						t.Fatal(err)
					}
					b.Remember(d, []*dep.HealthService{
						{
							Address: "1.2.3.4",
							Tags:    []string{"prod", "us-realm"},
						},
						{
							Address: "5.6.7.8",
							Tags:    []string{"prod", "ca-realm"},
						},
					})
					return b
				}(),
			},
			"1.2.3.4",
			false,
		},
		{
			"helper_containsAll__empty",
			&NewTemplateInput{
				Contents: `{{ $requiredTags := parseJSON "[]" }}{{ range service "webapp" }}{{ if .Tags | containsAll $requiredTags }}{{ .Address }}{{ end }}{{ end }}`,
			},
			&ExecuteInput{
				Brain: func() *Brain {
					b := NewBrain()
					d, err := dep.NewHealthServiceQuery("webapp")
					if err != nil {
						t.Fatal(err)
					}
					b.Remember(d, []*dep.HealthService{
						{
							Address: "1.2.3.4",
							Tags:    []string{"prod", "us-realm"},
						},
						{
							Address: "5.6.7.8",
							Tags:    []string{"prod", "ca-realm"},
						},
					})
					return b
				}(),
			},
			"1.2.3.45.6.7.8",
			false,
		},
		{
			"helper_containsAny",
			&NewTemplateInput{
				Contents: `{{ $acceptableTags := parseJSON "[\"v2\",\"v3\"]" }}{{ range service "webapp" }}{{ if .Tags | containsAny $acceptableTags }}{{ .Address }}{{ end }}{{ end }}`,
			},
			&ExecuteInput{
				Brain: func() *Brain {
					b := NewBrain()
					d, err := dep.NewHealthServiceQuery("webapp")
					if err != nil {
						t.Fatal(err)
					}
					b.Remember(d, []*dep.HealthService{
						{
							Address: "1.2.3.4",
							Tags:    []string{"prod", "v1"},
						},
						{
							Address: "5.6.7.8",
							Tags:    []string{"prod", "v2"},
						},
					})
					return b
				}(),
			},
			"5.6.7.8",
			false,
		},
		{
			"helper_containsAny__empty",
			&NewTemplateInput{
				Contents: `{{ $acceptableTags := parseJSON "[]" }}{{ range service "webapp" }}{{ if .Tags | containsAny $acceptableTags }}{{ .Address }}{{ end }}{{ end }}`,
			},
			&ExecuteInput{
				Brain: func() *Brain {
					b := NewBrain()
					d, err := dep.NewHealthServiceQuery("webapp")
					if err != nil {
						t.Fatal(err)
					}
					b.Remember(d, []*dep.HealthService{
						{
							Address: "1.2.3.4",
							Tags:    []string{"prod", "v1"},
						},
						{
							Address: "5.6.7.8",
							Tags:    []string{"prod", "v2"},
						},
					})
					return b
				}(),
			},
			"",
			false,
		},
		{
			"helper_containsNone",
			&NewTemplateInput{
				Contents: `{{ $forbiddenTags := parseJSON "[\"devel\",\"staging\"]" }}{{ range service "webapp" }}{{ if .Tags | containsNone $forbiddenTags }}{{ .Address }}{{ end }}{{ end }}`,
			},
			&ExecuteInput{
				Brain: func() *Brain {
					b := NewBrain()
					d, err := dep.NewHealthServiceQuery("webapp")
					if err != nil {
						t.Fatal(err)
					}
					b.Remember(d, []*dep.HealthService{
						{
							Address: "1.2.3.4",
							Tags:    []string{"prod", "v1"},
						},
						{
							Address: "5.6.7.8",
							Tags:    []string{"devel", "v2"},
						},
					})
					return b
				}(),
			},
			"1.2.3.4",
			false,
		},
		{
			"helper_containsNone__empty",
			&NewTemplateInput{
				Contents: `{{ $forbiddenTags := parseJSON "[]" }}{{ range service "webapp" }}{{ if .Tags | containsNone $forbiddenTags }}{{ .Address }}{{ end }}{{ end }}`,
			},
			&ExecuteInput{
				Brain: func() *Brain {
					b := NewBrain()
					d, err := dep.NewHealthServiceQuery("webapp")
					if err != nil {
						t.Fatal(err)
					}
					b.Remember(d, []*dep.HealthService{
						{
							Address: "1.2.3.4",
							Tags:    []string{"staging", "v1"},
						},
						{
							Address: "5.6.7.8",
							Tags:    []string{"devel", "v2"},
						},
					})
					return b
				}(),
			},
			"1.2.3.45.6.7.8",
			false,
		},
		{
			"helper_containsNotAll",
			&NewTemplateInput{
				Contents: `{{ $excludingTags := parseJSON "[\"es-v1\",\"es-v2\"]" }}{{ range service "webapp" }}{{ if .Tags | containsNotAll $excludingTags }}{{ .Address }}{{ end }}{{ end }}`,
			},
			&ExecuteInput{
				Brain: func() *Brain {
					b := NewBrain()
					d, err := dep.NewHealthServiceQuery("webapp")
					if err != nil {
						t.Fatal(err)
					}
					b.Remember(d, []*dep.HealthService{
						{
							Address: "1.2.3.4",
							Tags:    []string{"prod", "es-v1"},
						},
						{
							Address: "5.6.7.8",
							Tags:    []string{"prod", "hybrid", "es-v1", "es-v2"},
						},
					})
					return b
				}(),
			},
			"1.2.3.4",
			false,
		},
		{
			"helper_containsNotAll__empty",
			&NewTemplateInput{
				Contents: `{{ $excludingTags := parseJSON "[]" }}{{ range service "webapp" }}{{ if .Tags | containsNotAll $excludingTags }}{{ .Address }}{{ end }}{{ end }}`,
			},
			&ExecuteInput{
				Brain: func() *Brain {
					b := NewBrain()
					d, err := dep.NewHealthServiceQuery("webapp")
					if err != nil {
						t.Fatal(err)
					}
					b.Remember(d, []*dep.HealthService{
						{
							Address: "1.2.3.4",
							Tags:    []string{"prod", "es-v1"},
						},
						{
							Address: "5.6.7.8",
							Tags:    []string{"prod", "hybrid", "es-v1", "es-v2"},
						},
					})
					return b
				}(),
			},
			"",
			false,
		},
		{
			"helper_env",
			&NewTemplateInput{
				Contents: `{{ env "CT_TEST" }}`,
			},
			&ExecuteInput{
				Brain: func() *Brain {
					// Cheat and use the brain callback here to set the env.
					if err := os.Setenv("CT_TEST", "1"); err != nil {
						t.Fatal(err)
					}
					return NewBrain()
				}(),
			},
			"1",
			false,
		},
		{
			"helper_mustEnv",
			&NewTemplateInput{
				Contents: `{{ mustEnv "CT_TEST" }}`,
			},
			&ExecuteInput{
				Brain: func() *Brain {
					// Cheat and use the brain callback here to set the env.
					if err := os.Setenv("CT_TEST", "1"); err != nil {
						t.Fatal(err)
					}
					return NewBrain()
				}(),
			},
			"1",
			false,
		},
		{
			"helper_mustEnv_negative",
			&NewTemplateInput{
				Contents: `{{ mustEnv "CT_TEST_NONEXISTENT" }}`,
			},
			&ExecuteInput{
				Brain: NewBrain(),
			},
			"",
			true,
		},
		{
			"helper_env__override",
			&NewTemplateInput{
				Contents: `{{ env "CT_TEST" }}`,
			},
			&ExecuteInput{
				Env: []string{
					"CT_TEST=2",
				},
				Brain: NewBrain(),
			},
			"2",
			false,
		},
		{
			"helper_executeTemplate",
			&NewTemplateInput{
				Contents: `{{ define "custom" }}{{ key "foo" }}{{ end }}{{ executeTemplate "custom" }}`,
			},
			&ExecuteInput{
				Brain: func() *Brain {
					b := NewBrain()
					d, err := dep.NewKVGetQuery("foo")
					if err != nil {
						t.Fatal(err)
					}
					d.EnableBlocking()
					b.Remember(d, "bar")
					return b
				}(),
			},
			"bar",
			false,
		},
		{
			"helper_executeTemplate__dot",
			&NewTemplateInput{
				Contents: `{{ define "custom" }}{{ key . }}{{ end }}{{ executeTemplate "custom" "foo" }}`,
			},
			&ExecuteInput{
				Brain: func() *Brain {
					b := NewBrain()
					d, err := dep.NewKVGetQuery("foo")
					if err != nil {
						t.Fatal(err)
					}
					d.EnableBlocking()
					b.Remember(d, "bar")
					return b
				}(),
			},
			"bar",
			false,
		},
		{
			"helper_mergeMap",
			&NewTemplateInput{
				Contents: `{{ $base := "{\"voo\":{\"bar\":\"v\"}}" | parseJSON}}{{ $role := tree "list" | explode | mergeMap $base}}{{ range $k, $v := $role }}{{ $k }}{{ $v }}{{ end }}`,
			},
			&ExecuteInput{
				Brain: func() *Brain {
					b := NewBrain()
					d, err := dep.NewKVListQuery("list")
					if err != nil {
						t.Fatal(err)
					}
					b.Remember(d, []*dep.KeyPair{
						{Key: "", Value: ""},
						{Key: "foo/bar", Value: "a"},
						{Key: "zip/zap", Value: "b"},
					})
					return b
				}(),
			},
			"foomap[bar:a]voomap[bar:v]zipmap[zap:b]",
			false,
		},
		{
			"helper_mergeMapWithOverride",
			&NewTemplateInput{
				Contents: `{{ $base := "{\"zip\":{\"zap\":\"t\"},\"voo\":{\"bar\":\"v\"}}" | parseJSON}}{{ $role := tree "list" | explode | mergeMapWithOverride $base}}{{ range $k, $v := $role }}{{ $k }}{{ $v }}{{ end }}`,
			},
			&ExecuteInput{
				Brain: func() *Brain {
					b := NewBrain()
					d, err := dep.NewKVListQuery("list")
					if err != nil {
						t.Fatal(err)
					}
					b.Remember(d, []*dep.KeyPair{
						{Key: "", Value: ""},
						{Key: "foo/bar", Value: "a"},
						{Key: "zip/zap", Value: "b"},
					})
					return b
				}(),
			},
			"foomap[bar:a]voomap[bar:v]zipmap[zap:b]",
			false,
		},
		{
			"helper_explode",
			&NewTemplateInput{
				Contents: `{{ range $k, $v := tree "list" | explode }}{{ $k }}{{ $v }}{{ end }}`,
			},
			&ExecuteInput{
				Brain: func() *Brain {
					b := NewBrain()
					d, err := dep.NewKVListQuery("list")
					if err != nil {
						t.Fatal(err)
					}
					b.Remember(d, []*dep.KeyPair{
						{Key: "", Value: ""},
						{Key: "foo/bar", Value: "a"},
						{Key: "zip/zap", Value: "b"},
					})
					return b
				}(),
			},
			"foomap[bar:a]zipmap[zap:b]",
			false,
		},
		{
			"helper_explodemap",
			&NewTemplateInput{
				Contents: `{{ scratch.MapSet "explode-test" "foo/bar" "a"}}{{ scratch.MapSet "explode-test" "qux" "c"}}{{ scratch.MapSet "explode-test" "zip/zap" "d"}}{{ scratch.Get "explode-test" | explodeMap }}`,
			},
			&ExecuteInput{
				Brain: NewBrain(),
			},
			"map[foo:map[bar:a] qux:c zip:map[zap:d]]",
			false,
		},
		{
			"helper_in",
			&NewTemplateInput{
				Contents: `{{ range service "webapp" }}{{ if "prod" | in .Tags }}{{ .Address }}{{ end }}{{ end }}`,
			},
			&ExecuteInput{
				Brain: func() *Brain {
					b := NewBrain()
					d, err := dep.NewHealthServiceQuery("webapp")
					if err != nil {
						t.Fatal(err)
					}
					b.Remember(d, []*dep.HealthService{
						{
							Address: "1.2.3.4",
							Tags:    []string{"prod", "staging"},
						},
						{
							Address: "5.6.7.8",
							Tags:    []string{"staging"},
						},
					})
					return b
				}(),
			},
			"1.2.3.4",
			false,
		},
		{
			"helper_indent",
			&NewTemplateInput{
				Contents: `{{ "hello\nhello\r\nHELLO\r\nhello\nHELLO" | indent 4 }}`,
			},
			&ExecuteInput{
				Brain: NewBrain(),
			},
			"    hello\n    hello\r\n    HELLO\r\n    hello\n    HELLO",
			false,
		},
		{
			"helper_indent_negative",
			&NewTemplateInput{
				Contents: `{{ "hello\nhello\r\nHELLO\r\nhello\nHELLO" | indent -4 }}`,
			},
			&ExecuteInput{
				Brain: NewBrain(),
			},
			"    hello\n    hello\r\n    HELLO\r\n    hello\n    HELLO",
			true,
		},
		{
			"helper_indent_zero",
			&NewTemplateInput{
				Contents: `{{ "hello\nhello\r\nHELLO\r\nhello\nHELLO" | indent 0 }}`,
			},
			&ExecuteInput{
				Brain: NewBrain(),
			},
			"hello\nhello\r\nHELLO\r\nhello\nHELLO",
			false,
		},
		{
			"helper_loop",
			&NewTemplateInput{
				Contents: `{{ range loop 3 }}1{{ end }}`,
			},
			&ExecuteInput{
				Brain: NewBrain(),
			},
			"111",
			false,
		},
		{
			"helper_loop__i",
			&NewTemplateInput{
				Contents: `{{ range $i := loop 3 }}{{ $i }}{{ end }}`,
			},
			&ExecuteInput{
				Brain: NewBrain(),
			},
			"012",
			false,
		},
		{
			"helper_loop_start",
			&NewTemplateInput{
				Contents: `{{ range loop 1 3 }}1{{ end }}`,
			},
			&ExecuteInput{
				Brain: NewBrain(),
			},
			"11",
			false,
		},
		{
			"helper_loop_text",
			&NewTemplateInput{
				Contents: `{{ range loop 1 "3" }}1{{ end }}`,
			},
			&ExecuteInput{
				Brain: NewBrain(),
			},
			"11",
			false,
		},
		{
			"helper_loop_parseInt",
			&NewTemplateInput{
				Contents: `{{ $i := print "3" | parseInt }}{{ range loop 1 $i }}1{{ end }}`,
			},
			&ExecuteInput{
				Brain: NewBrain(),
			},
			"11",
			false,
		},
		{
			// GH-1143
			"helper_loop_var",
			&NewTemplateInput{
				Contents: `{{$n := 3 }}` +
					`{{ range $i := loop $n }}{{ $i }}{{ end }}`,
			},
			&ExecuteInput{
				Brain: NewBrain(),
			},
			"012",
			false,
		},
		{
			"helper_join",
			&NewTemplateInput{
				Contents: `{{ "a,b,c" | split "," | join ";" }}`,
			},
			&ExecuteInput{
				Brain: NewBrain(),
			},
			"a;b;c",
			false,
		},
		{
			"helper_trim",
			&NewTemplateInput{
				Contents: `{{ "!!hello world!!" | trim "!!" }}`,
			},
			&ExecuteInput{
				Brain: NewBrain(),
			},
			"hello world",
			false,
		},
		{
			"helper_trimPrefix",
			&NewTemplateInput{
				Contents: `{{ "hello world!!" | trimPrefix "hello " }}`,
			},
			&ExecuteInput{
				Brain: NewBrain(),
			},
			"world!!",
			false,
		},
		{
			"helper_trimSuffix",
			&NewTemplateInput{
				Contents: `{{ "hello world!!" | trimSuffix " world!!" }}`,
			},
			&ExecuteInput{
				Brain: NewBrain(),
			},
			"hello",
			false,
		},
		{
			"helper_parseBool",
			&NewTemplateInput{
				Contents: `{{ "true" | parseBool }}`,
			},
			&ExecuteInput{
				Brain: NewBrain(),
			},
			"true",
			false,
		},
		{
			"helper_parseFloat",
			&NewTemplateInput{
				Contents: `{{ "1.2" | parseFloat }}`,
			},
			&ExecuteInput{
				Brain: NewBrain(),
			},
			"1.2",
			false,
		},
		{
			"helper_parseFloat_format",
			&NewTemplateInput{
				Contents: `{{ "1.0" | parseFloat | printf "%.1f"}}`,
			},
			&ExecuteInput{
				Brain: NewBrain(),
			},
			"1.0",
			false,
		},
		{
			"helper_parseInt",
			&NewTemplateInput{
				Contents: `{{ "-1" | parseInt }}`,
			},
			&ExecuteInput{
				Brain: NewBrain(),
			},
			"-1",
			false,
		},
		{
			"helper_parseJSON",
			&NewTemplateInput{
				Contents: `{{ "{\"foo\": \"bar\"}" | parseJSON }}`,
			},
			&ExecuteInput{
				Brain: NewBrain(),
			},
			"map[foo:bar]",
			false,
		},
		{
			"helper_parseUint",
			&NewTemplateInput{
				Contents: `{{ "1" | parseUint }}`,
			},
			&ExecuteInput{
				Brain: NewBrain(),
			},
			"1",
			false,
		},
		{
			"helper_parseYAML",
			&NewTemplateInput{
				Contents: `{{ "foo: bar" | parseYAML }}`,
			},
			&ExecuteInput{
				Brain: NewBrain(),
			},
			"map[foo:bar]",
			false,
		},
		{
			"helper_parseYAMLv2",
			&NewTemplateInput{
				Contents: `{{ "foo: bar\nbaz: \"foo\"" | parseYAML }}`,
			},
			&ExecuteInput{
				Brain: NewBrain(),
			},
			"map[baz:foo foo:bar]",
			false,
		},
		{
			"helper_parseYAMLnested",
			&NewTemplateInput{
				Contents: `{{ "foo:\n  bar: \"baz\"\n  baz: 7" | parseYAML }}`,
			},
			&ExecuteInput{
				Brain: NewBrain(),
			},
			"map[foo:map[bar:baz baz:7]]",
			false,
		},
		{
			"helper_plugin",
			&NewTemplateInput{
				Contents: `{{ "1" | plugin "echo" }}`,
			},
			&ExecuteInput{
				Brain: NewBrain(),
			},
			"1",
			false,
		},
		{
			"helper_plugin_disabled",
			&NewTemplateInput{
				Contents:         `{{ "1" | plugin "echo" }}`,
				FunctionDenylist: []string{"plugin"},
			},
			&ExecuteInput{
				Brain: NewBrain(),
			},
			"",
			true,
		},
		{
			"helper_regexMatch",
			&NewTemplateInput{
				Contents: `{{ "foo" | regexMatch "[a-z]+" }}`,
			},
			&ExecuteInput{
				Brain: NewBrain(),
			},
			"true",
			false,
		},
		{
			"helper_regexReplaceAll",
			&NewTemplateInput{
				Contents: `{{ "foo" | regexReplaceAll "\\w" "x" }}`,
			},
			&ExecuteInput{
				Brain: NewBrain(),
			},
			"xxx",
			false,
		},
		{
			"helper_replaceAll",
			&NewTemplateInput{
				Contents: `{{ "hello my hello" | regexReplaceAll "hello" "bye" }}`,
			},
			&ExecuteInput{
				Brain: NewBrain(),
			},
			"bye my bye",
			false,
		},
		{
			"helper_split",
			&NewTemplateInput{
				Contents: `{{ "a,b,c" | split "," }}`,
			},
			&ExecuteInput{
				Brain: NewBrain(),
			},
			"[a b c]",
			false,
		},
		{
			"helper_splitToMap",
			&NewTemplateInput{
				Contents: `{{ "a:x,b:y,c:z" | splitToMap "," ":" }}`,
			},
			&ExecuteInput{
				Brain: NewBrain(),
			},
			"map[a:x b:y c:z]",
			false,
		},
		{
			"helper_timestamp",
			&NewTemplateInput{
				Contents: `{{ timestamp }}`,
			},
			&ExecuteInput{
				Brain: NewBrain(),
			},
			"1970-01-01T00:00:00Z",
			false,
		},
		{
			"helper_helper_timestamp__formatted",
			&NewTemplateInput{
				Contents: `{{ timestamp "2006-01-02" }}`,
			},
			&ExecuteInput{
				Brain: NewBrain(),
			},
			"1970-01-01",
			false,
		},
		{
			"helper_toJSON",
			&NewTemplateInput{
				Contents: `{{ "a,b,c" | split "," | toJSON }}`,
			},
			&ExecuteInput{
				Brain: NewBrain(),
			},
			"[\"a\",\"b\",\"c\"]",
			false,
		},
		{
			"helper_toUnescapedJSON",
			&NewTemplateInput{
				Contents: `{{ "a?b&c,x?y&z" | split "," | toUnescapedJSON }}`,
			},
			&ExecuteInput{
				Brain: NewBrain(),
			},
			"[\"a?b&c\",\"x?y&z\"]",
			false,
		},
		{
			"helper_toUnescapedJSONPretty",
			&NewTemplateInput{
				Contents: `{{ tree "key" | explode | toUnescapedJSONPretty }}`,
			},
			&ExecuteInput{
				Brain: func() *Brain {
					b := NewBrain()
					d, err := dep.NewKVListQuery("key")
					if err != nil {
						t.Fatal(err)
					}
					b.Remember(d, []*dep.KeyPair{
						{Key: "a", Value: "b&c"},
						{Key: "x", Value: "y&z"},
						{Key: "k", Value: "<>&&"},
					})
					return b
				}(),
			},
			`{
  "a": "b&c",
  "k": "<>&&",
  "x": "y&z"
}`,
			false,
		},
		{
			"helper_toLower",
			&NewTemplateInput{
				Contents: `{{ "HI" | toLower }}`,
			},
			&ExecuteInput{
				Brain: NewBrain(),
			},
			"hi",
			false,
		},
		{
			"helper_toTitle",
			&NewTemplateInput{
				Contents: `{{ "this is a sentence" | toTitle }}`,
			},
			&ExecuteInput{
				Brain: NewBrain(),
			},
			"This Is A Sentence",
			false,
		},
		{
			"helper_toTitle_unicode",
			&NewTemplateInput{
				Contents: `{{ "this is a sentence\u2026and another sentence\u2026with a \xf0\x9f\x9a\x80rocket" | toTitle }}`,
			},
			&ExecuteInput{
				Brain: NewBrain(),
			},
			"This Is A Sentence\u2026And Another Sentence\u2026With A \xf0\x9f\x9a\x80Rocket",
			false,
		},
		{
			"helper_toTOML",
			&NewTemplateInput{
				Contents: `{{ "{\"foo\":\"bar\"}" | parseJSON | toTOML }}`,
			},
			&ExecuteInput{
				Brain: NewBrain(),
			},
			"foo = \"bar\"",
			false,
		},
		{
			"helper_toUpper",
			&NewTemplateInput{
				Contents: `{{ "hi" | toUpper }}`,
			},
			&ExecuteInput{
				Brain: NewBrain(),
			},
			"HI",
			false,
		},
		{
			"helper_toYAML",
			&NewTemplateInput{
				Contents: `{{ "{\"foo\":\"bar\"}" | parseJSON | toYAML }}`,
			},
			&ExecuteInput{
				Brain: NewBrain(),
			},
			"foo: bar",
			false,
		},
		{
			"helper_trimSpace",
			&NewTemplateInput{
				Contents: `{{ "\t hi\n " | trimSpace }}`,
			},
			&ExecuteInput{
				Brain: NewBrain(),
			},
			"hi",
			false,
		},
		{
			"helper_sockaddr",
			&NewTemplateInput{
				Contents: `{{ sockaddr "GetAllInterfaces | include \"flag\" \"loopback\" | include \"type\" \"IPv4\" | sort \"address\" | limit 1 | attr \"address\""}}`,
			},
			&ExecuteInput{
				Brain: NewBrain(),
			},
			"127.0.0.1",
			false,
		},
		{
			"math_add",
			&NewTemplateInput{
				Contents: `{{ 2 | add 2 }}`,
			},
			&ExecuteInput{
				Brain: NewBrain(),
			},
			"4",
			false,
		},
		{
			"math_subtract",
			&NewTemplateInput{
				Contents: `{{ 2 | subtract 2 }}`,
			},
			&ExecuteInput{
				Brain: NewBrain(),
			},
			"0",
			false,
		},
		{
			"math_multiply",
			&NewTemplateInput{
				Contents: `{{ 2 | multiply 2 }}`,
			},
			&ExecuteInput{
				Brain: NewBrain(),
			},
			"4",
			false,
		},
		{
			"math_divide",
			&NewTemplateInput{
				Contents: `{{ 2 | divide 2 }}`,
			},
			&ExecuteInput{
				Brain: NewBrain(),
			},
			"1",
			false,
		},
		{
			"math_modulo",
			&NewTemplateInput{
				Contents: `{{ 3 | modulo 2 }}`,
			},
			&ExecuteInput{
				Brain: NewBrain(),
			},
			"1",
			false,
		},
		{
			"math_minimum",
			&NewTemplateInput{
				Contents: `{{ 3 | minimum 2 }}`,
			},
			&ExecuteInput{
				Brain: NewBrain(),
			},
			"2",
			false,
		},
		{
			"math_maximum",
			&NewTemplateInput{
				Contents: `{{ 3 | maximum 2 }}`,
			},
			&ExecuteInput{
				Brain: NewBrain(),
			},
			"3",
			false,
		},
		{
			"leaf_cert",
			&NewTemplateInput{
				Contents: `{{with caLeaf "foo"}}` +
					`{{.CertPEM}}{{.PrivateKeyPEM}}{{end}}`,
			},
			&ExecuteInput{
				Brain: func() *Brain {
					d := dep.NewConnectLeafQuery("foo")
					b := NewBrain()
					b.Remember(d, &api.LeafCert{
						Service:       "foo",
						CertPEM:       "PEM",
						PrivateKeyPEM: "KEY",
					})
					return b
				}(),
			},
			"PEMKEY",
			false,
		},
		{
			"leaf_cert_nil_pointer_evaluation",
			&NewTemplateInput{
				Contents: `{{ $v := caLeaf "foo" }}{{ $v.CertPEM }}`,
			},
			&ExecuteInput{
				Brain: NewBrain(),
			},
			"<no value>",
			false,
		},
		{
			"root_ca",
			&NewTemplateInput{
				Contents: `{{range caRoots}}{{.RootCertPEM}}{{end}}`,
			},
			&ExecuteInput{
				Brain: func() *Brain {
					d := dep.NewConnectCAQuery()
					b := NewBrain()
					b.Remember(d, []*api.CARoot{
						{
							Name:        "Consul CA Root Cert",
							RootCertPEM: "PEM",
							Active:      true,
						},
					})
					return b
				}(),
			},
			"PEM",
			false,
		},
		{
			"func_connect",
			&NewTemplateInput{
				Contents: `{{ range connect "webapp" }}{{ .Address }}{{ end }}`,
			},
			&ExecuteInput{
				Brain: func() *Brain {
					b := NewBrain()
					d, err := dep.NewHealthConnectQuery("webapp")
					if err != nil {
						t.Fatal(err)
					}
					b.Remember(d, []*dep.HealthService{
						{
							Node:    "node1",
							Address: "1.2.3.4",
						},
						{
							Node:    "node2",
							Address: "5.6.7.8",
						},
					})
					return b
				}(),
			},
			"1.2.3.45.6.7.8",
			false,
		},
		{
			"func_pkiCert",
			&NewTemplateInput{
				Contents:    `{{ with pkiCert "pki/issue/egs-dot-com" }}{{.Cert}}{{end}}`,
				Destination: "/dev/null",
			},
			&ExecuteInput{
				Brain: func() *Brain {
					b := NewBrain()
					d, err := dep.NewVaultPKIQuery("pki/issue/egs-dot-com", "/dev/null", nil)
					if err != nil {
						t.Fatal(err)
					}
					b.Remember(d, dep.PemEncoded{Cert: testCert})
					return b
				}(),
			},
			testCert,
			false,
		},
		{
			"func_pkiCert_Data_compat",
			&NewTemplateInput{
				Contents:    `{{ with pkiCert "pki/issue/egs-dot-com" }}{{.Data.Cert}}{{end}}`,
				Destination: "/dev/null",
			},
			&ExecuteInput{
				Brain: func() *Brain {
					b := NewBrain()
					d, err := dep.NewVaultPKIQuery("pki/issue/egs-dot-com", "/dev/null", nil)
					if err != nil {
						t.Fatal(err)
					}
					b.Remember(d, dep.PemEncoded{Cert: testCert})
					return b
				}(),
			},
			testCert,
			false,
		},
		{
			"spew_sdump_simple_output",
			&NewTemplateInput{
				Contents: `{{ timestamp "2006-01-02" | spew_sdump }}`,
			},
			&ExecuteInput{
				Brain: NewBrain(),
			},
			"(string) (len=10) \"1970-01-01\"\n",
			false,
		},
		{
			"spew_sdump_helper_split",
			&NewTemplateInput{
				Contents: `{{ "a,b,c" | split "," | spew_sdump}}`,
			},
			&ExecuteInput{
				Brain: NewBrain(),
			},
			"([]string) (len=3 cap=3) {\n (string) (len=1) \"a\",\n (string) (len=1) \"b\",\n (string) (len=1) \"c\"\n}\n",
			false,
		},
		{
			"func_nomadVariable",
			&NewTemplateInput{
				Contents: `{{with nomadVar "path" }}{{.k1}}{{end}}`,
			},
			&ExecuteInput{
				Brain: func() *Brain {
					b := NewBrain()
					d, err := dep.NewNVGetQuery("", "path")
					if err != nil {
						t.Fatal(err)
					}
					d.EnableBlocking()
					b.Remember(d, &dep.NomadVarItems{
						"k1": dep.NomadVarItem{Key: "k1", Value: "v1"},
						"k2": dep.NomadVarItem{Key: "k2", Value: "v2"},
					})
					return b
				}(),
			},
			"v1",
			false,
		},
		{
			"func_nomadVariableExists",
			&NewTemplateInput{
				Contents: `{{ nomadVarExists "path" }} {{ nomadVarExists "no_path" }}`,
			},
			&ExecuteInput{
				Brain: func() *Brain {
					b := NewBrain()
					d, err := dep.NewNVGetQuery("", "path")
					if err != nil {
						t.Fatal(err)
					}
					b.Remember(d, true)
					return b
				}(),
			},
			"true false",
			false,
		},
		{
			"func_nomadVariables",
			&NewTemplateInput{
				Contents: `{{ range nomadVarList "list" }}{{ .Path }} {{ end }}`,
			},
			&ExecuteInput{
				Brain: func() *Brain {
					b := NewBrain()
					d, err := dep.NewNVListQuery("", "list")
					if err != nil {
						t.Fatal(err)
					}
					b.Remember(d, []*dep.NomadVarMeta{
						{Path: "list"},
						{Path: "list/foo"},
						{Path: "list/foo/zip"},
					})
					return b
				}(),
			},
			"list list/foo list/foo/zip ",
			false,
		},
		{
			"func_nomadVariables_no_arg",
			&NewTemplateInput{
				Contents: `{{ range nomadVarList }}{{ .Path }} {{ end }}`,
			},
			&ExecuteInput{
				Brain: func() *Brain {
					b := NewBrain()
					d, err := dep.NewNVListQuery("", "")
					if err != nil {
						t.Fatal(err)
					}
					b.Remember(d, []*dep.NomadVarMeta{
						{Path: "list"},
						{Path: "list/foo"},
						{Path: "list/foo/zip"},
					})
					return b
				}(),
			},
			"list list/foo list/foo/zip ",
			false,
		},
		{
			"func_nomadVariables_too_many_args",
			&NewTemplateInput{
				Contents: `{{ range nomadVarList "a" "b" }}{{ .Path }} {{ end }}`,
			},
			nil,
			"",
			true,
		},
		{
			"func_nomadVar_ns_region",
			&NewTemplateInput{
				Contents: `{{with nomadVar "test@default.dc1" }}{{.k1}}{{end}}{{with nomadVar "test@default.global" }}{{.k1}}{{end}}`,
			},
			&ExecuteInput{
				Brain: func() *Brain {
					b := NewBrain()
					d1, err := dep.NewNVGetQuery("", "test@default.dc1")
					if err != nil {
						t.Fatal(err)
					}
					d1.EnableBlocking()
					b.Remember(d1, &dep.NomadVarItems{
						"k1": dep.NomadVarItem{Key: "k1", Value: "dc1"},
						"k2": dep.NomadVarItem{Key: "k2", Value: "v2"},
					})

					d2, err := dep.NewNVGetQuery("", "test@default.global")
					if err != nil {
						t.Fatal(err)
					}
					d2.EnableBlocking()
					b.Remember(d2, &dep.NomadVarItems{
						"k1": dep.NomadVarItem{Key: "k1", Value: "global"},
						"k2": dep.NomadVarItem{Key: "k2", Value: "v2"},
					})
					return b
				}(),
			},
			"dc1global",
			false,
		},
		{
			"func_nomadVariableExists_ns_region",
			&NewTemplateInput{
				Contents: `{{ nomadVarExists "path@default.global" }} {{ nomadVarExists "path@default.dc1" }}`,
			},
			&ExecuteInput{
				Brain: func() *Brain {
					b := NewBrain()
					d1, err := dep.NewNVGetQuery("", "path@default.global")
					if err != nil {
						t.Fatal(err)
					}
					b.Remember(d1, true)

					d2, err := dep.NewNVGetQuery("", "path@default.dc1")
					if err != nil {
						t.Fatal(err)
					}
					b.Remember(d2, nil)
					return b
				}(),
			},
			"true false",
			false,
		},
		{
			"func_nomadVarList_ns_region",
			&NewTemplateInput{
				Contents: `{{ range nomadVarList "list" }}{{ .Path }} {{ end }}{{ range nomadVarList "list@default.dc1" }}{{ .Path }} {{ end }}`,
			},
			&ExecuteInput{
				Brain: func() *Brain {
					b := NewBrain()
					d1, err := dep.NewNVListQuery("", "list")
					if err != nil {
						t.Fatal(err)
					}
					b.Remember(d1, []*dep.NomadVarMeta{
						{Path: "list"},
						{Path: "list/foo"},
						{Path: "list/foo/zip"},
					})

					d2, err := dep.NewNVListQuery("", "list@default.dc1")
					if err != nil {
						t.Fatal(err)
					}
					b.Remember(d2, []*dep.NomadVarMeta{
						{Path: "list"},
						{Path: "list/alpha"},
						{Path: "list/beta/zip"},
					})
					return b
				}(),
			},
			"list list/foo list/foo/zip list list/alpha list/beta/zip ",
			false,
		},
		{
			"external_func",
			&NewTemplateInput{
				Contents: `{{ toUpTest "abCba" }}`,
				ExtFuncMap: map[string]interface{}{
					"toUpTest": func(inString string) string {
						return strings.ToUpper(inString)
					},
				},
			},
			&ExecuteInput{
				Brain: NewBrain(),
			},
			"ABCBA",
			false,
		},
	}

	//	struct {
	//		name string
	//		ti   *NewTemplateInput
	//		i    *ExecuteInput
	//		e    string
	//		err  bool
	//	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%03d_%s", i, tc.name), func(t *testing.T) {
			tpl, err := NewTemplate(tc.ti)
			if err != nil {
				t.Fatal(err)
			}

			a, err := tpl.Execute(tc.i)
			if (err != nil) != tc.err {
				t.Fatal(err)
			}
			if a != nil && !bytes.Equal([]byte(tc.e), a.Output) {
				t.Errorf("\nexp: %#v\nact: %#v", tc.e, string(a.Output))
			}
		})
	}
}

func TestTemplate_error_secret_leak(t *testing.T) {
	tmplinput := &NewTemplateInput{
		Contents: `{{ with secret "secret/foo" }}
					{{- range $key, $value := .Data.zip }}
						export {{ $key }}="{{ $value }}"
					{{- end }}
				{{ end }}`,
	}

	execinput := &ExecuteInput{
		Brain: func() *Brain {
			b := NewBrain()
			b.RWMutex = sync.RWMutex{}
			d, err := dep.NewVaultReadQuery("secret/foo")
			if err != nil {
				t.Fatal(err)
			}
			b.Remember(d, &dep.Secret{
				LeaseID:       "abcd1234",
				LeaseDuration: 120,
				Renewable:     true,
				Data: map[string]interface{}{
					"zip": struct {
						Zap string
					}{
						Zap: "zoo",
					},
				},
			})
			return b
		}(),
	}

	tpl, err := NewTemplate(tmplinput)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tpl.Execute(execinput)
	if strings.Contains(err.Error(), "zoo") {
		t.Error("error contains vault secret... (zoo)\n", err.Error())
	}
}

func TestTemplate_error_secret_leak_SV(t *testing.T) {
	tmplinput := &NewTemplateInput{
		Contents: `
		{{ with nomadVar "var/test" }}
			{{range $key, $value := .varKey}}
				export {{ $key }}="{{ $value }}"
			{{- end }}
		{{ end }}`,
	}
	execinput := &ExecuteInput{
		Brain: func() *Brain {
			b := NewBrain()
			b.RWMutex = sync.RWMutex{}
			nVar, err := dep.NewNVGetQuery("", "var/test")
			if err != nil {
				t.Fatal(err)
			}
			nVar.EnableBlocking()
			b.Remember(nVar, &dep.NomadVarItems{
				"varKey": dep.NomadVarItem{
					Key:   "varKey",
					Value: "varSecret",
				},
			})
			return b
		}(),
	}

	tpl, err := NewTemplate(tmplinput)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tpl.Execute(execinput)
	require.Error(t, err)
	require.True(t, !strings.Contains(err.Error(), "varSecret"), "error contains variable secret (varSecret); err: %v", err)
	require.ErrorContains(t, err, "[redacted]")
}

func Test_writeToFile(t *testing.T) {
	// Use current user and its primary group for input
	currentUser, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	currentUsername := currentUser.Username
	currentGroup, err := user.LookupGroupId(currentUser.Gid)
	if err != nil {
		t.Fatal(err)
	}
	currentGroupName := currentGroup.Name

	cases := []struct {
		name        string
		filePath    string
		content     string
		username    string
		groupName   string
		permissions string
		flags       string
		expectation string
		wantErr     bool
	}{
		{
			"writeToFile_without_flags",
			"",
			"after",
			currentUsername,
			currentGroupName,
			"0644",
			"",
			"after",
			false,
		},
		{
			"writeToFile_with_different_file_permissions",
			"",
			"after",
			currentUsername,
			currentGroupName,
			"0666",
			"",
			"after",
			false,
		},
		{
			"writeToFile_with_append",
			"",
			"after",
			currentUsername,
			currentGroupName,
			"0644",
			`"append"`,
			"beforeafter",
			false,
		},
		{
			"writeToFile_with_newline",
			"",
			"after",
			currentUsername,
			currentGroupName,
			"0644",
			`"newline"`,
			"after\n",
			false,
		},
		{
			"writeToFile_with_append_and_newline",
			"",
			"after",
			currentUsername,
			currentGroupName,
			"0644",
			`"append,newline"`,
			"beforeafter\n",
			false,
		},
		{
			"writeToFile_default_owner",
			"",
			"after",
			"",
			"",
			"0644",
			"",
			"after",
			false,
		},
		{
			"writeToFile_provide_uid_gid",
			"",
			"after",
			currentUser.Uid,
			currentUser.Gid,
			"0644",
			"",
			"after",
			false,
		},
		{
			"writeToFile_provide_just_gid",
			"",
			"after",
			"",
			currentUser.Gid,
			"0644",
			"",
			"after",
			false,
		},
		{
			"writeToFile_provide_just_uid",
			"",
			"after",
			currentUser.Uid,
			"",
			"0644",
			"",
			"after",
			false,
		},
		{
			"writeToFile_create_directory",
			"demo/testing.tmp",
			"after",
			currentUsername,
			currentGroupName,
			"0644",
			"",
			"after",
			false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			outDir, err := os.MkdirTemp("", "")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(outDir)

			var outputFilePath string
			if tc.filePath == "" {
				outputFile, err := os.CreateTemp(outDir, "")
				if err != nil {
					t.Fatal(err)
				}
				_, err = outputFile.WriteString("before")
				if err != nil {
					t.Fatal(err)
				}
				outputFilePath = outputFile.Name()
			} else {
				outputFilePath = outDir + "/" + tc.filePath
			}

			templateContent := fmt.Sprintf(
				"{{ \"%s\" | writeToFile \"%s\" \"%s\" \"%s\" \"%s\"  %s}}",
				tc.content, outputFilePath, tc.username, tc.groupName, tc.permissions, tc.flags)
			ti := &NewTemplateInput{
				Contents: templateContent,
			}
			tpl, err := NewTemplate(ti)
			if err != nil {
				t.Fatal(err)
			}

			a, err := tpl.Execute(nil)
			if (err != nil) != tc.wantErr {
				t.Errorf("writeToFile() error = %v, wantErr %v", err, tc.wantErr)
				return
			}

			// Compare generated file content with the expectation.
			// The function should generate an empty string to the output.
			_generatedFileContent, err := os.ReadFile(outputFilePath)
			generatedFileContent := string(_generatedFileContent)
			if err != nil {
				t.Fatal(err)
			}
			if a != nil && !bytes.Equal([]byte(""), a.Output) {
				t.Errorf("writeToFile() template = %v, want empty string", a.Output)
			}
			if generatedFileContent != tc.expectation {
				t.Errorf("writeToFile() got = %v, want %v", generatedFileContent, tc.expectation)
			}
			// Assert output file permissions
			sts, err := os.Stat(outputFilePath)
			if err != nil {
				t.Fatal(err)
			}
			p_u, err := strconv.ParseUint(tc.permissions, 8, 32)
			if err != nil {
				t.Fatal(err)
			}
			perm := os.FileMode(p_u)
			if sts.Mode() != perm {
				t.Errorf("writeToFile() wrong permissions got = %v, want %v", perm, tc.permissions)
			}

			stat := sts.Sys().(*syscall.Stat_t)
			u := strconv.FormatUint(uint64(stat.Uid), 10)
			g := strconv.FormatUint(uint64(stat.Gid), 10)
			if u != currentUser.Uid || g != currentUser.Gid {
				t.Errorf("writeToFile() owner = %v:%v, wanted %v:%v", u, g, currentUser.Uid, currentUser.Gid)
			}
		})
	}
}

const testCert = `
-----BEGIN CERTIFICATE-----
MIIDWTCCAkGgAwIBAgIUUARA+vQExU8zjdsX/YXMMu1K5FkwDQYJKoZIhvcNAQEL
BQAwFjEUMBIGA1UEAxMLZXhhbXBsZS5jb20wHhcNMjIwMzAxMjIzMzAzWhcNMjIw
MzA0MjIzMzMzWjAaMRgwFgYDVQQDEw9mb28uZXhhbXBsZS5jb20wggEiMA0GCSqG
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDD3sktiNGo/CSvtL84+GIcsuDzp1VFjG++
8P682ZPiqPGjrgwe3P8ypyhQv6I8ZGOyu7helMqBN/S1mrhmHWUONy/4o95QWDsJ
CGw4H44dRil5hKC6K8BUrf79XGAGIQJr3T6I5CCwxukfYhU/+xNE3dq5AgLrIIB2
BtzZA6m1T5CmgAzSzI1byTjaRpxOJjucI37iKzkx7AkYS5hGfVsFmJgGi/UXhvzK
uwnHHIq9rLItx7p261dJV8mxRDFaf4x+4bZh2kYkEaG8REOfyHSCJ78RniWbF/DN
Jtgh8bT2/938/ecBtWcTN+psICD62DJii6988FD2qS+Yd8Eu8M5rAgMBAAGjgZow
gZcwDgYDVR0PAQH/BAQDAgOoMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcD
AjAdBgNVHQ4EFgQUfmm32UJb3xJNxfA7ZB0Q5RXsQIkwHwYDVR0jBBgwFoAUDoYJ
CtobWJrR1xmTsYJd9buj2jwwJgYDVR0RBB8wHYIPZm9vLmV4YW1wbGUuY29thwR/
AAABhwTAqAEpMA0GCSqGSIb3DQEBCwUAA4IBAQBzB+RM2PSZPmDG3xJssS1litV8
TOlGtBAOUi827W68kx1lprp35c9Jyy7l4AAu3Q1+az3iDQBfYBazq89GOZeXRvml
x9PVCjnXP2E7mH9owA6cE+Z1cLN/5h914xUZCb4t9Ahu04vpB3/bnoucXdM5GJsZ
EJylY99VsC/bZKPCheZQnC/LtFBC31WEGYb8rnB7gQxmH99H91+JxnJzYhT1a6lw
arHERAKScrZMTrYPLt2YqYoeyO//aCuT9YW6YdIa9jPQhzjeMKXywXLetE+Ip18G
eB01bl42Y5WwHl0IrjfbEevzoW0+uhlUlZ6keZHr7bLn/xuRCUkVfj3PRlMl
-----END CERTIFICATE-----
`

func TestTemplate_ExtFuncMap(t *testing.T) {
	t.Parallel()

	type expectedError struct {
		containsText string
	}

	cases := []struct {
		name string
		ti   *NewTemplateInput
		i    *ExecuteInput
		e    string
		err  *expectedError
	}{
		{
			"new_external_func",
			&NewTemplateInput{
				Contents: `{{ toUpTest "abCba" }}`,
				ExtFuncMap: map[string]interface{}{
					"toUpTest": func(inString string) string {
						return strings.ToUpper(inString)
					},
				},
			},
			&ExecuteInput{
				Brain: NewBrain(),
			},
			"ABCBA",
			nil,
		},
		{
			"external_func_opaques_existing",
			&NewTemplateInput{
				Contents: `{{ toLower "testValue" }}`,
				ExtFuncMap: map[string]interface{}{
					"toLower": func(s string) string {
						return "opaqued"
					},
				},
			},
			&ExecuteInput{
				Brain: NewBrain(),
			},
			"opaqued",
			nil,
		},
		{
			"denylist_blocks_extfunc",
			&NewTemplateInput{
				Contents: `{{ myBadFunc "testValue" }}`,
				ExtFuncMap: map[string]interface{}{
					"myBadFunc": func(s string) string {
						return "BAD"
					},
				},
				FunctionDenylist: []string{"myBadFunc"},
			},
			&ExecuteInput{
				Brain: NewBrain(),
			},
			"",
			&expectedError{
				containsText: "error calling myBadFunc: function is disabled",
			},
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%03d_%s", i+1, tc.name), func(t *testing.T) {
			tc := tc
			t.Parallel()
			tpl, err := NewTemplate(tc.ti)
			require.NoError(t, err)

			a, err := tpl.Execute(tc.i)
			if tc.err != nil {
				require.ErrorContains(t, err, tc.err.containsText)
				return
			}
			require.NotNil(t, a)
			require.Equal(t, []byte(tc.e), a.Output)
		})
	}
}
