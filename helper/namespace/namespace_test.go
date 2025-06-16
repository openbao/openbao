// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package namespace

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCanonicalize(t *testing.T) {
	tcases := []struct {
		nsPath string
		result string
	}{
		{
			"",
			"",
		},
		{
			"ns1",
			"ns1/",
		},
		{
			"/ns1",
			"ns1/",
		},
		{
			"ns1/ns2",
			"ns1/ns2/",
		},
	}

	for i, c := range tcases {
		result := Canonicalize(c.nsPath)
		if result != c.result {
			t.Fatalf("bad test case %d: %s != %s", i, result, c.result)
		}
	}
}

func TestSplitIDFromString(t *testing.T) {
	tcases := []struct {
		input  string
		id     string
		prefix string
	}{
		{
			"foo",
			"",
			"foo",
		},
		{
			"foo.id",
			"id",
			"foo",
		},
		{
			"foo.foo.id",
			"id",
			"foo.foo",
		},
		{
			"foo.foo/foo.id",
			"id",
			"foo.foo/foo",
		},
		{
			"foo.foo/.id",
			"id",
			"foo.foo/",
		},
		{
			"foo.foo/foo",
			"",
			"foo.foo/foo",
		},
		{
			"foo.foo/f",
			"",
			"foo.foo/f",
		},
		{
			"foo.foo/",
			"",
			"foo.foo/",
		},
		{
			"b.foo",
			"",
			"b.foo",
		},
		{
			"s.foo",
			"",
			"s.foo",
		},
		{
			"t.foo",
			"foo",
			"t",
		},
	}

	for i, c := range tcases {
		pre, id := SplitIDFromString(c.input)
		if pre != c.prefix || id != c.id {
			t.Fatalf("bad test case %d: %s != %s, %s != %s", i, pre, c.prefix, id, c.id)
		}
	}
}

func TestHasParent(t *testing.T) {
	// Create ns1
	ns1 := &Namespace{
		ID:   "id1",
		Path: "ns1/",
	}

	// Create ns1/ns2
	ns2 := &Namespace{
		ID:   "id2",
		Path: "ns1/ns2/",
	}

	// Create ns1/ns2/ns3
	ns3 := &Namespace{
		ID:   "id3",
		Path: "ns1/ns2/ns3/",
	}

	// Create ns4
	ns4 := &Namespace{
		ID:   "id4",
		Path: "ns4/",
	}

	// Create ns4/ns5
	ns5 := &Namespace{
		ID:   "id5",
		Path: "ns4/ns5/",
	}

	tests := []struct {
		name     string
		parent   *Namespace
		ns       *Namespace
		expected bool
	}{
		{
			"is root an ancestor of ns1",
			RootNamespace,
			ns1,
			true,
		},
		{
			"is ns1 an ancestor of ns2",
			ns1,
			ns2,
			true,
		},
		{
			"is ns2 an ancestor of ns3",
			ns2,
			ns3,
			true,
		},
		{
			"is ns1 an ancestor of ns3",
			ns1,
			ns3,
			true,
		},
		{
			"is root an ancestor of ns3",
			RootNamespace,
			ns3,
			true,
		},
		{
			"is ns4 an ancestor of ns3",
			ns4,
			ns3,
			false,
		},
		{
			"is ns5 an ancestor of ns3",
			ns5,
			ns3,
			false,
		},
		{
			"is ns1 an ancestor of ns5",
			ns1,
			ns5,
			false,
		},
	}

	for _, test := range tests {
		actual := test.ns.HasParent(test.parent)
		if actual != test.expected {
			t.Fatalf("bad ancestor calculation; name: %q, actual: %t, expected: %t", test.name, actual, test.expected)
		}
	}
}

func TestParentPath(t *testing.T) {
	// Create ns1
	ns1 := &Namespace{
		ID:   "id1",
		Path: "ns1/",
	}

	// Create ns1/ns2
	ns2 := &Namespace{
		ID:   "id2",
		Path: "ns1/ns2/",
	}

	// Create ns1/ns2/ns3
	ns3 := &Namespace{
		ID:   "id3",
		Path: "ns1/ns2/ns3/",
	}

	// Create ns4
	ns4 := &Namespace{
		ID:   "id4",
		Path: "ns4/",
	}

	// Create ns4/ns5
	ns5 := &Namespace{
		ID:   "id5",
		Path: "ns4/ns5/",
	}

	tests := []struct {
		name     string
		ns       *Namespace
		expected string
		ok       bool
	}{
		{
			"parent path of root",
			RootNamespace,
			"",
			false,
		},
		{
			"parent path of ns1",
			ns1,
			"",
			true,
		},
		{
			"parent path of ns2",
			ns2,
			"ns1/",
			true,
		},
		{
			"parent path of ns3",
			ns3,
			"ns1/ns2/",
			true,
		},
		{
			"parent path of ns4",
			ns4,
			"",
			true,
		},
		{
			"parent path of ns5",
			ns5,
			"ns4/",
			true,
		},
	}

	for _, test := range tests {
		actual, ok := test.ns.ParentPath()
		require.Equal(t, test.expected, actual)
		require.Equal(t, test.ok, ok)
	}
}

func TestValidate(t *testing.T) {
	tcases := []struct {
		namespace *Namespace
		wantError bool
	}{
		{
			RootNamespace,
			true,
		},
		{
			namespace: &Namespace{
				ID:   RootNamespaceID,
				Path: "test",
			},
			wantError: true,
		},
		{
			namespace: &Namespace{
				ID:   "nsid",
				Path: "root",
			},
			wantError: true,
		},
		{
			namespace: &Namespace{
				ID:   "nsid",
				Path: "cubbyhole",
			},
			wantError: true,
		},
		{
			namespace: &Namespace{
				ID:   "nsid",
				Path: "sys",
			},
			wantError: true,
		},
		{
			namespace: &Namespace{
				ID:   "nsid",
				Path: "comsys",
			},
		},
		{
			namespace: &Namespace{
				ID:   "nsid",
				Path: "path with space",
			},
			wantError: true,
		},
		{
			namespace: &Namespace{
				ID: "nsid",
				// empty second segment, as after canonicalize its "/e/"
				Path: "//e",
			},
			wantError: true,
		},
		{
			namespace: &Namespace{
				ID: "nsid",
				// valid as team_1 comes from header/context specification
				Path: "team_1/team_2",
			},
		},
		{
			namespace: &Namespace{
				ID: "nsid",
				// invalid as last segment is incorrect
				Path: "team_1/team_2/team 3",
			},
			wantError: true,
		},
		{
			namespace: &Namespace{
				ID:   "nsid",
				Path: "test/cubbyhole",
			},
			wantError: true,
		},
		{
			namespace: &Namespace{
				ID:   "nsid",
				Path: "test/cubbyhole_1",
			},
		},
		{
			namespace: &Namespace{
				ID:   "nsid",
				Path: "test/1_cubbyhole",
			},
		},
		{
			namespace: &Namespace{
				ID:   "nsid",
				Path: "test/1_cubbyhole_1",
			},
		},
		{
			namespace: &Namespace{
				ID:   "nsid",
				Path: "test/cubbyhole/test2",
			},
			wantError: true,
		},
		{
			namespace: &Namespace{
				ID:   "nsid",
				Path: "sys/test",
			},
			wantError: true,
		},
	}

	for _, tc := range tcases {
		gotErr := tc.namespace.Validate()
		require.Equal(t, tc.wantError, (gotErr != nil))
	}
}

// TestParseSpecifier validates the behavior of [ParseSpecifier].
func TestParseSpecifier(t *testing.T) {
	tcases := []struct {
		input     string
		kind      string
		value     string
		rest      string
		wantError bool
	}{
		// Good inputs:
		{input: "path:foo/bar/", kind: "path", value: "foo/bar/"},
		{input: "path:foo/bar:baz", kind: "path", value: "foo/bar:baz"},
		{input: "path:::", kind: "path", value: "::"},
		{input: "id:De0z6N", kind: "id", value: "De0z6N"},
		{
			input: "uuid:013fb57a-c56a-437f-9452-1996c0b68c27",
			kind:  "uuid",
			value: "013fb57a-c56a-437f-9452-1996c0b68c27",
		},

		// Nonsense input, but valid for all we care:
		{input: "path:", kind: "path", value: ""},

		// Bad inputs:
		{input: "", wantError: true},
		{input: ":", wantError: true},
		{input: "uuid", wantError: true},
		{input: "pat:foo/bar/", wantError: true},
	}

	for _, tc := range tcases {
		kind, spec, err := ParseSpecifier(tc.input)
		if tc.wantError {
			require.Error(t, err)
		} else {
			require.Equal(t, kind, tc.kind)
			require.Equal(t, spec, tc.value)
		}
	}
}

// TestCompareSpecifier validates the behavior of [Namespace.CompareSpecifier].
func TestCompareSpecifier(t *testing.T) {
	ns := &Namespace{
		Path: "foo/bar/",
		ID:   "De0z6N",
		UUID: "013fb57a-c56a-437f-9452-1996c0b68c27",
	}

	tcases := []struct {
		kind string
		spec string
		want bool
	}{
		// Good inputs:
		{kind: "path", spec: ns.Path, want: true},
		{kind: "id", spec: ns.ID, want: true},
		{kind: "uuid", spec: ns.UUID, want: true},

		// Bad inputs (value don't match):
		{kind: "path", spec: ns.ID, want: false},
		{kind: "id", spec: ns.UUID, want: false},

		// Bad inputs (nonsense kinds):
		{kind: "", spec: "", want: false},
		{kind: "foo", spec: "bar", want: false},
	}

	for _, tc := range tcases {
		require.Equal(t, tc.want, ns.CompareSpecifier(tc.kind, tc.spec))
	}
}
