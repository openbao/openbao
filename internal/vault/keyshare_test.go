// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"bytes"
	"reflect"
	"slices"
	"testing"
)

func TestContainsKeyShare(t *testing.T) {
	shares := [][]byte{[]byte("first share"), []byte("other share"), []byte("final share")}
	tests := []struct {
		name   string
		shares [][]byte
		key    []byte
		want   bool
	}{
		{"nil shares", nil, shares[0], false},
		{"empty shares", [][]byte{}, shares[0], false},
		{"absent", shares, []byte("extra share"), false},
		{"first", shares, shares[0], true},
		{"middle", shares, shares[1], true},
		{"last", shares, shares[2], true},
		{"matching prefix", shares, []byte("first sharf"), false},
		{"shorter key", shares, []byte("first"), false},
		{"longer key", shares, []byte("first share!"), false},
		{"different share lengths", [][]byte{[]byte("first"), shares[0]}, shares[0], true},
		{"multiple matches", [][]byte{shares[0], shares[0]}, shares[0], true},
		{"nil key", shares, nil, false},
		{"empty key and share", [][]byte{nil, {}}, []byte{}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := slices.Clone(tt.shares)
			for i, share := range before {
				before[i] = bytes.Clone(share)
			}
			keyBefore := bytes.Clone(tt.key)

			if got := containsKeyShare(tt.shares, tt.key); got != tt.want {
				t.Fatalf("containsKeyShare() = %v, want %v", got, tt.want)
			}
			if !reflect.DeepEqual(tt.shares, before) || !bytes.Equal(tt.key, keyBefore) {
				t.Fatal("share lookup changed its inputs")
			}
		})
	}
}
