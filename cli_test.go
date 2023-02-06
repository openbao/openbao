// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package kerberos

import (
	"testing"
	"time"

	"github.com/jcmturner/gokrb5/v8/keytab"
)

func TestCLI_RemoveInstanceName(t *testing.T) {
	type test struct {
		principalName string
		realm         string
		want          string
	}

	tests := []test{
		{principalName: "foobar/localhost", realm: "hashicorp.com", want: "foobar"},
		{principalName: "foobar/localhost/test", realm: "hashicorp.com", want: "foobar"},
		{principalName: "/localhost/test", realm: "hashicorp.com", want: ""},
	}

	for _, tc := range tests {
		kt := keytab.Keytab{}
		err := kt.AddEntry(tc.principalName, tc.realm, "password", time.Now(), 1, 17)
		if err != nil {
			t.Fatalf("got error adding entry, shouldn't have: %v", err)
		}

		removeInstanceNameFromKeytab(&kt)
		if kt.Entries[0].Principal.NumComponents != 1 {
			t.Fatalf("expected num components to be 1, got %d", kt.Entries[0].Principal.NumComponents)
		}

		if kt.Entries[0].Principal.Components[0] != tc.want {
			t.Fatalf("expected principal name to be %s, got %s", tc.want, kt.Entries[0].Principal.Components[0])
		}
	}
}
