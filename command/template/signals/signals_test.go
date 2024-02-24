// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package signals

import (
	"strings"
	"syscall"
	"testing"
)

func TestParse(t *testing.T) {
	s, err := Parse("SIGHUP")
	if err != nil {
		t.Fatal(err)
	}
	if s != syscall.SIGHUP {
		t.Errorf("expected %#v to be %#v", s, syscall.SIGHUP)
	}
}

func TestParse_case(t *testing.T) {
	s, err := Parse("sighup")
	if err != nil {
		t.Fatal(err)
	}
	if s != syscall.SIGHUP {
		t.Errorf("expected %#v to be %#v", s, syscall.SIGHUP)
	}
}

func TestParse_invalid(t *testing.T) {
	_, err := Parse("neverasignalnope")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "valid signals") {
		t.Errorf("bad error: %s", err)
	}
}
