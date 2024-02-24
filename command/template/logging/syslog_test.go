// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package logging

import (
	"io"
	"os"
	"runtime"
	"testing"

	gsyslog "github.com/hashicorp/go-syslog"
	"github.com/hashicorp/logutils"
)

func TestSyslogFilter(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.SkipNow()
	}

	// Travis does not support syslog for some reason
	for _, ci_env := range []string{"TRAVIS", "CIRCLECI"} {
		if ci := os.Getenv(ci_env); ci != "" {
			t.SkipNow()
		}
	}

	l, err := gsyslog.NewLogger(gsyslog.LOG_NOTICE, "LOCAL0", "consul-template")
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	filt, err := newLogFilter(io.Discard, logutils.LogLevel("INFO"))
	if err != nil {
		t.Fatal(err)
	}

	s := &SyslogWrapper{l, filt}
	infotest := []byte("[INFO] test")
	n, err := s.Write(infotest)
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	if n == 0 {
		t.Fatalf("should have logged")
	}
	if n != len(infotest) {
		t.Fatalf("byte count (%d) doesn't match output len (%d).",
			n, len(infotest))
	}

	n, err = s.Write([]byte("[DEBUG] test"))
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	if n != 0 {
		t.Fatalf("should not have logged")
	}
}
