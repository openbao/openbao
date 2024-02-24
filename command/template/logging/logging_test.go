// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package logging

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"
)

func TestNow(t *testing.T) {
	checkTime := func(timeStamp string) {
		logTime, err := time.Parse(timeFmt, timeStamp)
		if err != nil {
			t.Fatal("log time failed to parse:", err)
		}
		if time.Now().Before(logTime) {
			t.Fatal("log happened in the future?")
		}
	}
	// we just want to be sure now() returns a valid date string
	checkTime(now())

	// pull apart log message and check timestamp
	var buf bytes.Buffer
	config := newConfig(&buf)
	writer, err := newWriter(config)
	if err != nil {
		t.Fatal(err)
	}
	writer.Write([]byte("XXX"))
	logSplit := strings.Split(buf.String(), " ")
	checkTime(logSplit[0])
	if logSplit[1] != "XXX" {
		t.Fatalf("Where'd the XXX go?\n(%#v)", logSplit)
	}
}

func newConfig(w io.Writer) *Config {
	return &Config{
		Level:  "INFO",
		Writer: w,
	}
}

func TestWriter(t *testing.T) {
	// mock/de-mock now() func
	defer func(orig func() string) { now = orig }(now)
	now = func() string { return "*NOW*" }

	type testCase struct {
		name          string
		input, output string
	}
	runTest := func(tc testCase) {
		var buf bytes.Buffer
		config := newConfig(&buf)
		writer, err := newWriter(config)
		if err != nil {
			t.Error(err)
		}
		n, err := writer.Write([]byte(tc.input))
		if err != nil {
			t.Error(err)
		}
		if n != len(tc.input) {
			t.Errorf("byte count (%d) doesn't match output len (%d).",
				n, len(tc.input))
		}
		if buf.String() != tc.output {
			t.Errorf("unexpected log output string: '%s'", buf.String())
		}
	}

	for i, tc := range []testCase{
		{
			name:   "null",
			input:  "",
			output: "",
		},
		{
			name:   "err",
			input:  "[ERR] (test) should write",
			output: "*NOW* [ERR] (test) should write",
		},
		{
			name:   "warn",
			input:  "[WARN] (test) should write",
			output: "*NOW* [WARN] (test) should write",
		},
		{
			name:   "info",
			input:  "[INFO] (test) should write",
			output: "*NOW* [INFO] (test) should write",
		},
		{
			name:   "debug",
			input:  "[DEBUG] (test) should not write",
			output: "",
		},
		{
			name:   "trace",
			input:  "[TRACE] (test) should not write",
			output: "",
		},
	} {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name),
			func(t *testing.T) {
				runTest(tc)
			})
	}
}
