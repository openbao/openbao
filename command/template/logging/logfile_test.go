// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package logging

import (
	"io"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/hashicorp/consul-template/config"
	"github.com/hashicorp/logutils"
	"github.com/stretchr/testify/require"
)

func TestLogFileFilter(t *testing.T) {
	filt, err := newLogFilter(io.Discard, logutils.LogLevel("INFO"))
	if err != nil {
		t.Fatal(err)
	}

	tempDir, err := os.MkdirTemp("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)
	logFile := LogFile{
		fileName: "something.log",
		logPath:  tempDir,
		duration: 50 * time.Millisecond,
		filt:     filt,
	}

	logFile.Write([]byte("Hello World"))
	time.Sleep(3 * logFile.duration)
	logFile.Write([]byte("Second File"))
	require.Len(t, listDir(t, tempDir), 2)

	infotest := []byte("[INFO] test")
	n, err := logFile.Write(infotest)
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

	n, err = logFile.Write([]byte("[DEBUG] test"))
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	if n != 0 {
		t.Fatalf("should not have logged")
	}
}

func TestLogFileNoFilter(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)
	logFile := LogFile{
		fileName: "something.log",
		logPath:  tempDir,
		duration: 50 * time.Millisecond,
	}

	logFile.Write([]byte("Hello World"))
	time.Sleep(3 * logFile.duration)
	logFile.Write([]byte("Second File"))
	require.Len(t, listDir(t, tempDir), 2)

	infotest := []byte("[INFO] test")
	n, err := logFile.Write(infotest)
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

	n, err = logFile.Write([]byte("[DEBUG] test"))
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	if n == 0 {
		t.Fatalf("should have logged")
	}
}

func TestLogFile_Rotation_MaxDuration(t *testing.T) {
	if testing.Short() {
		t.Skip("too slow for testing.Short")
	}

	tempDir, err := os.MkdirTemp("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)
	logFile := LogFile{
		fileName: "something.log",
		logPath:  tempDir,
		duration: 50 * time.Millisecond,
	}

	logFile.Write([]byte("Hello World"))
	time.Sleep(3 * logFile.duration)
	logFile.Write([]byte("Second File"))
	require.Len(t, listDir(t, tempDir), 2)
}

func TestLogFile_openNew(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)
	logFile := LogFile{
		fileName: "something.log",
		logPath:  tempDir,
		duration: config.DefaultLogRotateDuration,
	}
	err = logFile.openNew()
	require.NoError(t, err)

	msg := "[INFO] Something"
	_, err = logFile.Write([]byte(msg))
	require.NoError(t, err)

	content, err := os.ReadFile(logFile.FileInfo.Name())
	require.NoError(t, err)
	require.Contains(t, string(content), msg)
}

func TestLogFile_Rotation_MaxBytes(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)
	logFile := LogFile{
		fileName: "somefile.log",
		logPath:  tempDir,
		MaxBytes: 10,
		duration: config.DefaultLogRotateDuration,
	}
	logFile.Write([]byte("Hello World"))
	logFile.Write([]byte("Second File"))
	require.Len(t, listDir(t, tempDir), 2)
}

func TestLogFile_PruneFiles(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)
	logFile := LogFile{
		fileName: "something.log",
		logPath:  tempDir,
		MaxBytes: 10,
		duration: config.DefaultLogRotateDuration,
		MaxFiles: 1,
	}
	logFile.Write([]byte("[INFO] Hello World"))
	logFile.Write([]byte("[INFO] Second File"))
	logFile.Write([]byte("[INFO] Third File"))

	logFiles := listDir(t, tempDir)
	sort.Strings(logFiles)
	require.Len(t, logFiles, 2)

	content, err := os.ReadFile(filepath.Join(tempDir, logFiles[0]))
	require.NoError(t, err)
	require.Contains(t, string(content), "Second File")

	content, err = os.ReadFile(filepath.Join(tempDir, logFiles[1]))
	require.NoError(t, err)
	require.Contains(t, string(content), "Third File")
}

func TestLogFile_PruneFiles_Disabled(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)
	logFile := LogFile{
		fileName: "somename.log",
		logPath:  tempDir,
		MaxBytes: 10,
		duration: config.DefaultLogRotateDuration,
		MaxFiles: 0,
	}
	logFile.Write([]byte("[INFO] Hello World"))
	logFile.Write([]byte("[INFO] Second File"))
	logFile.Write([]byte("[INFO] Third File"))
	require.Len(t, listDir(t, tempDir), 3)
}

func TestLogFile_FileRotation_Disabled(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)
	logFile := LogFile{
		fileName: "something.log",
		logPath:  tempDir,
		MaxBytes: 10,
		MaxFiles: -1,
	}
	logFile.Write([]byte("[INFO] Hello World"))
	logFile.Write([]byte("[INFO] Second File"))
	logFile.Write([]byte("[INFO] Third File"))
	require.Len(t, listDir(t, tempDir), 1)
}

func listDir(t *testing.T, name string) []string {
	t.Helper()
	fh, err := os.Open(name)
	require.NoError(t, err)
	files, err := fh.Readdirnames(100)
	require.NoError(t, err)
	return files
}
