// Copyright (c) OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package postgresql

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	thpsql "github.com/openbao/openbao/sdk/v2/helper/testhelpers/postgresql"
)

var (
	sharedOnce    sync.Once
	sharedURL     string
	sharedCleanup func()
	tableSeq      atomic.Uint64
	unsafeChars   = regexp.MustCompile(`[^a-z0-9]+`)
)

func ConnURL(t *testing.T) string {
	t.Helper()
	sharedOnce.Do(func() {
		sharedCleanup, sharedURL = thpsql.PrepareTestContainer(t, "17")
	})
	return sharedURL
}

func Stop() {
	if sharedCleanup != nil {
		sharedCleanup()
	}
}

func UniquePrefix(t *testing.T) string {
	name := unsafeChars.ReplaceAllString(strings.ToLower(t.Name()), "_")
	if len(name) > 40 {
		name = name[:40]
	}
	return fmt.Sprintf("t%d_%s", tableSeq.Add(1), name)
}

func Config(t *testing.T) map[string]string {
	t.Helper()
	prefix := UniquePrefix(t)
	return map[string]string{
		"connection_url": ConnURL(t),
		"table":          prefix + "_kv",
		"ha_table":       prefix + "_ha",
		"ha_enabled":     "true",
	}
}
