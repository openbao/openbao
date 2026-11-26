// Copyright IBM Corp. 2019, 2025
// SPDX-License-Identifier: MPL-2.0

package snapshot

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/hashicorp/raft"
	"github.com/stretchr/testify/require"
)

func TestArchive(t *testing.T) {
	// Create some fake snapshot data.
	metadata := raft.SnapshotMeta{
		Index: 2005,
		Term:  2011,
		Configuration: raft.Configuration{
			Servers: []raft.Server{
				{
					Suffrage: raft.Voter,
					ID:       raft.ServerID("hello"),
					Address:  raft.ServerAddress("127.0.0.1:8300"),
				},
			},
		},
		Size: 1024,
	}
	var snap bytes.Buffer
	var expected bytes.Buffer
	both := io.MultiWriter(&snap, &expected)
	_, err := io.Copy(both, io.LimitReader(rand.Reader, 1024))
	require.NoError(t, err)

	// Write out the snapshot.
	var archive bytes.Buffer
	require.NoError(t, write(&archive, &metadata, &snap, nil))

	// Read the snapshot back.
	var newMeta raft.SnapshotMeta
	var newSnap bytes.Buffer
	require.NoError(t, read(&archive, &newMeta, &newSnap, nil))

	// Check the contents.
	if !reflect.DeepEqual(newMeta, metadata) {
		t.Fatalf("bad: %#v", newMeta)
	}
	var buf bytes.Buffer
	_, err = io.Copy(&buf, &newSnap)
	require.NoError(t, err)
	if !bytes.Equal(buf.Bytes(), expected.Bytes()) {
		t.Fatalf("snapshot contents didn't match")
	}
}

func TestArchive_GoodData(t *testing.T) {
	paths := []string{
		"testdata/spaces-meta.tar",
	}
	for i, p := range paths {
		f, err := os.Open(p)
		require.NoError(t, err)
		defer func() {
			require.NoError(t, f.Close(), "failed to close")
		}()

		var metadata raft.SnapshotMeta
		err = read(f, &metadata, io.Discard, nil)
		require.NoErrorf(t, err, "case %d: should've read the snapshot, but didn't: %v", i, err)
	}
}

func TestArchive_BadData(t *testing.T) {
	cases := []struct {
		Name  string
		Error string
	}{
		{"testdata/empty.tar", "failed checking integrity of snapshot"},
		{"testdata/extra.tar", "unexpected file \"nope\""},
		{"testdata/missing-meta.tar", "hash check failed for \"meta.json\""},
		{"testdata/missing-state.tar", "hash check failed for \"state.bin\""},
		{"testdata/missing-sha.tar", "file missing"},
		{"testdata/corrupt-meta.tar", "hash check failed for \"meta.json\""},
		{"testdata/corrupt-state.tar", "hash check failed for \"state.bin\""},
		{"testdata/corrupt-sha.tar", "list missing hash for \"nope\""},
	}
	for i, c := range cases {
		f, err := os.Open(c.Name)
		require.NoError(t, err)
		defer func() {
			require.NoError(t, f.Close(), "failed to close")
		}()

		var metadata raft.SnapshotMeta
		err = read(f, &metadata, io.Discard, nil)
		if err == nil || !strings.Contains(err.Error(), c.Error) {
			t.Fatalf("case %d (%s): %v", i, c.Name, err)
		}
	}
}

func TestArchive_hashList(t *testing.T) {
	hl := newHashList()
	for i := range 16 {
		h := hl.Add(fmt.Sprintf("file-%d", i))
		_, err := io.CopyN(h, rand.Reader, 32)
		require.NoError(t, err)
	}

	// Do a normal round trip.
	var buf bytes.Buffer
	require.NoError(t, hl.Encode(&buf))
	require.NoError(t, hl.DecodeAndVerify(&buf))

	// Have a local hash that isn't in the file.
	buf.Reset()
	require.NoError(t, hl.Encode(&buf))
	hl.Add("nope")
	err := hl.DecodeAndVerify(&buf)
	if err == nil || !strings.Contains(err.Error(), "file missing for \"nope\"") {
		t.Fatalf("err: %v", err)
	}

	// Have a hash in the file that we haven't seen locally.
	buf.Reset()
	require.NoError(t, hl.Encode(&buf))
	delete(hl.hashes, "nope")
	err = hl.DecodeAndVerify(&buf)
	if err == nil || !strings.Contains(err.Error(), "list missing hash for \"nope\"") {
		t.Fatalf("err: %v", err)
	}
}
