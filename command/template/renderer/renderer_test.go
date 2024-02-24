// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package renderer

import (
	"bytes"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"testing"
)

func TestAtomicWrite(t *testing.T) {
	t.Run("parent_folder_missing", func(t *testing.T) {
		// Create a TempDir and a TempFile in that TempDir, then remove them to
		// "simulate" a non-existent folder
		outDir, err := os.MkdirTemp("", "")
		if err != nil {
			t.Error(err)
		}
		defer os.RemoveAll(outDir)
		outFile, err := os.CreateTemp(outDir, "")
		if err != nil {
			t.Error(err)
		}
		if err := os.RemoveAll(outDir); err != nil {
			t.Error(err)
		}

		if err := AtomicWrite(outFile.Name(), true, nil, 0o644, false); err != nil {
			t.Error(err)
		}

		if _, err := os.Stat(outFile.Name()); err != nil {
			t.Error(err)
		}
	})

	t.Run("retains_permissions", func(t *testing.T) {
		outDir, err := os.MkdirTemp("", "")
		if err != nil {
			t.Error(err)
		}
		defer os.RemoveAll(outDir)
		outFile, err := os.CreateTemp(outDir, "")
		if err != nil {
			t.Error(err)
		}
		os.Chmod(outFile.Name(), 0o600)

		if err := AtomicWrite(outFile.Name(), true, nil, 0, false); err != nil {
			t.Error(err)
		}

		stat, err := os.Stat(outFile.Name())
		if err != nil {
			t.Error(err)
		}

		expected := os.FileMode(0o600)
		if stat.Mode() != expected {
			t.Errorf("expected %q to be %q", stat.Mode(), expected)
		}
	})

	t.Run("non_existent", func(t *testing.T) {
		outDir, err := os.MkdirTemp("", "")
		if err != nil {
			t.Error(err)
		}
		os.RemoveAll(outDir)
		defer os.RemoveAll(outDir)

		// Try AtomicWrite to a file that doesn't exist yet
		file := filepath.Join(outDir, "nope/not/it/create")
		if err := AtomicWrite(file, true, nil, 0o644, false); err != nil {
			t.Error(err)
		}

		if _, err := os.Stat(file); err != nil {
			t.Error(err)
		}
	})

	t.Run("non_existent_no_create", func(t *testing.T) {
		outDir, err := os.MkdirTemp("", "")
		if err != nil {
			t.Error(err)
		}
		os.RemoveAll(outDir)
		defer os.RemoveAll(outDir)

		// Try AtomicWrite to a file that doesn't exist yet
		file := filepath.Join(outDir, "nope/not/it/nope-no-create")
		if err := AtomicWrite(file, false, nil, 0o644, false); err != ErrNoParentDir {
			t.Errorf("expected %q to be %q", err, ErrNoParentDir)
		}
	})

	t.Run("backup", func(t *testing.T) {
		outDir, err := os.MkdirTemp("", "")
		if err != nil {
			t.Error(err)
		}
		defer os.RemoveAll(outDir)
		outFile, err := os.CreateTemp(outDir, "")
		if err != nil {
			t.Error(err)
		}
		if err := os.Chmod(outFile.Name(), 0o600); err != nil {
			t.Error(err)
		}
		if _, err := outFile.Write([]byte("before")); err != nil {
			t.Error(err)
		}

		if err := AtomicWrite(outFile.Name(), true, []byte("after"), 0o644, true); err != nil {
			t.Error(err)
		}

		f, err := os.ReadFile(outFile.Name() + ".bak")
		if err != nil {
			t.Error(err)
		}
		if !bytes.Equal(f, []byte("before")) {
			t.Errorf("expected %q to be %q", f, []byte("before"))
		}

		if stat, err := os.Stat(outFile.Name() + ".bak"); err != nil {
			t.Error(err)
		} else {
			if stat.Mode() != 0o600 {
				t.Errorf("expected %d to be %d", stat.Mode(), 0o600)
			}
		}
	})

	t.Run("backup_not_exists", func(t *testing.T) {
		outDir, err := os.MkdirTemp("", "")
		if err != nil {
			t.Error(err)
		}
		defer os.RemoveAll(outDir)
		outFile, err := os.CreateTemp(outDir, "")
		if err != nil {
			t.Error(err)
		}
		if err := os.Remove(outFile.Name()); err != nil {
			t.Error(err)
		}

		if err := AtomicWrite(outFile.Name(), true, nil, 0o644, true); err != nil {
			t.Error(err)
		}

		// Shouldn't have a backup file, since the original file didn't exist
		if _, err := os.Stat(outFile.Name() + ".bak"); err == nil {
			t.Error("expected error")
		} else {
			if !os.IsNotExist(err) {
				t.Errorf("bad error: %s", err)
			}
		}
	})

	t.Run("backup_backup", func(t *testing.T) {
		outDir, err := os.MkdirTemp("", "")
		if err != nil {
			t.Error(err)
		}
		defer os.RemoveAll(outDir)
		outFile, err := os.CreateTemp(outDir, "")
		if err != nil {
			t.Error(err)
		}
		if _, err := outFile.Write([]byte("first")); err != nil {
			t.Error(err)
		}

		contains := func(filename, content string) {
			f, err := os.ReadFile(filename + ".bak")
			if err != nil {
				t.Error(err)
			}
			if !bytes.Equal(f, []byte(content)) {
				t.Errorf("expected %q to be %q", f, []byte(content))
			}
		}

		err = AtomicWrite(outFile.Name(), true, []byte("second"), 0o644, true)
		if err != nil {
			t.Error(err)
		}
		contains(outFile.Name(), "first")

		err = AtomicWrite(outFile.Name(), true, []byte("third"), 0o644, true)
		if err != nil {
			t.Error(err)
		}
		contains(outFile.Name(), "second")
	})
}

func TestRender(t *testing.T) {
	t.Run("file-exists-same-content", func(t *testing.T) {
		outDir, err := os.MkdirTemp("", "")
		if err != nil {
			t.Error(err)
		}
		defer os.RemoveAll(outDir)
		outFile, err := os.CreateTemp(outDir, "")
		if err != nil {
			t.Error(err)
		}
		contents := []byte("first")
		if _, err := outFile.Write(contents); err != nil {
			t.Error(err)
		}
		path := outFile.Name()
		if err = outFile.Close(); err != nil {
			t.Error(err)
		}

		rr, err := Render(&RenderInput{
			Path:     path,
			Contents: contents,
		})
		if err != nil {
			t.Error(err)
		}
		switch {
		case rr.WouldRender && !rr.DidRender:
		default:
			t.Errorf("Bad render results; would: %v, did: %v",
				rr.WouldRender, rr.DidRender)
		}
	})
	t.Run("file-exists-diff-content", func(t *testing.T) {
		outDir, err := os.MkdirTemp("", "")
		if err != nil {
			t.Error(err)
		}
		defer os.RemoveAll(outDir)
		outFile, err := os.CreateTemp(outDir, "")
		if err != nil {
			t.Error(err)
		}
		contents := []byte("first")
		if _, err := outFile.Write(contents); err != nil {
			t.Error(err)
		}
		path := outFile.Name()
		if err = outFile.Close(); err != nil {
			t.Error(err)
		}

		diff_contents := []byte("not-first")
		rr, err := Render(&RenderInput{
			Path:     path,
			Contents: diff_contents,
		})
		if err != nil {
			t.Error(err)
		}
		switch {
		case rr.WouldRender && rr.DidRender:
		default:
			t.Errorf("Bad render results; would: %v, did: %v",
				rr.WouldRender, rr.DidRender)
		}
	})
	t.Run("file-no-exists", func(t *testing.T) {
		outDir, err := os.MkdirTemp("", "")
		if err != nil {
			t.Error(err)
		}
		defer os.RemoveAll(outDir)
		path := path.Join(outDir, "no-exists")
		contents := []byte("first")

		rr, err := Render(&RenderInput{
			Path:     path,
			Contents: contents,
		})
		if err != nil {
			t.Error(err)
		}
		switch {
		case rr.WouldRender && rr.DidRender:
		default:
			t.Errorf("Bad render results; would: %v, did: %v",
				rr.WouldRender, rr.DidRender)
		}
	})
	t.Run("empty-file-no-exists", func(t *testing.T) {
		outDir, err := os.MkdirTemp("", "")
		if err != nil {
			t.Error(err)
		}
		defer os.RemoveAll(outDir)
		path := path.Join(outDir, "no-exists")
		contents := []byte{}

		rr, err := Render(&RenderInput{
			Path:     path,
			Contents: contents,
		})
		if err != nil {
			t.Error(err)
		}
		switch {
		case rr.WouldRender && rr.DidRender:
		default:
			t.Errorf("Bad render results; would: %v, did: %v",
				rr.WouldRender, rr.DidRender)
		}
	})
}

func TestRender_Chown(t *testing.T) {
	// Can't change uid unless root, but can try changing the group id

	// In order to test this behavior, the caller needs to be in at least two
	// groups. One to create the initial file and the other to test as part of
	// the change behavior

	// In order to make sure that this is tested properly we would have to
	// preconfigure the environment and specify the gid here or (better) add
	// the user to a group and leave this dynamic avoiding hardcoded values

	// Enumerate the groups the current user (running the tests) belongs to
	callerGroups, err := os.Getgroups()
	if err != nil {
		t.Errorf("getgroups: %s", err)
	}

	// If the caller isn't in any groups, there is no way to test changing the
	// group id
	if len(callerGroups) == 0 {
		t.Skip("The current user is not member of any group, cannot Chown, skipping...")
	}

	// If the caller belongs to one and only one group, the test can not run
	// properly because DidRender will be false
	if len(callerGroups) == 1 {
		t.Skip("This test requires the caller be in at least 2 groups, skipping...")
	}

	// Using os.Getgid will give us the caller's primary group. We can then use
	// that value to determine whether or not we take the first or second value
	// from the callerGroups list. This should allow the test function to remain
	// dynamic and avoid hardcoded magic values
	wantedGid := callerGroups[0]
	if wantedGid == os.Getgid() {
		wantedGid = callerGroups[1]
	}

	t.Run("sets-file-ownership-when-file-exists-same-content", func(t *testing.T) {
		outDir, err := os.MkdirTemp("", "")
		if err != nil {
			t.Error(err)
		}
		defer os.RemoveAll(outDir)

		outFile, err := os.CreateTemp(outDir, "")
		if err != nil {
			t.Error(err)
		}
		contents := []byte("first")
		if _, err := outFile.Write(contents); err != nil {
			t.Error(err)
		}
		path := outFile.Name()
		if err = outFile.Close(); err != nil {
			t.Error(err)
		}

		rr, err := Render(&RenderInput{
			Path:     path,
			Contents: contents,
			Group:    strconv.Itoa(wantedGid),
		})
		if err != nil {
			t.Error(err)
		}
		switch {
		case rr.WouldRender && rr.DidRender: // we expect rerendering to disk here
		default:
			t.Errorf("Bad render results; would: %v, did: %v",
				rr.WouldRender, rr.DidRender)
		}

		gotUid, gotGid, err := getFileOwnership(path)
		if err != nil {
			t.Errorf("getFileOwnership: %s", err)
		}
		if gotGid != wantedGid {
			t.Errorf("Bad render results; gotUid: %v, wantedGid: %v, gotGid: %v",
				gotUid, wantedGid, gotGid)
		}
	})

	t.Run("sets-file-ownership-when-file-exists-diff-content", func(t *testing.T) {
		outDir, err := os.MkdirTemp("", "")
		if err != nil {
			t.Error(err)
		}
		defer os.RemoveAll(outDir)
		outFile, err := os.CreateTemp(outDir, "")
		if err != nil {
			t.Error(err)
		}
		contents := []byte("first")
		if _, err := outFile.Write(contents); err != nil {
			t.Error(err)
		}
		path := outFile.Name()
		if err = outFile.Close(); err != nil {
			t.Error(err)
		}

		diff_contents := []byte("not-first")
		rr, err := Render(&RenderInput{
			Path:     path,
			Contents: diff_contents,
			Group:    strconv.Itoa(wantedGid),
		})
		if err != nil {
			t.Error(err)
		}
		switch {
		case rr.WouldRender && rr.DidRender:
		default:
			t.Errorf("Bad render results; would: %v, did: %v",
				rr.WouldRender, rr.DidRender)
		}

		gotUid, gotGid, err := getFileOwnership(path)
		if err != nil {
			t.Errorf("getFileOwnership: %s", err)
		}
		if gotGid != wantedGid {
			t.Errorf("Bad render results; gotUid: %v, wantedGid: %v, gotGid: %v",
				gotUid, wantedGid, gotGid)
		}
	})
	t.Run("sets-file-ownership-when-file-no-exists", func(t *testing.T) {
		outDir, err := os.MkdirTemp("", "")
		if err != nil {
			t.Error(err)
		}
		defer os.RemoveAll(outDir)
		path := path.Join(outDir, "no-exists")
		contents := []byte("first")

		rr, err := Render(&RenderInput{
			Path:     path,
			Contents: contents,
			Group:    strconv.Itoa(wantedGid),
		})
		if err != nil {
			t.Error(err)
		}
		switch {
		case rr.WouldRender && rr.DidRender:
		default:
			t.Errorf("Bad render results; would: %v, did: %v",
				rr.WouldRender, rr.DidRender)
		}

		gotUid, gotGid, err := getFileOwnership(path)
		if err != nil {
			t.Errorf("getFileOwnership: %s", err)
		}
		if gotGid != wantedGid {
			t.Errorf("Bad render results; gotUid: %v, wantedGid: %v, gotGid: %v",
				gotUid, wantedGid, gotGid)
		}
	})
	t.Run("sets-file-ownership-when-empty-file-no-exists", func(t *testing.T) {
		outDir, err := os.MkdirTemp("", "")
		if err != nil {
			t.Error(err)
		}
		defer os.RemoveAll(outDir)
		path := path.Join(outDir, "no-exists")
		contents := []byte{}

		rr, err := Render(&RenderInput{
			Path:     path,
			Contents: contents,
			Group:    strconv.Itoa(wantedGid),
		})
		if err != nil {
			t.Error(err)
		}
		switch {
		case rr.WouldRender && rr.DidRender:
		default:
			t.Errorf("Bad render results; would: %v, did: %v",
				rr.WouldRender, rr.DidRender)
		}

		gotUid, gotGid, err := getFileOwnership(path)
		if err != nil {
			t.Errorf("getFileOwnership: %s", err)
		}
		if gotGid != wantedGid {
			t.Errorf("Bad render results; gotUid: %v, wantedGid: %v, gotGid: %v",
				gotUid, wantedGid, gotGid)
		}
	})

	t.Run("should-be-noop-when-missing-user", func(t *testing.T) {
		outDir, err := os.MkdirTemp("", "")
		if err != nil {
			t.Error(err)
		}
		defer os.RemoveAll(outDir)
		outFile, err := os.CreateTemp(outDir, "")
		if err != nil {
			t.Error(err)
		}
		contents := []byte("first")
		if _, err := outFile.Write(contents); err != nil {
			t.Error(err)
		}
		path := outFile.Name()
		if err = outFile.Close(); err != nil {
			t.Error(err)
		}

		// getting file uid:gid for the default behaviour
		wantUid, wantGid, err := getFileOwnership(path)
		if err != nil {
			t.Errorf("getFileOwnership: %s", err)
		}
		rr, err := Render(&RenderInput{
			Path:     path,
			Contents: contents,
			Group:    "",
		})
		if err != nil {
			t.Error(err)
		}
		switch {
		case rr.WouldRender && !rr.DidRender:
		default:
			t.Errorf("Bad render results; would: %v, did: %v",
				rr.WouldRender, rr.DidRender)
		}

		gotUid, gotGid, err := getFileOwnership(path)
		if err != nil {
			t.Errorf("getFileOwnership: %s", err)
		}
		if gotUid != wantUid || gotGid != wantGid {
			t.Errorf("Bad render results; we shouldn't have altered uid/gid. wantUid: %v, wantGid: %v, gotUid: %v, gotGid: %v ",
				wantUid, wantGid, gotUid, gotGid)
		}
	})

	t.Run("should-be-noop-when-missing-group", func(t *testing.T) {
		outDir, err := os.MkdirTemp("", "")
		if err != nil {
			t.Error(err)
		}
		defer os.RemoveAll(outDir)
		outFile, err := os.CreateTemp(outDir, "")
		if err != nil {
			t.Error(err)
		}
		contents := []byte("first")
		if _, err := outFile.Write(contents); err != nil {
			t.Error(err)
		}
		path := outFile.Name()
		if err = outFile.Close(); err != nil {
			t.Error(err)
		}

		// getting file uid:gid for the default behaviour
		wantUid, wantGid, err := getFileOwnership(path)
		if err != nil {
			t.Errorf("getFileOwnership: %s", err)
		}

		rr, err := Render(&RenderInput{
			Path:     path,
			Contents: contents,
			User:     "",
		})
		if err != nil {
			t.Error(err)
		}
		switch {
		case rr.WouldRender && !rr.DidRender:
		default:
			t.Errorf("Bad render results; would: %v, did: %v",
				rr.WouldRender, rr.DidRender)
		}

		gotUid, gotGid, err := getFileOwnership(path)
		if err != nil {
			t.Errorf("getFileOwnership: %s", err)
		}
		if gotUid != wantUid || gotGid != wantGid {
			t.Errorf("Bad render results; we shouldn't have altered uid/gid. wantUid: %v, wantGid: %v, gotUid: %v, gotGid: %v ",
				wantUid, wantGid, gotUid, gotGid)
		}
	})

	t.Run("should-be-noop-when-user-and-group-are-both-empty", func(t *testing.T) {
		outDir, err := os.MkdirTemp("", "")
		if err != nil {
			t.Error(err)
		}
		defer os.RemoveAll(outDir)
		outFile, err := os.CreateTemp(outDir, "")
		if err != nil {
			t.Error(err)
		}
		contents := []byte("first")
		if _, err := outFile.Write(contents); err != nil {
			t.Error(err)
		}
		path := outFile.Name()
		if err = outFile.Close(); err != nil {
			t.Error(err)
		}

		// getting file uid:gid for the default behaviour
		wantUid, wantGid, err := getFileOwnership(path)
		if err != nil {
			t.Errorf("getFileOwnership: %s", err)
		}

		rr, err := Render(&RenderInput{
			Path:     path,
			Contents: contents,
			User:     "",
			Group:    "",
		})
		if err != nil {
			t.Error(err)
		}
		switch {
		case rr.WouldRender && !rr.DidRender:
		default:
			t.Errorf("Bad render results; would: %v, did: %v",
				rr.WouldRender, rr.DidRender)
		}

		gotUid, gotGid, err := getFileOwnership(path)
		if err != nil {
			t.Errorf("getFileOwnership: %s", err)
		}
		if gotUid != wantUid || gotGid != wantGid {
			t.Errorf("Bad render results; we shouldn't have altered uid/gid. wantUid: %v, wantGid: %v, gotUid: %v, gotGid: %v ",
				wantUid, wantGid, gotUid, gotGid)
		}
	})
	t.Run("should-be-noop-user-only-second-pass", func(t *testing.T) {
		outDir, err := os.MkdirTemp("", "")
		if err != nil {
			t.Error(err)
		}
		defer os.RemoveAll(outDir)
		outFile, err := os.CreateTemp(outDir, "")
		if err != nil {
			t.Error(err)
		}
		contents := []byte("first")
		if _, err := outFile.Write(contents); err != nil {
			t.Error(err)
		}
		path := outFile.Name()
		if err = outFile.Close(); err != nil {
			t.Error(err)
		}

		// getting file uid:gid for the default behaviour
		wantUid, wantGid, err := getFileOwnership(path)
		if err != nil {
			t.Errorf("getFileOwnership: %s", err)
		}

		rr, err := Render(&RenderInput{
			Path:     path,
			Contents: contents,
			User:     fmt.Sprint(wantUid),
		})
		if err != nil {
			t.Error(err)
		}
		switch {
		case rr.WouldRender && !rr.DidRender:
		default:
			t.Errorf("Bad render results; would: %v, did: %v",
				rr.WouldRender, rr.DidRender)
		}

		gotUid, gotGid, err := getFileOwnership(path)
		if err != nil {
			t.Errorf("getFileOwnership: %s", err)
		}
		if gotUid != wantUid || gotGid != wantGid {
			t.Errorf("Bad render results; we shouldn't have altered uid/gid. wantUid: %v, wantGid: %v, gotUid: %v, gotGid: %v ",
				wantUid, wantGid, gotUid, gotGid)
		}
	})
	t.Run("should-be-noop-group-only-second-pass", func(t *testing.T) {
		outDir, err := os.MkdirTemp("", "")
		if err != nil {
			t.Error(err)
		}
		defer os.RemoveAll(outDir)
		outFile, err := os.CreateTemp(outDir, "")
		if err != nil {
			t.Error(err)
		}
		contents := []byte("first")
		if _, err := outFile.Write(contents); err != nil {
			t.Error(err)
		}
		path := outFile.Name()
		if err = outFile.Close(); err != nil {
			t.Error(err)
		}

		// getting file uid:gid for the default behaviour
		wantUid, wantGid, err := getFileOwnership(path)
		if err != nil {
			t.Errorf("getFileOwnership: %s", err)
		}

		rr, err := Render(&RenderInput{
			Path:     path,
			Contents: contents,
			Group:    fmt.Sprint(wantGid),
		})
		if err != nil {
			t.Error(err)
		}
		switch {
		case rr.WouldRender && !rr.DidRender:
		default:
			t.Errorf("Bad render results; would: %v, did: %v",
				rr.WouldRender, rr.DidRender)
		}

		gotUid, gotGid, err := getFileOwnership(path)
		if err != nil {
			t.Errorf("getFileOwnership: %s", err)
		}
		if gotUid != wantUid || gotGid != wantGid {
			t.Errorf("Bad render results; we shouldn't have altered uid/gid. wantUid: %v, wantGid: %v, gotUid: %v, gotGid: %v ",
				wantUid, wantGid, gotUid, gotGid)
		}
	})
}
