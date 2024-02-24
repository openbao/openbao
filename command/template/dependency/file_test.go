// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package dependency

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func init() {
	FileQuerySleepTime = 50 * time.Millisecond
}

func TestNewFileQuery(t *testing.T) {
	cases := []struct {
		name string
		i    string
		exp  *FileQuery
		err  bool
	}{
		{
			"empty",
			"",
			nil,
			true,
		},
		{
			"path",
			"path",
			&FileQuery{
				path: "path",
			},
			false,
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			act, err := NewFileQuery(tc.i)
			if (err != nil) != tc.err {
				t.Fatal(err)
			}

			if act != nil {
				act.stopCh = nil
			}

			assert.Equal(t, tc.exp, act)
		})
	}
}

func TestFileQuery_Fetch(t *testing.T) {
	f, err := os.CreateTemp("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString("hello world"); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		i    string
		exp  string
		err  bool
	}{
		{
			"non_existent",
			"/not/a/real/path/ever",
			"",
			true,
		},
		{
			"contents",
			f.Name(),
			"hello world",
			false,
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			d, err := NewFileQuery(tc.i)
			if err != nil {
				t.Fatal(err)
			}

			act, _, err := d.Fetch(nil, nil)
			if (err != nil) != tc.err {
				t.Fatal(err)
			}

			assert.Equal(t, tc.exp, act)
		})
	}

	t.Run("stops", func(t *testing.T) {
		f, err := os.CreateTemp("", "")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(f.Name())

		d, err := NewFileQuery(f.Name())
		if err != nil {
			t.Fatal(err)
		}

		errCh := make(chan error, 1)
		go func() {
			for {
				_, _, err := d.Fetch(nil, nil)
				if err != nil {
					errCh <- err
					return
				}
			}
		}()

		d.Stop()

		select {
		case err := <-errCh:
			if err != ErrStopped {
				t.Fatal(err)
			}
		case <-time.After(100 * time.Millisecond):
			t.Errorf("did not stop")
		}
	})

	syncWriteFile := func(name string, data []byte, perm os.FileMode) error {
		f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|os.O_SYNC, perm)
		if err == nil {
			_, err = f.Write(data)
			if err1 := f.Close(); err1 != nil && err == nil {
				err = err1
			}
		}
		return err
	}
	t.Run("fires_changes", func(t *testing.T) {
		f, err := os.CreateTemp("", "")
		if err != nil {
			t.Fatal(err)
		}
		if err := syncWriteFile(f.Name(), []byte("hello"), 0o644); err != nil {
			t.Fatal(err)
		}
		defer os.Remove(f.Name())

		d, err := NewFileQuery(f.Name())
		if err != nil {
			t.Fatal(err)
		}

		dataCh := make(chan interface{}, 1)
		errCh := make(chan error, 1)
		go func() {
			for {
				data, _, err := d.Fetch(nil, nil)
				if err != nil {
					errCh <- err
					return
				}
				dataCh <- data
			}
		}()
		defer d.Stop()

		select {
		case err := <-errCh:
			t.Fatal(err)
		case <-dataCh:
		}

		if err := syncWriteFile(f.Name(), []byte("goodbye"), 0o644); err != nil {
			t.Fatal(err)
		}

		select {
		case err := <-errCh:
			t.Fatal(err)
		case data := <-dataCh:
			assert.Equal(t, "goodbye", data)
		}
	})
}

func TestFileQuery_String(t *testing.T) {
	cases := []struct {
		name string
		i    string
		exp  string
	}{
		{
			"path",
			"path",
			"file(path)",
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			d, err := NewFileQuery(tc.i)
			if err != nil {
				t.Fatal(err)
			}
			assert.Equal(t, tc.exp, d.String())
		})
	}
}
