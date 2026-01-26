// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package logical

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/go-test/deep"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/require"
)

var keyList = []string{
	"a",
	"b",
	"d",
	"foo",
	"foo42",
	"foo/a/b/c",
	"c/d/e/f/g",
	"bar/bar/bar",
	"bar/bar/bar/bar",
	"bar/bar/bar/bar/",
}

func TestScanView(t *testing.T) {
	s := prepKeyStorage(t)

	keys := make([]string, 0)
	err := ScanView(context.Background(), s, func(path string) {
		keys = append(keys, path)
	})
	if err != nil {
		t.Fatal(err)
	}

	if diff := deep.Equal(keys, keyList); diff != nil {
		t.Fatal(diff)
	}
}

func TestScanView_CancelContext(t *testing.T) {
	s := prepKeyStorage(t)

	ctx, cancelCtx := context.WithCancel(context.Background())
	var i int
	err := ScanView(ctx, s, func(path string) {
		cancelCtx()
		i++
	})

	if err == nil {
		t.Error("Want context cancel err, got none")
	}
	if i != 1 {
		t.Errorf("Want i==1, got %d", i)
	}
}

func TestScanViewPaginated(t *testing.T) {
	s := prepKeyStorage(t)

	keys := make([]string, 0)
	err := ScanViewWithLogger(context.Background(), s, nil, func(path string) {
		keys = append(keys, path)
	})
	if err != nil {
		t.Fatal(err)
	}

	if diff := deep.Equal(keys, keyList); diff != nil {
		t.Fatal(diff)
	}

	// Validate that recursing into a folder which only has references to
	// itself and/or files which bear the same name works.
	v := NewStorageView(s, "bar/")
	logger := hclog.NewNullLogger()
	for pageSize := 2; pageSize < 10; pageSize++ {
		keys = make([]string, 0)
		err = ScanViewPaginated(context.Background(), v, logger, pageSize, func(_ int, _ int, path string) (bool, error) {
			keys = append(keys, path)
			return true, nil
		})
		if err != nil {
			t.Fatal(err)
		}

		trimmedExpected := make([]string, 0)
		for _, path := range keyList[len(keyList)-3:] {
			trimmedExpected = append(trimmedExpected, strings.TrimPrefix(path, "bar/"))
		}
		if diff := deep.Equal(keys, trimmedExpected); diff != nil {
			t.Fatalf("page size: %v\ndiff: %v\n\tkeys: %v\n\texpected: %v", pageSize, diff, keys, trimmedExpected)
		}
	}
}

func TestCollectKeys(t *testing.T) {
	s := prepKeyStorage(t)

	keys, err := CollectKeys(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}

	if diff := deep.Equal(keys, keyList); diff != nil {
		t.Fatal(diff)
	}
}

func TestCollectKeysPrefix(t *testing.T) {
	s := prepKeyStorage(t)

	keys, err := CollectKeysWithPrefix(context.Background(), s, "foo")
	if err != nil {
		t.Fatal(err)
	}

	exp := []string{
		"foo",
		"foo42",
		"foo/a/b/c",
	}

	if diff := deep.Equal(keys, exp); diff != nil {
		t.Fatal(diff)
	}
}

func TestClearView(t *testing.T) {
	s := prepKeyStorage(t)

	keys, err := CollectKeys(context.Background(), s)
	require.NoError(t, err)
	require.Equal(t, keys, keyList)

	err = ClearView(context.Background(), s)
	require.NoError(t, err)

	keys, err = CollectKeys(context.Background(), s)
	require.Nil(t, err)
	require.Empty(t, keys)
}

func TestClearPaginatedView(t *testing.T) {
	s := prepKeyStorage(t)

	keys, err := CollectKeys(context.Background(), s)
	require.NoError(t, err)
	require.Equal(t, keys, keyList)

	err = ClearViewWithPagination(context.Background(), s, hclog.NewNullLogger())
	require.NoError(t, err)

	keys, err = CollectKeys(context.Background(), s)
	require.Nil(t, err)
	require.Empty(t, keys)
}

func TestClearUnpaginatedView(t *testing.T) {
	s := prepKeyStorage(t)

	keys, err := CollectKeys(context.Background(), s)
	require.NoError(t, err)
	require.Equal(t, keys, keyList)

	err = ClearViewWithoutPagination(context.Background(), s, hclog.NewNullLogger())
	require.NoError(t, err)

	keys, err = CollectKeys(context.Background(), s)
	require.Nil(t, err)
	require.Empty(t, keys)
}

func TestHandleListPageTermination(t *testing.T) {
	s := prepKeyStorage(t)

	keys, err := s.List(context.Background(), "")
	require.NoError(t, err)

	var seenKeys []string
	var batchCount int
	err = HandleListPage(context.Background(), s, "", 2, func(page int, index int, entry string) (bool, error) {
		seenKeys = append(seenKeys, entry)
		return true, nil
	}, func(page int, entries []string) (bool, error) {
		batchCount += 1
		return true, nil
	})
	require.NoError(t, err)
	require.ElementsMatch(t, seenKeys, keys)
	require.Equal(t, batchCount, len(keys)/2)

	var immediateCancel bool
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err = HandleListPage(ctx, s, "", 2, func(page int, index int, entry string) (bool, error) {
		immediateCancel = false
		time.Sleep(1 * time.Second)
		return true, nil
	}, func(page int, entries []string) (bool, error) {
		immediateCancel = false
		time.Sleep(1 * time.Second)
		return true, nil
	})

	require.Error(t, err)
	require.False(t, immediateCancel)
	require.Contains(t, err.Error(), "context")
}

func prepKeyStorage(t *testing.T) Storage {
	t.Helper()
	s := &InmemStorage{}

	for _, key := range keyList {
		if err := s.Put(context.Background(), &StorageEntry{
			Key:      key,
			Value:    nil,
			SealWrap: false,
		}); err != nil {
			t.Fatal(err)
		}
	}

	return s
}
