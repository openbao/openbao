// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package locksutil

import (
	"context"
	"testing"
	"testing/synctest"

	"github.com/stretchr/testify/require"
)

func TestKeyedCancelLock(t *testing.T) {
	ctx := t.Context()

	t.Run("Lock+Unlock", func(t *testing.T) {
		l := NewKeyedCancelLock[int]()

		require.NoError(t, l.Lock(ctx, 1))
		require.Len(t, l.locks, 1)

		l.Unlock(1)
		require.Empty(t, l.locks)

		require.NoError(t, l.Lock(ctx, 1))
		require.Len(t, l.locks, 1)

		require.NoError(t, l.Lock(ctx, 2))
		require.Len(t, l.locks, 2)

		l.Unlock(1)
		l.Unlock(2)
	})

	t.Run("UnlockTwice", func(t *testing.T) {
		l := NewKeyedCancelLock[int]()

		require.Panics(t, func() { l.Unlock(1) })
		require.Empty(t, l.locks)

		require.NoError(t, l.Lock(ctx, 1))
		require.Len(t, l.locks, 1)

		l.Unlock(1)
		require.Empty(t, l.locks)

		require.Panics(t, func() { l.Unlock(1) })
		require.Empty(t, l.locks)
	})

	t.Run("Cancel", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ctx := context.Background()

			l := NewKeyedCancelLock[int]()
			require.NoError(t, l.Lock(ctx, 1))

			canceled, cancel := context.WithCancel(ctx)

			var err error
			go func() {
				err = l.Lock(canceled, 1)
			}()

			synctest.Wait()
			cancel()
			synctest.Wait()

			require.Error(t, err)
			require.Len(t, l.locks, 1)

			l.Unlock(1)
			require.Empty(t, l.locks)
		})
	})

	t.Run("LockWhileUnlock", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ctx := context.Background()

			l := NewKeyedCancelLock[int]()
			require.NoError(t, l.Lock(ctx, 1))

			l.mu.Lock()

			go l.mu.Unlock()
			go l.Unlock(1)
			go func() {
				require.NoError(t, l.Lock(ctx, 1))
			}()

			synctest.Wait()

			require.Len(t, l.locks, 1)
			require.Equal(t, l.locks[1].refs, 1)
		})
	})
}
