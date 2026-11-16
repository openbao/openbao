// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package locksutil

import (
	"context"
	"testing"
	"testing/synctest"

	"github.com/stretchr/testify/require"
)

func TestCancelLock(t *testing.T) {
	ctx := t.Context()

	// Can lock and unlock immediately:
	t.Run("Lock+Unlock", func(t *testing.T) {
		l := NewCancelLock()
		require.NoError(t, l.Lock(ctx))
		l.Unlock()
	})

	// Unlocking twice panics:
	t.Run("UnlockTwice", func(t *testing.T) {
		l := NewCancelLock()
		require.Panics(t, l.Unlock)

		require.NoError(t, l.Lock(ctx))
		l.Unlock()
		require.Panics(t, l.Unlock)
	})

	// Lock fails if the context expires during acquisition:
	t.Run("Cancel", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			l := NewCancelLock()
			ctx := context.Background()

			require.NoError(t, l.Lock(ctx))

			canceled, cancel := context.WithCancel(ctx)

			var err error
			go func() {
				err = l.Lock(canceled)
			}()

			synctest.Wait()
			cancel()
			synctest.Wait()

			require.Error(t, err)
		})
	})

	// Can wait for a lock to unlock:
	t.Run("Wait", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			l := NewCancelLock()
			ctx := context.Background()

			require.NoError(t, l.Lock(ctx))

			var locked bool

			go l.Unlock()
			go func() {
				require.NoError(t, l.Lock(ctx))
				locked = true
			}()

			synctest.Wait()
			require.True(t, locked)
		})
	})
}
